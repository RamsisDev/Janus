package org.janusknot.janus

import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.io.FileOutputStream
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import uniffi.janus_ffi.Platform

/**
 * What the client needs from the OS: the storage key, a clock that counts during sleep, and a
 * data directory that is never backed up (`noBackupFilesDir`).
 */
class AndroidPlatform(context: Context) : Platform {
    private val dir = File(context.noBackupFilesDir, "janus").apply { mkdirs() }
    private val key: ByteArray
    /** Whether StrongBox or the TEE holds the wrapping key; otherwise only software does. */
    val hardwareBacked: Boolean

    init {
        val (key, hardwareBacked) = StorageKey.load(File(context.noBackupFilesDir, "storage-key"))
        this.key = key
        this.hardwareBacked = hardwareBacked
    }

    override fun storageKey(): ByteArray = key

    override fun nowMs(): ULong = SystemClock.elapsedRealtime().toULong()

    override fun dataDir(): String = dir.path
}

/**
 * 32 random bytes made on first launch, stored wrapped by an AES key that never leaves the
 * Android Keystore: in StrongBox where the device has it, else in the TEE. The wrapping key
 * needs no user authentication, so background work can open the client; the app lock is a
 * separate gate.
 */
private object StorageKey {
    private const val ALIAS = "janus-storage-wrap"
    private const val IV_LEN = 12

    fun load(file: File): Pair<ByteArray, Boolean> {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val wrap = keyStore.getKey(ALIAS, null) as SecretKey? ?: create()
        if (file.exists()) {
            val stored = file.readBytes()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, wrap, GCMParameterSpec(128, stored, 0, IV_LEN))
            return cipher.doFinal(stored, IV_LEN, stored.size - IV_LEN) to inHardware(wrap)
        }
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrap)
        val temp = File(file.path + ".tmp")
        FileOutputStream(temp).use {
            it.write(cipher.iv + cipher.doFinal(key))
            it.fd.sync()
        }
        check(temp.renameTo(file)) { "could not store the storage key" }
        // Without both syncs, a power loss can keep the rename and lose the bytes.
        FileChannel.open(file.parentFile!!.toPath(), StandardOpenOption.READ).use { it.force(true) }
        return key to inHardware(wrap)
    }

    private fun create(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        fun generate(strongBox: Boolean): SecretKey {
            val spec = KeyGenParameterSpec.Builder(
                ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setIsStrongBoxBacked(strongBox)
                .build()
            generator.init(spec)
            return generator.generateKey()
        }
        return try {
            generate(strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }
    }

    private fun inHardware(key: SecretKey): Boolean {
        val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
        val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            info.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE
        } else {
            @Suppress("DEPRECATION")
            info.isInsideSecureHardware
        }
    }
}
