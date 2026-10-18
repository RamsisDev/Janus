package org.janusknot.janus

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.io.IOException
import java.util.concurrent.Executors
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import uniffi.janus_ffi.Client
import uniffi.janus_ffi.Contact
import uniffi.janus_ffi.DevMailbox
import uniffi.janus_ffi.Event
import uniffi.janus_ffi.HistoryEntry
import uniffi.janus_ffi.JanusException
import uniffi.janus_ffi.NetworkInfo

/**
 * The app's one [Client] and what the screens show, shared by the activity and the background
 * worker. Every client call runs on one thread of its own, since any of them can wait on the
 * network; everything else runs on the main thread.
 */
class AppModel(private val context: Context) {
    /** A's side of an invitation. */
    sealed interface Invitation {
        /** Showing the 6 words until B answers. */
        data class Waiting(val words: String, val network: String) : Invitation

        /** B answered: the user types the 3 safety words B reads out. */
        data object Answered : Invitation
    }

    /** B's side of an invitation. */
    sealed interface Answer {
        data object Looking : Answer

        /** Showing the safety words until A says they match. */
        data class Joined(val contact: String, val safetyWords: String) : Answer
    }

    var contacts by mutableStateOf(emptyList<Contact>())
        private set
    var networks by mutableStateOf(emptyList<NetworkInfo>())
        private set
    val histories = mutableStateMapOf<String, List<HistoryEntry>>()
    var unread by mutableStateOf(emptySet<String>())
        private set
    var invitation by mutableStateOf<Invitation?>(null)
    var answer by mutableStateOf<Answer?>(null)
    /** Why the client could not open, or why the last tick failed. */
    var trouble by mutableStateOf<String?>(null)
        private set
    var hardwareBacked by mutableStateOf(true)
        private set
    /** The chat on screen, which reloads when a message arrives. */
    var openChat: String? = null

    private var client: Client? = null
    private val thread = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
    private val opening by lazy { MainScope().async { start() } }

    suspend fun open() = opening.await()

    suspend fun run() {
        open()
        while (true) {
            tick()
            delay(1000)
        }
    }

    /** A background wake-up. */
    suspend fun wake() {
        open()
        repeat(25) {
            tick()
            delay(1000)
        }
    }

    suspend fun invite(network: String, hours: UByte) {
        val words = call { it.invite(network, hours) }
        invitation = Invitation.Waiting(words, networks.firstOrNull { it.id == network }?.name.orEmpty())
    }

    suspend fun verify(typed: String, name: String) {
        call { it.verify(typed, name) }
        invitation = null
        refresh()
    }

    suspend fun join(network: String, words: String) {
        call { it.join(network, words) }
        answer = Answer.Looking
    }

    suspend fun confirm(contact: String, name: String) {
        call { it.confirm(contact, name) }
        answer = null
        refresh()
    }

    suspend fun send(text: String, contact: String) {
        call { it.send(contact, text.toByteArray()) }
        load(contact)
    }

    suspend fun close(contact: String) {
        call { it.close(contact) }
        if ((answer as? Answer.Joined)?.contact == contact) answer = null
        histories.remove(contact)
        refresh()
    }

    suspend fun safetyWords(contact: String): String? = call { it.safetyWords(contact) }

    suspend fun install(profile: ByteArray) {
        call { it.installNetwork(profile) }
        refresh()
    }

    suspend fun load(contact: String) {
        unread = unread - contact
        try {
            histories[contact] = call { it.history(contact) }
        } catch (e: JanusException) {
            histories.remove(contact)
        }
    }

    private suspend fun start() {
        try {
            val platform = withContext(thread) { AndroidPlatform(context) }
            hardwareBacked = platform.hardwareBacked
            val dev = devMailbox()
            client = withContext(thread) { Client(platform, dev) }
            refresh()
        } catch (e: Exception) {
            trouble = describe(e)
        }
    }

    private suspend fun tick() {
        if (client == null) return
        val events = try {
            call { it.tick() }.also { trouble = null }
        } catch (e: JanusException) {
            trouble = describe(e)
            return
        }
        for (event in events) {
            when (event) {
                Event.Answered -> if (invitation is Invitation.Waiting) invitation = Invitation.Answered
                is Event.Joined -> answer = Answer.Joined(event.contact, event.safetyWords)
                is Event.Message -> if (event.contact == openChat) {
                    load(event.contact)
                } else {
                    unread = unread + event.contact
                    histories.remove(event.contact)
                }
                is Event.Closed -> histories.remove(event.contact)
                is Event.Dormant, is Event.Awake -> {}
            }
        }
        if (events.isNotEmpty()) refresh()
    }

    private suspend fun refresh() {
        contacts = call { it.contacts() }
        networks = call { it.networks() }
    }

    private suspend fun <T> call(work: (Client) -> T): T {
        val client = client ?: throw JanusException.Storage("the client is not open")
        return withContext(thread) { work(client) }
    }

    /** The development mailbox of debug builds, if `make android` found its certificate. */
    private fun devMailbox(): DevMailbox? {
        if (!BuildConfig.DEBUG || BuildConfig.DEV_MAILBOX.isEmpty()) return null
        val cert = try {
            context.assets.open("mailbox.der").use { it.readBytes() }
        } catch (e: IOException) {
            return null
        }
        return DevMailbox(BuildConfig.DEV_MAILBOX, cert)
    }
}

fun describe(e: Throwable): String = when (e) {
    is JanusException.BadWords -> "Exactly 6 words from the list are needed."
    is JanusException.Expired -> "The invitation expired. Start a new one."
    is JanusException.Rejected -> "The words do not match."
    is JanusException.NotConfirmed -> "The safety words are not confirmed yet."
    is JanusException.TooLarge -> "The message is over 16 MB."
    is JanusException.UnknownNetwork -> "That network is not installed."
    is JanusException.BadProfile -> "This is not a network profile."
    is JanusException.UnknownContact -> "That contact no longer exists."
    is JanusException.BadInterval -> "Pick one of the offered intervals."
    is JanusException.BadKey -> "The storage key is damaged."
    is JanusException.Storage -> "Storage failed: ${e.reason}"
    else -> e.message ?: e.toString()
}

/** Words as the core expects them: lowercase, single spaces. */
fun words(typed: String): String =
    typed.lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ")
