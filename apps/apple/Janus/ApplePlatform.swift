import Darwin
import Foundation
import Security

/// What the client needs from the OS: the storage key, a clock that counts during sleep, and a
/// data directory kept out of backups.
final class ApplePlatform: Platform {
    let key: Data
    let dir: URL
    /// Whether the Secure Enclave wraps the storage key; without it the Keychain alone keeps it.
    let hardwareBacked: Bool

    init() throws {
        dir = try Self.dataDirectory()
        (key, hardwareBacked) = try StorageKey.load()
    }

    func storageKey() -> Data {
        key
    }

    func nowMs() -> UInt64 {
        var timebase = mach_timebase_info_data_t()
        mach_timebase_info(&timebase)
        let ticks = mach_continuous_time().multipliedFullWidth(by: UInt64(timebase.numer))
        return UInt64(timebase.denom).dividingFullWidth(ticks).quotient / 1_000_000
    }

    func dataDir() -> String {
        dir.path
    }

    /// Restoring a backup is a rollback that breaks sessions and revives deleted keys, so the
    /// whole directory is excluded from iCloud and computer backups.
    private static func dataDirectory() throws -> URL {
        var dir = try FileManager.default
            .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil,
                 create: true)
            .appendingPathComponent("janus", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try dir.setResourceValues(values)
        return dir
    }
}

struct KeychainError: Error {
    let status: OSStatus
}

/// 32 random bytes made on first launch, kept in the Keychain for this device only (never
/// synced or restored elsewhere), wrapped by a Secure Enclave key that never leaves the chip.
/// The key is readable after the first unlock, so background wake-ups can open the client.
enum StorageKey {
    private static let service = "org.janusknot.janus"
    private static let account = "storage-key"
    private static let tag = Data("org.janusknot.janus.storage-wrap".utf8)
    private static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    /// The first byte of the stored item: whether the rest is wrapped.
    private static let wrapped: UInt8 = 1
    private static let plain: UInt8 = 0

    static func load() throws -> (Data, Bool) {
        if let stored = try read() {
            let body = Data(stored.dropFirst())
            return stored.first == wrapped ? (try unwrap(body), true) : (body, false)
        }
        var key = Data(count: 32)
        let status = key.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw KeychainError(status: status) }
        if let enclave = try? enclaveKey(),
           let publicKey = SecKeyCopyPublicKey(enclave),
           let sealed = SecKeyCreateEncryptedData(publicKey, algorithm, key as CFData, nil) {
            try write(Data([wrapped]) + (sealed as Data))
            return (key, true)
        }
        try write(Data([plain]) + key)
        return (key, false)
    }

    private static func unwrap(_ sealed: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateDecryptedData(try enclaveKey(), algorithm, sealed as CFData,
                                                  &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return key as Data
    }

    /// The Secure Enclave key, created on first use.
    private static func enclaveKey() throws -> SecKey {
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain: true,
            kSecReturnRef: true,
        ]
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess {
            return item as! SecKey
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error)
        else {
            throw error!.takeRetainedValue() as Error
        }
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain: true,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag,
                kSecAttrAccessControl: access,
            ] as [CFString: Any],
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return key
    }

    private static var item: [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: true,
        ]
    }

    private static func read() throws -> Data? {
        var query = item
        query[kSecReturnData] = true
        var data: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &data)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError(status: status) }
        return data as? Data
    }

    private static func write(_ data: Data) throws {
        var query = item
        query[kSecValueData] = data
        query[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        query[kSecAttrSynchronizable] = false
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }
}
