// Shared by BOTH targets.
// Long-term device identity and pairing records (ADR-001 §2.2).
// All Keychain items are device-only: never synced to iCloud, never in backups, never exportable.
import Foundation
import CryptoKit
import Security

struct PairedDevice: Codable, Equatable, Identifiable {
    var publicKey: Data
    var name: String
    var pairedAt: Date
    var id: Data { publicKey }

    /// Short fingerprint for display, e.g. "3F9A·C21B".
    var fingerprint: String {
        let hex = Noise.hash(publicKey).prefix(4).map { String(format: "%02X", $0) }.joined()
        return "\(hex.prefix(4))·\(hex.suffix(4))"
    }
}

protocol PairingStore: AnyObject {
    /// Throws on storage errors so callers can fail closed instead of treating the peer as unknown.
    func contains(_ publicKey: Data) throws -> Bool
    func save(_ device: PairedDevice) throws
    func remove(_ publicKey: Data) throws
    func all() -> [PairedDevice]
}

enum KeychainError: Error, Equatable {
    case status(OSStatus)
    case corruptItem
}

enum Keychain {
    static let identityService = "com.msahalkc.extend.identity"
    static let peerService = "com.msahalkc.extend.peer"

    /// Base query. On macOS this uses the data-protection keychain so the iOS accessibility
    /// semantics (ThisDeviceOnly) apply there too.
    static func query(service: String, account: String? = nil) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: kCFBooleanFalse!,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let account { q[kSecAttrAccount as String] = account }
        return q
    }

    static func read(service: String, account: String) throws -> Data? {
        var q = query(service: service, account: account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecItemNotFound { return nil }
        guard st == errSecSuccess else { throw KeychainError.status(st) }
        guard let data = out as? Data else { throw KeychainError.corruptItem }
        return data
    }

    static func write(service: String, account: String, data: Data) throws {
        let q = query(service: service, account: account)
        let attrs: [String: Any] = [kSecValueData as String: data,
                                    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let update = SecItemUpdate(q as CFDictionary, attrs as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw KeychainError.status(update) }
        var add = q
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let st = SecItemAdd(add as CFDictionary, nil)
        guard st == errSecSuccess else { throw KeychainError.status(st) }
    }

    static func delete(service: String, account: String? = nil) throws {
        let st = SecItemDelete(query(service: service, account: account) as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw KeychainError.status(st) }
    }
}

enum Identity {
    private static let account = "static-x25519"

    /// This install's long-term X25519 key, created on first use.
    static func loadOrCreate() throws -> Curve25519.KeyAgreement.PrivateKey {
        if let raw = try Keychain.read(service: Keychain.identityService, account: account) {
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw)
        }
        let key = Curve25519.KeyAgreement.PrivateKey()
        try Keychain.write(service: Keychain.identityService, account: account, data: key.rawRepresentation)
        return key
    }
}

/// Pairing records in the Keychain, one item per peer (account = hex public key).
final class KeychainPairingStore: PairingStore {
    private let service: String

    init(service: String = Keychain.peerService) { self.service = service }

    func contains(_ publicKey: Data) throws -> Bool {
        try Keychain.read(service: service, account: Self.account(publicKey)) != nil
    }

    func save(_ device: PairedDevice) throws {
        try Keychain.write(service: service, account: Self.account(device.publicKey),
                           data: JSONEncoder().encode(device))
    }

    func remove(_ publicKey: Data) throws {
        try Keychain.delete(service: service, account: Self.account(publicKey))
    }

    func all() -> [PairedDevice] {
        var q = Keychain.query(service: service)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitAll
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let items = out as? [Data] else { return [] }
        return items.compactMap { try? JSONDecoder().decode(PairedDevice.self, from: $0) }
            .sorted { $0.pairedAt < $1.pairedAt }
    }

    private static func account(_ key: Data) -> String { key.map { String(format: "%02x", $0) }.joined() }
}

/// For tests and previews.
final class InMemoryPairingStore: PairingStore {
    private var devices: [Data: PairedDevice] = [:]
    func contains(_ publicKey: Data) -> Bool { devices[publicKey] != nil }
    func save(_ device: PairedDevice) throws { devices[device.publicKey] = device }
    func remove(_ publicKey: Data) throws { devices[publicKey] = nil }
    func all() -> [PairedDevice] { devices.values.sorted { $0.pairedAt < $1.pairedAt } }
}
