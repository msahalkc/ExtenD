// Shared by BOTH targets.
// Noise_XX_25519_AESGCM_SHA256, following the Noise Protocol Framework spec (revision 34),
// https://noiseprotocol.org/noise.html. Only what ExtenD needs: the XX pattern, no PSK.
// Section numbers in comments refer to that spec. Verified against official test vectors (ExtenDTests).
import Foundation
import CryptoKit

enum NoiseError: Error, Equatable {
    case decryptFailed
    case nonceExhausted
    case malformedMessage
    case wrongTurn
    case handshakeComplete
    case missingKey
}

enum Noise {
    static let protocolName = "Noise_XX_25519_AESGCM_SHA256"
    static let dhLen = 32
    static let hashLen = 32
    static let tagLen = 16
    static let maxMessageLen = 65535

    // MARK: - Crypto functions (§4)

    static func dh(_ priv: Curve25519.KeyAgreement.PrivateKey, _ pub: Data) throws -> Data {
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pub)
        let shared = try priv.sharedSecretFromKeyAgreement(with: peer)
        return shared.withUnsafeBytes { Data($0) }
    }

    /// AESGCM nonce: 32 bits of zeros followed by the big-endian 64-bit counter (§12.2).
    static func encrypt(_ k: SymmetricKey, _ n: UInt64, _ ad: Data, _ plaintext: Data) throws -> Data {
        let box = try AES.GCM.seal(plaintext, using: k, nonce: nonce(n), authenticating: ad)
        return box.ciphertext + box.tag
    }

    static func decrypt(_ k: SymmetricKey, _ n: UInt64, _ ad: Data, _ ciphertext: Data) throws -> Data {
        guard ciphertext.count >= tagLen else { throw NoiseError.decryptFailed }
        do {
            let split = ciphertext.endIndex - tagLen
            let box = try AES.GCM.SealedBox(nonce: nonce(n), ciphertext: ciphertext[..<split], tag: ciphertext[split...])
            return try AES.GCM.open(box, using: k, authenticating: ad)
        } catch {
            throw NoiseError.decryptFailed
        }
    }

    private static func nonce(_ n: UInt64) throws -> AES.GCM.Nonce {
        var bytes = Data(count: 4)
        withUnsafeBytes(of: n.bigEndian) { bytes.append(contentsOf: $0) }
        return try AES.GCM.Nonce(data: bytes)
    }

    static func hash(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

    static func hmac(_ key: Data, _ data: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    /// Noise HKDF (§4.3): returns 2 or 3 outputs of HASHLEN bytes.
    static func hkdf(_ chainingKey: Data, _ ikm: Data, outputs: Int) -> [Data] {
        let temp = hmac(chainingKey, ikm)
        let o1 = hmac(temp, Data([0x01]))
        let o2 = hmac(temp, o1 + Data([0x02]))
        if outputs == 2 { return [o1, o2] }
        let o3 = hmac(temp, o2 + Data([0x03]))
        return [o1, o2, o3]
    }
}

// MARK: - CipherState (§5.1)

struct CipherState {
    private(set) var key: SymmetricKey?
    private(set) var n: UInt64 = 0

    init(key: Data? = nil) { if let key { self.key = SymmetricKey(data: key) } }

    var hasKey: Bool { key != nil }

    mutating func encryptWithAd(_ ad: Data, _ plaintext: Data) throws -> Data {
        guard let key else { return plaintext }
        guard n < UInt64.max else { throw NoiseError.nonceExhausted }   // 2^64-1 is reserved
        let out = try Noise.encrypt(key, n, ad, plaintext)
        n += 1
        return out
    }

    mutating func decryptWithAd(_ ad: Data, _ ciphertext: Data) throws -> Data {
        guard let key else { return ciphertext }
        guard n < UInt64.max else { throw NoiseError.nonceExhausted }
        let out = try Noise.decrypt(key, n, ad, ciphertext)   // n only advances on success
        n += 1
        return out
    }

    /// REKEY (§4.2): k = first 32 bytes of ENCRYPT(k, maxnonce, zerolen, zeros).
    mutating func rekey() throws {
        guard let key else { throw NoiseError.missingKey }
        let out = try Noise.encrypt(key, UInt64.max, Data(), Data(count: 32))
        self.key = SymmetricKey(data: out.prefix(32))
    }
}

// MARK: - SymmetricState (§5.2)

struct SymmetricState {
    private(set) var cipher = CipherState()
    private(set) var ck: Data
    private(set) var h: Data

    init(protocolName: String) {
        let name = Data(protocolName.utf8)
        h = name.count <= Noise.hashLen ? name + Data(count: Noise.hashLen - name.count) : Noise.hash(name)
        ck = h
    }

    mutating func mixKey(_ ikm: Data) {
        let out = Noise.hkdf(ck, ikm, outputs: 2)
        ck = out[0]
        cipher = CipherState(key: out[1])   // HASHLEN == 32, no truncation needed
    }

    mutating func mixHash(_ data: Data) { h = Noise.hash(h + data) }

    mutating func encryptAndHash(_ plaintext: Data) throws -> Data {
        let c = try cipher.encryptWithAd(h, plaintext)
        mixHash(c)
        return c
    }

    mutating func decryptAndHash(_ ciphertext: Data) throws -> Data {
        let p = try cipher.decryptWithAd(h, ciphertext)
        mixHash(ciphertext)
        return p
    }

    func split() -> (CipherState, CipherState) {
        let out = Noise.hkdf(ck, Data(), outputs: 2)
        return (CipherState(key: out[0]), CipherState(key: out[1]))
    }
}

// MARK: - HandshakeState (§5.3), XX pattern only

/// XX:  -> e
///      <- e, ee, s, es
///      -> s, se
struct NoiseXXHandshake {
    enum Token { case e, s, ee, es, se }
    private static let pattern: [[Token]] = [[.e], [.e, .ee, .s, .es], [.s, .se]]

    /// Result once the third message is written/read.
    struct Result {
        var send: CipherState
        var receive: CipherState
        var handshakeHash: Data
        var remoteStatic: Data
    }

    let initiator: Bool
    private var symmetric: SymmetricState
    private let s: Curve25519.KeyAgreement.PrivateKey
    private var e: Curve25519.KeyAgreement.PrivateKey?
    private(set) var remoteStatic: Data?
    private var re: Data?
    private var step = 0

    /// `ephemeral` is for test vectors only; production code lets it be generated.
    init(initiator: Bool, prologue: Data, staticKey: Curve25519.KeyAgreement.PrivateKey,
         ephemeral: Curve25519.KeyAgreement.PrivateKey? = nil) {
        self.initiator = initiator
        self.s = staticKey
        self.e = ephemeral
        symmetric = SymmetricState(protocolName: Noise.protocolName)
        symmetric.mixHash(prologue)
    }

    var isComplete: Bool { step == Self.pattern.count }
    var handshakeHash: Data { symmetric.h }

    /// Whether it's this side's turn to write.
    var isMyTurn: Bool { !isComplete && (step % 2 == 0) == initiator }

    mutating func writeMessage(_ payload: Data = Data()) throws -> (message: Data, result: Result?) {
        guard !isComplete else { throw NoiseError.handshakeComplete }
        guard isMyTurn else { throw NoiseError.wrongTurn }
        var out = Data()
        for token in Self.pattern[step] {
            switch token {
            case .e:
                let key = e ?? Curve25519.KeyAgreement.PrivateKey()
                e = key
                out += key.publicKey.rawRepresentation
                symmetric.mixHash(key.publicKey.rawRepresentation)
            case .s:
                out += try symmetric.encryptAndHash(s.publicKey.rawRepresentation)
            default:
                try mixDH(token)
            }
        }
        out += try symmetric.encryptAndHash(payload)
        guard out.count <= Noise.maxMessageLen else { throw NoiseError.malformedMessage }
        step += 1
        return (out, try finishIfComplete())
    }

    mutating func readMessage(_ message: Data) throws -> (payload: Data, result: Result?) {
        guard !isComplete else { throw NoiseError.handshakeComplete }
        guard !isMyTurn else { throw NoiseError.wrongTurn }
        guard message.count <= Noise.maxMessageLen else { throw NoiseError.malformedMessage }
        var rest = message[...]
        for token in Self.pattern[step] {
            switch token {
            case .e:
                guard rest.count >= Noise.dhLen else { throw NoiseError.malformedMessage }
                let pub = Data(rest.prefix(Noise.dhLen))
                rest = rest.dropFirst(Noise.dhLen)
                re = pub
                symmetric.mixHash(pub)
            case .s:
                let len = Noise.dhLen + (symmetric.cipher.hasKey ? Noise.tagLen : 0)
                guard rest.count >= len else { throw NoiseError.malformedMessage }
                remoteStatic = try symmetric.decryptAndHash(Data(rest.prefix(len)))
                rest = rest.dropFirst(len)
            default:
                try mixDH(token)
            }
        }
        let payload = try symmetric.decryptAndHash(Data(rest))
        step += 1
        return (payload, try finishIfComplete())
    }

    private mutating func mixDH(_ token: Token) throws {
        guard let e else { throw NoiseError.missingKey }
        switch token {
        case .ee:
            guard let re else { throw NoiseError.missingKey }
            symmetric.mixKey(try Noise.dh(e, re))
        case .es:   // initiator: DH(e, rs); responder: DH(s, re)
            if initiator {
                guard let rs = remoteStatic else { throw NoiseError.missingKey }
                symmetric.mixKey(try Noise.dh(e, rs))
            } else {
                guard let re else { throw NoiseError.missingKey }
                symmetric.mixKey(try Noise.dh(s, re))
            }
        case .se:   // initiator: DH(s, re); responder: DH(e, rs)
            if initiator {
                guard let re else { throw NoiseError.missingKey }
                symmetric.mixKey(try Noise.dh(s, re))
            } else {
                guard let rs = remoteStatic else { throw NoiseError.missingKey }
                symmetric.mixKey(try Noise.dh(e, rs))
            }
        case .e, .s:
            break
        }
    }

    private mutating func finishIfComplete() throws -> Result? {
        guard isComplete else { return nil }
        guard let rs = remoteStatic else { throw NoiseError.missingKey }
        let (c1, c2) = symmetric.split()
        e = nil   // ephemeral private key is no longer needed
        return Result(send: initiator ? c1 : c2, receive: initiator ? c2 : c1,
                      handshakeHash: symmetric.h, remoteStatic: rs)
    }
}
