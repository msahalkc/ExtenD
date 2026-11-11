// Shared by BOTH targets.
// Encrypted, mutually authenticated channel over any byte stream (ADR-001 §2.1, §2.5).
// Socket bytes are [u16 BE length][body] messages: first the three Noise XX handshake messages,
// then AES-GCM records whose plaintexts form one continuous `Framing` stream.
// Any malformed, oversized, tampered, replayed or reordered input throws; the caller must close.
import Foundation
import CryptoKit

enum ChannelError: Error, Equatable {
    case notEstablished
    case malformedHandshakePayload
    /// Initiator only: `acceptResponder` declined the peer after message 2, so message 3 (our
    /// identity) was never sent. Carries the responder's authenticated key and name.
    case responderDeclined(publicKey: Data, name: String)
}

/// Authenticated identity of the other side, available once the handshake completes.
struct PeerInfo: Equatable {
    var publicKey: Data      // X25519 static key; the device identity
    var name: String         // self-reported display name (shown in the pairing prompt only)
    var handshakeHash: Data  // Noise h; binds the pairing code to this exact session
}

final class SecureChannel {
    enum Event: Equatable {
        case send(Data)                      // write these bytes to the socket
        case established(PeerInfo)
        case packet(PacketType, Data)
    }

    static let maxRecordPlaintext = Noise.maxMessageLen - Noise.tagLen
    /// Rekey both directions after this many records (ADR-001 §2.5).
    static let rekeyInterval: UInt64 = 1 << 30
    static let maxNameLength = 64

    private let lock = NSLock()
    private var handshake: NoiseXXHandshake?
    private var sendCipher: CipherState?
    private var receiveCipher: CipherState?
    private var sentRecords: UInt64 = 0
    private var receivedRecords: UInt64 = 0
    private let localName: String
    private var inbound = Data()
    private var parser = FrameParser()
    private var _peer: PeerInfo?
    /// The authenticated peer, once the handshake has completed. Thread-safe.
    var peer: PeerInfo? { lock.withLock { _peer } }

    /// Initiator only: decides, after reading handshake message 2 (the responder's authenticated
    /// static key and name), whether to continue. Declining aborts before our own identity is sent.
    private let acceptResponder: ((Data, String) -> Bool)?

    init(initiator: Bool, identity: Curve25519.KeyAgreement.PrivateKey, localName: String,
         acceptResponder: ((Data, String) -> Bool)? = nil) {
        self.acceptResponder = acceptResponder
        handshake = NoiseXXHandshake(initiator: initiator, prologue: WireConst.prologue, staticKey: identity)
        self.localName = String(localName.prefix(Self.maxNameLength))
    }

    var isEstablished: Bool { lock.withLock { _peer != nil } }

    /// Initiator only: the first handshake message to send. Returns nil for the responder.
    func start() throws -> Data? {
        try lock.withLock {
            guard var hs = handshake, hs.initiator, hs.isMyTurn else { return nil }
            let (msg, _) = try hs.writeMessage()   // message 1 is cleartext: no payload
            handshakeMessages += 1
            handshake = hs
            return Self.wire(msg)
        }
    }

    /// Feeds socket bytes in; returns what to send and what was received.
    func receive(_ bytes: Data) throws -> [Event] {
        try lock.withLock {
            inbound.append(bytes)
            var events: [Event] = []
            while let body = nextBody() {
                if var hs = handshake {
                    let (payload, readResult) = try hs.readMessage(body)
                    handshakeMessages += 1
                    if handshakeMessages == 1 {   // cleartext message: must carry nothing
                        guard payload.isEmpty else { throw ChannelError.malformedHandshakePayload }
                    } else {
                        peerName = try Self.decodeName(payload)
                    }
                    var result = readResult
                    if hs.initiator, handshakeMessages == 2, let accept = acceptResponder,
                       let key = hs.remoteStatic, let name = peerName, !accept(key, name) {
                        handshake = nil
                        throw ChannelError.responderDeclined(publicKey: key, name: name)
                    }
                    if hs.isMyTurn {
                        let (msg, writeResult) = try hs.writeMessage(Data(localName.utf8))
                        handshakeMessages += 1
                        events.append(.send(Self.wire(msg)))
                        result = writeResult
                    }
                    handshake = hs.isComplete ? nil : hs
                    if let result { try finish(result, into: &events) }
                } else {
                    guard var rc = receiveCipher else { throw ChannelError.notEstablished }
                    let plain = try rc.decryptWithAd(Data(), body)
                    receivedRecords += 1
                    if receivedRecords % Self.rekeyInterval == 0 { try rc.rekey() }
                    receiveCipher = rc
                    parser.append(plain)
                    while let (type, payload) = try parser.next() { events.append(.packet(type, payload)) }
                }
            }
            return events
        }
    }

    /// Encrypts one packet into one or more records, ready to write to the socket.
    func seal(_ type: PacketType, _ payload: Data) throws -> Data {
        try lock.withLock {
            guard var sc = sendCipher else { throw ChannelError.notEstablished }
            let plain = Framing.encode(type, payload)
            var out = Data(capacity: plain.count + (plain.count / Self.maxRecordPlaintext + 1) * 18)
            var offset = plain.startIndex
            while offset < plain.endIndex {
                let end = min(offset + Self.maxRecordPlaintext, plain.endIndex)
                out += Self.wire(try sc.encryptWithAd(Data(), plain[offset..<end]))
                sentRecords += 1
                if sentRecords % Self.rekeyInterval == 0 { try sc.rekey() }
                offset = end
            }
            sendCipher = sc
            return out
        }
    }

    // MARK: - Internals

    private var handshakeMessages = 0
    private var peerName: String?

    private func finish(_ result: NoiseXXHandshake.Result, into events: inout [Event]) throws {
        guard let peerName else { throw ChannelError.malformedHandshakePayload }
        sendCipher = result.send
        receiveCipher = result.receive
        let info = PeerInfo(publicKey: result.remoteStatic, name: peerName, handshakeHash: result.handshakeHash)
        _peer = info
        events.append(.established(info))
    }

    /// Next complete [u16 length][body] message, if buffered.
    private func nextBody() -> Data? {
        guard inbound.count >= 2 else { return nil }
        let s = inbound.startIndex
        let len = Int(inbound[s]) << 8 | Int(inbound[s + 1])
        guard inbound.count >= 2 + len else { return nil }
        let body = inbound.subdata(in: (s + 2)..<(s + 2 + len))
        inbound.removeSubrange(s..<(s + 2 + len))
        return body
    }

    private static func wire(_ body: Data) -> Data {
        precondition(body.count <= Noise.maxMessageLen)
        var d = Data([UInt8(body.count >> 8), UInt8(body.count & 0xFF)])
        d.append(body)
        return d
    }

    /// Handshake messages 2 and 3 carry the sender's display name as UTF-8 (encrypted by Noise).
    private static func decodeName(_ payload: Data) throws -> String {
        guard payload.count <= maxNameLength * 4, let name = String(data: payload, encoding: .utf8) else {
            throw ChannelError.malformedHandshakePayload
        }
        let clean = String(name.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
        return String(clean.prefix(maxNameLength))
    }
}
