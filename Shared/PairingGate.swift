// Shared by BOTH targets.
// Decides whether an authenticated SecureChannel may carry display/input traffic (ADR-001 §2.3–2.4).
//
// Right after the handshake each side sends `trustState` (1 = "your key is in my pairing records").
//  • Both 1    → active, silently.
//  • Otherwise → commit-reveal of fresh nonces, then both users compare a 6-digit code:
//        iPad (responder) → pairCommit  SHA-256(h ‖ Nb)
//        Mac (initiator)  → pairNonce   Na
//        iPad             → pairReveal  Nb            (Mac checks it against the commitment)
//        code = HMAC-SHA256(h, "ExtenD pairing code" ‖ Na ‖ Nb), 6 digits
//    The iPad commits before seeing Na, and the Mac's Na is fresh, so a man in the middle (two
//    separate handshakes) can't grind either side's code to match the other: 1-in-10⁶ per attempt.
//    Then each side sends `pairDecision`. Both accepted → active and both save; any reject → closed.
// Until active only these pairing packets are legal; anything else or out of order is a violation.
import Foundation
import CryptoKit

struct PairingGate {
    enum Output: Equatable {
        case send(PacketType, Data)
        case showPrompt(code: String)   // ask the local user, then call `decide(_:)`
        case activate(save: Bool)       // session may carry traffic; save the peer record when `save`
        case reject                     // pairing refused by either side: close the connection
    }

    enum Violation: Error, Equatable { case unexpectedPacket(PacketType), malformed, commitmentMismatch }

    static let nonceLength = 32

    private(set) var isActive = false
    private(set) var isPrompting = false
    private let initiator: Bool
    private let handshakeHash: Data
    private let localKnows: Bool
    private var remoteKnows: Bool?
    private var localNonce: Data?
    private var remoteCommit: Data?
    private var remoteNonce: Data?
    private var localDecision: Bool?
    private var remoteDecision: Bool?
    private let random: () -> Data

    init(peerKnown: Bool, initiator: Bool, handshakeHash: Data,
         random: @escaping () -> Data = { SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) } }) {
        localKnows = peerKnown
        self.initiator = initiator
        self.handshakeHash = handshakeHash
        self.random = random
    }

    /// What to send as soon as the channel is established.
    func start() -> [Output] { [.send(.trustState, Data([localKnows ? 1 : 0]))] }

    /// Feed every pairing packet received before `isActive`.
    mutating func receive(_ type: PacketType, _ payload: Data) throws -> [Output] {
        guard !isActive else { return [] }
        switch type {
        case .trustState where remoteKnows == nil:
            let flag = try Self.flag(payload)
            remoteKnows = flag
            if localKnows && flag { isActive = true; return [.activate(save: false)] }
            guard !initiator else { return [] }          // Mac waits for the iPad's commitment
            let nb = nonce()
            return [.send(.pairCommit, Self.commitment(handshakeHash, nb))]

        case .pairCommit where initiator && needsPairing && remoteCommit == nil:
            guard payload.count == Self.nonceLength else { throw Violation.malformed }
            remoteCommit = payload
            return [.send(.pairNonce, nonce())]

        case .pairNonce where !initiator && needsPairing && localNonce != nil && remoteNonce == nil:
            guard payload.count == Self.nonceLength else { throw Violation.malformed }
            remoteNonce = payload
            isPrompting = true
            return [.send(.pairReveal, localNonce!), .showPrompt(code: code())]

        case .pairReveal where initiator && remoteCommit != nil && remoteNonce == nil:
            guard payload.count == Self.nonceLength else { throw Violation.malformed }
            guard Self.commitment(handshakeHash, payload) == remoteCommit else { throw Violation.commitmentMismatch }
            remoteNonce = payload
            isPrompting = true
            return [.showPrompt(code: code())]

        case .pairDecision where isPrompting && remoteDecision == nil:
            remoteDecision = try Self.flag(payload)
            return resolve()

        default:
            throw Violation.unexpectedPacket(type)
        }
    }

    /// The local user's answer to the prompt.
    mutating func decide(_ accepted: Bool) -> [Output] {
        guard isPrompting, localDecision == nil, !isActive else { return [] }
        localDecision = accepted
        return [.send(.pairDecision, Data([accepted ? 1 : 0]))] + resolve()
    }

    // MARK: - Internals

    private var needsPairing: Bool { remoteKnows != nil && !(localKnows && remoteKnows == true) }

    private mutating func nonce() -> Data {
        let n = random()
        precondition(n.count == Self.nonceLength)
        localNonce = n
        return n
    }

    private func code() -> String {
        let na = initiator ? localNonce! : remoteNonce!
        let nb = initiator ? remoteNonce! : localNonce!
        return PairingCode.from(handshakeHash: handshakeHash, initiatorNonce: na, responderNonce: nb)
    }

    private mutating func resolve() -> [Output] {
        if localDecision == false || remoteDecision == false { return [.reject] }
        guard localDecision == true, remoteDecision == true else { return [] }
        isActive = true
        isPrompting = false
        return [.activate(save: true)]
    }

    private static func flag(_ payload: Data) throws -> Bool {
        guard payload.count == 1, payload[payload.startIndex] <= 1 else { throw Violation.malformed }
        return payload[payload.startIndex] == 1
    }

    static func commitment(_ h: Data, _ nonce: Data) -> Data {
        Noise.hash(Data("ExtenD commit".utf8) + h + nonce)
    }
}

/// 6-digit code both users compare during pairing (ADR-001 §2.3).
enum PairingCode {
    static func from(handshakeHash h: Data, initiatorNonce na: Data, responderNonce nb: Data) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data("ExtenD pairing code".utf8) + na + nb,
                                                  using: SymmetricKey(data: h))
        let v = Data(mac).prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        return String(format: "%06u", v % 1_000_000)
    }

    /// "123456" → "123 456" for display.
    static func formatted(_ code: String) -> String {
        guard code.count == 6 else { return code }
        return "\(code.prefix(3)) \(code.suffix(3))"
    }
}
