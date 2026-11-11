import XCTest
import CryptoKit

final class SecureChannelTests: XCTestCase {

    /// Moves bytes between two channels until both are quiet; returns events each side saw.
    private func pump(_ mac: SecureChannel, _ pad: SecureChannel, first: Data?) throws -> (mac: [SecureChannel.Event], pad: [SecureChannel.Event]) {
        var toPad = first.map { [$0] } ?? [], toMac: [Data] = []
        var macEvents: [SecureChannel.Event] = [], padEvents: [SecureChannel.Event] = []
        while !toPad.isEmpty || !toMac.isEmpty {
            for b in toPad { for e in try pad.receive(b) { padEvents.append(e); if case .send(let d) = e { toMac.append(d) } } }
            toPad = []
            for b in toMac { for e in try mac.receive(b) { macEvents.append(e); if case .send(let d) = e { toPad.append(d) } } }
            toMac = []
        }
        return (macEvents, padEvents)
    }

    private func established() throws -> (SecureChannel, SecureChannel, PeerInfo, PeerInfo, Curve25519.KeyAgreement.PrivateKey, Curve25519.KeyAgreement.PrivateKey) {
        let mk = Curve25519.KeyAgreement.PrivateKey(), pk = Curve25519.KeyAgreement.PrivateKey()
        let mac = SecureChannel(initiator: true, identity: mk, localName: "Sahal’s MacBook Air")
        let pad = SecureChannel(initiator: false, identity: pk, localName: "iPad Pro")
        let (me, pe) = try pump(mac, pad, first: try mac.start())
        let macPeer = try XCTUnwrap(me.compactMap { if case .established(let p) = $0 { return p }; return nil }.first)
        let padPeer = try XCTUnwrap(pe.compactMap { if case .established(let p) = $0 { return p }; return nil }.first)
        return (mac, pad, macPeer, padPeer, mk, pk)
    }

    func testHandshakeAuthenticatesBothSidesAndCodesMatch() throws {
        let (mac, pad, macPeer, padPeer, mk, pk) = try established()
        XCTAssertTrue(mac.isEstablished && pad.isEstablished)
        XCTAssertEqual(macPeer.publicKey, pk.publicKey.rawRepresentation)
        XCTAssertEqual(padPeer.publicKey, mk.publicKey.rawRepresentation)
        XCTAssertEqual(macPeer.name, "iPad Pro")
        XCTAssertEqual(padPeer.name, "Sahal’s MacBook Air")
        XCTAssertEqual(macPeer.handshakeHash, padPeer.handshakeHash)
        XCTAssertEqual(macPeer.handshakeHash.count, 32)
    }

    func testResponderHasNothingToStart() throws {
        let pad = SecureChannel(initiator: false, identity: .init(), localName: "iPad")
        XCTAssertNil(try pad.start())
    }

    func testPacketsRoundTripIncludingLargeFramesInChunks() throws {
        let (mac, pad, _, _, _, _) = try established()
        let big = Data((0..<(5 * 1024 * 1024)).map { UInt8(truncatingIfNeeded: $0 &* 31) })
        var wire = try mac.seal(.videoFrame, big)
        wire += try mac.seal(.videoConfig, Data([1, 2, 3]))
        XCTAssertGreaterThan(wire.count, big.count)   // > 80 records, each with tag + length

        // Deliver in awkward slices to exercise reassembly.
        var got: [SecureChannel.Event] = []
        var i = wire.startIndex
        while i < wire.endIndex {
            let j = min(i + 7_001, wire.endIndex)
            got += try pad.receive(wire[i..<j])
            i = j
        }
        XCTAssertEqual(got, [.packet(.videoFrame, big), .packet(.videoConfig, Data([1, 2, 3]))])

        let back = try pad.seal(.input, Data("{}".utf8))
        XCTAssertEqual(try mac.receive(back), [.packet(.input, Data("{}".utf8))])
    }

    func testTamperedRecordIsRejected() throws {
        let (mac, pad, _, _, _, _) = try established()
        var wire = try mac.seal(.input, Data("{\"kind\":\"leftDown\"}".utf8))
        wire[wire.startIndex + 5] ^= 0x40
        XCTAssertThrowsError(try pad.receive(wire)) { XCTAssertEqual($0 as? NoiseError, .decryptFailed) }
    }

    func testReplayedRecordIsRejected() throws {
        let (mac, pad, _, _, _, _) = try established()
        let wire = try mac.seal(.input, Data("{}".utf8))
        XCTAssertNoThrow(try pad.receive(wire))
        XCTAssertThrowsError(try pad.receive(wire))
    }

    func testSealBeforeHandshakeFails() throws {
        let mac = SecureChannel(initiator: true, identity: .init(), localName: "Mac")
        XCTAssertThrowsError(try mac.seal(.input, Data())) { XCTAssertEqual($0 as? ChannelError, .notEstablished) }
    }

    func testPlaintextPeerIsRejected() throws {
        // A v0.2 (unencrypted) client sends a bare Framing packet. It must not get through.
        // Its first bytes read as a ~2.8 KB length, so nothing is delivered and the caller's
        // handshake timeout closes the connection.
        let pad = SecureChannel(initiator: false, identity: .init(), localName: "iPad")
        XCTAssertEqual(try pad.receive(Framing.encode(.input, Data("{\"kind\":\"leftDown\"}".utf8))), [])
        XCTAssertFalse(pad.isEstablished)
        // Even a well-sized message can never yield packets before a completed handshake.
        let mac = SecureChannel(initiator: false, identity: .init(), localName: "iPad")
        XCTAssertThrowsError(try mac.receive(Data([0, 3, 1, 2, 3])))   // too short for message 1
        XCTAssertFalse(mac.isEstablished)
    }

    func testCleartextFirstMessageMustBeEmpty() throws {
        let pad = SecureChannel(initiator: false, identity: .init(), localName: "iPad")
        var hs = NoiseXXHandshake(initiator: true, prologue: WireConst.prologue, staticKey: .init())
        let msg = try hs.writeMessage(Data("smuggled".utf8)).message
        let wire = Data([UInt8(msg.count >> 8), UInt8(msg.count & 0xFF)]) + msg
        XCTAssertThrowsError(try pad.receive(wire)) { XCTAssertEqual($0 as? ChannelError, .malformedHandshakePayload) }
    }

    func testManInTheMiddleGetsTwoDifferentSessions() throws {
        // An attacker relaying between Mac and iPad must run two separate handshakes, so the
        // handshake hashes (and therefore the commit-reveal codes) are bound to different sessions.
        let mac = SecureChannel(initiator: true, identity: .init(), localName: "Mac")
        let mitmAsPad = SecureChannel(initiator: false, identity: .init(), localName: "iPad")
        let mitmAsMac = SecureChannel(initiator: true, identity: .init(), localName: "Mac")
        let pad = SecureChannel(initiator: false, identity: .init(), localName: "iPad")
        _ = try pump(mac, mitmAsPad, first: try mac.start())
        _ = try pump(mitmAsMac, pad, first: try mitmAsMac.start())
        XCTAssertNotEqual(mac.peer?.handshakeHash, pad.peer?.handshakeHash)
    }

    func testControlCharactersStrippedFromNames() throws {
        let mac = SecureChannel(initiator: true, identity: .init(), localName: "Mac")
        let pad = SecureChannel(initiator: false, identity: .init(), localName: "Evil\n\u{7}iPad" + String(repeating: "x", count: 200))
        _ = try pump(mac, pad, first: try mac.start())
        let name = try XCTUnwrap(mac.peer?.name)
        XCTAssertTrue(name.hasPrefix("EviliPad"))
        XCTAssertLessThanOrEqual(name.count, SecureChannel.maxNameLength)
    }

    func testPairingCodeFormatting() {
        XCTAssertEqual(PairingCode.formatted("012345"), "012 345")
        let code = PairingCode.from(handshakeHash: Data(count: 32), initiatorNonce: Data(count: 32), responderNonce: Data(count: 32))
        XCTAssertEqual(code.count, 6)
        XCTAssertTrue(code.allSatisfy(\.isNumber))
        XCTAssertNotEqual(code, PairingCode.from(handshakeHash: Data(count: 32), initiatorNonce: Data(repeating: 1, count: 32),
                                                 responderNonce: Data(count: 32)))
    }
}

final class PairingGateTests: XCTestCase {
    private let h = Data(repeating: 0x5A, count: 32)

    /// Mac (initiator) and iPad (responder) gates wired back to back.
    private struct Pair {
        var mac: PairingGate
        var pad: PairingGate
        var macPrompt: String?, padPrompt: String?
        var macActive: Bool?, padActive: Bool?     // save flag when activated
        var rejected = false

        /// Delivers outputs to the other side until nothing is left to send.
        mutating func run(fromMac: [PairingGate.Output], fromPad: [PairingGate.Output]) throws {
            var toPad = fromMac, toMac = fromPad
            while !toPad.isEmpty || !toMac.isEmpty {
                let a = toPad; toPad = []
                for o in a { toMac += try Self.deliver(o, to: &pad, prompt: &padPrompt, active: &padActive, rejected: &rejected) }
                let b = toMac; toMac = []
                for o in b { toPad += try Self.deliver(o, to: &mac, prompt: &macPrompt, active: &macActive, rejected: &rejected) }
            }
        }

        private static func deliver(_ o: PairingGate.Output, to gate: inout PairingGate, prompt: inout String?,
                                    active: inout Bool?, rejected: inout Bool) throws -> [PairingGate.Output] {
            guard case .send(let t, let p) = o else { return [] }
            let outs = try gate.receive(t, p)
            for out in outs {
                switch out {
                case .showPrompt(let code): prompt = code
                case .activate(let save): active = save
                case .reject: rejected = true
                case .send: break
                }
            }
            return outs.filter { if case .send = $0 { return true }; return false }
        }
    }

    private func pair(macKnows: Bool, padKnows: Bool) throws -> Pair {
        var p = Pair(mac: PairingGate(peerKnown: macKnows, initiator: true, handshakeHash: h),
                     pad: PairingGate(peerKnown: padKnows, initiator: false, handshakeHash: h))
        try p.run(fromMac: p.mac.start(), fromPad: p.pad.start())
        return p
    }

    func testBothKnownActivatesSilently() throws {
        let p = try pair(macKnows: true, padKnows: true)
        XCTAssertEqual(p.macActive, false); XCTAssertEqual(p.padActive, false)   // active, nothing to save
        XCTAssertNil(p.macPrompt); XCTAssertNil(p.padPrompt)
        XCTAssertTrue(p.mac.isActive && p.pad.isActive)
    }

    func testUnknownOnEitherSidePromptsBothWithTheSameCode() throws {
        for (m, i) in [(false, false), (true, false), (false, true)] {
            let p = try pair(macKnows: m, padKnows: i)
            let code = try XCTUnwrap(p.macPrompt)
            XCTAssertEqual(code, p.padPrompt)
            XCTAssertEqual(code.count, 6)
            XCTAssertFalse(p.mac.isActive || p.pad.isActive)
        }
    }

    func testBothAcceptActivatesAndSaves() throws {
        var p = try pair(macKnows: false, padKnows: false)
        try p.run(fromMac: p.mac.decide(true), fromPad: [])
        XCTAssertNil(p.padActive)                       // iPad hasn't decided yet
        XCTAssertFalse(p.mac.isActive)
        let padOut = p.pad.decide(true)
        XCTAssertTrue(padOut.contains(.activate(save: true)))
        try p.run(fromMac: [], fromPad: padOut)
        XCTAssertEqual(p.macActive, true)
        XCTAssertTrue(p.mac.isActive && p.pad.isActive)
    }

    func testAnyRejectRejects() throws {
        var p = try pair(macKnows: false, padKnows: false)
        XCTAssertTrue(p.pad.decide(false).contains(.reject))
        var q = try pair(macKnows: false, padKnows: false)
        try q.run(fromMac: q.mac.decide(false), fromPad: [])
        XCTAssertTrue(q.rejected)
        XCTAssertFalse(q.pad.isActive)
    }

    func testCodeDependsOnBothNonces() throws {
        let a = try pair(macKnows: false, padKnows: false), b = try pair(macKnows: false, padKnows: false)
        XCTAssertNotEqual(a.macPrompt, b.macPrompt, "fresh nonces → fresh code (1-in-10⁶ flake chance)")
    }

    func testRevealMustMatchCommitment() throws {
        var mac = PairingGate(peerKnown: false, initiator: true, handshakeHash: h)
        _ = mac.start()
        _ = try mac.receive(.trustState, Data([0]))
        let nb = Data(repeating: 3, count: 32)
        XCTAssertEqual(try mac.receive(.pairCommit, PairingGate.commitment(h, nb)).count, 1)   // sends Na
        XCTAssertThrowsError(try mac.receive(.pairReveal, Data(repeating: 4, count: 32))) {
            XCTAssertEqual($0 as? PairingGate.Violation, .commitmentMismatch)
        }
    }

    func testResponderMustCommitBeforeSeeingInitiatorNonce() throws {
        // The Mac never sends its nonce before receiving a commitment, and the iPad rejects an
        // unsolicited nonce: neither side can choose its nonce after seeing the other's.
        var mac = PairingGate(peerKnown: false, initiator: true, handshakeHash: h)
        XCTAssertEqual(try mac.receive(.trustState, Data([0])), [])   // waits for the commitment
        var pad = PairingGate(peerKnown: false, initiator: false, handshakeHash: h)
        XCTAssertThrowsError(try pad.receive(.pairNonce, Data(count: 32)))
    }

    func testTrafficBeforeActiveIsAViolation() throws {
        var g = PairingGate(peerKnown: true, initiator: true, handshakeHash: h)
        XCTAssertThrowsError(try g.receive(.input, Data([1])))
        XCTAssertThrowsError(try g.receive(.hello, Data([1])))
    }

    func testOutOfOrderAndMalformedAreViolations() throws {
        var g = PairingGate(peerKnown: false, initiator: false, handshakeHash: h)
        XCTAssertThrowsError(try g.receive(.pairDecision, Data([1])))   // decision before prompt
        XCTAssertThrowsError(try g.receive(.trustState, Data([7])))      // bad flag
        _ = try g.receive(.trustState, Data([0]))
        XCTAssertThrowsError(try g.receive(.trustState, Data([0])))      // trust twice
        XCTAssertThrowsError(try g.receive(.pairNonce, Data(count: 5)))   // bad length
        XCTAssertThrowsError(try g.receive(.pairReveal, Data(count: 32))) // wrong direction
    }

    func testDecideWithoutPromptDoesNothing() {
        var g = PairingGate(peerKnown: false, initiator: true, handshakeHash: h)
        XCTAssertEqual(g.decide(true), [])
    }

    func testPairingPacketsIgnoredOnceActive() throws {
        var p = try pair(macKnows: true, padKnows: true)
        XCTAssertEqual(try p.mac.receive(.pairDecision, Data([1])), [])
    }
}

final class PairingStoreTests: XCTestCase {
    func testInMemoryStore() throws {
        let s = InMemoryPairingStore()
        let d = PairedDevice(publicKey: Data(repeating: 7, count: 32), name: "iPad", pairedAt: Date())
        XCTAssertFalse(try s.contains(d.publicKey))
        try s.save(d)
        XCTAssertTrue(try s.contains(d.publicKey))
        XCTAssertEqual(s.all(), [d])
        try s.remove(d.publicKey)
        XCTAssertTrue(s.all().isEmpty)
        XCTAssertEqual(d.fingerprint.count, 9)
    }

    /// The data-protection keychain needs a signed app with a keychain-access-groups entitlement,
    /// which a hostless, ad-hoc-signed test bundle doesn't have. Skip rather than fail there.
    func testKeychainStoreWhenAvailable() throws {
        let s = KeychainPairingStore(service: "com.msahalkc.extend.peer.tests")
        let d = PairedDevice(publicKey: Data(repeating: 9, count: 32), name: "Test", pairedAt: Date())
        do { try s.save(d) } catch KeychainError.status(let st) {
            throw XCTSkip("Data-protection keychain unavailable in this test host (OSStatus \(st))")
        }
        defer { try? Keychain.delete(service: "com.msahalkc.extend.peer.tests") }
        XCTAssertTrue(try s.contains(d.publicKey))
        XCTAssertEqual(s.all().map(\.name), ["Test"])
        try s.remove(d.publicKey)
        XCTAssertFalse(try s.contains(d.publicKey))
    }
}
