import XCTest
import CryptoKit

/// Seeded fuzzing of everything that parses peer-controlled bytes. Deterministic (SplitMix64) so a
/// failure reproduces; bump `iterations` locally for longer runs.
final class FuzzTests: XCTestCase {
    private let iterations = 3_000

    private struct RNG: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E3779B97F4A7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
            z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
            return z ^ (z >> 31)
        }
        mutating func bytes(_ n: Int) -> Data { Data((0..<n).map { _ in UInt8.random(in: 0...255, using: &self) }) }
    }

    // MARK: - Random input never crashes and never yields packets

    func testFrameParserRandomBytes() {
        var rng = RNG(state: 1)
        for _ in 0..<iterations {
            var p = FrameParser()
            p.append(rng.bytes(Int.random(in: 0...64, using: &rng)))
            while let pkt = try? p.next() {
                XCTAssertLessThanOrEqual(pkt.1.count, pkt.0.maxPayload)
            }
        }
    }

    func testSecureChannelRandomBytesNeverDeliverPackets() {
        var rng = RNG(state: 2)
        for i in 0..<iterations {
            let ch = SecureChannel(initiator: i % 2 == 0, identity: .init(), localName: "x")
            _ = try? ch.start()
            var delivered: [SecureChannel.Event] = []
            for _ in 0..<Int.random(in: 1...4, using: &rng) {
                var chunk = rng.bytes(Int.random(in: 0...200, using: &rng))
                if Bool.random(using: &rng), chunk.count >= 2 {   // plausible length prefix
                    chunk[0] = 0; chunk[1] = UInt8(min(chunk.count - 2, 255))
                }
                guard let events = try? ch.receive(chunk) else { break }
                delivered += events
            }
            XCTAssertFalse(delivered.contains { if case .packet = $0 { return true }; return false })
            XCTAssertFalse(delivered.contains { if case .established = $0 { return true }; return false })
        }
    }

    func testPairingGateRandomPacketsNeverActivateWithoutBothDecisions() {
        var rng = RNG(state: 3)
        let types: [PacketType] = [.trustState, .pairDecision, .pairCommit, .pairNonce, .pairReveal, .input, .hello]
        for _ in 0..<iterations {
            var g = PairingGate(peerKnown: false, initiator: Bool.random(using: &rng), handshakeHash: rng.bytes(32))
            _ = g.start()
            var sawSaveActivation = false
            for _ in 0..<Int.random(in: 1...8, using: &rng) {
                let t = types.randomElement(using: &rng)!
                let payload = rng.bytes([0, 1, 32, 33].randomElement(using: &rng)!)
                guard let out = try? g.receive(t, payload) else { break }
                if out.contains(.activate(save: true)) { sawSaveActivation = true }
            }
            // The local user never accepted, so pairing can't have completed.
            XCTAssertFalse(sawSaveActivation)
            XCTAssertFalse(g.isActive)
        }
    }

    func testJSONDecodingOfPeerInputIsTotal() {
        var rng = RNG(state: 4)
        let seeds = [#"{"kind":"move","x":0.5,"y":0.5}"#, #"{"pixelWidth":2360,"pixelHeight":1640}"#,
                     #"{"kind":"keyDown","keyCode":4,"modifiers":8}"#]
        for _ in 0..<iterations {
            var d = Data(seeds.randomElement(using: &rng)!.utf8)
            for _ in 0..<Int.random(in: 1...4, using: &rng) where !d.isEmpty {
                d[Int.random(in: 0..<d.count, using: &rng)] = UInt8.random(in: 0...255, using: &rng)
            }
            _ = try? JSONDecoder().decode(InputEvent.self, from: d)   // must not crash
            if let h = try? JSONDecoder().decode(Hello.self, from: d), h.isValid {
                XCTAssertTrue(Hello.pixelRange.contains(h.pixelWidth) && Hello.pixelRange.contains(h.pixelHeight))
            }
        }
    }

    // MARK: - Integrity: a tampered stream can only truncate, never forge

    func testMutatedEncryptedStreamYieldsOnlyAPrefixOfTheRealPackets() throws {
        // One real session; capture the exact bytes Mac → iPad.
        let macKey = Curve25519.KeyAgreement.PrivateKey(), padKey = Curve25519.KeyAgreement.PrivateKey()
        let mac = SecureChannel(initiator: true, identity: macKey, localName: "Mac")
        let pad = SecureChannel(initiator: false, identity: padKey, localName: "iPad")
        var macToPad = [try XCTUnwrap(try mac.start())]
        var padToMac: [Data] = []
        for e in try pad.receive(macToPad[0]) { if case .send(let d) = e { padToMac.append(d) } }
        for e in try mac.receive(padToMac[0]) { if case .send(let d) = e { macToPad.append(d) } }
        let real: [(PacketType, Data)] = [(.videoConfig, Data([1, 2, 3])), (.videoFrame, Data(repeating: 7, count: 150_000)),
                                          (.trustState, Data([1])), (.videoFrame, Data(repeating: 9, count: 10))]
        for (t, p) in real { macToPad.append(try mac.seal(t, p)) }
        let stream = macToPad.reduce(Data(), +)
        let handshakeLen = macToPad[0].count + macToPad[1].count

        var rng = RNG(state: 5)
        for _ in 0..<300 {
            var s = stream
            switch Int.random(in: 0..<4, using: &rng) {
            case 0:   // flip bytes after the handshake
                for _ in 0..<Int.random(in: 1...3, using: &rng) {
                    let i = Int.random(in: handshakeLen..<s.count, using: &rng)
                    s[i] ^= UInt8.random(in: 1...255, using: &rng)
                }
            case 1:   // truncate
                s = s.prefix(Int.random(in: 0..<s.count, using: &rng))
            case 2:   // duplicate a slice (replay)
                let a = Int.random(in: handshakeLen..<s.count, using: &rng)
                let b = min(s.count, a + Int.random(in: 1...70_000, using: &rng))
                s.insert(contentsOf: s[a..<b], at: b)
            default:  // delete a slice (drop / reorder effect)
                let a = Int.random(in: handshakeLen..<s.count, using: &rng)
                let b = min(s.count, a + Int.random(in: 1...70_000, using: &rng))
                s.removeSubrange(a..<b)
            }

            // Replay attack: feed the (mutated) recorded transcript to a NEW iPad session that has the
            // same long-term key. Its fresh ephemeral key differs from the recorded one.
            let victim = SecureChannel(initiator: false, identity: padKey, localName: "iPad")
            var got: [(PacketType, Data)] = []
            do {
                for e in try victim.receive(s) { if case .packet(let t, let p) = e { got.append((t, p)) } }
            } catch {}
            // The victim never completed the handshake with the original Mac (its ephemeral differs),
            // so it must not accept ANY packet from this transcript.
            XCTAssertTrue(got.isEmpty, "packets accepted from a transcript bound to another ephemeral key")
        }

        // Same mutations against the real receiving channel state: only a prefix may come out.
        for _ in 0..<300 {
            let (m, p) = try freshPair()
            var wire = Data()
            for (t, pl) in real { wire += try m.seal(t, pl) }
            switch Int.random(in: 0..<3, using: &rng) {
            case 0: let i = Int.random(in: 0..<wire.count, using: &rng); wire[i] ^= UInt8.random(in: 1...255, using: &rng)
            case 1: let a = Int.random(in: 0..<wire.count, using: &rng); let b = min(wire.count, a + Int.random(in: 1...70_000, using: &rng)); wire.insert(contentsOf: wire[a..<b], at: b)
            default: let a = Int.random(in: 0..<wire.count, using: &rng); let b = min(wire.count, a + Int.random(in: 1...70_000, using: &rng)); wire.removeSubrange(a..<b)
            }
            var got: [(PacketType, Data)] = []
            do {
                for e in try p.receive(wire) { if case .packet(let t, let pl) = e { got.append((t, pl)) } }
            } catch {}
            XCTAssertLessThanOrEqual(got.count, real.count)
            for (i, g) in got.enumerated() {
                XCTAssertEqual(g.0, real[i].0, "forged packet type")
                XCTAssertEqual(g.1, real[i].1, "forged packet payload")
            }
        }
    }

    private func freshPair() throws -> (SecureChannel, SecureChannel) {
        let mac = SecureChannel(initiator: true, identity: .init(), localName: "Mac")
        let pad = SecureChannel(initiator: false, identity: .init(), localName: "iPad")
        var toPad = [try XCTUnwrap(try mac.start())]
        while let b = toPad.popLast() {
            for e in try pad.receive(b) {
                if case .send(let d) = e { for e2 in try mac.receive(d) { if case .send(let d2) = e2 { toPad.append(d2) } } }
            }
        }
        XCTAssertTrue(mac.isEstablished && pad.isEstablished)
        return (mac, pad)
    }
}

final class ProtocolLimitTests: XCTestCase {
    func testHelloSizeLimits() {
        XCTAssertTrue(Hello(pixelWidth: 2752, pixelHeight: 2064).isValid)    // iPad Pro 13"
        XCTAssertTrue(Hello(pixelWidth: 2348, pixelHeight: 1628).isValid)    // iPad (A16) inset area
        XCTAssertFalse(Hello(pixelWidth: 8192, pixelHeight: 8192).isValid)   // beyond H.264 level 5.2
        XCTAssertFalse(Hello(pixelWidth: 100, pixelHeight: 2000).isValid)
    }

    func testEveryPairingTypeIsCappedAndFlagged() {
        for raw in UInt8(20)...24 {
            let t = PacketType(rawValue: raw)!
            XCTAssertTrue(t.isPairing)
            XCTAssertLessThanOrEqual(t.maxPayload, 32)
        }
        for t in [PacketType.videoConfig, .videoFrame, .hello, .input, .keyframeRequest] { XCTAssertFalse(t.isPairing) }
    }
}
