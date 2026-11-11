import XCTest
import CryptoKit

final class NoiseTests: XCTestCase {

    // MARK: - Official test vectors (Tests/Resources/noise-vectors.json)

    private struct VectorFile: Decodable { var vectors: [Vector] }
    private struct Vector: Decodable {
        var protocol_name: String
        var init_prologue: String, init_static: String, init_ephemeral: String
        var resp_prologue: String, resp_static: String, resp_ephemeral: String
        var handshake_hash: String?
        var messages: [Message]
        var _source: String
    }
    private struct Message: Decodable { var payload: String, ciphertext: String }

    func testOfficialVectors() throws {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "noise-vectors", withExtension: "json"))
        let file = try JSONDecoder().decode(VectorFile.self, from: Data(contentsOf: url))
        XCTAssertEqual(file.vectors.count, 2)

        for v in file.vectors {
            XCTAssertEqual(v.protocol_name, Noise.protocolName)
            var initiator = NoiseXXHandshake(initiator: true, prologue: hex(v.init_prologue),
                                             staticKey: try key(v.init_static), ephemeral: try key(v.init_ephemeral))
            var responder = NoiseXXHandshake(initiator: false, prologue: hex(v.resp_prologue),
                                             staticKey: try key(v.resp_static), ephemeral: try key(v.resp_ephemeral))
            var iResult: NoiseXXHandshake.Result?, rResult: NoiseXXHandshake.Result?

            for (i, m) in v.messages.enumerated() {
                let fromInitiator = i % 2 == 0
                if i < 3 {   // handshake
                    let written: (message: Data, result: NoiseXXHandshake.Result?)
                    let read: (payload: Data, result: NoiseXXHandshake.Result?)
                    if fromInitiator {
                        written = try initiator.writeMessage(hex(m.payload))
                        read = try responder.readMessage(written.message)
                        iResult = written.result ?? iResult; rResult = read.result ?? rResult
                    } else {
                        written = try responder.writeMessage(hex(m.payload))
                        read = try initiator.readMessage(written.message)
                        rResult = written.result ?? rResult; iResult = read.result ?? iResult
                    }
                    XCTAssertEqual(written.message, hex(m.ciphertext), "\(v._source) handshake msg \(i)")
                    XCTAssertEqual(read.payload, hex(m.payload), "\(v._source) handshake msg \(i)")
                } else {     // transport
                    guard var ir = iResult, var rr = rResult else { return XCTFail("handshake incomplete") }
                    if fromInitiator {
                        let c = try ir.send.encryptWithAd(Data(), hex(m.payload))
                        XCTAssertEqual(c, hex(m.ciphertext), "\(v._source) transport msg \(i)")
                        XCTAssertEqual(try rr.receive.decryptWithAd(Data(), c), hex(m.payload))
                    } else {
                        let c = try rr.send.encryptWithAd(Data(), hex(m.payload))
                        XCTAssertEqual(c, hex(m.ciphertext), "\(v._source) transport msg \(i)")
                        XCTAssertEqual(try ir.receive.decryptWithAd(Data(), c), hex(m.payload))
                    }
                    iResult = ir; rResult = rr
                }
            }

            let ir = try XCTUnwrap(iResult), rr = try XCTUnwrap(rResult)
            XCTAssertEqual(ir.handshakeHash, rr.handshakeHash)
            if let hh = v.handshake_hash { XCTAssertEqual(ir.handshakeHash, hex(hh), v._source) }
            XCTAssertEqual(ir.remoteStatic, try key(v.resp_static).publicKey.rawRepresentation)
            XCTAssertEqual(rr.remoteStatic, try key(v.init_static).publicKey.rawRepresentation)
        }
    }

    // MARK: - Behaviour with generated keys

    func testRoundTripAndMutualIdentity() throws {
        let (i, r, iKey, rKey) = try handshake()
        XCTAssertEqual(i.remoteStatic, rKey.publicKey.rawRepresentation)
        XCTAssertEqual(r.remoteStatic, iKey.publicKey.rawRepresentation)
        XCTAssertEqual(i.handshakeHash, r.handshakeHash)

        var send = i.send, recv = r.receive
        for n in 0..<100 {
            let msg = Data("frame \(n)".utf8)
            XCTAssertEqual(try recv.decryptWithAd(Data(), try send.encryptWithAd(Data(), msg)), msg)
        }
    }

    func testTamperedTransportMessageFails() throws {
        var (i, r, _, _) = try handshake()
        var c = try i.send.encryptWithAd(Data(), Data("click".utf8))
        c[c.startIndex] ^= 0x01
        XCTAssertThrowsError(try r.receive.decryptWithAd(Data(), c)) { XCTAssertEqual($0 as? NoiseError, .decryptFailed) }
    }

    func testReplayAndReorderFail() throws {
        var (i, r, _, _) = try handshake()
        let c0 = try i.send.encryptWithAd(Data(), Data("a".utf8))
        let c1 = try i.send.encryptWithAd(Data(), Data("b".utf8))
        XCTAssertThrowsError(try r.receive.decryptWithAd(Data(), c1))   // reordered
        XCTAssertNoThrow(try r.receive.decryptWithAd(Data(), c0))
        XCTAssertThrowsError(try r.receive.decryptWithAd(Data(), c0))   // replayed
    }

    func testPrologueMismatchFails() throws {
        var a = NoiseXXHandshake(initiator: true, prologue: Data("ExtenD/1".utf8), staticKey: .init())
        var b = NoiseXXHandshake(initiator: false, prologue: Data("ExtenD/2".utf8), staticKey: .init())
        _ = try b.readMessage(try a.writeMessage().message)   // msg 1 has no encryption yet
        let m2 = try b.writeMessage().message
        XCTAssertThrowsError(try a.readMessage(m2)) { XCTAssertEqual($0 as? NoiseError, .decryptFailed) }
    }

    func testTamperedHandshakeFails() throws {
        var a = NoiseXXHandshake(initiator: true, prologue: Data(), staticKey: .init())
        var b = NoiseXXHandshake(initiator: false, prologue: Data(), staticKey: .init())
        _ = try b.readMessage(try a.writeMessage().message)
        var m2 = try b.writeMessage().message
        m2[m2.startIndex + 40] ^= 0x80   // inside the encrypted static key
        XCTAssertThrowsError(try a.readMessage(m2))
    }

    func testTurnOrderEnforced() throws {
        var a = NoiseXXHandshake(initiator: true, prologue: Data(), staticKey: .init())
        var b = NoiseXXHandshake(initiator: false, prologue: Data(), staticKey: .init())
        XCTAssertThrowsError(try b.writeMessage()) { XCTAssertEqual($0 as? NoiseError, .wrongTurn) }
        XCTAssertThrowsError(try a.readMessage(Data(count: 32))) { XCTAssertEqual($0 as? NoiseError, .wrongTurn) }
        XCTAssertThrowsError(try b.readMessage(Data(count: 10))) { XCTAssertEqual($0 as? NoiseError, .malformedMessage) }
    }

    func testRekeyChangesKeyOnBothSides() throws {
        var (i, r, _, _) = try handshake()
        try i.send.rekey(); try r.receive.rekey()
        let msg = Data("after rekey".utf8)
        XCTAssertEqual(try r.receive.decryptWithAd(Data(), try i.send.encryptWithAd(Data(), msg)), msg)
    }

    // MARK: - Helpers

    private func handshake() throws -> (NoiseXXHandshake.Result, NoiseXXHandshake.Result,
                                        Curve25519.KeyAgreement.PrivateKey, Curve25519.KeyAgreement.PrivateKey) {
        let iKey = Curve25519.KeyAgreement.PrivateKey(), rKey = Curve25519.KeyAgreement.PrivateKey()
        var a = NoiseXXHandshake(initiator: true, prologue: Data("ExtenD/1".utf8), staticKey: iKey)
        var b = NoiseXXHandshake(initiator: false, prologue: Data("ExtenD/1".utf8), staticKey: rKey)
        _ = try b.readMessage(try a.writeMessage().message)
        _ = try a.readMessage(try b.writeMessage().message)
        let (m3, ia) = try a.writeMessage()
        let (_, rb) = try b.readMessage(m3)
        return (try XCTUnwrap(ia), try XCTUnwrap(rb), iKey, rKey)
    }

    private func key(_ h: String) throws -> Curve25519.KeyAgreement.PrivateKey {
        try .init(rawRepresentation: hex(h))
    }

    private func hex(_ s: String) -> Data {
        var d = Data(capacity: s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return d
    }
}
