import XCTest
import CryptoKit

/// Runs the real Mac `Session` (threads, socket I/O, authorization) against a simulated iPad
/// built from the same SecureChannel + PairingGate the iPad app uses, over a Unix socket pair.
final class SessionEndToEndTests: XCTestCase {

    /// Minimal iPad side: reads the socket on a thread, answers the handshake, records packets.
    private final class FakePad {
        let fd: Int32
        let identity = Curve25519.KeyAgreement.PrivateKey()
        let channel: SecureChannel
        private let lock = NSLock()
        private var _packets: [(PacketType, Data)] = []
        var packets: [(PacketType, Data)] { lock.withLock { _packets } }
        private var _onPacket: (() -> Void)?
        var onPacket: (() -> Void)? {
            get { lock.withLock { _onPacket } }
            set { lock.withLock { _onPacket = newValue } }
        }

        init(fd: Int32) {
            self.fd = fd
            channel = SecureChannel(initiator: false, identity: identity, localName: "Test iPad")
            Thread.detachNewThread { [self] in
                var buf = [UInt8](repeating: 0, count: 64 * 1024)
                while true {
                    let n = read(fd, &buf, buf.count)
                    if n <= 0 { return }
                    guard let events = try? channel.receive(Data(buf[0..<n])) else { return }
                    for e in events {
                        switch e {
                        case .send(let d): _ = Sock.writeAll(fd, d)
                        case .packet(let t, let p): lock.withLock { _packets.append((t, p)) }; onPacket?()
                        case .established: break
                        }
                    }
                }
            }
        }

        func send(_ type: PacketType, _ payload: Data) throws { _ = Sock.writeAll(fd, try channel.seal(type, payload)) }
    }

    func testEncryptedSessionWithPairingGate() throws {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        let pad = FakePad(fd: fds[1])
        let session = Session(stream: FDStream(fd: fds[0]), transport: .usb(deviceID: 1), identity: .init(), localName: "Test Mac")

        let established = expectation(description: "established")
        var macPeer: PeerInfo?
        session.onEstablished = { macPeer = $0; established.fulfill() }
        var macPackets: [(PacketType, Data)] = []
        let gotInput = expectation(description: "input")
        session.onPacket = { t, p in macPackets.append((t, p)); if t == .input { gotInput.fulfill() } }
        let closed = expectation(description: "closed")
        session.onClose = { closed.fulfill() }

        session.start()
        wait(for: [established], timeout: 5)
        XCTAssertEqual(macPeer?.name, "Test iPad")
        XCTAssertEqual(macPeer?.handshakeHash, pad.channel.peer?.handshakeHash)
        XCTAssertEqual(macPeer?.publicKey, pad.identity.publicKey.rawRepresentation)

        // Not authorized yet: display traffic is refused, pairing traffic flows.
        XCTAssertFalse(session.send(.videoFrame, Data([1, 2, 3])))
        XCTAssertTrue(session.send(.trustState, Data([0])))

        session.authorize()
        let frame = Data((0..<300_000).map { UInt8(truncatingIfNeeded: $0) })
        let padGotFrame = expectation(description: "frame")
        pad.onPacket = { if pad.packets.contains(where: { $0.0 == .videoFrame }) { padGotFrame.fulfill(); pad.onPacket = nil } }
        XCTAssertTrue(session.send(.videoFrame, frame))
        wait(for: [padGotFrame], timeout: 5)
        XCTAssertEqual(pad.packets.map(\.0), [.trustState, .videoFrame])
        XCTAssertEqual(pad.packets.last?.1, frame)

        try pad.send(.input, Data("{\"kind\":\"move\"}".utf8))
        wait(for: [gotInput], timeout: 5)
        XCTAssertEqual(macPackets.last?.1, Data("{\"kind\":\"move\"}".utf8))

        session.close()
        wait(for: [closed], timeout: 5)
        close(fds[1])
    }

    func testGarbageFromPeerClosesSession() throws {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        let session = Session(stream: FDStream(fd: fds[0]), transport: .usb(deviceID: 1), identity: .init(), localName: "Test Mac")
        let closed = expectation(description: "closed")
        session.onClose = { closed.fulfill() }
        session.onPacket = { _, _ in XCTFail("no packet may get through") }
        session.start()
        var junk = Data([0, 40]); junk.append(Data(repeating: 0xAB, count: 40))   // bogus handshake msg 2
        _ = Sock.writeAll(fds[1], junk)
        wait(for: [closed], timeout: 5)
        close(fds[1])
    }
}

import Network

/// The Wi-Fi code path: the real Mac `Session` over `NWStream` (TCP), against a fake iPad listener.
/// Runs on localhost, so it exercises the stream and channel, not the LAN address policy (tested
/// separately in NetworkPolicyTests).
final class NWStreamEndToEndTests: XCTestCase {
    func testSessionOverTCPAndDeclineBeforeIdentity() throws {
        let padKey = Curve25519.KeyAgreement.PrivateKey()
        let queue = DispatchQueue(label: "fakepad")
        let listener = try NWListener(using: .tcp, on: .any)
        var padChannel: SecureChannel?
        var padConn: NWConnection?
        let padGotInput = expectation(description: "pad got packet")
        listener.newConnectionHandler = { c in
            padConn = c
            let ch = SecureChannel(initiator: false, identity: padKey, localName: "Wi-Fi iPad")
            padChannel = ch
            c.start(queue: queue)
            func loop() {
                c.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, done, _ in
                    if let data, let events = try? ch.receive(data) {
                        for e in events {
                            if case .send(let d) = e { c.send(content: d, completion: .idempotent) }
                            if case .packet(.trustState, _) = e { padGotInput.fulfill() }
                        }
                    }
                    if !done { loop() }
                }
            }
            loop()
        }
        let ready = expectation(description: "listening")
        listener.stateUpdateHandler = { if case .ready = $0 { ready.fulfill() } }
        listener.start(queue: queue)
        wait(for: [ready], timeout: 5)
        let port = try XCTUnwrap(listener.port)

        func connect() throws -> NWConnection {
            let c = NWConnection(host: "127.0.0.1", port: port, using: .tcp)
            let up = expectation(description: "connected")
            c.stateUpdateHandler = { if case .ready = $0 { up.fulfill() } }
            c.start(queue: DispatchQueue(label: "mac"))
            wait(for: [up], timeout: 5)
            return c
        }

        // 1. Known iPad: the session establishes over TCP and carries packets both ways.
        let s = Session(stream: NWStream(connection: try connect()), transport: .wifi(service: "ExtenD-TEST"),
                        identity: .init(), localName: "Mac",
                        acceptResponder: { key, _ in key == padKey.publicKey.rawRepresentation })
        let est = expectation(description: "established")
        s.onEstablished = { p in XCTAssertEqual(p.name, "Wi-Fi iPad"); est.fulfill() }
        s.start()
        wait(for: [est], timeout: 5)
        XCTAssertTrue(s.send(.trustState, Data([1])))
        wait(for: [padGotInput], timeout: 5)
        let closed = expectation(description: "closed")
        s.onClose = { closed.fulfill() }
        s.close()
        wait(for: [closed], timeout: 5)
        padConn?.cancel()

        // 2. Unknown iPad: declined after message 2; the iPad never learns the Mac's identity.
        let s2 = Session(stream: NWStream(connection: try connect()), transport: .wifi(service: "ExtenD-TEST"),
                         identity: .init(), localName: "Mac", acceptResponder: { _, _ in false })
        let declined = expectation(description: "declined")
        let closed2 = expectation(description: "closed2")
        s2.onDeclined = { key, name in
            XCTAssertEqual(key, padKey.publicKey.rawRepresentation); XCTAssertEqual(name, "Wi-Fi iPad"); declined.fulfill()
        }
        s2.onClose = { closed2.fulfill() }
        s2.onEstablished = { _ in XCTFail("must not establish") }
        s2.start()
        wait(for: [declined, closed2], timeout: 5)
        queue.sync {}
        XCTAssertNil(padChannel?.peer)
        listener.cancel()
    }
}
