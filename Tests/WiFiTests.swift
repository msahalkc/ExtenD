import XCTest
import Network
import CryptoKit

final class NetworkPolicyTests: XCTestCase {
    private func ep(_ s: String) -> NWEndpoint { .hostPort(host: NWEndpoint.Host(s), port: 1234) }

    func testPrivateAndLinkLocalAllowed() {
        for a in ["10.0.0.5", "172.16.1.1", "172.31.255.254", "192.168.1.20", "169.254.3.4",
                  "fe80::1", "fd12:3456::1", "::ffff:192.168.0.9"] {
            XCTAssertTrue(NetworkPolicy.isPrivateLAN(ep(a)), a)
        }
    }

    func testPublicLoopbackAndOddAddressesRefused() {
        for a in ["8.8.8.8", "172.32.0.1", "172.15.0.1", "100.64.0.1", "127.0.0.1", "::1",
                  "2001:4860::8888", "::ffff:8.8.8.8", "0.0.0.0", "224.0.0.251"] {
            XCTAssertFalse(NetworkPolicy.isPrivateLAN(ep(a)), a)
        }
        XCTAssertFalse(NetworkPolicy.isPrivateLAN(.service(name: "x", type: "_extend._tcp", domain: "local", interface: nil)))
    }

    func testLanParametersExcludeCellularVPNAndLoopback() {
        let p = NetworkPolicy.lanParameters()
        XCTAssertFalse(p.includePeerToPeer)
        for t in [NWInterface.InterfaceType.cellular, .loopback, .other] {
            XCTAssertTrue(p.prohibitedInterfaceTypes?.contains(t) == true)
        }
    }
}

final class ResponderDeclineTests: XCTestCase {
    /// The Mac (initiator) can inspect the iPad's authenticated key after message 2 and stop before
    /// message 3, so an unknown iPad on the Wi-Fi never learns who the Mac is.
    func testInitiatorDeclinesBeforeRevealingItself() throws {
        let padKey = Curve25519.KeyAgreement.PrivateKey()
        var seen: (Data, String)?
        let mac = SecureChannel(initiator: true, identity: .init(), localName: "Mac") { key, name in
            seen = (key, name); return false
        }
        let pad = SecureChannel(initiator: false, identity: padKey, localName: "Someone’s iPad")
        var toMac: [Data] = []
        for e in try pad.receive(try XCTUnwrap(try mac.start())) { if case .send(let d) = e { toMac.append(d) } }
        XCTAssertThrowsError(try mac.receive(toMac[0])) {
            XCTAssertEqual($0 as? ChannelError, .responderDeclined(publicKey: padKey.publicKey.rawRepresentation, name: "Someone’s iPad"))
        }
        XCTAssertEqual(seen?.0, padKey.publicKey.rawRepresentation)
        XCTAssertFalse(mac.isEstablished)
        XCTAssertFalse(pad.isEstablished)   // never got message 3: the Mac's identity stayed private
        XCTAssertNil(pad.peer)
    }

    func testInitiatorAcceptsKnownResponder() throws {
        let padKey = Curve25519.KeyAgreement.PrivateKey()
        let mac = SecureChannel(initiator: true, identity: .init(), localName: "Mac") { key, _ in
            key == padKey.publicKey.rawRepresentation
        }
        let pad = SecureChannel(initiator: false, identity: padKey, localName: "iPad")
        var toMac: [Data] = [], toPad: [Data] = []
        for e in try pad.receive(try XCTUnwrap(try mac.start())) { if case .send(let d) = e { toMac.append(d) } }
        for e in try mac.receive(toMac[0]) { if case .send(let d) = e { toPad.append(d) } }
        _ = try pad.receive(toPad[0])
        XCTAssertTrue(mac.isEstablished && pad.isEstablished)
    }
}
