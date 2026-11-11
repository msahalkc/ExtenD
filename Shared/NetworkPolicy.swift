// Shared by BOTH targets.
// Local-network-only policy for the Wi-Fi transport (ADR-002 §2): same LAN, private addresses,
// never cellular, VPN tunnels, peer-to-peer Wi-Fi or the internet.
import Foundation
import Network

enum NetworkPolicy {
    static let bonjourType = "_extend._tcp"

    /// TCP parameters for Wi-Fi/Ethernet LAN connections and listeners.
    static func lanParameters() -> NWParameters {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.enableKeepalive = true          // notice a vanished peer (Wi-Fi drop) within seconds
        tcp.keepaliveIdle = 2
        tcp.keepaliveInterval = 1
        tcp.keepaliveCount = 3
        let params = NWParameters(tls: nil, tcp: tcp)
        // IPv4 only: LAN peers then always have RFC 1918 / link-local addresses, so a dual-stack
        // iPad is never refused for resolving to its global IPv6 address.
        if let ip = params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options { ip.version = .v4 }
        params.includePeerToPeer = false
        params.prohibitedInterfaceTypes = [.cellular, .loopback, .other]   // .other = VPN/utun tunnels
        return params
    }

    /// Defence in depth: the connection really runs over Wi-Fi or wired Ethernet (not a VPN tunnel
    /// that happens to use private addresses, not cellular).
    static func isLANPath(_ path: NWPath?) -> Bool {
        guard let path else { return false }
        return (path.usesInterfaceType(.wifi) || path.usesInterfaceType(.wiredEthernet))
            && !path.usesInterfaceType(.other) && !path.usesInterfaceType(.cellular)
    }

    /// True for private or link-local unicast addresses: the only peers allowed over Wi-Fi.
    static func isPrivateLAN(_ endpoint: NWEndpoint) -> Bool {
        guard case let .hostPort(host, _) = endpoint else { return false }
        switch host {
        case .ipv4(let a): return isPrivate(v4: a.rawValue)
        case .ipv6(let a):
            if let v4 = a.asIPv4 { return isPrivate(v4: v4.rawValue) }
            let b = [UInt8](a.rawValue)
            guard b.count == 16 else { return false }
            if b[0] == 0xFE && (b[1] & 0xC0) == 0x80 { return true }   // fe80::/10 link-local
            if (b[0] & 0xFE) == 0xFC { return true }                     // fc00::/7 unique local
            return false
        default:
            return false
        }
    }

    static func isPrivate(v4 raw: Data) -> Bool {
        let b = [UInt8](raw)
        guard b.count == 4 else { return false }
        switch (b[0], b[1]) {
        case (10, _): return true                          // 10.0.0.0/8
        case (172, 16...31): return true                   // 172.16.0.0/12
        case (192, 168): return true                       // 192.168.0.0/16
        case (169, 254): return true                       // 169.254.0.0/16 link-local
        default: return false
        }
    }
}
