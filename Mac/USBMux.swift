import Foundation

/// Blocking socket helpers.
enum Sock {
    static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { raw -> Bool in
            guard var p = raw.baseAddress else { return true }
            var left = raw.count
            while left > 0 {
                let n = Darwin.write(fd, p, left)
                if n < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                left -= n
                p = p.advanced(by: n)
            }
            return true
        }
    }

    static func readExact(_ fd: Int32, _ count: Int) -> Data? {
        if count == 0 { return Data() }
        var data = Data(count: count)
        let ok = data.withUnsafeMutableBytes { raw -> Bool in
            var got = 0
            while got < count {
                let n = Darwin.read(fd, raw.baseAddress!.advanced(by: got), count - got)
                if n < 0 && errno == EINTR { continue }
                if n <= 0 { return false }
                got += n
            }
            return true
        }
        return ok ? data : nil
    }
}

/// Minimal client for usbmuxd, the macOS daemon that Finder/Xcode use to reach iOS devices over USB.
/// Message = 16-byte little-endian header [length, version=1, type=8 (plist), tag] + XML plist.
final class USBMux {
    var onAttach: ((Int, String?) -> Void)?   // (DeviceID, serial/UDID), delivered on the main queue
    var onDetach: ((Int) -> Void)?

    private static let socketPath = "/var/run/usbmuxd"
    private static let progName = "ExtenDMac"

    func start() {
        Thread.detachNewThread { self.listenLoop() }
    }

    private func listenLoop() {
        while true {
            guard let fd = USBMux.openSocket() else { sleep(2); continue }
            let ok = USBMux.sendPlist(fd, ["MessageType": "Listen",
                                           "ClientVersionString": Self.progName,
                                           "ProgName": Self.progName])
            while ok, let msg = USBMux.readPlist(fd) {
                guard let type = msg["MessageType"] as? String else { continue }
                if type == "Attached",
                   let id = msg["DeviceID"] as? Int,
                   let props = msg["Properties"] as? [String: Any],
                   props["ConnectionType"] as? String == "USB" {
                    let serial = props["SerialNumber"] as? String
                    DispatchQueue.main.async { self.onAttach?(id, serial) }
                } else if type == "Detached", let id = msg["DeviceID"] as? Int {
                    DispatchQueue.main.async { self.onDetach?(id) }
                }
            }
            Darwin.close(fd)
            sleep(1)
        }
    }

    /// Opens a raw TCP tunnel to `port` on the device. Blocking. Returns a socket fd or nil.
    static func openTunnel(deviceID: Int, port: UInt16) -> Int32? {
        guard let fd = openSocket() else { return nil }
        let msg: [String: Any] = [
            "MessageType": "Connect",
            "DeviceID": deviceID,
            "PortNumber": Int(port.byteSwapped),   // usbmuxd expects network byte order
            "ClientVersionString": progName,
            "ProgName": progName,
        ]
        setTimeout(fd, SO_RCVTIMEO, seconds: 5)   // usbmuxd must answer promptly
        guard sendPlist(fd, msg), let reply = readPlist(fd), reply["Number"] as? Int == 0 else {
            Darwin.close(fd)
            return nil
        }
        setTimeout(fd, SO_RCVTIMEO, seconds: 0)   // tunnel reads block until the iPad sends
        return fd   // from here on the socket is a plain byte stream to the iPad app
    }

    // MARK: - Internals

    private static func openSocket() -> Int32? {
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_un()
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        addr.sun_len = UInt8(len)
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            for (i, b) in pathBytes.prefix(buf.count - 1).enumerated() { buf[i] = b }
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, len) }
        }
        guard rc == 0 else { Darwin.close(fd); return nil }
        return fd
    }

    private static func setTimeout(_ fd: Int32, _ option: Int32, seconds: Int) {
        var tv = timeval(tv_sec: seconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, option, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    private static func sendPlist(_ fd: Int32, _ dict: [String: Any]) -> Bool {
        guard let body = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        else { return false }
        let header: [UInt32] = [UInt32(16 + body.count), 1, 8, 1].map { $0.littleEndian }
        var packet = header.withUnsafeBytes { Data($0) }
        packet.append(body)
        return Sock.writeAll(fd, packet)
    }

    private static func readPlist(_ fd: Int32) -> [String: Any]? {
        guard let head = Sock.readExact(fd, 16) else { return nil }
        let length = Int(UInt32(littleEndian: head.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }))
        guard length >= 16, length <= 1 << 20, let body = Sock.readExact(fd, length - 16) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: body, options: [], format: nil)) as? [String: Any]
    }
}
