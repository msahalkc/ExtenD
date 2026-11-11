// Shared by BOTH targets (add this file to the Mac app and the iPad app).
import Foundation

enum WireConst {
    /// TCP port the iPad app listens on. The Mac reaches it through usbmuxd (USB only).
    static let port: UInt16 = 7878
    /// Noise prologue. Bump on any incompatible wire change; mismatched peers fail the handshake.
    static let prologue = Data("ExtenD/1".utf8)
    static let handshakeTimeout: TimeInterval = 10
    static let pairingTimeout: TimeInterval = 60
    /// After a rejected or timed-out pairing, no new attempt for this long (stops prompt spam).
    static let pairingCooldown: TimeInterval = 5
    /// Without USB, how long the Mac keeps the iPad display after the last link drops (ADR-002 §6).
    static let wifiDisplayGrace: TimeInterval = 120
    /// Video bitrate per transport (ADR-002 §7).
    static let usbBitrate = 30_000_000
    static let wifiBitrate = 15_000_000
}

// Wire layering (ADR-001):
//   socket  = sequence of [u16 BE length][body]           (SecureChannel)
//   body    = Noise handshake message, then AES-GCM records
//   records = decrypt to a continuous Framing byte stream  (below)

enum PacketType: UInt8 {
    case videoConfig     = 1   // Mac → iPad: [u16 spsLen][sps][u16 ppsLen][pps]
    case videoFrame      = 2   // Mac → iPad: [u8 isKey][H.264 AVCC data, 4-byte NAL lengths]
    case hello           = 10  // iPad → Mac: JSON Hello
    case input           = 11  // iPad → Mac: JSON InputEvent
    case keyframeRequest = 12  // iPad → Mac: empty
    case trustState      = 20  // both ways, first packet after the handshake: [u8 1 = peer already paired]
    case pairDecision    = 21  // both ways, only while pairing: [u8 1 = user accepted]
    case pairCommit      = 22  // iPad → Mac, pairing: SHA-256 commitment to the iPad's nonce
    case pairNonce       = 23  // Mac → iPad, pairing: Mac's 32-byte nonce
    case pairReveal      = 24  // iPad → Mac, pairing: iPad's 32-byte nonce

    /// Largest payload accepted for this type. Anything bigger is a protocol violation.
    var maxPayload: Int {
        switch self {
        case .videoConfig:     return 4 * 1024
        case .videoFrame:      return 16 * 1024 * 1024
        case .hello, .input:   return 1024
        case .keyframeRequest: return 0
        case .trustState, .pairDecision: return 1
        case .pairCommit, .pairNonce, .pairReveal: return PairingGate.nonceLength
        }
    }

    /// Only these may flow before both sides have authorized the session (see PairingGate).
    var isPairing: Bool { rawValue >= 20 && rawValue <= 24 }
}

enum ProtocolError: Error {
    case unknownType(UInt8)
    case oversized(PacketType, Int)
}

struct Hello: Codable {
    var pixelWidth: Int
    var pixelHeight: Int

    /// Accepted display size range in pixels (largest iPad today is 2752×2064).
    static let pixelRange = 256...8192
    /// H.264 level 5.2 frame-size limit (36,864 macroblocks); larger sizes can't be encoded.
    static let maxPixels = 36_864 * 256
    var isValid: Bool {
        Self.pixelRange.contains(pixelWidth) && Self.pixelRange.contains(pixelHeight)
            && pixelWidth * pixelHeight <= Self.maxPixels
    }
}

struct InputEvent: Codable {
    enum Kind: String, Codable {
        case move, leftDown, leftDrag, leftUp, rightClick, scroll, keyDown, keyUp
        /// Finger tap: the Mac clicks, nudging a near miss onto a small control (TouchAssist).
        case tap
        /// One-finger pan with `phase`: the Mac drags or scrolls, depending on what's under the
        /// start point (sliders, title bars → drag; scrollable content → scroll).
        case pan
    }
    var kind: Kind
    var x: Double = 0            // normalized 0…1 across the iPad screen
    var y: Double = 0
    var dx: Double = 0           // scroll delta: points, or normalized 0…1 units when `phase` is set
    var dy: Double = 0
    var pressure: Double? = nil  // Apple Pencil only, 0…1
    var tiltX: Double? = nil     // Apple Pencil only, -1…1
    var tiltY: Double? = nil
    var keyCode: Int? = nil      // USB HID usage (UIKey.keyCode)
    var modifiers: Int = 0       // ModifierBits
    var touch: Bool? = nil       // true = from a finger: the Mac returns the cursor afterwards
    /// Trackpad-style scroll / pan phase (GesturePhase). With it, `.scroll` scrolls continuously,
    /// with rubber-banding and, after `.ended`, momentum from `vx`/`vy`.
    var phase: Int? = nil
    var vx: Double? = nil        // release velocity at `.ended`, normalized units per second
    var vy: Double? = nil
}

enum GesturePhase {
    static let began = 1, changed = 2, ended = 3, cancelled = 4
}

enum ModifierBits {
    static let shift = 1, control = 2, option = 4, command = 8, capsLock = 16
}

/// Wire framing: [type u8][length u32 big-endian][payload]
enum Framing {
    static func encode(_ type: PacketType, _ payload: Data) -> Data {
        var d = Data(capacity: 5 + payload.count)
        d.append(type.rawValue)
        let len = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: len) { d.append(contentsOf: $0) }
        d.append(payload)
        return d
    }
}

/// Incremental parser for `Framing`.
/// Throws on an unknown type or an oversized length, checked from the header before the
/// payload is buffered. The caller must then drop the connection.
struct FrameParser {
    private var buffer = Data()

    mutating func append(_ data: Data) { buffer.append(data) }

    mutating func next() throws -> (PacketType, Data)? {
        guard buffer.count >= 5 else { return nil }
        let s = buffer.startIndex
        guard let type = PacketType(rawValue: buffer[s]) else { throw ProtocolError.unknownType(buffer[s]) }
        let len = Int(buffer[(s + 1)..<(s + 5)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) })
        guard len <= type.maxPayload else { throw ProtocolError.oversized(type, len) }
        let total = 5 + len
        guard buffer.count >= total else { return nil }
        let payload = buffer.subdata(in: (s + 5)..<(s + total))
        buffer.removeSubrange(s..<(s + total))
        return (type, payload)
    }
}
