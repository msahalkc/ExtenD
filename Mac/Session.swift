import Foundation
import CryptoKit

/// One live, encrypted connection to the iPad app, over USB (usbmuxd) or the local Wi-Fi.
/// See ADR-001 (channel, pairing) and ADR-002 (transports).
/// The Mac is the Noise initiator. Nothing but pairing packets can be sent until `authorize()`.
/// Timeouts for the handshake and pairing setup are enforced by the owner (AppModel).
final class Session {
    enum Transport: Equatable { case usb(deviceID: Int), wifi(service: String) }

    var onEstablished: ((PeerInfo) -> Void)?       // main queue
    var onPacket: ((PacketType, Data) -> Void)?    // main queue
    /// The responder was declined after handshake message 2 (see `acceptResponder`). Main queue,
    /// before `onClose`.
    var onDeclined: ((Data, String) -> Void)?
    var onClose: (() -> Void)?                     // main queue

    let transport: Transport
    private let stream: ByteStream
    private let channel: SecureChannel
    private let writeQueue = DispatchQueue(label: "session.write")
    private let lock = NSLock()
    private var closed = false
    private var authorized = false
    private var pendingBytes = 0

    /// Queued-bytes limits for droppable video: P-frames drop early, keyframes only when the link
    /// is clearly stalled. Control and pairing packets are never dropped.
    static let frameQueueLimit = 200_000      // ≈ 3–4 frames at 30 Mbit/s: keeps latency low
    static let keyframeQueueLimit = 8_000_000
    /// A write that can't make progress for this long means the iPad is stalled: close the session.
    static let writeTimeout: TimeInterval = 5

    /// `acceptResponder`: decide, from the iPad's authenticated key and name, whether to continue
    /// the handshake before revealing our identity (used for Wi-Fi peers, ADR-002 §4).
    init(stream: ByteStream, transport: Transport, identity: Curve25519.KeyAgreement.PrivateKey,
         localName: String, acceptResponder: ((Data, String) -> Bool)? = nil) {
        self.stream = stream
        self.transport = transport
        channel = SecureChannel(initiator: true, identity: identity, localName: localName,
                                acceptResponder: acceptResponder)
    }

    var isWiFi: Bool { if case .wifi = transport { return true } else { return false } }

    func start() {
        stream.start(onData: { [weak self] bytes in self?.received(bytes) },
                     onEnd: { [weak self] in self?.close() })
        do {
            if let first = try channel.start() { write(first) }
        } catch {
            close()
        }
    }

    private func received(_ bytes: Data) {
        guard !isClosed else { return }
        do {
            for event in try channel.receive(bytes) {
                switch event {
                case .send(let out):
                    write(out)
                case .established(let peer):
                    DispatchQueue.main.async { self.onEstablished?(peer) }
                case .packet(let type, let payload):
                    DispatchQueue.main.async { self.onPacket?(type, payload) }
                }
            }
        } catch ChannelError.responderDeclined(let key, let name) {
            DispatchQueue.main.async { self.onDeclined?(key, name) }
            close()
        } catch {
            NSLog("Dropping iPad session: \(error)")
            close()
        }
    }

    /// Lets display/input traffic through. Call only once the PairingGate is active.
    func authorize() {
        lock.withLock { authorized = true }
    }

    /// Queues a packet. With `dropAbove`, returns false (and drops it) when more than that many
    /// bytes are already waiting to be written.
    @discardableResult
    func send(_ type: PacketType, _ payload: Data, dropAbove: Int? = nil) -> Bool {
        lock.lock()
        if closed || (!authorized && !type.isPairing) { lock.unlock(); return false }
        if let limit = dropAbove, pendingBytes > limit { lock.unlock(); return false }
        pendingBytes += payload.count
        lock.unlock()

        writeQueue.async { [self] in   // serial: record nonces go out in order
            defer { lock.withLock { pendingBytes -= payload.count } }
            guard !isClosed else { return }
            let ok: Bool
            do { ok = stream.write(try channel.seal(type, payload)) } catch { ok = false }
            if !ok { close() }
        }
        return true
    }

    private var isClosed: Bool { lock.withLock { closed } }

    private func write(_ bytes: Data) {
        writeQueue.async { [self] in
            guard !isClosed else { return }
            if !stream.write(bytes) { close() }
        }
    }

    func close() {
        let first: Bool = lock.withLock { defer { closed = true }; return !closed }
        guard first else { return }
        stream.shutdown()
        DispatchQueue.main.async { self.onClose?() }
    }
}
