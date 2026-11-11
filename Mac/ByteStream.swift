import Foundation
import Network

/// A bidirectional byte stream to the iPad: the usbmuxd tunnel (FDStream) or a LAN TCP
/// connection (NWStream). `Session` runs the same secure channel over either (ADR-002 §8).
protocol ByteStream: AnyObject {
    /// Delivers received bytes serially on a background thread; `onEnd` fires exactly once.
    func start(onData: @escaping (Data) -> Void, onEnd: @escaping () -> Void)
    /// Blocking write, called serially. Returns false on error or when the peer stalls for
    /// `Session.writeTimeout`; the caller then closes the session.
    func write(_ data: Data) -> Bool
    /// Idempotent. Unblocks reads and writes; `onEnd` follows.
    func shutdown()
}

/// usbmuxd tunnel socket. The fd is closed only by the reader thread, after reading stopped and any
/// in-flight write finished, so no read or write can ever touch a reused descriptor number.
final class FDStream: ByteStream {
    private let fd: Int32
    private let ioLock = NSLock()      // held for each write; the reader takes it before close()
    private let stateLock = NSLock()
    private var shut = false

    init(fd: Int32) {
        self.fd = fd
        var tv = timeval(tv_sec: Int(Session.writeTimeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    func start(onData: @escaping (Data) -> Void, onEnd: @escaping () -> Void) {
        Thread.detachNewThread { [self] in
            var buf = [UInt8](repeating: 0, count: 64 * 1024)
            while true {
                let n = Darwin.read(fd, &buf, buf.count)
                if n < 0 && errno == EINTR { continue }
                if n <= 0 { break }
                onData(Data(buf[0..<n]))
            }
            shutdown()
            onEnd()
            ioLock.lock()   // wait for an in-flight write; later writes see `shut` and skip the fd
            Darwin.close(fd)
            ioLock.unlock()
        }
    }

    func write(_ data: Data) -> Bool {
        ioLock.lock(); defer { ioLock.unlock() }
        guard !isShut else { return false }
        return Sock.writeAll(fd, data)
    }

    func shutdown() {
        let first: Bool = stateLock.withLock { defer { shut = true }; return !shut }
        if first { Darwin.shutdown(fd, SHUT_RDWR) }   // wakes the reader, fails a blocked write
    }

    private var isShut: Bool { stateLock.withLock { shut } }
}

/// LAN TCP connection (already `.ready`, address-checked by the caller).
final class NWStream: ByteStream {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "nwstream")
    private let lock = NSLock()
    private var ended = false
    private var onEnd: (() -> Void)?

    init(connection: NWConnection) { self.connection = connection }

    func start(onData: @escaping (Data) -> Void, onEnd: @escaping () -> Void) {
        self.onEnd = onEnd
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed, .cancelled: self?.finish()
            default: break
            }
        }
        if connection.queue == nil { connection.start(queue: queue) }
        receive(onData)
    }

    private func receive(_ onData: @escaping (Data) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, done, error in
            guard let self else { return }
            if let data, !data.isEmpty { onData(data) }
            if done || error != nil { self.shutdown(); self.finish(); return }
            self.receive(onData)
        }
    }

    func write(_ data: Data) -> Bool {
        guard !isEnded else { return false }
        let sent = DispatchSemaphore(value: 0)
        var ok = false
        connection.send(content: data, completion: .contentProcessed { error in
            ok = error == nil
            sent.signal()
        })
        // A stalled peer (iPad suspended, Wi-Fi gone) must not block the writer forever.
        guard sent.wait(timeout: .now() + Session.writeTimeout) == .success else { return false }
        return ok
    }

    func shutdown() { connection.cancel() }

    private var isEnded: Bool { lock.withLock { ended } }

    private func finish() {
        let callback: (() -> Void)? = lock.withLock {
            if ended { return nil }
            ended = true
            return onEnd
        }
        callback?()
    }
}
