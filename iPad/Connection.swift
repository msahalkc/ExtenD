import Foundation
import Network
import CryptoKit
import UIKit
import os

private let log = Logger(subsystem: "com.msahalkc.extend", category: "connection")

/// Accepts the Mac over two transports (ADR-002):
/// - **USB**: loopback listener on WireConst.port. usbmuxd tunnels arrive on the iPad as TCP from localhost.
/// - **Wi-Fi**: Bonjour `_extend._tcp` on the local network (Wi-Fi/Ethernet, never cellular or VPN),
///   anonymous service name, peers must have private or link-local addresses. On by default.
///
/// Every connection is a SecureChannel (Noise XX responder, ADR-001) followed by a PairingGate.
/// Display packets are delivered, and input is sent, only on the current link once its gate is active.
///
/// One current link at a time. While the current link is an active Wi-Fi session, one USB *candidate*
/// may connect in parallel; it replaces the Wi-Fi link only after its gate is active and its peer key
/// equals the current peer's (authenticated hand-over), and it is never allowed to prompt.
final class Connection {
    enum State: Equatable {
        case waiting
        case securing
        case pairing(attempt: Int, peerName: String, code: String)   // ask the user, then decidePairing
        case awaitingPeerDecision(peerName: String)                  // user accepted; the Mac hasn't yet
        case connected(peerName: String, wifi: Bool)
        case failed(String)
    }

    var onPacket: ((PacketType, Data) -> Void)?   // main queue, only while connected
    var onStateChange: ((State) -> Void)?         // main queue

    let store: PairingStore = KeychainPairingStore()

    /// Wi-Fi connections allowed (default on; user setting).
    var wifiEnabled: Bool {
        get { UserDefaults.standard.object(forKey: "WiFiEnabled") as? Bool ?? true }
        set {
            UserDefaults.standard.set(newValue, forKey: "WiFiEnabled")
            queue.async { self.restartListeners() }
        }
    }

    /// Per-connection state.
    private final class Link {
        let connection: NWConnection
        let wifi: Bool
        let channel: SecureChannel
        let attempt: Int
        let created = Date()
        var gate: PairingGate?
        var peer: PeerInfo?
        var pairingTimer: DispatchWorkItem?
        init(_ c: NWConnection, wifi: Bool, channel: SecureChannel, attempt: Int) {
            connection = c; self.wifi = wifi; self.channel = channel; self.attempt = attempt
        }
        var isActive: Bool { gate?.isActive == true }
        var isPrompting: Bool { gate?.isPrompting == true }
    }

    private var usbListener: NWListener?
    private var wifiListener: NWListener?
    private var running = false   // app is in the foreground
    private var current: Link?
    private var candidate: Link?
    private var attempt = 0
    private var identity: Curve25519.KeyAgreement.PrivateKey?
    /// After an unfinished pairing prompt, that transport refuses new connections briefly. Separate
    /// per transport, so a LAN host can never block the USB cable.
    private var usbCooldownUntil = Date.distantPast
    private var wifiCooldownUntil = Date.distantPast
    /// Over Wi-Fi, a Mac this iPad doesn't know may pair only while the user has armed it on the iPad
    /// ("Pair a New Mac", user choice 2026-11-11): a LAN host can't make the iPad prompt unasked.
    private var wifiPairingArmedUntil = Date.distantPast
    static let wifiPairingWindow: TimeInterval = 60
    private let queue = DispatchQueue(label: "net")   // all link/channel/gate state lives here
    private let localName = UIDevice.current.name

    // MARK: - Lifecycle

    /// Starts listening. Call when the app comes to the foreground.
    func start() {
        queue.async {
            self.running = true
            self.restartListeners()
        }
    }

    /// Stops listening and drops any connection. Call when the app goes to the background: iPadOS
    /// tears down a suspended app's sockets, so we close cleanly and listen afresh on return.
    func stop() {
        queue.async {
            self.running = false
            self.dropCandidate()
            self.drop()
            self.stopListeners()
            log.info("Stopped listening (app in background)")
        }
    }

    private func stopListeners() {
        usbListener?.cancel(); usbListener = nil
        wifiListener?.cancel(); wifiListener = nil
    }

    private func restartListeners() {
        stopListeners()
        if current?.wifi == true && !wifiEnabled { drop() }
        guard running else { return }
        if identity == nil {
            do {
                identity = try Identity.loadOrCreate()
            } catch {
                report(.failed("Can't access the Keychain (\(error))."))
                return
            }
        }
        startUSBListener()
        if wifiEnabled { startWiFiListener() }
    }

    private func startUSBListener() {
        guard running, usbListener == nil else { return }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let params = NWParameters(tls: nil, tcp: tcp)
        params.allowLocalEndpointReuse = true
        params.requiredInterfaceType = .loopback   // usbmuxd tunnels only
        params.includePeerToPeer = false
        guard let l = try? NWListener(using: params, on: NWEndpoint.Port(rawValue: WireConst.port)!) else {
            log.error("Couldn't create USB listener; retrying")
            queue.asyncAfter(deadline: .now() + 1) { self.startUSBListener() }
            return
        }
        l.newConnectionHandler = { [weak self] c in self?.accept(c, wifi: false) }
        l.stateUpdateHandler = { [weak self, weak l] state in
            guard let self, let l, l === self.usbListener else { return }
            switch state {
            case .ready:
                log.info("Listening for USB on loopback:\(WireConst.port)")
            case .failed(let error), .waiting(let error):
                // Includes sockets torn down by the system: rebuild the listener.
                log.error("USB listener \(String(describing: state)): \(error.localizedDescription); restarting")
                l.cancel()
                self.usbListener = nil
                self.queue.asyncAfter(deadline: .now() + 1) { self.startUSBListener() }
            default:
                break
            }
        }
        usbListener = l
        l.start(queue: queue)
    }

    private func startWiFiListener() {
        guard running, wifiEnabled, wifiListener == nil else { return }
        guard let l = try? NWListener(using: NetworkPolicy.lanParameters()) else {
            log.error("Couldn't create Wi-Fi listener; retrying")
            queue.asyncAfter(deadline: .now() + 2) { self.startWiFiListener() }
            return
        }
        // Anonymous per launch: never advertise the device name on the network.
        let suffix = String(UInt16.random(in: 0...UInt16.max), radix: 16, uppercase: true)
        l.service = NWListener.Service(name: "ExtenD-\(suffix)", type: NetworkPolicy.bonjourType)
        l.newConnectionHandler = { [weak self] c in self?.accept(c, wifi: true) }
        l.stateUpdateHandler = { [weak self, weak l] state in
            guard let self, let l, l === self.wifiListener else { return }
            switch state {
            case .ready:
                log.info("Advertising on the local network as ExtenD-\(suffix)")
            case .failed(let error), .waiting(let error):
                log.error("Wi-Fi listener \(String(describing: state)): \(error.localizedDescription); restarting")
                l.cancel()
                self.wifiListener = nil
                self.queue.asyncAfter(deadline: .now() + 2) { self.startWiFiListener() }
            default:
                break
            }
        }
        wifiListener = l
        l.start(queue: queue)
    }

    // MARK: - API (any thread)

    /// Sends a packet to the Mac. Dropped unless the current session is paired and active.
    func send(_ type: PacketType, _ payload: Data) {
        queue.async {
            guard let link = self.current, link.isActive else { return }
            self.sendNow(link, type, payload)
        }
    }

    /// The user's answer to a specific prompt. Ignored if that connection is gone.
    func decidePairing(attempt: Int, accepted: Bool) {
        queue.async {
            guard let link = self.current, link.attempt == attempt, var g = link.gate, let p = link.peer else { return }
            let outputs = g.decide(accepted)
            link.gate = g
            if accepted { self.report(.awaitingPeerDecision(peerName: p.name)) }
            self.apply(outputs, on: link)
        }
    }

    /// Lets a new Mac pair over Wi-Fi for the next `wifiPairingWindow` seconds.
    func armWiFiPairing() {
        queue.async { self.wifiPairingArmedUntil = Date().addingTimeInterval(Self.wifiPairingWindow) }
    }

    func forget(_ device: PairedDevice) {
        queue.async {
            do {
                try self.store.remove(device.publicKey)
            } catch {
                self.report(.failed("Couldn't forget \(device.name) (\(error)). It is still paired."))
                return
            }
            if self.current?.peer?.publicKey == device.publicKey { self.drop() }
            if self.candidate?.peer?.publicKey == device.publicKey { self.dropCandidate() }
        }
    }

    // MARK: - Accepting (queue)

    private func accept(_ c: NWConnection, wifi: Bool) {
        // Transport policy: USB = loopback (usbmuxd); Wi-Fi = private/link-local LAN addresses only.
        let allowed = wifi ? (wifiEnabled && NetworkPolicy.isPrivateLAN(c.endpoint)) : Self.isLoopback(c.endpoint)
        let cooldown = wifi ? wifiCooldownUntil : usbCooldownUntil
        guard allowed, Date() >= cooldown, let identity else {
            c.cancel()
            return
        }
        func newLink(wifi: Bool) -> Link {
            attempt += 1
            return Link(c, wifi: wifi, channel: SecureChannel(initiator: false, identity: identity, localName: localName),
                        attempt: attempt)
        }
        if let cur = current {
            if wifi {
                // Wi-Fi never displaces a link that's active or prompting, nor a USB link that's
                // still setting up normally. A link stuck in setup (a squatter) may be replaced.
                let stuck = Date().timeIntervalSince(cur.created) > 3
                guard !cur.isActive, !cur.isPrompting, cur.wifi || stuck else { c.cancel(); return }
            } else if cur.wifi && cur.isActive {
                // USB joining an active Wi-Fi session: authenticated hand-over candidate.
                guard candidate == nil else { c.cancel(); return }
                let link = newLink(wifi: false)
                candidate = link
                log.info("USB hand-over candidate connected (attempt \(link.attempt))")
                run(link)
                return
            } else if cur.isPrompting || (!cur.wifi && cur.isActive) {
                // A prompting link (either transport) is never replaced: no bait-and-switch of the code
                // on screen. Nor is an active USB link.
                c.cancel()
                return
            }
            // Otherwise USB preempts: a Wi-Fi link that isn't active or prompting, or a USB link in setup.
        }
        drop(notify: false)
        let link = newLink(wifi: wifi)
        current = link
        log.info("Mac connected over \(wifi ? "Wi-Fi" : "USB") (attempt \(link.attempt))")
        report(.securing)
        run(link)
    }

    private func run(_ link: Link) {
        let c = link.connection
        c.stateUpdateHandler = { [weak self, weak link] state in
            guard let self, let link else { return }
            switch state {
            case .ready:
                // Defence in depth: a Wi-Fi link must really run over Wi-Fi or Ethernet (not a VPN).
                if link.wifi && !NetworkPolicy.isLANPath(c.currentPath) {
                    log.error("Refusing Wi-Fi link: not on the local network")
                    self.end(link)
                }
            case .failed, .cancelled: self.end(link)
            default: break
            }
        }
        c.start(queue: queue)
        // Handshake, trust exchange and commit-reveal must finish quickly; only the prompt may take longer.
        queue.asyncAfter(deadline: .now() + WireConst.handshakeTimeout) { [weak self, weak link] in
            guard let self, let link, !link.isActive, !link.isPrompting else { return }
            NSLog("Dropping Mac connection: setup timed out")
            self.end(link)
        }
        receive(link)
    }

    private func receive(_ link: Link) {
        link.connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { [weak self, weak link] data, _, done, error in
            guard let self, let link, link === self.current || link === self.candidate else { return }
            if let data {
                do {
                    for event in try link.channel.receive(data) {
                        guard link === self.current || link === self.candidate else { return }   // dropped meanwhile
                        try self.handle(event, on: link)
                    }
                } catch {
                    NSLog("Dropping Mac connection: \(error)")
                    self.end(link)
                    return
                }
            }
            if done || error != nil { self.end(link); return }
            self.receive(link)
        }
    }

    private func handle(_ event: SecureChannel.Event, on link: Link) throws {
        let isCandidate = link === candidate
        switch event {
        case .send(let bytes):
            link.connection.send(content: bytes, completion: .contentProcessed { _ in })
        case .established(let p):
            link.peer = p
            if isCandidate {
                // A hand-over candidate must be the very Mac of the active session.
                guard p.publicKey == current?.peer?.publicKey else { dropCandidate(); return }
            }
            let known: Bool
            do {
                known = try store.contains(p.publicKey)
            } catch {   // fail closed: never turn a Keychain error into a pairing prompt
                if !isCandidate { report(.failed("Can't read paired Macs from the Keychain (\(error)).")) }
                end(link, notify: false)
                return
            }
            if link.wifi, !isCandidate, !known, Date() >= wifiPairingArmedUntil {
                // Quietly: the Mac explains arming to its user; a stranger's attempt mustn't nudge ours.
                // The cooldown stops a LAN host from looping handshakes.
                log.info("Declined an unknown Mac over Wi-Fi: pairing not armed on this iPad")
                wifiCooldownUntil = Date().addingTimeInterval(WireConst.pairingCooldown)
                end(link)
                return
            }
            let g = PairingGate(peerKnown: known, initiator: false, handshakeHash: p.handshakeHash)
            link.gate = g
            apply(g.start(), on: link)
        case .packet(let type, let payload):
            guard var g = link.gate else { throw PairingGate.Violation.unexpectedPacket(type) }
            if g.isActive {
                if !isCandidate && !type.isPairing { DispatchQueue.main.async { self.onPacket?(type, payload) } }
            } else {
                let outputs = try g.receive(type, payload)
                link.gate = g
                apply(outputs, on: link)
            }
        }
    }

    private func apply(_ outputs: [PairingGate.Output], on link: Link) {
        let isCandidate = link === candidate
        for output in outputs {
            guard let peer = link.peer, link === current || link === candidate else { return }
            switch output {
            case .send(let type, let payload):
                sendNow(link, type, payload)
            case .showPrompt(let code):
                if isCandidate { dropCandidate(); return }   // a candidate never prompts
                report(.pairing(attempt: link.attempt, peerName: peer.name, code: PairingCode.formatted(code)))
                let timer = DispatchWorkItem { [weak self, weak link] in
                    guard let self, let link, link === self.current, !link.isActive else { return }
                    self.endPairingAttempt("Pairing timed out.")
                }
                link.pairingTimer = timer
                queue.asyncAfter(deadline: .now() + WireConst.pairingTimeout, execute: timer)
            case .activate(let save):
                link.pairingTimer?.cancel()
                if isCandidate { promoteCandidate(); return }
                if save {
                    wifiPairingArmedUntil = .distantPast   // one new Mac per arming
                    do {
                        try store.save(PairedDevice(publicKey: peer.publicKey, name: peer.name, pairedAt: Date()))
                    } catch {
                        report(.failed("Couldn't save the pairing (\(error))."))
                        end(link, notify: false)
                        return
                    }
                }
                log.info("Session active over \(link.wifi ? "Wi-Fi" : "USB") (save: \(save))")
                report(.connected(peerName: peer.name, wifi: link.wifi))
            case .reject:
                if isCandidate { dropCandidate(); return }
                endPairingAttempt("Pairing declined.")
                return
            }
        }
    }

    /// The USB candidate authenticated as the active Mac: it becomes the current link; Wi-Fi closes.
    private func promoteCandidate() {
        guard let link = candidate, link.isActive, link.peer?.publicKey == current?.peer?.publicKey,
              let peer = link.peer else { dropCandidate(); return }
        log.info("Handed over from Wi-Fi to USB")
        let old = current
        candidate = nil
        current = link
        old?.pairingTimer?.cancel()
        // Stop using the Wi-Fi link but let the Mac close it, so it learns of the hand-over over USB
        // first; cancel it ourselves only if it lingers. Its events are ignored (not current).
        if let old { queue.asyncAfter(deadline: .now() + 3) { old.connection.cancel() } }
        report(.connected(peerName: peer.name, wifi: false))   // UI sends Hello again on the new link
    }

    private func endPairingAttempt(_ message: String) {
        report(.failed(message))
        drop(notify: false)
    }

    private func sendNow(_ link: Link, _ type: PacketType, _ payload: Data) {
        guard let bytes = try? link.channel.seal(type, payload) else { return }
        link.connection.send(content: bytes, completion: .contentProcessed { _ in })
    }

    /// A link ended (closed by the peer, failed, timed out or dropped).
    private func end(_ link: Link, notify: Bool = true) {
        if link === candidate { dropCandidate() } else if link === current { drop(notify: notify) }
    }

    private func dropCandidate() {
        guard let link = candidate else { return }
        candidate = nil
        link.pairingTimer?.cancel()
        link.connection.cancel()
    }

    /// Closes the current link, if any. A link that reached the pairing prompt but never activated
    /// starts the cooldown (stops prompt spam).
    private func drop(notify: Bool = true) {
        guard let link = current else { return }
        log.info("Connection closed (Wi-Fi: \(link.wifi), active: \(link.isActive))")
        if link.isPrompting {
            let until = Date().addingTimeInterval(WireConst.pairingCooldown)
            if link.wifi { wifiCooldownUntil = until } else { usbCooldownUntil = until }
        }
        current = nil
        link.pairingTimer?.cancel()
        link.connection.cancel()
        dropCandidate()
        if notify { report(.waiting) }
    }

    private func report(_ state: State) {
        DispatchQueue.main.async { self.onStateChange?(state) }
    }

    private static func isLoopback(_ endpoint: NWEndpoint) -> Bool {
        guard case let .hostPort(host, _) = endpoint else { return false }
        switch host {
        case .ipv4(let a): return a.isLoopback
        case .ipv6(let a): return a.isLoopback || a.asIPv4?.isLoopback == true
        default: return false
        }
    }
}
