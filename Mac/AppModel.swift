import Foundation
import ApplicationServices
import CoreGraphics
import CryptoKit
import AppKit
import Network
import os

private let log = Logger(subsystem: "com.msahalkc.extend", category: "connection")

/// Orchestrates: USB attach / Wi-Fi discovery → transport → encrypted handshake → pairing gate → hello
/// → virtual display → capture → encode → send; input back. All state is touched on the main queue.
///
/// Transports (ADR-002): USB is preferred; Wi-Fi (same LAN, private addresses) is the fallback. A live
/// Wi-Fi session hands over to USB when that iPad is plugged in, after the USB link authenticates as
/// the same paired iPad.
final class AppModel: ObservableObject {
    /// Shown while the user must confirm a new or re-paired iPad.
    struct PairingRequest: Equatable {
        var id: UUID
        var peerName: String
        var code: String
    }

    /// An iOS device currently plugged in over USB, as shown in the menu.
    struct AttachedDevice: Identifiable, Equatable {
        enum State: Equatable {
            case waiting      // plugged in; ExtenD not open on it (or not yet connected)
            case connecting   // handshake / verifying
            case pairing      // a pairing prompt is up
            case connected    // paired and active
            case notPaired    // forgotten while plugged in: waits for "Pair…"
        }
        var id: Int           // usbmuxd DeviceID
        var name: String
        var state: State
    }

    /// An unpaired iPad seen on the local network; pairing starts only when the user clicks Pair….
    struct WiFiPeer: Identifiable, Equatable {
        var id: String        // Bonjour service name (anonymous, per launch)
        var name: String      // the iPad's name, from its authenticated handshake message
        var key: Data         // the iPad's authenticated static key: Pair… accepts only this key
    }

    @Published var status = "Waiting for an iPad (USB or Wi-Fi)…"
    @Published var hasAccessibility = false
    @Published var hasScreenRecording = false
    @Published var pairingRequest: PairingRequest? { didSet { refreshAttached() } }
    @Published var pairedDevices: [PairedDevice] = []
    @Published private(set) var attached: [AttachedDevice] = []
    @Published private(set) var wifiAvailable: [WiFiPeer] = []
    /// Name of the iPad connected over Wi-Fi right now, if any (shown under "Connected").
    @Published private(set) var wifiConnectedName: String?
    @Published private(set) var wifiEnabled = UserDefaults.standard.object(forKey: "WiFiEnabled") as? Bool ?? true
    /// How big the Mac's UI looks on the iPad. Larger = bigger touch targets, slightly softer image
    /// (the display has fewer pixels and the iPad scales it up).
    @Published private(set) var displayScale =
        DisplayScale(rawValue: UserDefaults.standard.string(forKey: "DisplayScale") ?? "") ?? .standard

    enum DisplayScale: String, CaseIterable, Identifiable {
        case standard, larger, largest
        var id: String { rawValue }
        var factor: Double { switch self { case .standard: 1; case .larger: 1.25; case .largest: 1.5 } }
        var label: String { switch self { case .standard: "Default"; case .larger: "Larger"; case .largest: "Largest" } }
    }
    /// True while a paired iPad is connected and may send input (drives the menu-bar indicator).
    @Published private(set) var isActive = false { didSet { refreshAttached() } }

    private let mux = USBMux()
    private let injector = InputInjector()
    private let decoder = JSONDecoder()
    private let store: PairingStore = KeychainPairingStore()
    private var identity: Curve25519.KeyAgreement.PrivateKey?
    private let localName = Host.current().localizedName ?? "Mac"
    private var peer: PeerInfo?
    private var gate: PairingGate?
    private var pairingTimer: DispatchWorkItem?
    private var nextAttempt = Date.distantPast

    // USB
    private var attachedDevices: [Int] = [] { didSet { refreshAttached() } }
    private var serials: [Int: String] = [:]          // DeviceID → serial (UDID), from usbmuxd
    private var names: [String: String] = [:] { didSet { refreshAttached() } }   // serial → last known name
    private var serialForKey: [Data: String] = [:]    // peer key → serial, learned at the handshake
    /// Serials forgotten while plugged in: not connected to until "Pair…" or unplug/replug.
    private var forgottenWhileAttached: Set<String> = [] { didSet { refreshAttached() } }
    private var sessionDeviceID: Int? { didSet { refreshAttached() } }

    // Wi-Fi
    private var browser: NWBrowser?
    private var wifiServices: [String: NWEndpoint] = [:]   // Bonjour service name → endpoint
    private var declinedServices: Set<String> = []         // probed: an unpaired iPad, not connected to
    private var pairing: WiFiPeer?                         // user clicked Pair… for this Wi-Fi iPad
    private var sessionSolicited = false                   // current Wi-Fi session came from Pair…
    private var wifiCursor = 0                              // round-robin over Wi-Fi services
    private var pendingWiFi: NWConnection?
    private let wifiQueue = DispatchQueue(label: "wifi")   // network I/O stays off the main thread
    /// Per-service backoff after connections that fail before the handshake completes (finding 7).
    private var backoff: [String: (until: Date, delay: TimeInterval)] = [:]

    // USB hand-over candidate while a Wi-Fi session is active (ADR-002 §5)
    private var candidate: Session?
    private var candidateGate: PairingGate?
    private var candidateDeviceID: Int?

    private var lastKeyframeRequest = Date.distantPast
    private var pendingHello: DispatchWorkItem?
    private var pipelineGeneration = 0
    private var displayDeviceID: Int?   // the USB device whose (possibly idle) virtual display we hold
    private var displayGrace: DispatchWorkItem?
    private var connecting = false
    private var session: Session?
    private var display: VirtualDisplay?
    private var capture: ScreenCapture?
    private var encoder: H264Encoder?
    private var currentSize: (Int, Int)?
    private var lastHello: Hello?   // to rebuild the display when `displayScale` changes

    init() {
        refreshPermissions(prompt: true)
        do {
            identity = try Identity.loadOrCreate()
        } catch {
            status = "Can't access the Keychain (\(error)). ExtenD won't connect without its device key."
            return
        }
        pairedDevices = store.all()
        mux.onAttach = { [weak self] id, serial in self?.attached(id, serial: serial) }
        mux.onDetach = { [weak self] id in self?.detached(id) }
        mux.start()
        if wifiEnabled { startBrowsing() }
    }

    func refreshPermissions(prompt: Bool = false) {
        let opts = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: prompt] as CFDictionary
        hasAccessibility = AXIsProcessTrustedWithOptions(opts)
        hasScreenRecording = CGPreflightScreenCaptureAccess()
        if prompt && !hasScreenRecording { CGRequestScreenCaptureAccess() }
    }

    // MARK: USB

    private func attached(_ id: Int, serial: String?) {
        if !attachedDevices.contains(id) { attachedDevices.append(id) }
        if let serial { serials[id] = serial }
        if session == nil { status = "iPad on USB. Open the iPad app…" }
        if session?.isWiFi == true, gate?.isActive == true {
            startCandidate(deviceID: id)   // the cable is faster: try to hand the Wi-Fi session over
        } else {
            tryConnect()
        }
    }

    private func detached(_ id: Int) {
        attachedDevices.removeAll { $0 == id }
        if let serial = serials.removeValue(forKey: id) { forgottenWhileAttached.remove(serial) }   // replug = fresh start
        if id == candidateDeviceID { discardCandidate() }
        if id == sessionDeviceID { session?.close() }
        if id == displayDeviceID, session == nil {
            // Unplugged: with Wi-Fi on, give the iPad a moment to come back over Wi-Fi.
            if wifiEnabled { scheduleDisplayGrace() } else { stopPipeline(keepDisplay: false) }
        }
        if attachedDevices.isEmpty, session == nil { status = "Waiting for an iPad (USB or Wi-Fi)…" }
    }

    private var usbCandidates: [Int] {
        attachedDevices.filter { serials[$0].map { !forgottenWhileAttached.contains($0) } ?? true }
    }

    // MARK: Wi-Fi discovery (ADR-002)

    func setDisplayScale(_ scale: DisplayScale) {
        guard scale != displayScale else { return }
        displayScale = scale
        UserDefaults.standard.set(scale.rawValue, forKey: "DisplayScale")
        if let h = lastHello, encoder != nil, gate?.isActive == true { startPipeline(h) }
    }

    func setWiFi(_ on: Bool) {
        wifiEnabled = on
        UserDefaults.standard.set(on, forKey: "WiFiEnabled")
        if on {
            startBrowsing()
        } else {
            browser?.cancel()
            browser = nil
            if pendingWiFi != nil { connecting = false }   // its handler won't run for a cancelled attempt
            pendingWiFi?.cancel()
            pendingWiFi = nil
            wifiServices = [:]
            declinedServices = []
            wifiAvailable = []
            backoff = [:]
            if session?.isWiFi == true { session?.close() }
            tryConnect()
        }
    }

    private func startBrowsing() {
        guard browser == nil else { return }
        let b = NWBrowser(for: .bonjour(type: NetworkPolicy.bonjourType, domain: "local."),
                          using: NetworkPolicy.lanParameters())
        b.browseResultsChangedHandler = { [weak self] results, _ in
            DispatchQueue.main.async { self?.updateServices(results) }
        }
        b.stateUpdateHandler = { [weak self, weak b] state in
            if case .failed(let error) = state {
                log.error("Wi-Fi browsing failed: \(error.localizedDescription, privacy: .public); restarting")
                DispatchQueue.main.async {
                    guard let self, let b, b === self.browser else { return }
                    self.browser = nil
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { if self.wifiEnabled { self.startBrowsing() } }
                }
            }
        }
        browser = b
        b.start(queue: .main)
    }

    private func updateServices(_ results: Set<NWBrowser.Result>) {
        var found: [String: NWEndpoint] = [:]
        for r in results {
            if case let .service(name, _, _, _) = r.endpoint { found[name] = r.endpoint }
        }
        let gone = Set(wifiServices.keys).subtracting(found.keys)
        if Set(found.keys) != Set(wifiServices.keys) {
            log.info("Wi-Fi: \(found.count) iPad(s) advertised: \(found.keys.sorted().joined(separator: ", "), privacy: .public)")
        }
        wifiServices = found
        declinedServices.subtract(gone)
        wifiAvailable.removeAll { gone.contains($0.id) }
        for g in gone { backoff[g] = nil }
        if let p = pairing, gone.contains(p.id) { pairing = nil }
        tryConnect()
    }

    /// Wi-Fi services worth trying: the one the user asked to pair first, then any not known to be
    /// an unpaired iPad.
    private var wifiCandidates: [String] {
        guard wifiEnabled else { return [] }
        let now = Date()
        var list = wifiServices.keys.filter { !declinedServices.contains($0) && (backoff[$0]?.until ?? .distantPast) <= now }.sorted()
        if let p = pairing?.id, wifiServices[p] != nil { list.removeAll { $0 == p }; list.insert(p, at: 0) }
        return list
    }

    private func noteFailure(_ service: String) {
        let delay = min((backoff[service]?.delay ?? 1) * 2, 60)
        backoff[service] = (Date().addingTimeInterval(delay), delay)
    }

    /// A pairing with `key` was just saved: that iPad is no longer "unpaired" on Wi-Fi.
    private func refreshDeclined(savedKey key: Data) {
        let nowPaired = wifiAvailable.filter { $0.key == key }.map(\.id)
        declinedServices.subtract(nowPaired)
        wifiAvailable.removeAll { $0.key == key }
    }

    /// Starts pairing with an iPad seen on Wi-Fi (the user clicked Pair…).
    func pair(_ peer: WiFiPeer) {
        pairing = peer
        backoff[peer.id] = nil
        declinedServices.remove(peer.id)
        wifiAvailable.removeAll { $0.id == peer.id }
        nextAttempt = .distantPast
        status = "Pairing with \(peer.name) over Wi-Fi…"
        if session == nil { tryConnect() }
    }

    // MARK: Connecting

    /// USB first (faster), then Wi-Fi. Retries while anything is plugged in or advertised.
    private func tryConnect() {
        guard identity != nil, session == nil, !connecting else { return }
        let wait = nextAttempt.timeIntervalSinceNow
        if wait > 0 {   // pairing cooldown
            DispatchQueue.main.asyncAfter(deadline: .now() + wait) { self.tryConnect() }
            return
        }
        let usb = usbCandidates, wifi = wifiCandidates
        guard !usb.isEmpty || !wifi.isEmpty else {
            // Services advertised but all backing off: come back when the earliest backoff ends.
            let waiting = wifiServices.keys.filter { !declinedServices.contains($0) }.compactMap { backoff[$0]?.until }
            if wifiEnabled, let next = waiting.min() {
                DispatchQueue.main.asyncAfter(deadline: .now() + max(0.1, next.timeIntervalSinceNow)) { self.tryConnect() }
            }
            return
        }
        connecting = true
        DispatchQueue.global().async {
            var found: (id: Int, fd: Int32)?
            for id in usb {
                if let fd = USBMux.openTunnel(deviceID: id, port: WireConst.port) { found = (id, fd); break }
            }
            DispatchQueue.main.async {
                if let found {
                    self.connecting = false
                    guard self.session == nil, self.attachedDevices.contains(found.id) else {
                        Darwin.close(found.fd)
                        return
                    }
                    log.info("Tunnel opened to device \(found.id)")
                    self.sessionDeviceID = found.id
                    self.startSession(FDStream(fd: found.fd), transport: .usb(deviceID: found.id))
                } else if !wifi.isEmpty {
                    let service = wifi[self.wifiCursor % wifi.count]
                    self.wifiCursor += 1
                    self.connectWiFi(service)
                } else {   // ExtenD not open on any plugged-in device yet — retry
                    self.connecting = false
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.tryConnect() }
                }
            }
        }
    }

    private func connectWiFi(_ service: String) {
        guard let endpoint = wifiServices[service] else { connecting = false; retrySoon(); return }
        let c = NWConnection(to: endpoint, using: NetworkPolicy.lanParameters())
        pendingWiFi = c
        log.info("Wi-Fi: trying \(service, privacy: .public)")
        let giveUp = DispatchWorkItem { [weak self, weak c] in
            guard let self, let c, c === self.pendingWiFi else { return }
            c.cancel()
        }
        c.stateUpdateHandler = { [weak self, weak c] state in
            DispatchQueue.main.async {
                guard let self, let c, c === self.pendingWiFi else { return }
                switch state {
                case .waiting(let error):
                    log.error("Wi-Fi: \(service, privacy: .public) waiting: \(error.localizedDescription, privacy: .public)")
                case .ready:
                    giveUp.cancel()
                    self.pendingWiFi = nil
                    self.connecting = false
                    // Same LAN only: a private/link-local peer, over Wi-Fi or Ethernet (not a VPN).
                    guard let remote = c.currentPath?.remoteEndpoint, NetworkPolicy.isPrivateLAN(remote),
                          NetworkPolicy.isLANPath(c.currentPath), self.session == nil else {
                        log.error("Refusing Wi-Fi peer \(service, privacy: .public): not on the local network")
                        c.cancel()
                        self.noteFailure(service)
                        self.retrySoon()
                        return
                    }
                    log.info("Wi-Fi connected to \(service, privacy: .public)")
                    self.startSession(NWStream(connection: c), transport: .wifi(service: service))
                case .failed, .cancelled:
                    log.error("Wi-Fi: \(service, privacy: .public) failed (\(String(describing: state), privacy: .public))")
                    giveUp.cancel()
                    self.pendingWiFi = nil
                    self.connecting = false
                    c.cancel()
                    self.noteFailure(service)
                    self.retrySoon()
                default:
                    break
                }
            }
        }
        c.start(queue: wifiQueue)
        DispatchQueue.main.asyncAfter(deadline: .now() + 12, execute: giveUp)   // Wi-Fi can be slow to resolve/connect
    }

    private func retrySoon() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.tryConnect() }
    }

    private func startSession(_ stream: ByteStream, transport: Session.Transport) {
        guard let identity else { stream.shutdown(); return }
        // Over Wi-Fi, continue the handshake only with a paired iPad, or the one the user asked to
        // pair; anything else is listed under "Available on Wi-Fi" and our identity stays private.
        var accept: ((Data, String) -> Bool)?
        sessionSolicited = false
        if case .wifi(let service) = transport {
            let known = Set(store.all().map(\.publicKey))
            let pairKey = pairing?.id == service ? pairing?.key : nil
            sessionSolicited = pairKey != nil
            accept = { key, _ in known.contains(key) || key == pairKey }
        }
        let s = Session(stream: stream, transport: transport, identity: identity, localName: localName,
                        acceptResponder: accept)
        // Every callback is bound to this session, so late events from an old one are ignored.
        s.onEstablished = { [weak self, weak s] peer in
            guard let self, let s, s === self.session else { return }
            self.established(peer)
        }
        s.onPacket = { [weak self, weak s] type, payload in
            guard let self, let s, s === self.session else { return }
            self.handle(type, payload)
        }
        s.onDeclined = { [weak self] key, name in
            guard let self, case .wifi(let service) = transport else { return }
            self.listAvailable(WiFiPeer(id: service, name: name, key: key))
        }
        s.onClose = { [weak self, weak s] in
            guard let self, let s, s === self.session else { return }
            self.sessionEnded()
        }
        session = s
        s.start()
        status = "Securing connection…"
        // Handshake + trust exchange + commit-reveal must finish quickly; only the human prompt may take longer.
        DispatchQueue.main.asyncAfter(deadline: .now() + WireConst.handshakeTimeout) { [weak self, weak s] in
            guard let self, let s, s === self.session, self.gate?.isActive != true,
                  self.gate?.isPrompting != true else { return }   // stays prompting after a local accept
            NSLog("Dropping iPad session: setup timed out")
            self.status = "The iPad didn't complete the secure handshake."
            s.close()
        }
    }

    private func listAvailable(_ peer: WiFiPeer) {
        declinedServices.insert(peer.id)
        wifiAvailable.removeAll { $0.id == peer.id }
        wifiAvailable.append(peer)
    }

    private func sessionEnded() {
        let wasActive = gate?.isActive == true
        // A Wi-Fi attempt that never got past the handshake counts against that service (backoff).
        if case .wifi(let service)? = session?.transport, peer == nil, !declinedServices.contains(service) {
            noteFailure(service)
        }
        let reachedPrompt = gate?.isPrompting == true
        let wasWiFi = session?.isWiFi == true
        isActive = false
        log.info("Session ended (was active: \(wasActive), Wi-Fi: \(wasWiFi))")
        // Keep the iPad display (and its windows): while the cable stays connected (user choice), or —
        // without USB — for a grace period while the iPad may come back over either transport.
        let usbStillThere = sessionDeviceID.map(attachedDevices.contains) == true
        // A Wi-Fi pairing the user asked for, closed by the iPad before its prompt: most likely the iPad
        // isn't armed for pairing (it only accepts new Macs over Wi-Fi for a minute after the user asks).
        let notArmed = sessionSolicited && peer != nil && !reachedPrompt && !wasActive ? pairing : nil
        session = nil
        peer = nil
        gate = nil
        pairingRequest = nil
        pairingTimer?.cancel()
        sessionDeviceID = nil
        wifiConnectedName = nil
        if sessionSolicited { pairing = nil }
        sessionSolicited = false
        pendingHello?.cancel()
        discardCandidate()
        stopPipeline(keepDisplay: wasActive && (usbStillThere || wifiEnabled))
        if wasActive && !usbStillThere && display != nil { scheduleDisplayGrace() }
        // A pairing attempt that reached the prompt but didn't complete (reject, timeout, hang-up)
        // waits out the cooldown, so a port squatter can't make the Mac prompt again and again.
        if reachedPrompt { nextAttempt = max(nextAttempt, Date().addingTimeInterval(WireConst.pairingCooldown)) }
        if let p = notArmed {
            listAvailable(p)   // don't retry it in a loop; the user clicks Pair… again
            status = "Pairing with \(p.name) didn't start. If the iPad isn't ready to pair, tap Paired Macs… → Pair a New Mac over Wi-Fi on it, then click Pair… again."
        }
        if wasActive {
            status = display != nil
                ? "iPad display kept. Open ExtenD on the iPad to continue."
                : "iPad app closed. Reopen it to reconnect…"
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.tryConnect() }
    }

    private func scheduleDisplayGrace() {
        displayGrace?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.session == nil || self.encoder == nil, self.displayDeviceID.map(self.attachedDevices.contains) != true
            else { return }
            log.info("No reconnect within the grace period: releasing the iPad display")
            self.stopPipeline(keepDisplay: false)
        }
        displayGrace = work
        DispatchQueue.main.asyncAfter(deadline: .now() + WireConst.wifiDisplayGrace, execute: work)
    }

    // MARK: USB hand-over (ADR-002 §5)

    /// A paired iPad on Wi-Fi was plugged in: open a candidate USB session. It may replace the Wi-Fi
    /// session only after it authenticates as the same iPad; it never prompts.
    private func startCandidate(deviceID: Int) {
        guard candidate == nil, let identity, let current = peer?.publicKey,
              serials[deviceID].map({ !forgottenWhileAttached.contains($0) }) ?? true else { return }
        candidateDeviceID = deviceID
        DispatchQueue.global().async {
            let fd = USBMux.openTunnel(deviceID: deviceID, port: WireConst.port)
            DispatchQueue.main.async {
                guard let fd else { self.candidateDeviceID = nil; return }   // e.g. an iPhone: stay on Wi-Fi
                guard self.candidateDeviceID == deviceID, self.session?.isWiFi == true, self.peer?.publicKey == current else {
                    Darwin.close(fd)
                    return
                }
                let c = Session(stream: FDStream(fd: fd), transport: .usb(deviceID: deviceID), identity: identity,
                                localName: self.localName, acceptResponder: { key, _ in key == current })
                c.onEstablished = { [weak self, weak c] p in
                    guard let self, let c, c === self.candidate else { return }
                    if let serial = self.serials[deviceID] { self.names[serial] = p.name; self.serialForKey[p.publicKey] = serial }
                    let g = PairingGate(peerKnown: true, initiator: true, handshakeHash: p.handshakeHash)
                    self.candidateGate = g
                    for case let .send(t, payload) in g.start() { c.send(t, payload) }
                }
                c.onPacket = { [weak self, weak c] type, payload in
                    guard let self, let c, c === self.candidate, var g = self.candidateGate else { return }
                    do {
                        let outputs = try g.receive(type, payload)
                        self.candidateGate = g
                        for output in outputs {
                            switch output {
                            case .send(let t, let p): c.send(t, p)
                            case .activate: self.promoteCandidate()
                            case .showPrompt, .reject: self.discardCandidate()   // a candidate never prompts
                            }
                        }
                    } catch {
                        self.discardCandidate()
                    }
                }
                c.onClose = { [weak self, weak c] in
                    guard let self, let c, c === self.candidate else { return }
                    self.candidate = nil
                    self.candidateGate = nil
                    self.candidateDeviceID = nil
                }
                self.candidate = c
                c.start()
                DispatchQueue.main.asyncAfter(deadline: .now() + WireConst.handshakeTimeout) { [weak self, weak c] in
                    guard let self, let c, c === self.candidate else { return }
                    self.discardCandidate()
                }
            }
        }
    }

    private func promoteCandidate() {
        guard let c = candidate, let g = candidateGate, g.isActive, let deviceID = candidateDeviceID else { return }
        log.info("Handing over from Wi-Fi to USB (device \(deviceID))")
        let old = session
        candidate = nil
        candidateGate = nil
        candidateDeviceID = nil
        stopPipeline(keepDisplay: true)   // the iPad sends Hello again on USB; the same display is reused
        session = c
        gate = g
        sessionDeviceID = deviceID
        wifiConnectedName = nil
        // Re-route the promoted session's callbacks to the main handlers.
        c.onPacket = { [weak self, weak c] type, payload in
            guard let self, let c, c === self.session else { return }
            self.handle(type, payload)
        }
        c.onClose = { [weak self, weak c] in
            guard let self, let c, c === self.session else { return }
            self.sessionEnded()
        }
        c.authorize()
        isActive = true
        status = "Switched to USB. Waiting for screen size…"
        old?.close()   // its callbacks no longer match `session`, so this is silent
    }

    private func discardCandidate() {
        let c = candidate
        candidate = nil
        candidateGate = nil
        candidateDeviceID = nil
        c?.close()
    }

    // MARK: Pairing (ADR-001 §2.3–2.4)

    private func established(_ peer: PeerInfo) {
        self.peer = peer
        if let id = sessionDeviceID, let serial = serials[id] {
            names[serial] = peer.name
            serialForKey[peer.publicKey] = serial
        }
        let known: Bool
        do {
            known = try store.contains(peer.publicKey)
        } catch {   // fail closed: never turn a Keychain error into a pairing prompt
            status = "Can't read paired devices from the Keychain (\(error))."
            session?.close()
            return
        }
        let g = PairingGate(peerKnown: known, initiator: true, handshakeHash: peer.handshakeHash)
        let outputs = g.start()
        gate = g
        status = "Verifying \(peer.name)…"
        apply(outputs)
    }

    /// The user's answer to a specific pairing prompt. Ignored if that prompt is no longer current.
    func decidePairing(_ request: PairingRequest, accepted: Bool) {
        guard request == pairingRequest, var g = gate else { return }
        let outputs = g.decide(accepted)
        gate = g
        pairingRequest = nil
        if accepted { status = "Waiting for the iPad to accept…" }
        apply(outputs)
    }

    private func apply(_ outputs: [PairingGate.Output]) {
        for output in outputs {
            guard let peer, let session else { return }
            switch output {
            case .send(let type, let payload):
                session.send(type, payload)
            case .showPrompt(let code):
                if session.isWiFi && !sessionSolicited {
                    // The iPad doesn't trust us (e.g. it forgot this Mac): never prompt unasked over
                    // Wi-Fi. List it under "Available on Wi-Fi"; the user may click Pair….
                    if case .wifi(let service) = session.transport {
                        listAvailable(WiFiPeer(id: service, name: peer.name, key: peer.publicKey))
                    }
                    gate = nil
                    session.close()
                    return
                }
                pairingRequest = PairingRequest(id: UUID(), peerName: peer.name, code: PairingCode.formatted(code))
                status = "Pair with \(peer.name)? Check the code matches on the iPad."
                NSApp.requestUserAttention(.informationalRequest)   // never steals focus
                let timer = DispatchWorkItem { [weak self, weak session] in
                    guard let self, let session, session === self.session, self.gate?.isActive == false else { return }
                    self.status = "Pairing timed out."
                    self.endPairingAttempt()
                }
                pairingTimer = timer
                DispatchQueue.main.asyncAfter(deadline: .now() + WireConst.pairingTimeout, execute: timer)
            case .activate(let save):
                pairingTimer?.cancel()
                pairingRequest = nil
                if save {
                    do {
                        try store.save(PairedDevice(publicKey: peer.publicKey, name: peer.name, pairedAt: Date()))
                    } catch {
                        status = "Couldn't save the pairing (\(error))."
                        gate = nil
                        session.close()
                        return
                    }
                    pairedDevices = store.all()
                    refreshDeclined(savedKey: peer.publicKey)
                }
                session.authorize()
                if case .wifi(let service) = session.transport { backoff[service] = nil }
                if sessionSolicited { pairing = nil }
                displayGrace?.cancel()
                if session.isWiFi { wifiConnectedName = peer.name }
                isActive = true
                log.info("Session active (save: \(save), Wi-Fi: \(session.isWiFi))")
                status = "Connected to \(peer.name). Waiting for screen size…"
            case .reject:
                status = "Pairing declined."
                endPairingAttempt()
                return
            }
        }
    }

    private func endPairingAttempt() {
        pairingTimer?.cancel()
        pairingRequest = nil
        gate = nil   // nothing more from this session is processed, even if already queued
        nextAttempt = Date().addingTimeInterval(WireConst.pairingCooldown)
        session?.close()
    }

    func forget(_ device: PairedDevice) {
        do {
            try store.remove(device.publicKey)
        } catch {
            status = "Couldn't forget \(device.name) (\(error)). It is still paired."
            return
        }
        pairedDevices = store.all()
        // Still plugged in? Keep listing it as "Not paired" and don't reconnect (and so don't
        // prompt) until the user clicks "Pair…" or replugs it. Over Wi-Fi it simply becomes an
        // unpaired iPad, which is never connected to without "Pair…".
        if let serial = serialForKey[device.publicKey], serials.values.contains(serial) {
            names[serial] = device.name
            forgottenWhileAttached.insert(serial)
        }
        if peer?.publicKey == device.publicKey {
            gate = nil   // stop injecting input immediately, before the close lands
            isActive = false
            session?.close()
        }
        status = "Forgot \(device.name)."
    }

    /// Starts pairing with a device that was forgotten while plugged in.
    func pair(_ device: AttachedDevice) {
        guard let serial = serials[device.id] else { return }
        forgottenWhileAttached.remove(serial)
        nextAttempt = .distantPast
        status = "Pairing with \(device.name)…"
        tryConnect()
    }

    private func refreshAttached() {
        let list = attachedDevices.map { id -> AttachedDevice in
            let serial = serials[id]
            let name = serial.flatMap { names[$0] } ?? "iPad"
            let state: AttachedDevice.State
            if let serial, forgottenWhileAttached.contains(serial) {
                state = .notPaired
            } else if id == sessionDeviceID {
                state = pairingRequest != nil ? .pairing : isActive ? .connected : .connecting
            } else {
                state = .waiting
            }
            return AttachedDevice(id: id, name: name, state: state)
        }
        if list != attached { attached = list }
    }

    private func handle(_ type: PacketType, _ payload: Data) {
        guard var g = gate else { session?.close(); return }   // no gate: forgotten, ended, or pre-handshake
        if !g.isActive {
            do {
                let outputs = try g.receive(type, payload)
                gate = g
                apply(outputs)
            } catch {
                NSLog("Dropping iPad session: pairing violation \(error)")
                gate = nil
                session?.close()
            }
            return
        }
        switch type {
        case .hello:
            // Debounced (latest wins): each new size rebuilds the display, which moves windows.
            guard let h = try? decoder.decode(Hello.self, from: payload), h.isValid else { return }
            pendingHello?.cancel()
            let work = DispatchWorkItem { [weak self] in
                guard let self, self.gate?.isActive == true else { return }   // e.g. forgotten meanwhile
                self.startPipeline(h)
            }
            pendingHello = work
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3, execute: work)
        case .input:
            if let e = try? decoder.decode(InputEvent.self, from: payload) { injector.handle(e) }
        case .keyframeRequest:
            guard Date().timeIntervalSince(lastKeyframeRequest) > 0.5 else { return }   // rate limit
            lastKeyframeRequest = Date()
            encoder?.requestKeyFrame()
        default:
            break
        }
    }

    // MARK: Display pipeline

    private func startPipeline(_ hello: Hello) {
        lastHello = hello
        let f = displayScale.factor
        let w = Int(Double(hello.pixelWidth) / f) & ~1, h = Int(Double(hello.pixelHeight) / f) & ~1   // even sizes
        guard w > 0, h > 0, let s = session else { return }
        let sameSize = currentSize.map { $0 == (w, h) } ?? false
        if sameSize, display != nil, encoder != nil {   // e.g. a repeated Hello: just refresh
            encoder?.requestKeyFrame()
            return
        }
        if sameSize, display != nil {
            stopPipeline(keepDisplay: true)   // reconnect at the same size: reuse the kept display
            log.info("Reusing kept display \(w)×\(h)")
        } else {
            log.info("Creating display \(w)×\(h)")
            stopPipeline(keepDisplay: false)
            guard let d = VirtualDisplay(pixelWidth: w, pixelHeight: h) else {
                status = "Couldn't create virtual display."
                return
            }
            display = d
            currentSize = (w, h)
        }
        let bitrate = s.isWiFi ? WireConst.wifiBitrate : WireConst.usbBitrate
        guard let d = display, let enc = H264Encoder(width: w, height: h, bitrate: bitrate) else {
            status = "Couldn't create video encoder."
            return
        }
        displayGrace?.cancel()
        displayDeviceID = sessionDeviceID
        pipelineGeneration += 1
        let generation = pipelineGeneration
        encoder = enc
        injector.displayID = d.displayID

        enc.onConfig = { sps, pps in
            var p = Data()
            p.append(UInt8(sps.count >> 8)); p.append(UInt8(sps.count & 0xFF)); p.append(sps)
            p.append(UInt8(pps.count >> 8)); p.append(UInt8(pps.count & 0xFF)); p.append(pps)
            s.send(.videoConfig, p)
        }
        // Back-pressure: P-frames drop when the link is busy; after a drop we wait for one clean
        // keyframe and request it only once (no keyframe storm). Keyframes drop only above a hard
        // byte cap, so a stalled iPad can't make the Mac queue unbounded video.
        var needKey = false, keyRequested = false
        enc.onFrame = { [weak enc] data, isKey in
            if needKey && !isKey { return }
            var p = Data([isKey ? 1 : 0])
            p.append(data)
            let queued = s.send(.videoFrame, p,
                                dropAbove: isKey ? Session.keyframeQueueLimit : Session.frameQueueLimit)
            if queued {
                if isKey { needKey = false; keyRequested = false }
            } else {
                needKey = true
                if isKey { keyRequested = false }   // the recovery keyframe itself was dropped: ask again
                if !keyRequested { keyRequested = true; enc?.requestKeyFrame() }
            }
        }

        let cap = ScreenCapture { [weak enc] buffer in enc?.encode(buffer) }
        capture = cap
        status = "Starting capture…"
        let via = s.isWiFi ? "Wi-Fi" : "USB"
        Task {
            do {
                try await cap.start(displayID: d.displayID, pixelWidth: w, pixelHeight: h)
                DispatchQueue.main.async {
                    guard generation == self.pipelineGeneration else { return }   // superseded meanwhile
                    self.status = "Streaming \(w)×\(h) over \(via), encrypted"
                }
            } catch {
                DispatchQueue.main.async {
                    guard generation == self.pipelineGeneration, !cap.isStopped else { return }
                    self.status = "Capture failed: \(error.localizedDescription). Check Screen Recording permission."
                }
            }
        }
    }

    /// Stops capture and encoding and releases any held input. With `keepDisplay`, the virtual
    /// display stays so a reconnect at the same size reuses it.
    private func stopPipeline(keepDisplay: Bool) {
        pipelineGeneration += 1
        capture?.stop()
        capture = nil
        encoder?.invalidate()
        encoder = nil
        injector.releaseAll()
        injector.displayID = 0
        if !keepDisplay {
            displayGrace?.cancel()
            display = nil          // releasing removes the virtual display; macOS moves its windows back
            currentSize = nil
            displayDeviceID = nil
        }
    }
}
