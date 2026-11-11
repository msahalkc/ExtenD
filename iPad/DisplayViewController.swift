import UIKit
import AVFoundation

/// Full-screen view: shows the Mac's virtual display and sends touch, Pencil, mouse/trackpad and keyboard input back.
///
/// Finger:   tap = click (near misses snap to small controls, on the Mac)
///           drag = scroll content, or drag sliders / title bars / toolbars (the Mac decides)
///           hold, then move = pick up and drag · hold still = right-click · 2-finger tap = right-click
///           2-finger drag = scroll with momentum · 2-finger pinch = zoom (⌘= / ⌘-)
///           3-finger swipe = like a Mac trackpad: ←/→ switch Spaces, ↑ Mission Control, ↓ App Exposé
///           3-finger pinch in/out = copy/paste · 3-finger double-tap = undo (⇧ held: redo)
/// Pencil:   draw/drag with pressure + tilt · hover = move pointer (supported iPads)
/// Mouse/trackpad on iPad: move, click, right-click, drag, scroll
/// Hardware keyboard: keys + modifiers
final class DisplayViewController: UIViewController {
    private let connection = Connection()
    private let renderer = VideoRenderer()
    private let statusLabel = UILabel()
    private let pairedButton = UIButton(configuration: .gray())
    private weak var pairingAlert: UIAlertController?
    private var isConnected = false
    private weak var dragRecognizer: UIPanGestureRecognizer?
    private weak var holdRecognizer: UILongPressGestureRecognizer?
    private weak var twoFingerScrollRecognizer: UIPanGestureRecognizer?
    private var fingerRecognizers: Set<ObjectIdentifier> = []
    /// Whether the event being built comes from a finger (vs. Pencil, mouse or trackpad).
    private var eventFromFinger = false
    private func markSource(_ g: UIGestureRecognizer) { eventFromFinger = fingerRecognizers.contains(ObjectIdentifier(g)) }
    private var pendingCopy: DispatchWorkItem?   // 3-finger pinch-in waits briefly for a second one (= cut)
    private let jsonEncoder = JSONEncoder()
    private var pencilActive = false
    private var wifiPairingArmedUntil = Date.distantPast

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        view.layer.addSublayer(renderer.layer)

        statusLabel.text = "Waiting for your Mac…"
        statusLabel.textColor = .white
        statusLabel.font = .preferredFont(forTextStyle: .title3)
        statusLabel.numberOfLines = 0
        statusLabel.textAlignment = .center
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(statusLabel)

        pairedButton.setTitle("Paired Macs…", for: .normal)
        pairedButton.addTarget(self, action: #selector(showPairedMacs), for: .touchUpInside)
        pairedButton.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(pairedButton)

        NSLayoutConstraint.activate([
            statusLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            statusLabel.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            statusLabel.widthAnchor.constraint(lessThanOrEqualTo: view.widthAnchor, constant: -64),
            pairedButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            pairedButton.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 24),
        ])

        setupGestures()
        renderer.onNeedKeyFrame = { [weak self] in self?.connection.send(.keyframeRequest, Data()) }
        connection.onPacket = { [weak self] type, payload in self?.handle(type, payload) }
        connection.onStateChange = { [weak self] state in self?.connectionChanged(state) }
        connection.start()
        // If the app loses focus with a modifier held (⌘-Tab, Globe…), its key-up never arrives here.
        NotificationCenter.default.addObserver(forName: UIApplication.willResignActiveNotification, object: nil,
                                               queue: .main) { [weak self] _ in self?.heldModifiers = [] }
        // iPadOS suspends us in the background and tears down our sockets: close cleanly and
        // listen afresh when we're back, so the Mac reconnects within a second.
        NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil,
                                               queue: .main) { [weak self] _ in self?.connection.stop() }
        NotificationCenter.default.addObserver(forName: UIApplication.willEnterForegroundNotification, object: nil,
                                               queue: .main) { [weak self] _ in self?.connection.start() }
    }

    /// Where the Mac display is drawn: inside the safe area and clear of the rounded screen corners,
    /// so every Mac pixel (menu bar indicators, window corners) is visible. Touches map to this rect.
    private var contentRect: CGRect {
        // A rectangle inset by ~0.3·r on every side never touches a corner of radius r. iPad display
        // corners are ≈18 pt, so 6 pt clears them; the safe area wins where it's larger.
        let corner: CGFloat = 6
        let s = view.safeAreaInsets
        let inset = UIEdgeInsets(top: max(s.top, corner), left: max(s.left, corner),
                                 bottom: max(s.bottom, corner), right: max(s.right, corner))
        let scale = traitCollection.displayScale
        var r = view.bounds.inset(by: inset)
        // Whole, even pixel sizes so the Mac's virtual display matches exactly.
        r.size.width = CGFloat(Int(r.width * scale) & ~1) / scale
        r.size.height = CGFloat(Int(r.height * scale) & ~1) / scale
        return r
    }

    override func viewSafeAreaInsetsDidChange() {
        super.viewSafeAreaInsetsDidChange()
        if isConnected { sendHello() }   // the usable area changed: Mac rebuilds the display
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        renderer.layer.frame = contentRect
        CATransaction.commit()
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        becomeFirstResponder()   // needed for hardware keyboard events
    }

    override var canBecomeFirstResponder: Bool { true }
    /// iPadOS's own 3-finger editing gestures would fire alongside ours (we're first responder).
    override var editingInteractionConfiguration: UIEditingInteractionConfiguration { .none }
    override var prefersStatusBarHidden: Bool { true }
    override var prefersHomeIndicatorAutoHidden: Bool { true }

    override func viewWillTransition(to size: CGSize, with coordinator: UIViewControllerTransitionCoordinator) {
        super.viewWillTransition(to: size, with: coordinator)
        coordinator.animate(alongsideTransition: nil) { [weak self] _ in self?.sendHello() }   // Mac rebuilds display
    }

    // MARK: - Connection & video

    private func connectionChanged(_ state: Connection.State) {
        if case .pairing = state {} else { pairingAlert?.dismiss(animated: true) }
        if case .connected = state { isConnected = true } else { isConnected = false; heldModifiers = [] }
        UIApplication.shared.isIdleTimerDisabled = isConnected   // auto-lock only while disconnected
        switch state {
        case .waiting:
            showStatus(connection.wifiEnabled ? "Waiting for your Mac (USB or Wi-Fi)…" : "Waiting for Mac over USB…")
            renderer.reset()
        case .securing:
            showStatus("Securing connection…")
        case .pairing(let attempt, let name, let code):
            showStatus("Pairing with \(name)…")
            presentPairingPrompt(attempt: attempt, name: name, code: code)
        case .awaitingPeerDecision(let name):
            showStatus("Waiting for \(name) to accept…")
        case .connected(_, let wifi):
            showStatus(wifi ? "Connected over Wi-Fi. Starting display…" : "Connected. Starting display…")
            pairedButton.isHidden = true
            sendHello()
        case .failed(let message):
            showStatus(message)
            renderer.reset()
        }
    }

    private func showStatus(_ text: String) {
        statusLabel.text = text
        statusLabel.isHidden = false
        pairedButton.isHidden = false
    }

    // MARK: - Pairing UI (ADR-001 §2.3)

    private func presentPairingPrompt(attempt: Int, name: String, code: String) {
        pairingAlert?.dismiss(animated: false)
        let alert = UIAlertController(
            title: "Pair with “\(name)”?",
            message: "Only accept if the Mac shows the same code:\n\n\(code)",
            preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Reject", style: .cancel) { [weak self] _ in
            self?.connection.decidePairing(attempt: attempt, accepted: false)
        })
        alert.addAction(UIAlertAction(title: "Accept", style: .default) { [weak self] _ in
            self?.connection.decidePairing(attempt: attempt, accepted: true)
        })
        pairingAlert = alert
        present(alert, animated: true)
    }

    @objc private func showPairedMacs() {
        let devices = connection.store.all()
        let sheet = UIAlertController(
            title: "Paired Macs",
            message: (devices.isEmpty ? "None yet. Connect a Mac to pair it." : "Tap a Mac to forget it.")
                + (connection.wifiEnabled ? "\n\nWi-Fi connections are on (same network only)." : "\n\nWi-Fi connections are off: USB only."),
            preferredStyle: .actionSheet)
        for device in devices {
            sheet.addAction(UIAlertAction(title: "\(device.name)  (\(device.fingerprint))", style: .destructive) {
                [weak self] _ in self?.confirmForget(device)
            })
        }
        let wifiOn = connection.wifiEnabled
        if wifiOn {
            sheet.addAction(UIAlertAction(title: "Pair a New Mac over Wi-Fi", style: .default) { [weak self] _ in
                self?.armWiFiPairing()
            })
        }
        sheet.addAction(UIAlertAction(title: wifiOn ? "Turn Off Wi-Fi Connections" : "Turn On Wi-Fi Connections",
                                      style: .default) { [weak self] _ in self?.connection.wifiEnabled = !wifiOn })
        sheet.addAction(UIAlertAction(title: "Done", style: .cancel))
        sheet.popoverPresentationController?.sourceView = pairedButton
        present(sheet, animated: true)
    }

    /// A new Mac may pair over Wi-Fi for the next minute (USB pairing needs no arming).
    private func armWiFiPairing() {
        connection.armWiFiPairing()
        let text = "Ready to pair over Wi-Fi for \(Int(Connection.wifiPairingWindow)) seconds.\nOn the Mac, click Pair… next to this iPad."
        showStatus(text)
        let until = Date().addingTimeInterval(Connection.wifiPairingWindow)
        wifiPairingArmedUntil = until
        DispatchQueue.main.asyncAfter(deadline: .now() + Connection.wifiPairingWindow) { [weak self] in
            // Only the latest arming's timer reverts the status (re-arming extends the window).
            guard let self, self.wifiPairingArmedUntil == until, !self.isConnected,
                  self.statusLabel.text == text else { return }
            self.showStatus("Wi-Fi pairing window closed. Waiting for your Mac (USB or Wi-Fi)…")
        }
    }

    private func confirmForget(_ device: PairedDevice) {
        let alert = UIAlertController(
            title: "Forget “\(device.name)”?",
            message: "It will need to be paired again, with a code on both screens.",
            preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Forget", style: .destructive) { [weak self] _ in
            self?.connection.forget(device)
        })
        present(alert, animated: true)
    }

    private func sendHello() {
        let scale = traitCollection.displayScale
        let r = contentRect
        let w = Int(r.width * scale), h = Int(r.height * scale)
        guard w > 0, h > 0, let data = try? jsonEncoder.encode(Hello(pixelWidth: w, pixelHeight: h)) else { return }
        connection.send(.hello, data)
    }

    private func handle(_ type: PacketType, _ payload: Data) {
        switch type {
        case .videoConfig: renderer.setConfig(payload)
        case .videoFrame:
            if renderer.display(payload) {
                statusLabel.isHidden = true
                pairedButton.isHidden = true
            }
        default: break
        }
    }

    // MARK: - Gestures (fingers, mouse, trackpad)

    private func setupGestures() {
        let finger = NSNumber(value: UITouch.TouchType.direct.rawValue)
        let pointer = NSNumber(value: UITouch.TouchType.indirectPointer.rawValue)

        // Finger and pointer variants are separate so events can say whether they came from a finger.
        let tap = UITapGestureRecognizer(target: self, action: #selector(onTap(_:)))
        tap.allowedTouchTypes = [finger]
        let pointerTap = UITapGestureRecognizer(target: self, action: #selector(onTap(_:)))
        pointerTap.allowedTouchTypes = [pointer]

        let twoFingerTap = UITapGestureRecognizer(target: self, action: #selector(onRightClick(_:)))
        twoFingerTap.numberOfTouchesRequired = 2
        twoFingerTap.allowedTouchTypes = [finger]

        let secondaryClick = UITapGestureRecognizer(target: self, action: #selector(onRightClick(_:)))
        secondaryClick.buttonMaskRequired = .secondary
        secondaryClick.allowedTouchTypes = [pointer]

        // Finger: hold first = pick up / right-click; move at once = pan (Mac: drag or scroll).
        let hold = UILongPressGestureRecognizer(target: self, action: #selector(onHold(_:)))
        hold.minimumPressDuration = Self.pickUpDelay
        hold.allowableMovement = Self.holdSlop
        hold.allowedTouchTypes = [finger]
        holdRecognizer = hold
        let drag = UIPanGestureRecognizer(target: self, action: #selector(onPan(_:)))
        drag.maximumNumberOfTouches = 1
        dragRecognizer = drag
        drag.allowedTouchTypes = [finger]
        drag.require(toFail: hold)
        tap.require(toFail: hold)
        let pointerDrag = UIPanGestureRecognizer(target: self, action: #selector(onDrag(_:)))
        pointerDrag.maximumNumberOfTouches = 1
        pointerDrag.allowedTouchTypes = [pointer]

        let twoFingerScroll = UIPanGestureRecognizer(target: self, action: #selector(onScroll(_:)))
        twoFingerScroll.minimumNumberOfTouches = 2
        twoFingerScroll.maximumNumberOfTouches = 2   // 3 fingers are editing gestures, not scrolling
        twoFingerScrollRecognizer = twoFingerScroll
        twoFingerScroll.allowedTouchTypes = [finger]

        let trackpadScroll = UIPanGestureRecognizer(target: self, action: #selector(onScroll(_:)))
        trackpadScroll.allowedScrollTypesMask = .continuous
        trackpadScroll.allowedTouchTypes = []   // scroll events only
        let wheelScroll = UIPanGestureRecognizer(target: self, action: #selector(onWheel(_:)))
        wheelScroll.allowedScrollTypesMask = .discrete
        wheelScroll.allowedTouchTypes = []

        let hover = UIHoverGestureRecognizer(target: self, action: #selector(onHover(_:)))

        // 2-finger pinch = zoom; Sidecar's three-finger editing gestures (Apple Support 102597).
        let threePinch = UIPinchGestureRecognizer(target: self, action: #selector(onPinch(_:)))
        threePinch.allowedTouchTypes = [finger]
        // Three-finger swipes act like a Mac trackpad (Mission Control shortcuts, user choice 2026-11-10).
        // Our own pan, not UISwipeGestureRecognizer: it fires as soon as the direction is clear.
        let threeSwipe = UIPanGestureRecognizer(target: self, action: #selector(onThreeFingerSwipe(_:)))
        threeSwipe.minimumNumberOfTouches = 3
        threeSwipe.maximumNumberOfTouches = 3
        threeSwipe.allowedTouchTypes = [finger]
        let undoTap = UITapGestureRecognizer(target: self, action: #selector(onUndo))
        undoTap.numberOfTapsRequired = 2
        undoTap.numberOfTouchesRequired = 3
        undoTap.allowedTouchTypes = [finger]
        threePinch.delegate = self   // must not block two-finger scrolling (see delegate below)

        fingerRecognizers = Set([tap, twoFingerTap, hold, drag, twoFingerScroll].map(ObjectIdentifier.init))
        ([tap, pointerTap, twoFingerTap, secondaryClick, hold, drag, pointerDrag, twoFingerScroll, trackpadScroll,
          wheelScroll, hover, threePinch, undoTap, threeSwipe])
            .forEach { view.addGestureRecognizer($0) }
    }

    @objc private func onTap(_ g: UITapGestureRecognizer) {
        markSource(g)
        let p = g.location(in: view)
        if eventFromFinger {
            sendEvent(makeEvent(.tap, at: p))   // the Mac may nudge a near miss onto a small control
        } else {
            sendEvent(makeEvent(.leftDown, at: p))
            sendEvent(makeEvent(.leftUp, at: p))
        }
    }

    @objc private func onRightClick(_ g: UITapGestureRecognizer) {
        markSource(g)
        sendEvent(makeEvent(.rightClick, at: g.location(in: view)))
    }

    @objc private func onDrag(_ g: UIPanGestureRecognizer) {
        markSource(g)
        let p = g.location(in: view)
        switch g.state {
        case .began:
            let t = g.translation(in: view)
            sendEvent(makeEvent(.leftDown, at: CGPoint(x: p.x - t.x, y: p.y - t.y)))
            sendEvent(makeEvent(.leftDrag, at: p))
        case .changed:
            sendEvent(makeEvent(.leftDrag, at: p))
        case .ended, .cancelled, .failed:
            sendEvent(makeEvent(.leftUp, at: p))
        default:
            break
        }
    }

    // MARK: - Finger pan, hold, scroll (trackpad-style phases; the Mac adds momentum)

    private static let pickUpDelay: TimeInterval = 0.35   // hold this long, then move = pick up and drag
    private static let menuDelay: TimeInterval = 0.3      // …or keep still this much longer = right-click
    private static let holdSlop: CGFloat = 10

    private enum HoldState { case waiting, dragging, menuShown }
    private var holdState = HoldState.waiting
    private var holdStart = CGPoint.zero
    private var holdMenu: DispatchWorkItem?

    /// One finger moving straight away. The Mac decides: drag (sliders, title bars…) or scroll.
    @objc private func onPan(_ g: UIPanGestureRecognizer) {
        markSource(g)
        let p = g.location(in: view)
        var e: InputEvent
        switch g.state {
        case .began:
            let t = g.translation(in: view)
            e = makeEvent(.pan, at: CGPoint(x: p.x - t.x, y: p.y - t.y))   // where the finger landed
            e.phase = GesturePhase.began
            sendEvent(e)
            e = makeEvent(.pan, at: p)
            e.phase = GesturePhase.changed
        case .changed:
            e = makeEvent(.pan, at: p)
            e.phase = GesturePhase.changed
        case .ended:
            e = makeEvent(.pan, at: p)
            e.phase = GesturePhase.ended
            (e.vx, e.vy) = normalized(g.velocity(in: view))
        case .cancelled, .failed:
            e = makeEvent(.pan, at: p)
            e.phase = GesturePhase.cancelled
        default:
            return
        }
        sendEvent(e)
    }

    /// Finger held still: moving now picks up and drags (files, selections); staying still a bit
    /// longer right-clicks; lifting before that clicks.
    @objc private func onHold(_ g: UILongPressGestureRecognizer) {
        markSource(g)
        let p = g.location(in: view)
        switch g.state {
        case .began:
            holdState = .waiting
            holdStart = p
            sendEvent(makeEvent(.move, at: p))   // show where it will act
            let menu = DispatchWorkItem { [weak self] in
                guard let self, self.holdState == .waiting else { return }
                self.holdState = .menuShown
                self.eventFromFinger = true
                self.sendEvent(self.makeEvent(.rightClick, at: self.holdStart))
            }
            holdMenu = menu
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.menuDelay, execute: menu)
        case .changed:
            switch holdState {
            case .waiting where hypot(p.x - holdStart.x, p.y - holdStart.y) > Self.holdSlop:
                holdMenu?.cancel()
                holdState = .dragging
                sendEvent(makeEvent(.leftDown, at: holdStart))
                sendEvent(makeEvent(.leftDrag, at: p))
            case .dragging:
                sendEvent(makeEvent(.leftDrag, at: p))
            default:
                break
            }
        case .ended, .cancelled, .failed:
            holdMenu?.cancel()
            holdMenu = nil
            switch holdState {
            case .dragging:
                sendEvent(makeEvent(.leftUp, at: p))
            case .waiting where g.state == .ended:   // lifted before the menu: a (slow) click
                sendEvent(makeEvent(.leftDown, at: holdStart))
                sendEvent(makeEvent(.leftUp, at: holdStart))
            default:
                break
            }
            holdState = .waiting
        default:
            break
        }
    }

    /// Two fingers, or a trackpad on the iPad: continuous, phased scrolling.
    @objc private func onScroll(_ g: UIPanGestureRecognizer) {
        markSource(g)
        if zoomEngaged, g.state == .began || g.state == .changed { return }   // pinching, not scrolling
        var e = makeEvent(.scroll, at: g.location(in: view))
        switch g.state {
        case .began: e.phase = GesturePhase.began
        case .changed: e.phase = GesturePhase.changed
        case .ended: e.phase = GesturePhase.ended
        case .cancelled, .failed: e.phase = GesturePhase.cancelled
        default: return
        }
        (e.dx, e.dy) = normalized(g.translation(in: view))
        g.setTranslation(.zero, in: view)
        if e.phase == GesturePhase.ended, !zoomEngaged { (e.vx, e.vy) = normalized(g.velocity(in: view)) }
        sendEvent(e)
    }

    /// Mouse wheel on the iPad: discrete steps, no momentum.
    @objc private func onWheel(_ g: UIPanGestureRecognizer) {
        markSource(g)
        guard g.state == .began || g.state == .changed else { return }
        let t = g.translation(in: view)
        g.setTranslation(.zero, in: view)
        var e = makeEvent(.scroll, at: g.location(in: view))
        e.dx = Double(t.x)
        e.dy = Double(t.y)
        sendEvent(e)
    }

    // MARK: - Three-finger editing gestures → ⌘ shortcuts on the Mac

    /// Most fingers seen during the current pinch (UIKit reports 0 touches once it has ended).
    private var pinchFingers = 0
    /// 2-finger pinch: scale at the last zoom step, and whether zooming took over from scrolling.
    private var zoomBase: CGFloat = 1
    private var zoomEngaged = false
    private static let zoomStep: CGFloat = 1.25

    @objc private func onPinch(_ g: UIPinchGestureRecognizer) {
        switch g.state {
        case .began, .changed:
            pinchFingers = max(pinchFingers, g.numberOfTouches)
            pinchScale = g.scale
            if pinchFingers == 2 { zoomByPinch(g.scale) }
            return
        case .ended:
            break
        default:
            pinchFingers = 0
            pinchScale = 1
            zoomBase = 1
            zoomEngaged = false
            return
        }
        defer { pinchFingers = 0; pinchScale = 1; zoomBase = 1; zoomEngaged = false }
        guard pinchFingers == 3 else { return }   // 2-finger pinch is zoom, not an editing gesture
        guard !swipeFired else { return }         // that was a swipe, not a pinch
        if g.scale < 0.8 {                        // pinch in: copy, or cut if repeated quickly
            if let pending = pendingCopy {
                pending.cancel()
                pendingCopy = nil
                sendShortcut(HIDKey.x)
            } else {
                let copy = DispatchWorkItem { [weak self] in
                    self?.pendingCopy = nil
                    self?.sendShortcut(HIDKey.c)
                }
                pendingCopy = copy
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.4, execute: copy)
            }
        } else if g.scale > 1.25 {                // pinch out: paste
            sendShortcut(HIDKey.v)
        }
    }

    /// ⌘= / ⌘- for each 1.25× of pinch: zoom in browsers, Preview, Pages, Finder, Xcode…
    /// (real trackpad pinch events need a private API, which we don't use).
    private func zoomByPinch(_ scale: CGFloat) {
        while scale >= zoomBase * Self.zoomStep || scale <= zoomBase / Self.zoomStep {
            let zoomIn = scale > zoomBase
            if !zoomEngaged {
                zoomEngaged = true   // stop the two-finger scroll that started with the pinch
                var e = InputEvent(kind: .scroll)
                e.phase = GesturePhase.cancelled
                e.touch = true   // keeps the Mac's cursor-return for this finger gesture
                sendEvent(e)
            }
            sendShortcut(zoomIn ? HIDKey.equals : HIDKey.minus)
            zoomBase *= zoomIn ? Self.zoomStep : 1 / Self.zoomStep
        }
    }

    private static let swipeDistance: CGFloat = 40
    private var swipeFired = false
    private var pinchScale: CGFloat = 1

    @objc private func onUndo() { sendShortcut(HIDKey.z, shift: heldModifiers.contains(.shift)) }

    /// Swipe left = the Space to the right (content follows the fingers), as on a trackpad. The pointer
    /// first moves to the fingers, so the switch happens on the iPad's display.
    /// Fires once per gesture, as soon as the fingers have moved `swipeDistance` mostly one way
    /// while not pinching (3-finger pinch = copy/paste).
    @objc private func onThreeFingerSwipe(_ g: UIPanGestureRecognizer) {
        switch g.state {
        case .began, .changed:
            break
        default:
            return   // swipeFired stays set until the next gesture starts (touchesBegan): the pinch
                     // handler may end after this one and must still know
        }
        let t = g.translation(in: view)
        guard !swipeFired, hypot(t.x, t.y) >= Self.swipeDistance,
              pinchScale > 0.85, pinchScale < 1.18 else { return }
        let key: Int
        if abs(t.x) >= 1.5 * abs(t.y) {
            key = t.x < 0 ? HIDKey.rightArrow : HIDKey.leftArrow
        } else if abs(t.y) >= 1.5 * abs(t.x) {
            key = t.y < 0 ? HIDKey.upArrow : HIDKey.downArrow   // Mission Control / App Exposé
        } else {
            return   // diagonal: wait until the direction is clear
        }
        swipeFired = true
        eventFromFinger = true
        sendEvent(makeEvent(.move, at: g.location(in: view)))
        sendShortcut(key, modifiers: ModifierBits.control)
    }

    private enum HIDKey {
        static let c = 0x06, v = 0x19, x = 0x1B, z = 0x1D, minus = 0x2D, equals = 0x2E
        static let rightArrow = 0x4F, leftArrow = 0x50, downArrow = 0x51, upArrow = 0x52
    }

    private func sendShortcut(_ hid: Int, shift: Bool = false, modifiers: Int = ModifierBits.command) {
        var mods = modifiers
        if shift { mods |= ModifierBits.shift }
        for kind in [InputEvent.Kind.keyDown, .keyUp] {
            var e = InputEvent(kind: kind)
            e.keyCode = hid
            e.modifiers = mods
            sendEvent(e)
        }
    }

    @objc private func onHover(_ g: UIHoverGestureRecognizer) {
        eventFromFinger = false
        if g.state == .began || g.state == .changed { sendEvent(makeEvent(.move, at: g.location(in: view))) }
    }

    // MARK: - Apple Pencil (raw touches; gestures above ignore Pencil)

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
        // More fingers joined a one-finger drag: it's becoming a scroll or 3-finger gesture, so end
        // the drag now (sends leftUp) instead of dragging on the Mac throughout the gesture.
        let fingers = event?.allTouches?.filter { $0.type == .direct }.count ?? 0
        // First finger(s) of a new gesture: forget the last one's swipe.
        if fingers > 0, fingers == touches.filter({ $0.type == .direct }).count { swipeFired = false }
        if fingers > 1 {
            // More fingers joined: the one-finger gesture (or, at 3, the 2-finger scroll) gives way.
            let giveWay: [UIGestureRecognizer?] = fingers > 2 ? [dragRecognizer, holdRecognizer, twoFingerScrollRecognizer]
                                                              : [dragRecognizer, holdRecognizer]
            for g in giveWay {
                guard let g, g.state == .began || g.state == .changed else { continue }
                g.isEnabled = false   // cancels: the Mac gets a release / cancelled phase
                g.isEnabled = true
            }
        }
        guard let t = touches.first(where: { $0.type == .pencil }) else { return super.touchesBegan(touches, with: event) }
        pencilActive = true
        sendPencil(.leftDown, t)
    }

    override func touchesMoved(_ touches: Set<UITouch>, with event: UIEvent?) {
        guard pencilActive, let t = touches.first(where: { $0.type == .pencil }) else {
            return super.touchesMoved(touches, with: event)
        }
        for c in event?.coalescedTouches(for: t) ?? [t] { sendPencil(.leftDrag, c) }
    }

    override func touchesEnded(_ touches: Set<UITouch>, with event: UIEvent?) {
        guard pencilActive, let t = touches.first(where: { $0.type == .pencil }) else {
            return super.touchesEnded(touches, with: event)
        }
        pencilActive = false
        sendPencil(.leftUp, t, liftOff: true)
    }

    override func touchesCancelled(_ touches: Set<UITouch>, with event: UIEvent?) {
        guard pencilActive, let t = touches.first(where: { $0.type == .pencil }) else {
            return super.touchesCancelled(touches, with: event)
        }
        pencilActive = false
        sendPencil(.leftUp, t, liftOff: true)
    }

    private func sendPencil(_ kind: InputEvent.Kind, _ t: UITouch, liftOff: Bool = false) {
        eventFromFinger = false   // Pencil is a pointer, like in Sidecar: the cursor follows it
        var e = makeEvent(kind, at: t.preciseLocation(in: view))
        e.pressure = liftOff ? 0 : (t.maximumPossibleForce > 0 ? Double(t.force / t.maximumPossibleForce) : 1)
        let tilt = cos(Double(t.altitudeAngle))              // 0 = upright, 1 = flat
        let azimuth = Double(t.azimuthAngle(in: view))
        e.tiltX = tilt * cos(azimuth)
        e.tiltY = tilt * sin(azimuth)
        sendEvent(e)
    }

    // MARK: - Hardware keyboard

    /// Modifier keys currently held on a hardware keyboard; applied to touch/pointer events too,
    /// so ⌘-click, ⇧-click and ⌘-scroll work.
    private var heldModifiers: UIKeyModifierFlags = []

    override func pressesBegan(_ presses: Set<UIPress>, with event: UIPressesEvent?) {
        heldModifiers = event?.modifierFlags ?? heldModifiers
        let keys = presses.compactMap(\.key)
        guard !keys.isEmpty else { return super.pressesBegan(presses, with: event) }
        keys.forEach { sendKey(.keyDown, $0) }
    }

    override func pressesEnded(_ presses: Set<UIPress>, with event: UIPressesEvent?) {
        heldModifiers = event?.modifierFlags ?? []
        let keys = presses.compactMap(\.key)
        guard !keys.isEmpty else { return super.pressesEnded(presses, with: event) }
        keys.forEach { sendKey(.keyUp, $0) }
    }

    override func pressesCancelled(_ presses: Set<UIPress>, with event: UIPressesEvent?) {
        heldModifiers = []
        let keys = presses.compactMap(\.key)
        guard !keys.isEmpty else { return super.pressesCancelled(presses, with: event) }
        keys.forEach { sendKey(.keyUp, $0) }
    }

    private func sendKey(_ kind: InputEvent.Kind, _ key: UIKey) {
        var e = InputEvent(kind: kind)
        e.keyCode = key.keyCode.rawValue
        e.modifiers = Self.modifierBits(key.modifierFlags)
        sendEvent(e)
    }

    private static func modifierBits(_ f: UIKeyModifierFlags) -> Int {
        var m = 0
        if f.contains(.shift) { m |= ModifierBits.shift }
        if f.contains(.control) { m |= ModifierBits.control }
        if f.contains(.alternate) { m |= ModifierBits.option }
        if f.contains(.command) { m |= ModifierBits.command }
        if f.contains(.alphaShift) { m |= ModifierBits.capsLock }
        return m
    }

    // MARK: - Helpers

    private func makeEvent(_ kind: InputEvent.Kind, at p: CGPoint) -> InputEvent {
        // Touches on the border clamp to the nearest Mac edge. While the Mac rebuilds the display after a
        // rotation, the old stream is letterboxed inside contentRect: map to where the video really is.
        let b = renderer.videoSize.map { AVMakeRect(aspectRatio: $0, insideRect: contentRect) } ?? contentRect
        var e = InputEvent(kind: kind)
        e.x = Double(min(max((p.x - b.minX) / max(b.width, 1), 0), 1))
        e.y = Double(min(max((p.y - b.minY) / max(b.height, 1), 0), 1))
        e.modifiers = Self.modifierBits(heldModifiers)
        if eventFromFinger { e.touch = true }
        return e
    }


    /// A translation or velocity as a fraction of the shown Mac screen (the Mac scales it to its points).
    private func normalized(_ v: CGPoint) -> (Double, Double) {
        let b = renderer.videoSize.map { AVMakeRect(aspectRatio: $0, insideRect: contentRect) } ?? contentRect
        return (Double(v.x / max(b.width, 1)), Double(v.y / max(b.height, 1)))
    }

    private func sendEvent(_ e: InputEvent) {
        guard let data = try? jsonEncoder.encode(e) else { return }
        connection.send(.input, data)
    }
}

extension DisplayViewController: UIGestureRecognizerDelegate {
    /// The 3-finger pinch watches alongside everything else; it only acts when it saw 3 fingers.
    func gestureRecognizer(_ g: UIGestureRecognizer,
                           shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool {
        g is UIPinchGestureRecognizer || other is UIPinchGestureRecognizer
    }
}
