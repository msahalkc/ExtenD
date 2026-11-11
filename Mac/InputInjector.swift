import AppKit
import CoreGraphics

/// Turns iPad input events into real macOS mouse/keyboard/tablet events on the virtual display.
/// Requires Accessibility permission.
///
/// Every event is sanitized (finite, clamped values) and rate-limited, and all input is dropped
/// while the Mac's screen is locked or the user session is not on the console.
final class InputInjector {
    var displayID: CGDirectDisplayID = 0

    private var lastDownTime: TimeInterval = 0
    private var lastDownPoint = CGPoint.zero
    private var clickCount: Int64 = 1

    // What we have pressed on the Mac, so it can always be released (disconnect, lock, rebuild).
    private var leftButtonDown = false
    private var lastPoint = CGPoint.zero
    private var heldKeys: Set<CGKeyCode> = []

    // Finger input doesn't keep the cursor (Sidecar-like): where it was before a touch interaction,
    // and the pending "put it back" once the interaction is over.
    private var cursorBeforeTouch: CGPoint?
    private var cursorRestore: DispatchWorkItem?
    private static let touchSettleDelay: TimeInterval = 0.45   // > double-tap gap, scroll pauses

    // Trackpad-style scrolling: phases, a fixed anchor (the cursor doesn't follow the fingers, so the
    // same view keeps scrolling), sub-point remainders, and momentum after a flick.
    private var scrolling = false
    private var scrollAnchor = CGPoint.zero
    private var scrollRemainder = CGPoint.zero
    private var momentum: Momentum?
    private var momentumStarted = false
    private var momentumModifiers = 0
    private var momentumTimer: DispatchSourceTimer?
    private var lastMomentumTick: TimeInterval = 0
    // One-finger pan: decided once at its start (TouchAssist.panMode).
    private var panMode: TouchAssist.PanMode?
    private var panLast = CGPoint.zero

    // Token bucket: Pencil (240 Hz, coalesced) + hover stays well below this.
    private static let maxEventsPerSecond = 2000.0
    private static let burst = 500.0
    private var tokens = InputInjector.burst
    private var lastRefill = ProcessInfo.processInfo.systemUptime

    private var screenLocked = InputInjector.sessionIsLocked()
    private var observers: [NSObjectProtocol] = []

    init() {
        let lock: (Notification) -> Void = { [weak self] _ in
            self?.releaseAll()   // nothing may stay pressed behind the lock screen
            self?.screenLocked = true
        }
        let recheck: (Notification) -> Void = { [weak self] _ in self?.screenLocked = InputInjector.sessionIsLocked() }

        let distributed = DistributedNotificationCenter.default()
        observers.append(distributed.addObserver(forName: .init("com.apple.screenIsLocked"), object: nil,
                                                 queue: .main, using: lock))
        observers.append(distributed.addObserver(forName: .init("com.apple.screenIsUnlocked"), object: nil,
                                                 queue: .main, using: recheck))
        // Fast user switching: another user takes the console.
        let workspace = NSWorkspace.shared.notificationCenter
        observers.append(workspace.addObserver(forName: NSWorkspace.sessionDidResignActiveNotification, object: nil,
                                               queue: .main, using: lock))
        observers.append(workspace.addObserver(forName: NSWorkspace.sessionDidBecomeActiveNotification, object: nil,
                                               queue: .main, using: recheck))
    }

    deinit {
        observers.forEach {
            DistributedNotificationCenter.default().removeObserver($0)
            NSWorkspace.shared.notificationCenter.removeObserver($0)
        }
    }

    func handle(_ raw: InputEvent) {
        guard displayID != 0, !screenLocked else { return }
        // Releases (and gesture ends) are never rate-limited, so a flood can't leave a button or
        // key stuck down, or a scroll unfinished.
        // Decided on the sanitized event: an out-of-range phase must not pass as a release.
        let e = Self.sanitized(raw)
        // Only scroll/pan ends count as phase releases: any other kind with a phase is rate-limited.
        let isRelease = e.kind == .leftUp || e.kind == .keyUp
            || ((e.kind == .scroll || e.kind == .pan) && (e.phase ?? 0) >= GesturePhase.ended)
        guard isRelease || takeToken() else { return }
        let isKey = e.kind == .keyDown || e.kind == .keyUp
        // Mouse events only ever land on our own display, and only once it's online (bounds can be
        // empty while it comes up). Keys and releases aren't gated on the display: a sleeping
        // display must not swallow them (keys wake the Mac; releases must never be lost).
        let b = CGDisplayBounds(displayID)
        let displayReady = !b.isEmpty && CGDisplayIsOnline(displayID) != 0
        if !isKey && !displayReady {
            if isRelease { releaseAll() }
            return
        }
        let p = displayReady
            ? CGPoint(x: min(b.minX + e.x * b.width, b.maxX - 1), y: min(b.minY + e.y * b.height, b.maxY - 1))
            : lastPoint
        // A new touch stops a coasting scroll, as on a trackpad.
        if [.leftDown, .tap, .rightClick].contains(e.kind) || (e.kind == .scroll && e.phase == nil)
            || e.phase == GesturePhase.began { stopMomentum() }
        // A tap on a control presses it directly (no pointer movement at all). ⌘/⇧/⌃/⌥-taps stay
        // clicks (Caps Lock doesn't count).
        var tapPoint = p
        if e.kind == .tap {
            let held = e.modifiers & ~ModifierBits.capsLock
            switch held == 0 ? TouchAssist.tapAction(at: p, within: b) : .click(p) {
            case .press(let control, let fallback):
                if TouchAssist.press(control) { return }
                tapPoint = fallback
            case .click(let q):
                tapPoint = q
            }
        }
        if !isKey { trackCursor(fromFinger: e.touch == true) }
        defer { if !isKey, e.touch == true { scheduleCursorRestore() } }

        switch e.kind {
        case .move:
            postMouse(.mouseMoved, p, e)
        case .leftDown:
            pressLeft(p, e)
        case .leftDrag:
            dragLeft(p, e)
        case .leftUp:
            releaseLeft(p, e)
        case .tap:
            let t = CGPoint(x: min(max(tapPoint.x, b.minX), b.maxX - 1), y: min(max(tapPoint.y, b.minY), b.maxY - 1))
            pressLeft(t, e)
            releaseLeft(t, e)
        case .rightClick:
            postMouse(.rightMouseDown, p, e, button: .right)
            postMouse(.rightMouseUp, p, e, button: .right)
        case .pan:
            pan(e, at: p, in: b)
        case .scroll where e.phase != nil:
            scrollPhase(e.phase!, dx: e.dx * b.width, dy: e.dy * b.height,
                        vx: (e.vx ?? 0) * b.width, vy: (e.vy ?? 0) * b.height, at: p, e)
        case .scroll:   // discrete (mouse wheel)
            postMouse(.mouseMoved, p, e)
            let ev = CGEvent(scrollWheelEvent2Source: nil, units: .pixel, wheelCount: 2,
                             wheel1: Int32(e.dy.rounded()), wheel2: Int32(e.dx.rounded()), wheel3: 0)
            ev?.location = p
            ev?.flags = flags(e.modifiers)   // ⌘-scroll (zoom in many apps)
            ev?.post(tap: .cghidEventTap)
        case .keyDown, .keyUp:
            guard let hid = e.keyCode, let vk = KeyMap.hidToMac[hid] else { return }
            if e.kind == .keyDown {
                heldKeys.insert(vk)
            } else if heldKeys.remove(vk) == nil {
                return   // never pressed (or already released by releaseAll)
            }
            let ev = CGEvent(keyboardEventSource: nil, virtualKey: vk, keyDown: e.kind == .keyDown)
            var f = flags(e.modifiers)
            // Real arrow keys carry these; macOS needs them to match ⌃-arrow Mission Control shortcuts.
            if (0x7B...0x7E).contains(vk) { f.formUnion([.maskSecondaryFn, .maskNumericPad]) }
            ev?.flags = f
            ev?.post(tap: .cghidEventTap)
        }
    }

    private func pressLeft(_ p: CGPoint, _ e: InputEvent) {
        let now = ProcessInfo.processInfo.systemUptime
        let near = hypot(p.x - lastDownPoint.x, p.y - lastDownPoint.y) < 8
        clickCount = (now - lastDownTime < NSEvent.doubleClickInterval && near) ? clickCount + 1 : 1
        lastDownTime = now
        lastDownPoint = p
        leftButtonDown = true
        lastPoint = p
        postMouse(.leftMouseDown, p, e)
    }

    private func dragLeft(_ p: CGPoint, _ e: InputEvent) {
        guard leftButtonDown else { return }
        lastPoint = p
        postMouse(.leftMouseDragged, p, e)
    }

    private func releaseLeft(_ p: CGPoint, _ e: InputEvent) {
        guard leftButtonDown else { return }
        leftButtonDown = false
        postMouse(.leftMouseUp, p, e)
    }

    // MARK: - One-finger pan and trackpad-style scrolling

    private func pan(_ e: InputEvent, at p: CGPoint, in b: CGRect) {
        switch e.phase {
        case GesturePhase.began:
            let mode = TouchAssist.panMode(at: p)
            panMode = mode
            panLast = p
            if mode == .drag { pressLeft(p, e) } else { scrollPhase(GesturePhase.began, dx: 0, dy: 0, vx: 0, vy: 0, at: p, e) }
        case GesturePhase.changed:
            guard let mode = panMode else { return }
            if mode == .drag {
                dragLeft(p, e)
            } else {
                scrollPhase(GesturePhase.changed, dx: p.x - panLast.x, dy: p.y - panLast.y, vx: 0, vy: 0, at: p, e)
            }
            panLast = p
        case GesturePhase.ended, GesturePhase.cancelled:
            guard let mode = panMode else { return }
            panMode = nil
            if mode == .drag {
                releaseLeft(p, e)
            } else {
                scrollPhase(e.phase!, dx: p.x - panLast.x, dy: p.y - panLast.y,
                            vx: (e.vx ?? 0) * b.width, vy: (e.vy ?? 0) * b.height, at: p, e)
            }
        default:
            break
        }
    }

    /// Deltas and velocities in points (finger direction: content follows the fingers).
    private func scrollPhase(_ phase: Int, dx: Double, dy: Double, vx: Double, vy: Double,
                             at p: CGPoint, _ e: InputEvent) {
        switch phase {
        case GesturePhase.began:
            scrolling = true
            scrollAnchor = p
            scrollRemainder = .zero
            postMouse(.mouseMoved, p, e)   // scroll the view under the fingers
            postScroll(0, 0, phase: .began, momentum: .none, modifiers: e.modifiers)
            if dx != 0 || dy != 0 { postScroll(dx, dy, phase: .changed, momentum: .none, modifiers: e.modifiers) }
        case GesturePhase.changed:
            guard scrolling else { return }
            postScroll(dx, dy, phase: .changed, momentum: .none, modifiers: e.modifiers)
        default:
            guard scrolling else { return }
            if dx != 0 || dy != 0 { postScroll(dx, dy, phase: .changed, momentum: .none, modifiers: e.modifiers) }
            scrolling = false
            let ended = phase == GesturePhase.ended
            postScroll(0, 0, phase: ended ? .ended : .cancelled, momentum: .none, modifiers: e.modifiers)
            if ended, let m = Momentum(vx: vx, vy: vy) { startMomentum(m, modifiers: e.modifiers) }
        }
    }

    private func postScroll(_ dx: Double, _ dy: Double, phase: CGScrollPhase?, momentum: CGMomentumScrollPhase,
                            modifiers: Int) {
        // Whole points per event; the fractions carry over so slow scrolls still move.
        let x = dx + scrollRemainder.x, y = dy + scrollRemainder.y
        let ix = x.rounded(), iy = y.rounded()
        scrollRemainder = CGPoint(x: x - ix, y: y - iy)
        guard let ev = CGEvent(scrollWheelEvent2Source: nil, units: .pixel, wheelCount: 2,
                               wheel1: Int32(clamping: Int(iy)), wheel2: Int32(clamping: Int(ix)), wheel3: 0)
        else { return }
        ev.setIntegerValueField(.scrollWheelEventIsContinuous, value: 1)
        ev.setIntegerValueField(.scrollWheelEventScrollPhase, value: Int64(phase?.rawValue ?? 0))
        ev.setIntegerValueField(.scrollWheelEventMomentumPhase, value: Int64(momentum.rawValue))
        ev.location = scrollAnchor
        ev.flags = flags(modifiers)
        ev.post(tap: .cghidEventTap)
    }

    private func startMomentum(_ m: Momentum, modifiers: Int) {
        momentum = m
        momentumStarted = false
        momentumModifiers = modifiers
        lastMomentumTick = ProcessInfo.processInfo.systemUptime
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + 1.0 / 120, repeating: 1.0 / 120)
        timer.setEventHandler { [weak self] in self?.momentumTick() }
        momentumTimer = timer
        timer.resume()
    }

    private func momentumTick() {
        let now = ProcessInfo.processInfo.systemUptime
        let dt = now - lastMomentumTick
        lastMomentumTick = now
        guard !screenLocked, displayID != 0, var m = momentum, let d = m.step(dt) else { return stopMomentum() }
        momentum = m
        postScroll(d.dx, d.dy, phase: nil, momentum: momentumStarted ? .continuous : .begin,
                   modifiers: momentumModifiers)
        momentumStarted = true
    }

    /// Ends a coasting scroll (new touch, release, or it slowed down).
    private func stopMomentum() {
        momentumTimer?.cancel()
        momentumTimer = nil
        guard momentum != nil else { return }
        momentum = nil
        if momentumStarted { postScroll(0, 0, phase: nil, momentum: .end, modifiers: momentumModifiers) }
        if cursorBeforeTouch != nil || cursorHidden { scheduleCursorRestore() }
    }

    private func postMouse(_ type: CGEventType, _ p: CGPoint, _ e: InputEvent, button: CGMouseButton = .left) {
        guard let ev = CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: p, mouseButton: button)
        else { return }
        switch type {
        case .leftMouseDown, .leftMouseUp, .leftMouseDragged:
            ev.setIntegerValueField(.mouseEventClickState, value: clickCount)
        default: break
        }
        if let pressure = e.pressure {   // Apple Pencil → tablet point data
            ev.setIntegerValueField(.mouseEventSubtype, value: 1)   // kCGEventMouseSubtypeTabletPoint
            ev.setDoubleValueField(.mouseEventPressure, value: pressure)
            ev.setDoubleValueField(.tabletEventPointPressure, value: pressure)
            ev.setDoubleValueField(.tabletEventTiltX, value: e.tiltX ?? 0)
            ev.setDoubleValueField(.tabletEventTiltY, value: e.tiltY ?? 0)
        }
        ev.flags = flags(e.modifiers)
        ev.post(tap: .cghidEventTap)
    }

    // MARK: - Cursor: hidden during finger input, then returned

    private var cursorHidden = false
    /// Lets CGDisplayHideCursor work while we're in the background (private, see bridging header).
    private static let backgroundCursorControl: Void = {
        let cid = _CGSDefaultConnection()
        _ = CGSSetConnectionProperty(cid, cid, "SetsCursorInBackground" as CFString, kCFBooleanTrue)
    }()

    private func setCursorHidden(_ hidden: Bool) {
        guard hidden != cursorHidden else { return }   // hide/show calls are counted: keep them paired
        cursorHidden = hidden
        if hidden {
            Self.backgroundCursorControl
            CGDisplayHideCursor(CGMainDisplayID())
        } else {
            CGDisplayShowCursor(CGMainDisplayID())
        }
    }

    private func trackCursor(fromFinger: Bool) {
        cursorRestore?.cancel()
        cursorRestore = nil
        if fromFinger {
            setCursorHidden(true)   // before the first event moves it
            if cursorBeforeTouch == nil { cursorBeforeTouch = CGEvent(source: nil)?.location }
        } else {
            cursorBeforeTouch = nil   // mouse, trackpad or Pencil: the cursor follows, as usual
            setCursorHidden(false)
        }
    }

    private func scheduleCursorRestore() {
        // Mid-drag or mid-scroll (incl. coasting): wait, or the scroll would follow the cursor away.
        guard !leftButtonDown, !scrolling, momentum == nil else { return }
        let work = DispatchWorkItem { [weak self] in self?.restoreCursor() }
        cursorRestore = work
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.touchSettleDelay, execute: work)
    }

    private func restoreCursor() {
        cursorRestore?.cancel()
        cursorRestore = nil
        guard !leftButtonDown, !scrolling, momentum == nil else { return }
        if let p = cursorBeforeTouch {
            cursorBeforeTouch = nil
            CGWarpMouseCursorPosition(p)
            CGAssociateMouseAndMouseCursorPosition(1)   // no input freeze for the real mouse after the warp
        }
        setCursorHidden(false)   // shown again only once it's back where it was
    }

    /// Releases any mouse button or key we pressed. Called on session end, display rebuild and lock.
    func releaseAll() {
        stopMomentum()
        panMode = nil
        if scrolling {
            scrolling = false
            postScroll(0, 0, phase: .cancelled, momentum: .none, modifiers: 0)
        }
        if leftButtonDown {
            leftButtonDown = false
            CGEvent(mouseEventSource: nil, mouseType: .leftMouseUp, mouseCursorPosition: lastPoint,
                    mouseButton: .left)?.post(tap: .cghidEventTap)
        }
        for vk in heldKeys {
            CGEvent(keyboardEventSource: nil, virtualKey: vk, keyDown: false)?.post(tap: .cghidEventTap)
        }
        heldKeys.removeAll()
        restoreCursor()
    }

    // MARK: - Safeguards

    private func takeToken() -> Bool {
        let now = ProcessInfo.processInfo.systemUptime
        tokens = min(Self.burst, tokens + (now - lastRefill) * Self.maxEventsPerSecond)
        lastRefill = now
        guard tokens >= 1 else { return false }
        tokens -= 1
        return true
    }

    /// True when the screen is locked or this user's session is not the active console session.
    private static func sessionIsLocked() -> Bool {
        guard let dict = CGSessionCopyCurrentDictionary() as? [String: Any] else { return true }
        if dict["CGSSessionScreenIsLocked"] as? Bool == true { return true }
        return dict[kCGSessionOnConsoleKey as String] as? Bool == false
    }

    /// Replaces NaN/∞ and out-of-range values so nothing malformed reaches CGEvent.
    private static func sanitized(_ e: InputEvent) -> InputEvent {
        func clamp(_ v: Double, _ lo: Double, _ hi: Double) -> Double { v.isFinite ? min(max(v, lo), hi) : 0 }
        var s = e
        s.x = clamp(e.x, 0, 1)
        s.y = clamp(e.y, 0, 1)
        s.dx = clamp(e.dx, -10_000, 10_000)
        s.dy = clamp(e.dy, -10_000, 10_000)
        s.pressure = e.pressure.map { clamp($0, 0, 1) }
        s.tiltX = e.tiltX.map { clamp($0, -1, 1) }
        s.tiltY = e.tiltY.map { clamp($0, -1, 1) }
        s.modifiers = e.modifiers & 0x1F   // only the five ModifierBits
        s.phase = e.phase.flatMap { (GesturePhase.began...GesturePhase.cancelled).contains($0) ? $0 : nil }
        s.vx = e.vx.map { clamp($0, -50, 50) }   // normalized screens per second
        s.vy = e.vy.map { clamp($0, -50, 50) }
        return s
    }

    private func flags(_ m: Int) -> CGEventFlags {
        var f = CGEventFlags()
        if m & ModifierBits.shift != 0 { f.insert(.maskShift) }
        if m & ModifierBits.control != 0 { f.insert(.maskControl) }
        if m & ModifierBits.option != 0 { f.insert(.maskAlternate) }
        if m & ModifierBits.command != 0 { f.insert(.maskCommand) }
        if m & ModifierBits.capsLock != 0 { f.insert(.maskAlphaShift) }
        return f
    }
}
