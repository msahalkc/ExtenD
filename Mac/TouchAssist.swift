import ApplicationServices
import CoreGraphics
import Foundation

/// Makes finger input land like real touch, using the public Accessibility API (ExtenD already
/// holds the Accessibility permission for input injection):
/// - `panMode`: a one-finger pan drags sliders, scroll bars, splitters, title bars and toolbars,
///   and scrolls anything inside a scroll view or web page (like touch on macOS 27).
/// - `tapAction`: in native apps, a tap on a button, checkbox, tab or menu item presses it directly
///   (AXPress: the pointer doesn't move); a tap on empty space right next to a small control presses
///   that control. Web content (web pages, Electron apps) gets a real click.
/// Lookups run on a small time budget, so a hung app can't stall input.
enum TouchAssist {
    enum PanMode { case drag, scroll }

    static let dragRoles: Set<String> = ["AXSlider", "AXScrollBar", "AXValueIndicator", "AXSplitter",
                                         "AXIncrementor", "AXColorWell", "AXLevelIndicator", "AXHandle"]
    static let scrollContainers: Set<String> = ["AXScrollArea", "AXWebArea"]
    /// "Nothing in particular" under the finger: a tap here may be a near miss.
    static let emptyRoles: Set<String> = ["AXWindow", "AXToolbar", "AXGroup", "AXSplitGroup", "AXTabGroup",
                                          "AXSheet", "AXDrawer", "AXUnknown", "AXLayoutArea"]
    static let pressableRoles: Set<String> = ["AXButton", "AXCheckBox", "AXRadioButton", "AXPopUpButton",
                                              "AXMenuButton", "AXMenuBarItem", "AXMenuItem",
                                              "AXDisclosureTriangle", "AXLink"]
    static let snapRadius: CGFloat = 10                          // points
    static let maxSnapControl = CGSize(width: 120, height: 44)   // only small controls attract taps
    private static let budget: TimeInterval = 0.08

    // MARK: Pure decisions (unit-tested)

    /// `roles`: the element under the finger, then its ancestors (nearest first). `complete` is false
    /// when the walk stopped early (time budget): then scroll, which is also Apple's fallback.
    static func panMode(roles: [String], complete: Bool) -> PanMode {
        guard complete, let first = roles.first else { return .scroll }
        if dragRoles.contains(first) { return .drag }
        for r in roles {
            if scrollContainers.contains(r) { return .scroll }
            if r == "AXWindow" { break }
        }
        return .drag   // title bars, toolbars, window backgrounds, menus
    }

    /// Index of the nearest small control within `snapRadius` of `p`, or nil.
    static func nearestControl(_ p: CGPoint, controls: [CGRect]) -> Int? {
        func distance(_ f: CGRect) -> CGFloat {
            hypot(max(f.minX - p.x, 0, p.x - f.maxX), max(f.minY - p.y, 0, p.y - f.maxY))
        }
        return controls.indices
            .filter { let f = controls[$0]
                return f.width > 0 && f.height > 0 && f.width <= maxSnapControl.width
                    && f.height <= maxSnapControl.height && distance(f) <= snapRadius }
            .min(by: { distance(controls[$0]) < distance(controls[$1]) })
    }

    /// The point to click for a tap at `p`: well inside the nearest small control, or nil.
    static func snapPoint(_ p: CGPoint, controls: [CGRect]) -> CGPoint? {
        guard let i = nearestControl(p, controls: controls) else { return nil }
        let f = controls[i]
        let inset = min(f.width, f.height) / 4
        return CGPoint(x: min(max(p.x, f.minX + inset), f.maxX - inset),
                       y: min(max(p.y, f.minY + inset), f.maxY - inset))
    }

    // MARK: Live lookups

    static func panMode(at p: CGPoint) -> PanMode {
        let deadline = now + budget
        guard AXIsProcessTrusted(), var element = element(at: p) else { return .scroll }
        var roles: [String] = []
        var complete = false
        for _ in 0..<16 {
            guard now < deadline, let r = role(element) else { break }
            roles.append(r)
            if r == "AXWindow" || scrollContainers.contains(r) || (roles.count == 1 && dragRoles.contains(r)) {
                complete = true
                break
            }
            guard let up = parent(element) else { complete = true; break }   // reached the app
            element = up
        }
        return panMode(roles: roles, complete: complete)
    }

    enum TapAction {
        /// Press this control via Accessibility; if that's refused, click at `fallback`.
        case press(AXUIElement, fallback: CGPoint)
        case click(CGPoint)
    }

    /// `roles`: the element under the finger, then its ancestors (nearest first). Returns the index of
    /// the element to press (the control itself, or its label/icon up to two levels inside it), or nil
    /// to click. Web content (Electron apps such as Spotify and Teams, web pages) always clicks: its
    /// AXPress skips the pointer-down events many web apps listen to, so the press silently does nothing.
    static func pressIndex(roles: [String], complete: Bool) -> Int? {
        guard complete, !roles.contains("AXWebArea") else { return nil }
        return roles.prefix(3).firstIndex(where: pressableRoles.contains)
    }

    /// Whether a tap on `roles` may snap to a nearby control: native, empty space only.
    static func maySnap(roles: [String], complete: Bool) -> Bool {
        guard complete, let first = roles.first else { return false }
        return !roles.contains("AXWebArea") && emptyRoles.contains(first)
    }

    /// `bounds`: the iPad's display. Snapping never reaches past it (e.g. onto the Mac's own screen).
    static func tapAction(at p: CGPoint, within bounds: CGRect) -> TapAction {
        let deadline = now + budget
        guard AXIsProcessTrusted(), let hit = element(at: p) else { return .click(p) }
        var chain: [AXUIElement] = [], roles: [String] = []
        var complete = false, e = hit
        for _ in 0..<24 {
            guard now < deadline, let r = role(e) else { break }
            chain.append(e)
            roles.append(r)
            guard r != "AXWindow", r != "AXWebArea", let up = parent(e) else { complete = true; break }
            e = up
        }
        if let i = pressIndex(roles: roles, complete: complete) { return .press(chain[i], fallback: p) }
        guard maySnap(roles: roles, complete: complete) else { return .click(p) }
        var found: [(AXUIElement, CGRect)] = []
        for i in 0..<8 {
            guard now < deadline else { break }
            let a = Double(i) * .pi / 4
            let q = CGPoint(x: p.x + snapRadius * cos(a), y: p.y + snapRadius * sin(a))
            guard bounds.contains(q), let c = element(at: q), let cr = role(c), pressableRoles.contains(cr),
                  let f = frame(c), bounds.contains(f) else { continue }
            found.append((c, f))
        }
        let frames = found.map(\.1)
        guard let i = nearestControl(p, controls: frames), let s = snapPoint(p, controls: frames) else { return .click(p) }
        return .press(found[i].0, fallback: s)
    }

    /// AXPress. True when it was done, or is being done: a timeout means the app is busy running the
    /// action (e.g. it opened a modal), so the caller must not click as well.
    static func press(_ e: AXUIElement) -> Bool {
        let err = AXUIElementPerformAction(e, kAXPressAction as CFString)
        return err == .success || err == .cannotComplete
    }

    // MARK: Accessibility helpers

    private static var now: TimeInterval { ProcessInfo.processInfo.systemUptime }

    /// Setting the timeout on the system-wide element sets it for every element.
    private static let systemWide: AXUIElement = {
        let e = AXUIElementCreateSystemWide()
        AXUIElementSetMessagingTimeout(e, 0.05)
        return e
    }()

    private static func element(at p: CGPoint) -> AXUIElement? {
        var e: AXUIElement?
        guard AXUIElementCopyElementAtPosition(systemWide, Float(p.x), Float(p.y), &e) == .success else { return nil }
        return e
    }

    private static func attribute(_ e: AXUIElement, _ name: String) -> CFTypeRef? {
        var v: CFTypeRef?
        guard AXUIElementCopyAttributeValue(e, name as CFString, &v) == .success else { return nil }
        return v
    }

    private static func role(_ e: AXUIElement) -> String? { attribute(e, kAXRoleAttribute) as? String }

    private static func parent(_ e: AXUIElement) -> AXUIElement? {
        guard let v = attribute(e, kAXParentAttribute), CFGetTypeID(v) == AXUIElementGetTypeID() else { return nil }
        return (v as! AXUIElement)
    }

    private static func frame(_ e: AXUIElement) -> CGRect? {
        guard let pv = attribute(e, kAXPositionAttribute), CFGetTypeID(pv) == AXValueGetTypeID(),
              let sv = attribute(e, kAXSizeAttribute), CFGetTypeID(sv) == AXValueGetTypeID() else { return nil }
        var origin = CGPoint.zero, size = CGSize.zero
        guard AXValueGetValue(pv as! AXValue, .cgPoint, &origin),
              AXValueGetValue(sv as! AXValue, .cgSize, &size) else { return nil }
        return CGRect(origin: origin, size: size)
    }
}

/// iOS-style deceleration after a flick: velocity decays by 0.998 per millisecond.
struct Momentum {
    static let decayPerMs = 0.998
    static let startSpeed = 100.0    // points/s; slower releases just stop
    static let stopSpeed = 20.0
    static let maxSpeed = 8000.0

    private(set) var vx: Double
    private(set) var vy: Double

    init?(vx: Double, vy: Double) {
        let speed = hypot(vx, vy)
        guard speed.isFinite, speed >= Self.startSpeed else { return nil }
        let k = min(1, Self.maxSpeed / speed)
        self.vx = vx * k
        self.vy = vy * k
    }

    /// Advances `dt` seconds. Returns the distance travelled in that time, or nil once stopped.
    mutating func step(_ dt: Double) -> (dx: Double, dy: Double)? {
        guard hypot(vx, vy) >= Self.stopSpeed, dt > 0 else { return nil }
        let f = pow(Self.decayPerMs, dt * 1000)
        let t = (f - 1) / (log(Self.decayPerMs) * 1000)   // ∫ decay over dt, in seconds
        defer { vx *= f; vy *= f }
        return (vx * t, vy * t)
    }
}
