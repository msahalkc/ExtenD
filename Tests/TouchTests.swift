import XCTest

/// Touch input: wire format of the new events, the pan drag-or-scroll decision, tap snapping and
/// scroll momentum (TouchAssist.swift, Protocol.swift).
final class TouchTests: XCTestCase {
    // MARK: Wire format

    func testPhasedEventsRoundTripAndFitThePayloadCap() throws {
        var e = InputEvent(kind: .pan, x: 0.25, y: 0.75)
        e.phase = GesturePhase.ended
        e.vx = -1.5
        e.vy = 0.5
        e.touch = true
        let data = try JSONEncoder().encode(e)
        XCTAssertLessThan(data.count, PacketType.input.maxPayload)
        let d = try JSONDecoder().decode(InputEvent.self, from: data)
        XCTAssertEqual(d.kind, .pan)
        XCTAssertEqual(d.phase, GesturePhase.ended)
        XCTAssertEqual(d.vx, -1.5)
        XCTAssertEqual(d.vy, 0.5)
    }

    func testOldEventsStillDecodeWithoutPhase() throws {
        let old = #"{"kind":"scroll","x":0.5,"y":0.5,"dx":3,"dy":-4,"modifiers":0}"#
        let d = try JSONDecoder().decode(InputEvent.self, from: Data(old.utf8))
        XCTAssertNil(d.phase)   // legacy discrete scroll path
        XCTAssertNil(d.vx)
    }

    // MARK: Pan: drag or scroll

    func testPanDragsControlsAndChrome() {
        XCTAssertEqual(TouchAssist.panMode(roles: ["AXSlider", "AXGroup", "AXWindow"], complete: true), .drag)
        XCTAssertEqual(TouchAssist.panMode(roles: ["AXScrollBar", "AXScrollArea"], complete: true), .drag)
        XCTAssertEqual(TouchAssist.panMode(roles: ["AXToolbar", "AXWindow"], complete: true), .drag)   // title bar
        XCTAssertEqual(TouchAssist.panMode(roles: ["AXWindow"], complete: true), .drag)
    }

    func testPanScrollsContent() {
        XCTAssertEqual(TouchAssist.panMode(roles: ["AXStaticText", "AXGroup", "AXWebArea"], complete: true), .scroll)
        XCTAssertEqual(TouchAssist.panMode(roles: ["AXRow", "AXOutline", "AXScrollArea"], complete: true), .scroll)
        XCTAssertEqual(TouchAssist.panMode(roles: ["AXTextArea", "AXScrollArea"], complete: true), .scroll)
    }

    func testPanFallsBackToScrollWhenUnsure() {
        XCTAssertEqual(TouchAssist.panMode(roles: [], complete: true), .scroll)              // nothing found
        XCTAssertEqual(TouchAssist.panMode(roles: ["AXGroup"], complete: false), .scroll)    // out of time
    }

    // MARK: Tap press-or-click

    func testPressesNativeControlOrItsLabel() {
        XCTAssertEqual(TouchAssist.pressIndex(roles: ["AXButton", "AXGroup", "AXWindow"], complete: true), 0)
        XCTAssertEqual(TouchAssist.pressIndex(roles: ["AXImage", "AXGroup", "AXCheckBox", "AXWindow"], complete: true), 2)
        XCTAssertNil(TouchAssist.pressIndex(roles: ["AXImage", "AXGroup", "AXGroup", "AXButton"], complete: true))
        XCTAssertNil(TouchAssist.pressIndex(roles: ["AXTextField", "AXWindow"], complete: true))
    }

    func testWebContentAndUnknownChainsClick() {
        // Spotify / Teams sidebar: a button inside web content must be clicked, not AXPressed.
        XCTAssertNil(TouchAssist.pressIndex(roles: ["AXButton", "AXGroup", "AXWebArea"], complete: true))
        XCTAssertNil(TouchAssist.pressIndex(roles: ["AXButton"], complete: false))
        XCTAssertFalse(TouchAssist.maySnap(roles: ["AXGroup", "AXGroup", "AXWebArea"], complete: true))
        XCTAssertFalse(TouchAssist.maySnap(roles: ["AXGroup"], complete: false))
        XCTAssertTrue(TouchAssist.maySnap(roles: ["AXToolbar", "AXWindow"], complete: true))
    }

    // MARK: Tap snapping

    func testTapSnapsInsideTheNearestSmallControl() {
        let close = CGRect(x: 100, y: 100, width: 14, height: 14)
        let far = CGRect(x: 130, y: 100, width: 14, height: 14)
        let p = CGPoint(x: 120, y: 107)   // 6 pt right of `close`
        let s = TouchAssist.snapPoint(p, controls: [far, close])!
        XCTAssertTrue(close.contains(s))
        XCTAssertGreaterThan(s.x, close.minX + 3)   // well inside, not on the edge
        XCTAssertLessThan(s.x, close.maxX - 3)
    }

    func testNearestControlPicksTheClosest() {
        let p = CGPoint(x: 50, y: 50)
        let a = CGRect(x: 58, y: 45, width: 14, height: 14)   // 8 pt away
        let b = CGRect(x: 30, y: 45, width: 16, height: 14)   // 4 pt away
        XCTAssertEqual(TouchAssist.nearestControl(p, controls: [a, b]), 1)
        XCTAssertNil(TouchAssist.nearestControl(p, controls: []))
    }

    func testTapDoesNotSnapToFarOrLargeTargets() {
        let p = CGPoint(x: 0, y: 0)
        XCTAssertNil(TouchAssist.snapPoint(p, controls: [CGRect(x: 20, y: 0, width: 14, height: 14)]))   // 20 pt away
        XCTAssertNil(TouchAssist.snapPoint(p, controls: [CGRect(x: 5, y: 0, width: 400, height: 300)]))  // not small
        XCTAssertNil(TouchAssist.snapPoint(p, controls: [.zero]))
    }

    // MARK: Momentum

    func testSlowReleaseDoesNotCoast() {
        XCTAssertNil(Momentum(vx: 50, vy: 50))
        XCTAssertNil(Momentum(vx: .nan, vy: 0))
    }

    func testMomentumDeceleratesToAStopOverTheExpectedDistance() {
        var m = Momentum(vx: 0, vy: 2000)!
        var total = 0.0, steps = 0, last = Double.infinity
        while let d = m.step(1.0 / 120) {
            XCTAssertLessThanOrEqual(d.dy, last)   // never speeds up
            last = d.dy
            total += d.dy
            steps += 1
            XCTAssertLessThan(steps, 1200)          // ends within 10 s
        }
        // Analytic distance v0 / (−ln 0.998 · 1000) ≈ 999 pt, minus the tail below the stop speed.
        XCTAssertEqual(total, 990, accuracy: 15)
        XCTAssertEqual(steps, Int((log(Momentum.stopSpeed / 2000) / log(0.998) / (1000.0 / 120)).rounded(.up)), accuracy: 2)
    }

    func testMomentumIsCappedAndKeepsDirection() {
        var m = Momentum(vx: -30_000, vy: 40_000)!
        XCTAssertEqual(hypot(m.vx, m.vy), Momentum.maxSpeed, accuracy: 0.001)
        let d = m.step(0.01)!
        XCTAssertLessThan(d.dx, 0)
        XCTAssertGreaterThan(d.dy, 0)
        XCTAssertEqual(d.dx / d.dy, -0.75, accuracy: 1e-9)
    }
}
