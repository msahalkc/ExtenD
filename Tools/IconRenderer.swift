// ExtenD app icon renderer ("Graphite": one window spanning a Mac display and an iPad).
// Run from the repo root:  swiftc -O -o /tmp/icon Tools/IconRenderer.swift && /tmp/icon
// Writes the 1024 px masters; Tools/make-icons.sh turns them into the asset catalogs.
import AppKit
import CoreGraphics

let S: CGFloat = 1024
let cs = CGColorSpace(name: CGColorSpace.displayP3)!
func c(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(colorSpace: CGColorSpace(name: CGColorSpace.sRGB)!, components: [CGFloat((hex >> 16) & 0xFF)/255, CGFloat((hex >> 8) & 0xFF)/255, CGFloat(hex & 0xFF)/255, a])!
}
func lin(_ ctx: CGContext, _ cols: [CGColor], _ locs: [CGFloat]? = nil, _ a: CGPoint, _ b: CGPoint) {
    let g = CGGradient(colorsSpace: cs, colors: cols as CFArray, locations: locs)!
    ctx.drawLinearGradient(g, start: a, end: b, options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
}
func rad(_ ctx: CGContext, _ cols: [CGColor], _ center: CGPoint, _ r: CGFloat) {
    let g = CGGradient(colorsSpace: cs, colors: cols as CFArray, locations: nil)!
    ctx.drawRadialGradient(g, startCenter: center, startRadius: 0, endCenter: center, endRadius: r, options: [.drawsAfterEndLocation])
}
func rr(_ r: CGRect, _ k: CGFloat) -> CGPath { CGPath(roundedRect: r, cornerWidth: k, cornerHeight: k, transform: nil) }
func clip(_ ctx: CGContext, _ p: CGPath, _ body: () -> Void) { ctx.saveGState(); ctx.addPath(p); ctx.clip(); body(); ctx.restoreGState() }
func noise(_ ctx: CGContext, alpha: CGFloat, seed: UInt64) {
    var s = seed
    for _ in 0..<60000 {
        s = s &* 6364136223846793005 &+ 1442695040888963407
        let x = CGFloat(s >> 33 & 1023), y = CGFloat(s >> 13 & 1023), v = CGFloat(s >> 50 & 1)
        ctx.setFillColor(v > 0 ? c(0xFFFFFF, alpha) : c(0x000000, alpha))
        ctx.fill(CGRect(x: x, y: y, width: 1.5, height: 1.5))
    }
}
func render(_ path: String, opaque: Bool, _ draw: (CGContext) -> Void) {
    let info = opaque ? CGImageAlphaInfo.noneSkipLast.rawValue : CGImageAlphaInfo.premultipliedLast.rawValue
    let ctx = CGContext(data: nil, width: Int(S), height: Int(S), bitsPerComponent: 8, bytesPerRow: 0, space: cs,
                        bitmapInfo: info)!
    ctx.interpolationQuality = .high
    draw(ctx)
    let rep = NSBitmapImageRep(cgImage: ctx.makeImage()!)
    try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: path))
}

// Shared geometry: a display and an iPad side by side, screens in one coordinate space.
let mac = CGRect(x: 96, y: 372, width: 560, height: 372)        // outer bezel
let macScreen = mac.insetBy(dx: 20, dy: 20)
let pad = CGRect(x: 676, y: 392, width: 252, height: 336)       // portrait iPad, slightly lower
let padScreen = pad.insetBy(dx: 20, dy: 20)
// The window that straddles both screens.
let window = CGRect(x: 420, y: 470, width: 400, height: 200)

/// Draws the continuous desktop (wallpaper + spanning window) clipped to both screens.
func desktop(_ ctx: CGContext, wallpaper: [CGColor], locs: [CGFloat], windowFill: CGColor, chrome: CGColor, dots: Bool) {
    let screens = CGMutablePath()
    screens.addPath(rr(macScreen, 10)); screens.addPath(rr(padScreen, 16))
    clip(ctx, screens) {
        lin(ctx, wallpaper, locs, CGPoint(x: 0, y: macScreen.maxY), CGPoint(x: 0, y: macScreen.minY))
        // window shadow + body
        ctx.setShadow(offset: CGSize(width: 0, height: -8), blur: 22, color: c(0x000000, 0.35))
        ctx.addPath(rr(window, 14)); ctx.setFillColor(windowFill); ctx.fillPath()
        ctx.setShadow(offset: .zero, blur: 0, color: nil)
        // title bar
        clip(ctx, rr(window, 14)) {
            ctx.setFillColor(chrome); ctx.fill(CGRect(x: window.minX, y: window.maxY - 38, width: window.width, height: 38))
            // content lines
            ctx.setFillColor(c(0x000000, 0.10))
            for (i, w) in [300.0, 240, 330, 190].enumerated() {
                ctx.addPath(rr(CGRect(x: window.minX + 28, y: window.maxY - 74 - CGFloat(i) * 28, width: CGFloat(w), height: 11), 5.5)); ctx.fillPath()
            }
        }
        if dots {
            for (i, col) in [0xFF5F57, 0xFEBC2E, 0x28C840].enumerated() {
                ctx.setFillColor(c(UInt32(col)))
                ctx.fillEllipse(in: CGRect(x: window.minX + 18 + CGFloat(i) * 22, y: window.maxY - 26, width: 13, height: 13))
            }
        }
    }
}

/// Device frames: glossy black glass with a thin machined rim.
func devices(_ ctx: CGContext, rimLight: UInt32, rimDark: UInt32) {
    for (r, k) in [(mac, 26.0), (pad, 34.0)] {
        ctx.setShadow(offset: CGSize(width: 0, height: -22), blur: 46, color: c(0x000000, 0.45))
        ctx.addPath(rr(r, k)); ctx.setFillColor(c(0x0A0A0B)); ctx.fillPath()
        ctx.setShadow(offset: .zero, blur: 0, color: nil)
        // machined rim
        clip(ctx, rr(r, k)) {
            ctx.addPath(rr(r, k)); ctx.addPath(rr(r.insetBy(dx: 5, dy: 5), k - 5))
            ctx.clip(using: .evenOdd)
            lin(ctx, [c(rimLight), c(rimDark), c(rimLight)], [0, 0.55, 1], CGPoint(x: 0, y: r.maxY), CGPoint(x: 0, y: r.minY))
        }
    }
    // display stand
    let neck = CGRect(x: mac.midX - 54, y: 286, width: 108, height: 88)
    clip(ctx, CGPath(rect: neck, transform: nil)) { lin(ctx, [c(rimDark), c(rimLight), c(rimDark)], nil, CGPoint(x: neck.minX, y: 0), CGPoint(x: neck.maxX, y: 0)) }
    let foot = CGRect(x: mac.midX - 150, y: 268, width: 300, height: 22)
    ctx.setShadow(offset: CGSize(width: 0, height: -6), blur: 14, color: c(0x000000, 0.35))
    ctx.addPath(rr(foot, 11)); ctx.setFillColor(c(rimLight)); ctx.fillPath()
    ctx.setShadow(offset: .zero, blur: 0, color: nil)
}

/// Glass reflection across the screens.
func glare(_ ctx: CGContext) {
    let screens = CGMutablePath(); screens.addPath(rr(macScreen, 10)); screens.addPath(rr(padScreen, 16))
    clip(ctx, screens) {
        let p = CGMutablePath()
        p.move(to: CGPoint(x: 96, y: 744)); p.addLine(to: CGPoint(x: 520, y: 744)); p.addLine(to: CGPoint(x: 260, y: 372)); p.addLine(to: CGPoint(x: 96, y: 372))
        ctx.addPath(p); ctx.clip()
        lin(ctx, [c(0xFFFFFF, 0.10), c(0xFFFFFF, 0.0)], nil, CGPoint(x: 96, y: 744), CGPoint(x: 400, y: 500))
    }
}


/// The full-bleed artwork in a 1024×1024 coordinate space.
func graphite(_ ctx: CGContext) {
    lin(ctx, [c(0x3A3C41), c(0x1B1C1F)], nil, CGPoint(x: 0, y: S), CGPoint(x: 0, y: 0))
    rad(ctx, [c(0xFFFFFF, 0.10), c(0xFFFFFF, 0)], CGPoint(x: S/2, y: S * 0.95), 620)
    noise(ctx, alpha: 0.035, seed: 7)
    devices(ctx, rimLight: 0x9EA2A8, rimDark: 0x4A4D52)
    desktop(ctx, wallpaper: [c(0x0F2742), c(0x2E5A87), c(0xE8A15C), c(0x7A3B2A)], locs: [0, 0.48, 0.80, 1],
            windowFill: c(0xF5F5F7), chrome: c(0xE6E6EA), dots: true)
    glare(ctx)
}

let outDir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "Tools/icon-masters"
try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)

// iPadOS: opaque, full bleed; the system applies the corner mask.
render("\(outDir)/ipad-1024.png", opaque: true) { graphite($0) }

// macOS: the artwork on the standard icon grid, an 824 pt rounded-square tile with a soft shadow.
render("\(outDir)/mac-1024.png", opaque: false) { ctx in
    let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
    let shape = rr(tile, 185)
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 28, color: c(0x000000, 0.40))
    ctx.addPath(shape); ctx.setFillColor(c(0x1B1C1F)); ctx.fillPath()
    ctx.restoreGState()
    clip(ctx, shape) {
        ctx.translateBy(x: tile.minX, y: tile.minY)
        ctx.scaleBy(x: tile.width / S, y: tile.height / S)
        graphite(ctx)
    }
    // hairline edge highlight, like machined metal catching light
    ctx.addPath(rr(tile.insetBy(dx: 1, dy: 1), 184)); ctx.setStrokeColor(c(0xFFFFFF, 0.12)); ctx.setLineWidth(2); ctx.strokePath()
}
