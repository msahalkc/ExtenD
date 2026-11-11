import Foundation
import CoreGraphics

/// A Retina virtual display matching the iPad's pixel size. Releasing this object removes the display.
final class VirtualDisplay {
    private let display: CGVirtualDisplay
    var displayID: CGDirectDisplayID { display.displayID }

    init?(pixelWidth: Int, pixelHeight: Int) {
        let desc = CGVirtualDisplayDescriptor()
        desc.queue = DispatchQueue.main
        desc.name = "ExtenD"
        desc.maxPixelsWide = UInt32(pixelWidth)
        desc.maxPixelsHigh = UInt32(pixelHeight)
        let mmPerPixel = 25.4 / 264.0                       // ~iPad pixel density
        desc.sizeInMillimeters = CGSize(width: Double(pixelWidth) * mmPerPixel,
                                        height: Double(pixelHeight) * mmPerPixel)
        desc.vendorID = 0x1A2B
        desc.productID = 0x3C4D
        desc.serialNum = 0x0001
        // sRGB primaries
        desc.redPrimary = CGPoint(x: 0.6797, y: 0.3203)
        desc.greenPrimary = CGPoint(x: 0.2559, y: 0.6983)
        desc.bluePrimary = CGPoint(x: 0.1494, y: 0.0557)
        desc.whitePoint = CGPoint(x: 0.3125, y: 0.3291)
        desc.terminationHandler = { _, _ in }

        let display = CGVirtualDisplay(descriptor: desc)
        let settings = CGVirtualDisplaySettings()
        settings.hiDPI = 1
        // Mode is in points; with hiDPI the backing store is 2× → matches iPad pixels.
        settings.modes = [CGVirtualDisplayMode(width: UInt(pixelWidth / 2), height: UInt(pixelHeight / 2), refreshRate: 60)]
        guard display.applySettings(settings) else { return nil }
        self.display = display
    }
}
