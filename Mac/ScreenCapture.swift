import Foundation
import ScreenCaptureKit
import CoreMedia

enum CaptureError: LocalizedError {
    case displayNotFound
    var errorDescription: String? { "Virtual display not visible to ScreenCaptureKit" }
}

/// Captures one display with ScreenCaptureKit and hands out complete frames.
final class ScreenCapture: NSObject, SCStreamOutput, SCStreamDelegate {
    private let output: (CVPixelBuffer) -> Void
    private let sampleQueue = DispatchQueue(label: "capture.samples")
    private var stream: SCStream?
    private let lock = NSLock()
    private var stopped = false
    /// True once `stop()` was called; a start still in flight then tears itself down.
    var isStopped: Bool { lock.withLock { stopped } }

    init(output: @escaping (CVPixelBuffer) -> Void) { self.output = output }

    func start(displayID: CGDirectDisplayID, pixelWidth: Int, pixelHeight: Int) async throws {
        var found: SCDisplay?
        for _ in 0..<20 {   // a new virtual display can take a moment to show up
            if isStopped { throw CancellationError() }
            let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: false)
            found = content.displays.first { $0.displayID == displayID }
            if found != nil { break }
            try await Task.sleep(nanoseconds: 250_000_000)
        }
        guard let display = found else { throw CaptureError.displayNotFound }

        let config = SCStreamConfiguration()
        config.width = pixelWidth
        config.height = pixelHeight
        config.minimumFrameInterval = CMTime(value: 1, timescale: 60)
        config.pixelFormat = kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
        config.showsCursor = true
        config.queueDepth = 5

        let filter = SCContentFilter(display: display, excludingWindows: [])
        let stream = SCStream(filter: filter, configuration: config, delegate: self)
        try stream.addStreamOutput(self, type: .screen, sampleHandlerQueue: sampleQueue)
        try await stream.startCapture()
        let keep: Bool = lock.withLock {
            if stopped { return false }
            self.stream = stream
            return true
        }
        if !keep {   // stop() ran while we were starting: don't leave an orphaned stream
            try? await stream.stopCapture()
            throw CancellationError()
        }
    }

    func stop() {
        let s: SCStream? = lock.withLock {
            stopped = true
            defer { stream = nil }
            return stream
        }
        s?.stopCapture { _ in }
    }

    func stream(_ stream: SCStream, didOutputSampleBuffer sb: CMSampleBuffer, of type: SCStreamOutputType) {
        guard type == .screen, sb.isValid,
              let attachments = CMSampleBufferGetSampleAttachmentsArray(sb, createIfNecessary: false)
                as? [[SCStreamFrameInfo: Any]],
              let rawStatus = attachments.first?[.status] as? Int,
              SCFrameStatus(rawValue: rawStatus) == .complete,   // skip idle (unchanged) frames
              let pixelBuffer = sb.imageBuffer
        else { return }
        output(pixelBuffer)
    }

    func stream(_ stream: SCStream, didStopWithError error: Error) {
        NSLog("Capture stopped: \(error.localizedDescription)")
    }
}
