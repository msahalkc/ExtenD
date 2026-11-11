import Foundation
import VideoToolbox

/// Low-latency hardware H.264 encoder.
final class H264Encoder {
    var onConfig: ((Data, Data) -> Void)?   // (sps, pps) — sent before every keyframe
    var onFrame: ((Data, Bool) -> Void)?    // (AVCC data, isKeyframe)

    private var session: VTCompressionSession?
    private let queue = DispatchQueue(label: "encoder")
    private var forceKey = true
    private var lastBuffer: CVPixelBuffer?

    init?(width: Int, height: Int, bitrate: Int) {
        var s: VTCompressionSession?
        let lowLatency = [kVTVideoEncoderSpecification_EnableLowLatencyRateControl: true] as CFDictionary
        var status = VTCompressionSessionCreate(
            allocator: nil, width: Int32(width), height: Int32(height),
            codecType: kCMVideoCodecType_H264, encoderSpecification: lowLatency,
            imageBufferAttributes: nil, compressedDataAllocator: nil,
            outputCallback: nil, refcon: nil, compressionSessionOut: &s)
        if status != noErr {   // fall back to the normal rate controller
            status = VTCompressionSessionCreate(
                allocator: nil, width: Int32(width), height: Int32(height),
                codecType: kCMVideoCodecType_H264, encoderSpecification: nil,
                imageBufferAttributes: nil, compressedDataAllocator: nil,
                outputCallback: nil, refcon: nil, compressionSessionOut: &s)
        }
        guard status == noErr, let s else { return nil }

        VTSessionSetProperty(s, key: kVTCompressionPropertyKey_RealTime, value: kCFBooleanTrue)
        VTSessionSetProperty(s, key: kVTCompressionPropertyKey_AllowFrameReordering, value: kCFBooleanFalse)
        VTSessionSetProperty(s, key: kVTCompressionPropertyKey_ProfileLevel,
                             value: kVTProfileLevel_H264_ConstrainedHigh_AutoLevel)
        VTSessionSetProperty(s, key: kVTCompressionPropertyKey_AverageBitRate, value: NSNumber(value: bitrate))
        VTSessionSetProperty(s, key: kVTCompressionPropertyKey_ExpectedFrameRate, value: NSNumber(value: 60))
        VTSessionSetProperty(s, key: kVTCompressionPropertyKey_MaxKeyFrameIntervalDuration, value: NSNumber(value: 5))
        VTCompressionSessionPrepareToEncodeFrames(s)
        session = s
    }

    func encode(_ buffer: CVPixelBuffer) {
        queue.async {
            self.lastBuffer = buffer
            self.encodeNow(buffer)
        }
    }

    func requestKeyFrame() {
        queue.async {
            self.forceKey = true
            // The screen may be static (no new frames), so re-encode the last image as a keyframe.
            self.queue.asyncAfter(deadline: .now() + 0.1) {
                if self.forceKey, let last = self.lastBuffer { self.encodeNow(last) }
            }
        }
    }

    func invalidate() {
        queue.sync {
            if let session {
                VTCompressionSessionCompleteFrames(session, untilPresentationTimeStamp: .invalid)
                VTCompressionSessionInvalidate(session)
            }
            session = nil
            lastBuffer = nil
            onFrame = nil
            onConfig = nil
        }
    }

    private func encodeNow(_ buffer: CVPixelBuffer) {
        guard let session else { return }
        let pts = CMClockGetTime(CMClockGetHostTimeClock())
        let props: CFDictionary? = forceKey ? [kVTEncodeFrameOptionKey_ForceKeyFrame: true] as CFDictionary : nil
        forceKey = false
        VTCompressionSessionEncodeFrame(session, imageBuffer: buffer, presentationTimeStamp: pts,
                                        duration: .invalid, frameProperties: props,
                                        infoFlagsOut: nil) { [weak self] status, _, sample in
            guard status == noErr, let sample, let self else {
                if status != noErr { NSLog("H.264 encode failed: \(status)") }
                return
            }
            self.emit(sample)
        }
    }

    private func emit(_ sample: CMSampleBuffer) {
        let attachments = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: false) as? [[CFString: Any]]
        let notSync = attachments?.first?[kCMSampleAttachmentKey_NotSync] as? Bool ?? false
        let isKey = !notSync

        if isKey, let fmt = sample.formatDescription {
            var spsPtr: UnsafePointer<UInt8>?, ppsPtr: UnsafePointer<UInt8>?
            var spsLen = 0, ppsLen = 0
            CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fmt, parameterSetIndex: 0,
                parameterSetPointerOut: &spsPtr, parameterSetSizeOut: &spsLen,
                parameterSetCountOut: nil, nalUnitHeaderLengthOut: nil)
            CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fmt, parameterSetIndex: 1,
                parameterSetPointerOut: &ppsPtr, parameterSetSizeOut: &ppsLen,
                parameterSetCountOut: nil, nalUnitHeaderLengthOut: nil)
            if let spsPtr, let ppsPtr {
                onConfig?(Data(bytes: spsPtr, count: spsLen), Data(bytes: ppsPtr, count: ppsLen))
            }
        }

        guard let block = sample.dataBuffer else { return }
        let length = CMBlockBufferGetDataLength(block)
        var data = Data(count: length)
        let st = data.withUnsafeMutableBytes {
            CMBlockBufferCopyDataBytes(block, atOffset: 0, dataLength: length, destination: $0.baseAddress!)
        }
        guard st == kCMBlockBufferNoErr else { return }
        onFrame?(data, isKey)
    }
}
