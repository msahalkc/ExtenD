import UIKit
import AVFoundation
import CoreMedia

/// Feeds H.264 frames straight into AVSampleBufferDisplayLayer (hardware decode, minimal latency).
final class VideoRenderer {
    let layer = AVSampleBufferDisplayLayer()
    var onNeedKeyFrame: (() -> Void)?

    private var format: CMVideoFormatDescription?

    /// Pixel size of the stream currently shown, if known (used to map touches while letterboxed).
    var videoSize: CGSize? {
        guard let format else { return nil }
        let d = CMVideoFormatDescriptionGetDimensions(format)
        return CGSize(width: Int(d.width), height: Int(d.height))
    }
    private var waitingForKey = true

    init() {
        layer.videoGravity = .resizeAspect
        layer.backgroundColor = UIColor.black.cgColor
    }

    func reset() {
        layer.flush()
        format = nil
        waitingForKey = true
    }

    /// payload: [u16 spsLen][sps][u16 ppsLen][pps]
    func setConfig(_ payload: Data) {
        let b = [UInt8](payload)
        guard b.count >= 2 else { return }
        let sl = Int(b[0]) << 8 | Int(b[1])
        guard sl > 0, b.count >= 4 + sl else { return }
        let pl = Int(b[2 + sl]) << 8 | Int(b[3 + sl])
        guard pl > 0, b.count >= 4 + sl + pl else { return }
        let sps = Array(b[2..<(2 + sl)]), pps = Array(b[(4 + sl)..<(4 + sl + pl)])

        var fmt: CMVideoFormatDescription?
        sps.withUnsafeBufferPointer { s in
            pps.withUnsafeBufferPointer { p in
                let ptrs = [s.baseAddress!, p.baseAddress!]
                let sizes = [sps.count, pps.count]
                CMVideoFormatDescriptionCreateFromH264ParameterSets(
                    allocator: kCFAllocatorDefault, parameterSetCount: 2,
                    parameterSetPointers: ptrs, parameterSetSizes: sizes,
                    nalUnitHeaderLength: 4, formatDescriptionOut: &fmt)
            }
        }
        if let fmt { format = fmt }
    }

    /// payload: [u8 isKey][AVCC]. Returns true when a frame was shown.
    @discardableResult
    func display(_ payload: Data) -> Bool {
        guard payload.count > 1, let format else { return false }
        let isKey = payload[payload.startIndex] == 1
        if layer.status == .failed {
            layer.flush()
            waitingForKey = true
            onNeedKeyFrame?()
        }
        if waitingForKey && !isKey { return false }
        waitingForKey = false

        let data = payload.subdata(in: (payload.startIndex + 1)..<payload.endIndex)
        var block: CMBlockBuffer?
        guard CMBlockBufferCreateWithMemoryBlock(
                allocator: kCFAllocatorDefault, memoryBlock: nil, blockLength: data.count,
                blockAllocator: kCFAllocatorDefault, customBlockSource: nil, offsetToData: 0,
                dataLength: data.count, flags: kCMBlockBufferAssureMemoryNowFlag,
                blockBufferOut: &block) == kCMBlockBufferNoErr, let block else { return false }
        let copied = data.withUnsafeBytes {
            CMBlockBufferReplaceDataBytes(with: $0.baseAddress!, blockBuffer: block,
                                          offsetIntoDestination: 0, dataLength: data.count)
        }
        guard copied == kCMBlockBufferNoErr else { return false }

        var sample: CMSampleBuffer?
        var size = data.count
        guard CMSampleBufferCreateReady(
                allocator: kCFAllocatorDefault, dataBuffer: block, formatDescription: format,
                sampleCount: 1, sampleTimingEntryCount: 0, sampleTimingArray: nil,
                sampleSizeEntryCount: 1, sampleSizeArray: &size, sampleBufferOut: &sample) == noErr,
              let sample else { return false }

        if let arr = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: true),
           CFArrayGetCount(arr) > 0 {
            let dict = unsafeBitCast(CFArrayGetValueAtIndex(arr, 0), to: CFMutableDictionary.self)
            CFDictionarySetValue(dict,
                                 Unmanaged.passUnretained(kCMSampleAttachmentKey_DisplayImmediately).toOpaque(),
                                 Unmanaged.passUnretained(kCFBooleanTrue).toOpaque())
        }
        layer.enqueue(sample)
        return true
    }
}
