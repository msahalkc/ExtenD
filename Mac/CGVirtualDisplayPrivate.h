// Bridging header for the Mac target.
// Declares Apple's PRIVATE CoreGraphics virtual-display API (present since macOS 10.14,
// used by Chromium, BetterDisplay, etc.). Not public, not App Store safe, may change with macOS updates.
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

@class CGVirtualDisplay;

@interface CGVirtualDisplayDescriptor : NSObject
@property (retain, nonatomic) dispatch_queue_t queue;
@property (copy, nonatomic) NSString *name;
@property (nonatomic) unsigned int maxPixelsWide;
@property (nonatomic) unsigned int maxPixelsHigh;
@property (nonatomic) CGSize sizeInMillimeters;
@property (nonatomic) unsigned int serialNum;
@property (nonatomic) unsigned int productID;
@property (nonatomic) unsigned int vendorID;
@property (nonatomic) CGPoint redPrimary;
@property (nonatomic) CGPoint greenPrimary;
@property (nonatomic) CGPoint bluePrimary;
@property (nonatomic) CGPoint whitePoint;
@property (copy, nonatomic, nullable) void (^terminationHandler)(id, CGVirtualDisplay *);
@end

@interface CGVirtualDisplayMode : NSObject
@property (readonly, nonatomic) NSUInteger width;
@property (readonly, nonatomic) NSUInteger height;
@property (readonly, nonatomic) double refreshRate;
- (instancetype)initWithWidth:(NSUInteger)width height:(NSUInteger)height refreshRate:(double)refreshRate;
@end

@interface CGVirtualDisplaySettings : NSObject
@property (retain, nonatomic) NSArray<CGVirtualDisplayMode *> *modes;
@property (nonatomic) unsigned int hiDPI;
@end

@interface CGVirtualDisplay : NSObject
@property (readonly, nonatomic) CGDirectDisplayID displayID;
- (instancetype)initWithDescriptor:(CGVirtualDisplayDescriptor *)descriptor;
- (BOOL)applySettings:(CGVirtualDisplaySettings *)settings NS_SWIFT_NAME(applySettings(_:));
@end

// PRIVATE window-server connection API (user-approved exception, 2026-11-10): with
// "SetsCursorInBackground" set, CGDisplayHideCursor also works for a background app, so the pointer
// can stay hidden during finger input. If it stops working, the pointer just shows (fails safe).
typedef int CGSConnectionID;
extern CGSConnectionID _CGSDefaultConnection(void);
extern CGError CGSSetConnectionProperty(CGSConnectionID cid, CGSConnectionID targetCID,
                                        CFStringRef key, CFTypeRef value);

NS_ASSUME_NONNULL_END
