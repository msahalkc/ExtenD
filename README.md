# ExtenD

Use an iPad as an **extended display** for your Mac — over the USB-C cable or your local Wi-Fi — with touch, Apple Pencil, keyboard and trackpad input sent back to the Mac.

Works when Sidecar doesn't: the iPad and Mac **don't need the same Apple Account**.

Website: [extend.msahalkc.com](https://extend.msahalkc.com)

> ExtenD is an independent project, not affiliated with or endorsed by Apple. Mac, iPad, Apple Pencil and Sidecar are trademarks of Apple Inc.

## Features
- **A real second display.** A virtual display at the iPad's native resolution (HiDPI). Arrange it in System Settings → Displays; it follows the iPad's rotation. *Size on iPad* lets you make everything larger.
- **USB first, Wi-Fi as a fallback.** Plug in for the lowest latency; unplug and it carries on over Wi-Fi; plug back in and it hands over to USB.
- **Touch that feels like touch.** Tap buttons without the pointer jumping, drag to scroll with momentum, hold to pick things up, two-finger pinch to zoom, three-finger swipes for Spaces and Mission Control.
- **Apple Pencil** with pressure and tilt, and hover on supported iPads.
- **Private by design.** End-to-end encrypted (Noise XX). Devices pair once, by comparing a code on both screens. No accounts, no servers, no analytics; nothing leaves your cable or local network.

## Requirements
- A Mac with Apple silicon, running macOS 15 or later
- An iPad running iPadOS 18 or later
- Xcode (the version this repo is developed with: 27) and [XcodeGen](https://github.com/yonaskolb/XcodeGen)

## Build and install
There are no prebuilt downloads yet; build both apps from source.

1. Install XcodeGen and generate the project:
   ```bash
   brew install xcodegen
   xcodegen generate
   ```
2. Set your signing team and a bundle ID prefix of your own:
   ```bash
   cp Config/Local.xcconfig.example Config/Local.xcconfig
   ```
   Then edit `Config/Local.xcconfig`. A free Apple ID works, but **apps signed with a free account stop launching on the iPad after 7 days**: rebuild and reinstall to renew.
3. **Mac:** open `ExtenD.xcodeproj` and run the **ExtenDMac** scheme (or copy the built app into `/Applications`). It lives in the menu bar. When asked, grant **Screen & System Audio Recording** and **Accessibility** in System Settings → Privacy & Security, then relaunch it.
4. **iPad:** connect it by cable, tap **Trust**, turn on **Developer Mode** (Settings → Privacy & Security), then run the **ExtenDPad** scheme on it. On first launch, allow **Local Network** access.

## Use
1. Open ExtenD on the Mac and on the iPad, and connect the cable.
2. The first time, both screens show a code. If they match, accept on both.
3. The iPad becomes a display; arrange it in System Settings → Displays.

**Pairing over Wi-Fi:** on the iPad, tap **Paired Macs… → Pair a New Mac over Wi-Fi**, then click **Pair…** next to the iPad in the Mac's menu within 60 seconds. Paired devices reconnect over Wi-Fi automatically.

## Touch and input
| On the iPad | On the Mac |
|---|---|
| Tap | Click (buttons in native apps are pressed directly, without moving the pointer) |
| Drag | Scroll, or drag sliders, title bars and toolbars |
| Hold, then move | Pick up and drag (files, selections) |
| Hold still / two-finger tap | Right-click |
| Two-finger drag | Scroll with momentum |
| Two-finger pinch | Zoom (⌘+ / ⌘−) |
| Three-finger swipe ← → | Switch Spaces |
| Three-finger swipe ↑ / ↓ | Mission Control / App Exposé |
| Three-finger pinch in / out | Copy (twice quickly: cut) / Paste |
| Three-finger double-tap | Undo (with ⇧ held: redo) |
| Apple Pencil | Click and drag with pressure and tilt; hover moves the pointer |
| Trackpad, mouse, keyboard on the iPad | Work as on the Mac |

## Security
ExtenD controls your Mac's input, so it is built defensively:
- Every connection is a mutually authenticated **Noise XX** session (X25519, AES-GCM, SHA-256). There is no plaintext mode.
- Pairing uses a **commit-reveal code** shown on both screens; keys stay in each device's Keychain and never sync or back up.
- Wi-Fi is limited to private local networks; a new Mac can pair over Wi-Fi only right after you allow it on the iPad.
- Input is accepted only from a paired, active session, is rate-limited, lands only on the iPad's display, and is ignored while the Mac is locked.

Design and threat model: [ADR-001 secure transport](docs/ADR-001-secure-transport.md) · [ADR-002 local Wi-Fi](docs/ADR-002-local-wifi.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Known limitations
- **Private macOS APIs.** The virtual display uses `CGVirtualDisplay`, and hiding the pointer during touch uses a private window-server setting. Neither is public API: a macOS update may break them, and the Mac app can't be on the Mac App Store.
- **Not real multi-touch on the Mac.** macOS has no public way to inject touch, so touches are translated into clicks, scrolls, drags and shortcuts.
- **Free signing expires.** iPad builds signed with a free Apple ID last 7 days.
- Pinch-to-zoom sends ⌘+ / ⌘−, so it only works in apps with those shortcuts.

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License
[MIT](LICENSE) © 2026 Muhammed Sahal K C

Test vectors from third-party projects are credited in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
