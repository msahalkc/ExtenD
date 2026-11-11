# Contributing

Thanks for helping. Bug reports, device test results and pull requests are all welcome.

## Setup
```bash
brew install xcodegen
cp Config/Local.xcconfig.example Config/Local.xcconfig   # your team ID and bundle ID prefix
xcodegen generate
```
`ExtenD.xcodeproj` is generated from `project.yml`: change `project.yml`, never the project file.

## Build and test without signing
```bash
xcodebuild -project ExtenD.xcodeproj -scheme ExtenDMac -destination generic/platform=macOS -derivedDataPath build CODE_SIGNING_ALLOWED=NO build
xcodebuild -project ExtenD.xcodeproj -scheme ExtenDPad -destination generic/platform=iOS -derivedDataPath build CODE_SIGNING_ALLOWED=NO build
xcodebuild -project ExtenD.xcodeproj -scheme ExtenDTests -destination platform=macOS -derivedDataPath build CODE_SIGNING_ALLOWED=NO test
```

## Layout
- `Shared/` — wire protocol, Noise XX, pairing, network policy. Used by both apps: a wire-format change needs both sides updated.
- `Mac/` — menu-bar app: virtual display, capture and H.264 encoding, usbmuxd and Wi-Fi transport, input injection.
- `iPad/` — full-screen app: video, gestures, Pencil and keyboard input.
- `Tests/` — unit, fuzz and end-to-end tests (run on macOS).
- `docs/` — architecture decision records, including the threat model.

## Guidelines
- Keep security-relevant changes small and explain them in the PR; anything touching `Shared/`, pairing or input injection gets extra review.
- No new third-party dependencies without discussion in an issue first.
- Add or update tests for protocol and decision logic.
- Please test on real hardware when you can, and say which Mac, iPad and OS versions you used.
