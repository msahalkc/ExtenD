# Security policy

ExtenD has Accessibility permission on the Mac (it injects mouse and keyboard input) and records the iPad's virtual display, so security reports are very welcome.

## Reporting a vulnerability
Please **don't open a public issue**. Report privately through GitHub:
[Report a vulnerability](https://github.com/msahalkc/ExtenD/security/advisories/new).

Include what an attacker needs (same Wi-Fi, a USB cable, an app on one of the devices…), the steps to reproduce, and the impact. You'll get a reply within a week. Once a fix is released, you'll be credited unless you'd rather not be.

## Scope
In scope: the pairing and encrypted transport (`Shared/`), the Mac and iPad connection handling, input injection, and anything that lets a device that isn't paired see the display or control the Mac.

Out of scope: attacks that need full control of the Mac user account, and breakage caused by the private macOS APIs ExtenD relies on.

## Supported versions
Only the latest commit on `main` is supported.

The design and threat model are in [docs/ADR-001-secure-transport.md](docs/ADR-001-secure-transport.md) and [docs/ADR-002-local-wifi.md](docs/ADR-002-local-wifi.md).
