# ADR-002: Local Wi-Fi transport

**Status:** Accepted 2026-10-09. The user made the product decisions; this records them and the design.
**Builds on:** ADR-001 (Noise XX secure channel, pairing gate). Nothing in the security model is relaxed.

## Decisions (user)
| Question | Decision |
|---|---|
| Network scope | Same local network only: Wi-Fi or Ethernet via the router, peers on private or link-local addresses. Never the internet, cellular, VPN tunnels or peer-to-peer Wi-Fi. |
| Pairing over Wi-Fi | Allowed (6-digit code on both screens, as over USB). |
| Default | Wi-Fi on by default. Toggles on the Mac (menu) and the iPad ("Paired Macs…" sheet). |
| USB vs Wi-Fi | "Whichever is faster": USB is faster (bandwidth, latency, reliability). So USB is preferred, with automatic fallback to Wi-Fi when unplugged and an automatic hand-over back to USB when plugged in. |

## Design
1. **Discovery.** While its app is in the foreground, the iPad advertises the Bonjour service `_extend._tcp` under an anonymous instance name (`ExtenD-xxxx`, random per launch), never the device name. The Mac browses for it. Both apps declare `NSBonjourServices` and `NSLocalNetworkUsageDescription`.
2. **Network policy (both sides, `Shared/NetworkPolicy.swift`).**
   - Prohibited interfaces: cellular, loopback (reserved for the USB tunnel), other (VPN/utun). `includePeerToPeer = false`.
   - The remote address must be private or link-local: 10/8, 172.16/12, 192.168/16, 169.254/16, fe80::/10, fc00::/7, or an IPv4-mapped equivalent. Otherwise the connection is closed before any byte is read.
3. **Same secure channel.** Wi-Fi carries exactly the ADR-001 byte stream: Noise XX, then pairing gate, then encrypted records.
4. **No unsolicited prompts from Wi-Fi (Mac).** For a Wi-Fi peer, the Mac checks the iPad's authenticated static key after handshake message 2, before sending message 3. That means before revealing its own identity.
   - **Known (paired) key:** continue and connect silently.
   - **Unknown key:** abort. The iPad is listed under *Available on Wi-Fi* with **Pair…**. Only that click starts a pairing, with codes on both screens.
   - This stops other people's iPads on an office network from triggering prompts, and the Mac never discloses its identity to them.
5. **Hand-over USB ⇄ Wi-Fi.**
   - **Fallback:** the USB link ends (unplugged), so the Mac reconnects to the same iPad over Wi-Fi, silently, because it's paired.
   - **Hand-over to USB:** while a Wi-Fi session is active and a USB device attaches, the Mac opens a *candidate* USB session. It continues only if the iPad's authenticated key equals the current peer's.
     - The iPad accepts a loopback candidate alongside an active Wi-Fi session. It promotes the candidate (and drops Wi-Fi) only once that candidate's pairing gate is active **and** its peer key equals the active peer's.
     - A candidate is never allowed to prompt.
     - So nothing unauthenticated, neither a local app nor a LAN host, can displace an active session.
   - The virtual display is kept across hand-overs (same size, so it's reused).
6. **Display lifetime.** It's kept while USB is attached, as before (user choice 2026-10-06). Without USB, it's kept for 2 minutes after the last link is lost, waiting for a reconnect over either transport, then released.
7. **Bitrate.** 30 Mbit/s over USB, 15 Mbit/s over Wi-Fi. The existing back-pressure and keyframe recovery apply to both.
8. **Mac transport abstraction.** `Session` runs over a `ByteStream`: `FDStream` for the usbmuxd fd, `NWStream` for Wi-Fi. Both have the same stall timeout and fd/connection lifecycle guarantees.

## Residual risks
- **Pairing prompts from the network:** ~~anyone on the same network can make the *iPad* show a pairing prompt~~. Closed 2026-11-11 (security review, user choice "arm on iPad"): over Wi-Fi the iPad declines Macs it doesn't know unless the user tapped *Pair a New Mac over Wi-Fi* within the last 60 s; one new Mac per arming. The decline happens after Noise message 3 (the responder can't learn the initiator's key sooner), so a LAN host still learns the iPad's name and public key, as noted below. USB pairing needs no arming. A pairing prompt (either transport) can no longer be replaced by a new connection.
- **Presence and name disclosure:** observers on the LAN can see that *an* ExtenD iPad is present (anonymous Bonjour name). A host that connects learns the iPad's display name and public key (Noise XX message 2), as with any LAN service.
- **Blocked discovery:** corporate or guest Wi-Fi often uses client isolation or blocks mDNS. Discovery then fails, and USB still works.
