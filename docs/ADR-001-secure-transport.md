# ADR-001: Secure transport and pairing

**Status:** Accepted 2026-10-06. D1 Noise XX, D2 Keychain X25519, D3 AES-GCM, D4 prompt on unknown device, D5 add ExtenDTests: all approved as recommended.
**Date:** 2026-10-06
**Scope:** Shared protocol, Mac app, iPad app

## 1. Problem

v0.2 restricts the iPad listener to the USB tunnel, but **every connection is still unauthenticated and plaintext**. The threats below are concrete:

| # | Threat | Impact |
|---|---|---|
| T1 | **A rogue iPad app listens on port 7878** while ExtenD isn't running. The Mac connects to it. | Rogue app **injects mouse and keyboard input into the Mac** (full control). |
| T2 | **Another iPad app** connects to localhost:7878 and replaces the Mac's session. | Shows a fake screen on the iPad; captures everything typed or drawn on the iPad. |
| T3 | **Any Mac process** can reach the iPad through usbmuxd (no special rights needed). | Same as T2, from the Mac side: captures typing and Pencil input. |
| T4 | Someone sniffs or taps the USB link (physical access, specialist hardware). | Reads the screen contents and keystrokes. |
| T5 | Replay, reordering or downgrade to plaintext. | Re-injects old input; strips protection. |

**Goal:** only an iPad and a Mac that the user has explicitly paired can talk to each other, and everything they exchange is confidential and tamper-proof. This must hold even if the attacker has an app on either device. It must not rely on Apple ID or iCloud.

## 2. Decision (proposed)

### 2.1 Protocol: Noise XX
- **Noise Protocol Framework**, pattern **`Noise_XX_25519_AESGCM_SHA256`**, implemented with **Apple CryptoKit**. There are **no third-party dependencies**.
  - Noise is the handshake used by WireGuard and WhatsApp.
  - The spec is small, formally analysed, and has public test vectors.
  - The XX pattern does mutual authentication. Each side proves it holds its static key, and the transcript is encrypted.
- **Roles:** the Mac is the initiator, because it opens the usbmuxd tunnel. The iPad is the responder.
- **Prologue:** `"ExtenD/1"` (protocol version). A mismatch fails the handshake, so downgrade is impossible (T5).
- **There is no plaintext mode at all.** Nothing except handshake messages is accepted before the handshake completes:
  - no `Hello`
  - no video
  - no input
  - no virtual display created

### 2.2 Identity and keys
- Each install generates **one long-term X25519 key pair** on first launch. A device's identity is its public key, not its usbmux DeviceID, name or Apple ID.
- The private key is stored in the Keychain with these settings:
  - `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
  - `kSecAttrSynchronizable = false`

  As a result it is never synced to iCloud, never in backups, and never leaves the device.
- **Pairing records** hold the peer's public key, a display name, and the pairing date. They are stored in the Keychain with the same flags.

### 2.3 First pairing: confirm on both screens with a matching code
1. The XX handshake completes, and each side learns the other's static public key.
2. If that key is not in the local pairing records, both sides enter **pairing mode**. No display is created and no input is accepted.
3. Both screens show a **6-digit code** derived from the Noise handshake hash: `HKDF(h, "ExtenD pairing code")`, taken mod 10⁶. A man in the middle would produce a different hash, so the codes would differ (T4).
4. The user taps **Accept on both** the Mac and the iPad. Only then does each side save the other's key.
5. Rejections and timeouts after 60 s close the connection. Pairing attempts are rate-limited to 1 every 5 s, so a hostile app can't spam prompts.

### 2.4 Reconnect: silent
- The XX handshake runs on every connection. If the peer's key is in the pairing records, the session starts silently.
- **If an unknown key appears, the user always gets a prompt, even when another iPad is already paired.** This is the defence against T1, T2 and T3: a rogue app can't present the paired device's key, because it doesn't have its private key.
- **Forget device** deletes the pairing record on that side. One side forgetting is enough to block the session.

### 2.5 Record layer after the handshake
- The existing `Framing` / `FrameParser` packets stay unchanged. They become the *plaintext* inside encrypted records.
- Wire format: `[u16 BE length][AES-GCM ciphertext + 16-byte tag]`, up to 65,535 bytes per record (the Noise limit). Large video frames are split across records. The overhead is about 0.03%.
- There are separate keys per direction (Noise `Split()`), with strict 64-bit nonce counters. Any decryption failure **drops the connection** (T5).
- The connection rekeys (Noise `Rekey`) every 2³⁰ records, which in practice is never.
- Performance: AES-GCM runs in hardware on Apple Silicon and on USB-C iPads (several GB/s). Our stream is 30–100 Mbit/s, so the added CPU and latency are negligible.

### 2.6 Authorization rules (enforced in code)
- The Mac creates the virtual display and injects input **only for an authenticated, paired session**.
- The iPad renders video and sends input **only to an authenticated, paired Mac**.
- With several iPads, each one has its own pairing record and session. Sessions are keyed by public key.
- The v0.2 safeguards stay in place, working inside the encrypted session:
  - size caps
  - input sanitization and rate limit
  - input blocked while the Mac is locked

## 3. Alternatives considered

| Option | Why not |
|---|---|
| **TLS 1.3 with pinned self-signed certificates** | The Mac side talks to usbmuxd over a raw socket, which Network.framework's TLS can't wrap. The only remaining path is the deprecated SecureTransport API. iOS also has no public API to create certificates, so we would need the swift-certificates dependency. More code, more attack surface, same security. |
| **TLS-PSK from a pairing code** | Network.framework's PSK support is limited, and a low-entropy code as a PSK can be brute-forced offline. |
| **Custom ECDH + AES-GCM** | Rolling our own handshake is the classic source of crypto bugs. Noise gives the same building blocks in a reviewed pattern. |
| **Secure Enclave keys** | The Secure Enclave supports P-256 only, while Noise standardizes 25519 and 448. Using it would mean a non-standard Noise variant or an extra signing layer. See decision D2 below. |
| **Trust USB pairing ("Trust this computer") alone** | It authenticates the Mac to iOS, not to *our app*. Any Mac process or iPad app can still connect (T1–T3). |

## 4. Residual risks
- **Pairing a look-alike app.** If the user installs a malicious app and accepts its pairing prompt, it becomes trusted. This is mitigated because pairing shows the device name and requires confirmation on both screens. No transport design can fully remove it.
- **Compromised OS.** A jailbroken iPad or a Mac with root malware can read Keychain items and the screen. This is out of scope.
- **Implementation bugs.** These are mitigated by running the official Noise test vectors and our own handshake and record tests in CI. An external review is advisable before a commercial release.

## 5. Implementation plan

| Step | Work | Est. |
|---|---|---|
| 1 | `Shared/Noise.swift`: CipherState, SymmetricState, HandshakeState (XX only). Passes the cacophony test vectors. | 1 day |
| 2 | `Shared/SecureChannel.swift`: handshake driver + record layer (chunking, nonces, fail-closed) | 1 day |
| 3 | `Shared/Identity.swift`: key generation and pairing records in the Keychain | 0.5 day |
| 4 | Mac: `Session` runs over `SecureChannel`; pairing alert with code; "Paired devices / Forget" UI | 1 day |
| 5 | iPad: `Connection` runs over `SecureChannel`; pairing sheet with code; Forget in settings | 1 day |
| 6 | Add an `ExtenDTests` unit-test target (Noise vectors, tamper/replay/oversize tests, pairing state machine). Update NOTES.md. | 0.5 day |

**Total: about 5 days.**

The wire format changes, so v0.2 and v1 apps can't talk to each other. That's acceptable before any release.

## 6. Decisions needed from you

| # | Question | Recommendation |
|---|---|---|
| D1 | Noise XX via CryptoKit (no dependencies), or TLS 1.3 + swift-certificates? | **Noise XX** |
| D2 | Long-term key: X25519 in the Keychain (device-only), or Secure Enclave P-256 (non-standard Noise variant, roughly +1–2 days)? | **X25519 in the Keychain** |
| D3 | Cipher: AES-GCM (hardware-accelerated), or ChaCha20-Poly1305? | **AES-GCM** |
| D4 | When an unknown device appears while another is paired: prompt to pair, or reject silently? | **Prompt** (needed for multi-iPad) |
| D5 | May I add a unit-test target (`ExtenDTests`) and vendor the public Noise test-vector JSON file? | **Yes** |

## 7. Amendment (2026-10-06, implementation review)

An independent review found that §2.3 as written (code = HKDF(h) mod 10⁶) doesn't hold against an **active** man in the middle.
- **The attack:** the attacker learns the iPad-side code first. It can then grind about 2²⁰ ephemeral keys on the Mac-facing handshake until that handshake's code matches, which takes seconds.
- **Fix (same UX, one extra round trip during pairing only):** a commit-reveal step, as in Bluetooth numeric comparison and ZRTP.
  - iPad → Mac: `pairCommit` = SHA-256("ExtenD commit" ‖ h ‖ Nb)
  - Mac → iPad: `pairNonce` = Na (32 random bytes)
  - iPad → Mac: `pairReveal` = Nb. The Mac verifies the commitment and treats a mismatch as a protocol violation.
  - code = HMAC-SHA256(key: h, "ExtenD pairing code" ‖ Na ‖ Nb) → first 4 bytes mod 10⁶
- **Result:** neither side can choose its nonce after seeing the other's, so a man in the middle matches the codes with probability 10⁻⁶ per attempt. The pairing cooldown limits attempts.

Other review fixes:
- **Connection replacement:** the iPad never replaces a connection that is active or showing a pairing prompt. A connection still in setup may be replaced, so a squatter can't hog the slot.
- **Cooldown:** a pairing attempt that reached the prompt but didn't complete starts a 5 s cooldown on both sides. That allows at most one prompt every 5 s.
- **Setup timeout:** covers the handshake, the trust exchange and commit-reveal. It stops once a prompt is showing, including after a local accept while waiting for the peer.
- **Forget:** if the Keychain delete fails, the error is shown instead of claiming success.
- **Mac prompt:**
  - never steals focus
  - has no Return shortcut
  - keeps Accept disabled for 1.5 s
- **Keychain:** errors fail closed rather than being treated as an unknown device.
- **Mac session:** the fd is closed only by the reader thread.

