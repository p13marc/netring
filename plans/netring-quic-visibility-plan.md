# netring — QUIC & encrypted-traffic visibility (plan)

> **Status:** plan, 2026-06-16. Candidate feature; no fixed release slot.
> **flowscope-led** (we own it): the QUIC parser + fingerprints land there,
> netring surfaces them. Additive (`quic` feature + a `Quic` protocol marker).

## 1. Why

QUIC is the relevance frontier for traffic analysis. The research is blunt:
*"QUIC… Wireshark, Zeek, Suricata, and Snort lose visibility."* Tools that key on
TLS-over-TCP ClientHello see only opaque UDP. **But QUIC Initial packets are
passively readable on-path** — they're encrypted with a key derived from the
plaintext Destination Connection ID + a version salt
([RFC 9001 §5.2](https://datatracker.ietf.org/doc/html/rfc9001)), so a passive
observer can decrypt the ClientHello and recover **SNI / ALPN / JA4** without any
secret (the GFW does exactly this for censorship). Value is also migrating to
*encrypted-traffic metadata* — JA4-style fingerprints — which netring already does
for TLS; extending to QUIC keeps netring current where the incumbents are blind.

## 2. Design

### flowscope side — `quic` feature (a purpose-built minimal parser, NOT a QUIC stack)
- **Do not** pull `quinn`/`quiche` — they're full transport stacks (handshake,
  congestion control, async), wrong shape and weight for passive parsing. Build a
  small Initial-only parser (~few hundred LoC), like the GFW/Wireshark approach:
  1. Recognise the QUIC **long header** Initial (first byte `0xC0` mask, version),
     read the plaintext DCID/SCID.
  2. Derive `initial_secret = HKDF-Extract(salt_v1, DCID)`, then client initial
     secret → **header-protection key + AEAD key/iv** (RFC 9001 §5).
  3. Remove header protection (AES-ECB/ChaCha sample → XOR) to get the packet
     number, then **AES-128-GCM decrypt** the payload → CRYPTO frames →
     reassemble the TLS **ClientHello** → SNI, ALPN, and reuse flowscope's
     existing JA4 over the ClientHello.
  - Deps: an AEAD + HKDF (`aes-gcm`/`chacha20poly1305` + `hkdf`, or `ring`). Keep
    behind the `quic` feature so the crypto deps are opt-in.
  - Emit a **strongly-typed** `QuicMessage { version: QuicVersion, dcid:
    ConnId, scid: ConnId, sni: Option<String>, alpn: Vec<String>, ja4:
    Option<Ja4> }` — `enum QuicVersion { V1, V2, Other(u32) }` (not a raw `u32`;
    drives the salt table + a clean "unknown → skip" match), `ConnId` a small
    bounded inline type (`ArrayVec<u8, 20>` — CIDs are ≤ 20 bytes, no heap).
    Datagram-style parser on UDP/443 (+ configurable), like DNS.
  - Robustness: only the v1 (and v2) salts; bail cleanly on unknown versions,
    Retry/0-RTT/short-header packets (no SNI there) — emit `QuicMessage` with
    `sni: None` rather than failing the flow.
- **Encrypted-flow fingerprints (stretch):** a `flowscope::fingerprint` module —
  packet-size / inter-arrival sequence fingerprints for *any* encrypted session
  (QUIC or TLS), the "encrypted visibility" angle without decryption. Reuses the
  detector/scoring primitives. **Perf caveat:** unlike QUIC-Initial parsing (once
  per connection), fingerprints touch the *per-packet* path — so accumulate a
  fixed-size, alloc-free running summary (first-N packet sizes in an
  `ArrayVec`/ring, not a growing `Vec`), preserve dhat Δ0, and only finalize the
  fingerprint at flow end. This is why it's a *separate* opt-in feature, not folded
  into the always-on session tier.

### netring side
- `Quic` **`MessageProtocol`** marker → `on::<Quic>(|m: &QuicMessage, …|)`.
- Subscription tier: `session::<Quic>().sni_glob("*.bank.example")` — QUIC's SNI
  slots straight into the existing `L7Fields` gating (alongside TLS/HTTP/DNS), so
  the kernel pushdown (UDP/443) + userspace SNI gate work unchanged.
- Fingerprint surfacing via the existing `on_fingerprint` hook + EVE
  `event_type:"quic"` record (mirrors the 0.25 `EveTlsSink`).

## 3. flowscope side
New `quic` feature (parser + crypto deps + `QuicMessage`), optional
`fingerprint` module. JA4 (client) stays BSD; JA4S/JA4+ remain behind the existing
`ja4plus` gate (Arch §9.6 — QUIC parsing itself is unencumbered). Publish flowscope,
then netring `cargo update --precise` + the `Quic` passthrough.

## 4. Milestones
- **M1** flowscope `quic`: long-header Initial recognition + key derivation +
  header-protection removal + GCM decrypt + ClientHello→SNI/ALPN (publish).
- **M2** JA4-over-QUIC reuse + `QuicMessage` shape finalised + version v1/v2 salts.
- **M3** netring `Quic` protocol marker + `session::<Quic>` `L7Fields` + EVE record.
- **M4** example (`monitor/quic_sni.rs` — live QUIC SNI watch) + docs (what's
  visible: Initial-only; 0-RTT/short-header carry no SNI).
- **M5 (stretch)** encrypted-flow fingerprints + `on_fingerprint` surfacing.

## 5. Testing
- Cap-free: golden QUIC Initial packets (captured ClientHello bytes) → assert
  SNI/ALPN/JA4 decode; fuzz the parser (it touches attacker-controlled crypto
  inputs — **must be panic-free**, feed it to `cargo-fuzz` like the other parsers).
- Negative cases: unknown version, Retry, short-header, truncated CRYPTO → graceful
  `None`, no panic.
- Live: a real QUIC client (`curl --http3`) on `lo` → assert the SNI is recovered
  end-to-end through the Monitor. Cross-version coverage is HW/library-gated.

## 6. Risks & open decisions
- **Crypto correctness + safety.** On-path decryption parses adversarial input;
  fuzzing + the salts-allowlist + strict bounds are mandatory. Keep it
  `#![forbid(unsafe_code)]` in the parser.
- **Version churn.** New QUIC versions rotate the initial salt; structure the salt
  table so adding a version is a one-line change. Unknown version ⇒ skip, never
  fail the flow.
- **Scope creep.** This is *passive Initial parsing*, **not** a QUIC transport
  decoder (no stream reassembly of the encrypted application data — that needs
  per-session keys we don't have). Document the boundary clearly so expectations
  match (SNI/ALPN/JA4 + fingerprints, not payload).
- **Open:** ship fingerprints (M5) in this plan or split to its own? Recommend
  split — QUIC SNI is the headline; fingerprints are a separate, reusable feature.
