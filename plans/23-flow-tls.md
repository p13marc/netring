# Plan 23 — `netring-flow-tls` companion crate

## Summary

Bridge `tls-parser` (rusticata) into `FlowStream` for passive TLS
handshake observation. Emit `TlsClientHello`, `TlsServerHello`,
`TlsAlert` events; expose SNI, ALPN, cipher suite list, optional
JA3/JA4 fingerprints. No decryption — pure handshake metadata.

## Status

Not started.

## Prerequisites

- Plans 00–04 published.
- Plan 12 fixtures (would need a `tls_handshake.pcap` fixture too —
  add to plan 12 or generate locally).

## Out of scope

- Full TLS record decryption (would need session keys).
- TLS 1.3 0-RTT data inspection (encrypted by default).
- Active TLS interception (this is **passive** observation only).
- HTTP/2 negotiation tracking after the handshake (separate plan).

---

## Why this crate

Passive TLS observation answers very common security/visibility
questions:

- "What server name was requested?" (SNI)
- "What protocol does the client support?" (ALPN list)
- "What's the JA3/JA4 fingerprint?" (client identification)
- "Did the handshake succeed or alert?" (TLS state)

Currently, users have to: implement an `AsyncReassembler` that
appends bytes to a buffer, then run `tls-parser` over the buffer.
This crate ships that bridge.

---

## Files

### NEW

```
netring-flow-tls/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── handler.rs       # TlsHandler trait
│   ├── parser.rs        # incremental record + handshake parsing
│   ├── reassembler.rs   # AsyncReassembler impl
│   ├── factory.rs       # TlsFactory<H>
│   └── fingerprint.rs   # JA3 / JA4 (optional, behind feature)
└── examples/
    └── tls_observer.rs  # live: print SNI + ALPN per connection
```

---

## API

### Events

```rust
/// Parsed ClientHello.
#[derive(Debug, Clone)]
pub struct TlsClientHello {
    pub version: TlsVersion,           // record-layer version
    pub legacy_version: TlsVersion,    // ClientHello.legacy_version
    pub random: [u8; 32],
    pub session_id: Bytes,
    pub cipher_suites: Vec<u16>,
    pub compression: Vec<u8>,
    pub sni: Option<String>,           // server_name extension
    pub alpn: Vec<String>,             // ALPN protocol IDs
    pub supported_versions: Vec<TlsVersion>,
    pub supported_groups: Vec<u16>,    // signature/curve list
    pub extensions: Vec<u16>,          // ordered extension types (for fingerprinting)
}

/// Parsed ServerHello.
#[derive(Debug, Clone)]
pub struct TlsServerHello {
    pub version: TlsVersion,
    pub legacy_version: TlsVersion,
    pub random: [u8; 32],
    pub session_id: Bytes,
    pub cipher_suite: u16,
    pub compression: u8,
    pub alpn: Option<String>,          // negotiated ALPN
    pub supported_versions: Option<TlsVersion>,
}

/// TLS Alert record (often signals failure or close_notify).
#[derive(Debug, Clone)]
pub struct TlsAlert {
    pub level: TlsAlertLevel,          // Warning / Fatal
    pub description: u8,                // RFC 5246 §7.2 codes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Ssl3_0,
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
    Other(u16),
}

pub trait TlsHandler: Send + Sync + 'static {
    fn on_client_hello(&self, _hello: &TlsClientHello) {}
    fn on_server_hello(&self, _hello: &TlsServerHello) {}
    fn on_alert(&self, _alert: &TlsAlert) {}

    /// Optional: receive computed JA3 fingerprint (only with `ja3` feature).
    #[cfg(feature = "ja3")]
    fn on_ja3(&self, _hash_md5: &str, _string: &str) {}

    /// Optional: receive computed JA4 fingerprint (only with `ja4` feature).
    #[cfg(feature = "ja4")]
    fn on_ja4(&self, _ja4: &str) {}
}
```

### Factory

```rust
pub struct TlsFactory<H: TlsHandler> {
    handler: Arc<H>,
    config: TlsConfig,
}

impl<H: TlsHandler> TlsFactory<H> {
    pub fn with_handler(handler: H) -> Self;
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Compute JA3 fingerprints for ClientHello (requires `ja3` feature).
    pub ja3: bool,
    /// Compute JA4 fingerprints (requires `ja4` feature).
    pub ja4: bool,
    /// Stop parsing after the handshake completes (don't watch alerts).
    pub handshake_only: bool,
    /// Max buffered bytes per direction. Default: 64 KiB (handshake
    /// records typically << 16 KiB).
    pub max_buffer: usize,
}

impl<K, H> AsyncReassemblerFactory<K> for TlsFactory<H>
where
    K: Eq + std::hash::Hash + Clone + Send + Sync + 'static,
    H: TlsHandler,
{
    type Reassembler = TlsReassembler;
    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> TlsReassembler;
}
```

### Usage

```rust
struct LogHandler;
impl TlsHandler for LogHandler {
    fn on_client_hello(&self, h: &TlsClientHello) {
        println!("SNI: {:?}, ALPN: {:?}", h.sni, h.alpn);
    }
}

let mut stream = cap
    .flow_stream(FiveTuple::bidirectional())
    .with_async_reassembler(TlsFactory::with_handler(LogHandler));
```

---

## Parsing strategy

### Record-layer framing

TLS records are length-prefixed:

```
ContentType (1 byte)
ProtocolVersion (2 bytes)
Length (2 bytes, big-endian)
Fragment (Length bytes)
```

Per direction, we accumulate bytes in a `BytesMut`. As soon as 5
bytes are available, peek the length and check whether the full
record is buffered. If yes, parse via `tls_parser::parse_tls_record`
and dispatch by `ContentType`:

- 22 (Handshake) → parse handshake messages, may span multiple
  records (TLS allows fragmentation).
- 21 (Alert) → emit `TlsAlert` event.
- 20 (ChangeCipherSpec) → ignore for stats; transition to
  encrypted-records phase.
- 23 (Application Data) → encrypted; we stop parsing the handshake
  and hand control back (or log opaque sizes for traffic analysis).

### Handshake messages

After ChangeCipherSpec, handshake messages are encrypted. We only
need to capture the first few records:
- ClientHello (one record, sometimes split over two for jumbo
  extensions)
- ServerHello + Certificate + ServerKeyExchange + ServerHelloDone
  (in TLS 1.2)
- ServerHello + EncryptedExtensions (in TLS 1.3) — only ServerHello
  is in cleartext after the version-detect; our visibility ends
  there.

For the typical use case (SNI/ALPN extraction), we only need to
fully parse ClientHello and the unencrypted portion of ServerHello.

### Limit buffering

Since we only care about the first handshake, after observing
ChangeCipherSpec or after a configurable byte limit, transition the
reassembler to a "drop everything" mode — saves memory on long-lived
TLS connections.

---

## JA3 / JA4 fingerprints (optional features)

### JA3

JA3 hashes a comma-separated string of:

```
TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
```

Each section is dash-separated; missing extensions become empty
strings. The output is the MD5 hex of the joined string.

### JA4

JA4 is a more recent fingerprint (FoxIO) with separate parts:
TCP/QUIC indicator, TLS version, SNI presence, count of cipher
suites + extensions, ALPN, and SHA256-truncated hash of cipher
suites + extensions.

### Implementation

`ja3` feature: hand-roll the algorithm using extracted ClientHello
fields. ~50 LOC.

`ja4` feature: same, slightly more complex. ~100 LOC. Or depend on
`huginn-net` if its API is stable enough — defer to v0.2 of this
crate.

---

## Cargo.toml

```toml
[package]
name = "netring-flow-tls"
version = "0.1.0"
# ... workspace inheritance

description = "Passive TLS handshake observer for netring-flow"
keywords = ["tls", "ssl", "netring", "flow", "passive"]
categories = ["network-programming", "parser-implementations"]

[dependencies]
netring-flow = { version = "0.1", path = "../netring-flow", default-features = false, features = ["tracker", "reassembler"] }
tls-parser = "0.12"
bytes = { workspace = true }
thiserror = { workspace = true }
md-5 = { version = "0.10", optional = true }
sha2 = { version = "0.10", optional = true }
hex = { version = "0.4", optional = true }

[features]
default = []
ja3 = ["dep:md-5", "dep:hex"]
ja4 = ["dep:sha2", "dep:hex"]

[dev-dependencies]
netring-flow-pcap = { version = "0.1", path = "../netring-flow-pcap" }
```

---

## Implementation steps

1. **Skeleton crate.**
2. **Define event types** + `TlsHandler` trait.
3. **Implement record-layer framer** (`parser.rs`):
   - peek length, return None if partial, else split off and parse.
4. **Implement handshake parser** using `tls_parser::parse_tls_handshake_msg`.
   - Map `tls_parser`'s structures to our event types.
5. **Implement `TlsReassembler`** owning the per-direction
   `BytesMut` + state.
6. **Implement `TlsFactory`** with the `AsyncReassemblerFactory`
   trait.
7. **JA3 implementation** (behind `ja3` feature):
   - Format the canonical string from `TlsClientHello` fields.
   - MD5 it via `md-5` crate.
   - Call `handler.on_ja3(hash_md5, string)`.
8. **JA4 implementation** (behind `ja4` feature):
   - Format per FoxIO spec.
   - SHA256-truncate via `sha2`.
9. **Examples**:
   - `tls_observer.rs` — print SNI/ALPN per ClientHello.
   - `tls_fingerprint.rs` (gated on `ja3,ja4`) — print JA3+JA4 hashes.
10. **Integration test** using a `tls_handshake.pcap` fixture.

---

## Edge cases

- **TLS records spanning multiple TCP segments.** Handled
  automatically by buffering via `BytesMut`.
- **ClientHello fragmented across records.** Rare but RFC-permitted.
  `tls-parser` handles handshake-message defragmentation
  automatically.
- **TLS 1.3 ServerHello with ChangeCipherSpec interleaved.** TLS 1.3
  sends a fake CCS for middlebox compatibility. Our parser must not
  trip on this. `tls-parser` does the right thing.
- **GREASE** (RFC 8701 reserved values in cipher suite / extension
  lists). Pass through — they look like normal values, just in the
  reserved space. Document that JA3/JA4 implementations may or may
  not strip them depending on the variant.
- **HelloRetryRequest** in TLS 1.3 — looks like a ServerHello with
  a fixed Random. Handle as a separate event or document as an edge
  case.

---

## Tests

### Unit (`tests/parser.rs`)

- `parse_client_hello_basic` — synthetic CH, expect SNI + ALPN.
- `parse_server_hello_tls12`
- `parse_alert` — synthetic alert record, expect TlsAlert event.
- `record_spanning_segments` — feed CH in 3 chunks, expect 1 event
  at the third.
- `change_cipher_spec_stops_parsing` — record after CCS is not
  parsed.

### Fingerprint tests (gated on `ja3` / `ja4`)

- `ja3_known_value` — feed a CH from a known fingerprint test
  vector, check MD5 matches the published value.
- `ja4_known_value` — same for JA4 (vectors from the FoxIO
  reference).

### Integration

- `tls_handshake_pcap` — fixture-driven, expect ≥1 ClientHello + 1
  ServerHello.

---

## Acceptance criteria

- [ ] Crate builds without features.
- [ ] Crate builds with `--features ja3`.
- [ ] Crate builds with `--features ja4`.
- [ ] Crate builds with `--features ja3,ja4`.
- [ ] ≥7 unit tests pass; ≥1 integration test.
- [ ] `tls_observer` example runs against a real TLS connection
      (e.g., `curl https://example.com` while capturing on `lo`).
- [ ] README explains the passive-observation scope.
- [ ] `cargo publish -p netring-flow-tls --dry-run` succeeds.

---

## Risks

1. **`tls-parser` API churn.** Rusticata's parser is mature but
   pre-1.0. Pin to a minor version.
2. **JA3/JA4 spec drift.** JA4 is newer (FoxIO maintains the spec).
   Verify against published test vectors before claiming
   compatibility.
3. **TLS 1.3 visibility limits.** ServerHello onward is encrypted
   (after CCS). Document this — users get SNI + ALPN + cipher list,
   but not certificate details unless they have keys.
4. **Allocation cost.** Each ClientHello copies cipher suite list
   (Vec<u16>), extensions (Vec<u16>), etc. For high-rate TLS
   observation this could matter. v1: accept the cost; v0.2 might
   move to `Cow<[u16]>` borrowed from `BytesMut`.
5. **Fingerprint false positives.** JA3 has known collision concerns
   with extension-order shuffling clients. Document.

---

## Effort

- LOC: ~900 (parser + types + reassembler + factory + ja3/ja4 +
  tests).
- Time: 2 days.

---

## What this unlocks

- Out-of-the-box passive TLS observability — single most-requested
  feature for security tooling.
- JA3/JA4 fingerprinting in one line for IDS / threat-intel
  integrations.
- Reference for "low-throughput, header-only L7 parser" — useful
  template for users wanting to do similar with QUIC, SSH, etc.
