# Plan 01 — Flow extractor + built-ins

## Summary

Land the `FlowExtractor` trait and its supporting types (`PacketView`,
`Extracted`, `Orientation`, `L4Proto`, `TcpInfo`, `TcpFlags`) in
`netring-flow`. Ship five built-in extractors (`FiveTuple`, `IpPair`,
`MacPair`) and four decap combinators (`StripVlan`, `StripMpls`,
`InnerVxlan`, `InnerGtpU`). Add `Packet::view()` bridge in `netring`.

No tracker yet (plan 02), no async stream yet (plan 02). This plan
gives the user the building blocks to write a custom extractor and
test it against synthetic frames.

## Status

Not started.

## Prerequisites

- [Plan 00](./00-workspace-split.md) complete.

## Out of scope

- `FlowTracker` and any flow accounting (plan 02).
- TCP state machine (plan 02).
- `AsyncCapture::flow_stream` (plan 02).
- `Reassembler` trait (plan 03).
- `flow` feature on `netring` (added in plan 02 when the tracker
  arrives).

---

## Files

### NEW (in `netring-flow`)

```
netring-flow/src/
├── view.rs            # PacketView<'_>
├── extractor.rs       # trait FlowExtractor, Extracted, Orientation, L4Proto, TcpInfo, TcpFlags
└── extract/
    ├── mod.rs         # pub mod re-exports
    ├── parse.rs       # internal helpers: walk encapsulations, parse TCP/UDP
    ├── five_tuple.rs  # FiveTuple, FiveTupleKey
    ├── ip_pair.rs     # IpPair, IpPairKey
    ├── mac_pair.rs    # MacPair, MacPairKey
    ├── encap_vlan.rs  # StripVlan
    ├── encap_mpls.rs  # StripMpls (we parse — etherparse doesn't)
    ├── encap_vxlan.rs # InnerVxlan (we parse — etherparse doesn't)
    └── encap_gtp.rs   # InnerGtpU (we parse — etherparse doesn't)
```

### NEW (in `netring-flow/tests`)

- `extractor_basics.rs` — synthetic-frame tests for each built-in.
- `extractor_pcap.rs` — runs `FiveTuple` against a small pcap and
  prints the keys; integration test using `pcap-file` (dev-dep
  in `netring-flow`).

### NEW (in `netring-flow/examples`)

- `pcap_flow_keys.rs` — read a pcap, extract 5-tuples, print one per
  line. Demonstrates source-agnosticism. **No tokio.**

### NEW (in `netring/examples`)

- `async_flow_keys.rs` — live capture, run a custom extractor, print
  events. Stays compiling-only until plan 02 adds `flow_stream`.
  (For plan 01, this example just builds an extractor and runs it
  against a single owned packet from `cap.recv().await` to prove the
  shape.)

### MODIFIED (in `netring`)

- `netring/src/packet.rs` — add `Packet::view() -> PacketView<'_>`
  method.
- `netring/src/lib.rs` — re-export `netring_flow::flow_extract` types
  under `netring::flow::extract` when `parse` feature is on (so users
  don't need to add `netring-flow` to their `Cargo.toml` for typical
  use).

---

## API

### `netring-flow/src/view.rs`

```rust
use crate::Timestamp;

#[derive(Debug, Clone, Copy)]
pub struct PacketView<'a> {
    pub frame: &'a [u8],
    pub timestamp: Timestamp,
}

impl<'a> PacketView<'a> {
    #[inline]
    pub fn new(frame: &'a [u8], timestamp: Timestamp) -> Self {
        Self { frame, timestamp }
    }

    /// For decap combinators: produce a new view pointing at `frame`,
    /// keeping the original timestamp.
    #[inline]
    pub fn with_frame(self, frame: &'a [u8]) -> Self {
        Self { frame, ..self }
    }
}
```

### `netring-flow/src/extractor.rs`

```rust
use crate::view::PacketView;
use bitflags::bitflags;

pub trait FlowExtractor: Send + Sync + 'static {
    type Key: Eq + std::hash::Hash + Clone + Send + Sync + 'static;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<Self::Key>>;
}

#[derive(Debug, Clone)]
pub struct Extracted<K> {
    pub key: K,
    pub orientation: Orientation,
    pub l4: Option<L4Proto>,
    pub tcp: Option<TcpInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Orientation { Forward, Reverse }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L4Proto { Tcp, Udp, Icmp, IcmpV6, Sctp, Other(u8) }

#[derive(Debug, Clone, Copy)]
pub struct TcpInfo {
    pub flags: TcpFlags,
    pub seq: u32,
    pub ack: u32,
    pub payload_offset: usize,
    pub payload_len: usize,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TcpFlags: u8 {
        const FIN = 0b0000_0001;
        const SYN = 0b0000_0010;
        const RST = 0b0000_0100;
        const PSH = 0b0000_1000;
        const ACK = 0b0001_0000;
        const URG = 0b0010_0000;
        const ECE = 0b0100_0000;
        const CWR = 0b1000_0000;
    }
}
```

### `netring-flow/src/extract/parse.rs` (internal)

Helpers used by all built-in extractors. Wraps `etherparse` for the
parts it handles and adds inline parsers for what it doesn't.

```rust
pub(crate) struct ParsedFrame<'a> {
    pub eth_payload: &'a [u8],          // after L2 (post any VLAN strip)
    pub link_proto: u16,                // ethertype seen
    pub ip: Option<ParsedIp<'a>>,
    pub l4: Option<ParsedL4<'a>>,
}

pub(crate) struct ParsedIp<'a> {
    pub src: std::net::IpAddr,
    pub dst: std::net::IpAddr,
    pub proto: u8,
    pub l4_payload: &'a [u8],
    pub _hdr_slice: &'a [u8],
}

pub(crate) enum ParsedL4<'a> {
    Tcp(ParsedTcp<'a>),
    Udp(ParsedUdp<'a>),
    Other,
}

pub(crate) struct ParsedTcp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: super::extractor::TcpFlags,
    pub seq: u32,
    pub ack: u32,
    pub payload_offset: usize,    // offset into the *original* frame
    pub payload: &'a [u8],
}

pub(crate) struct ParsedUdp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
    pub payload_offset: usize,
}

pub(crate) fn parse_eth(frame: &[u8]) -> Option<ParsedFrame<'_>>;
pub(crate) fn parse_from_ip(frame: &[u8]) -> Option<ParsedFrame<'_>>;
```

Implementation notes:

- `parse_eth` uses `etherparse::SlicedPacket::from_ethernet`. It
  handles VLAN as link extensions automatically (etherparse 0.16
  supports up to 3 link extensions per
  [its changelog](https://github.com/JulianSchmid/etherparse/blob/master/changelog.md)).
- `parse_from_ip` uses `etherparse::SlicedPacket::from_ip` for inner
  frames after VXLAN/GTP-U decap.
- TCP flags map directly from `etherparse`'s TcpHeaderSlice.

### `netring-flow/src/extract/five_tuple.rs`

```rust
use std::net::SocketAddr;
use crate::extractor::{Extracted, FlowExtractor, L4Proto, Orientation, TcpFlags, TcpInfo};
use crate::view::PacketView;
use super::parse::{self, ParsedL4};

#[derive(Debug, Clone, Copy)]
pub struct FiveTuple {
    bidirectional: bool,
}

impl FiveTuple {
    pub fn directional() -> Self { Self { bidirectional: false } }
    pub fn bidirectional() -> Self { Self { bidirectional: true } }
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct FiveTupleKey {
    pub proto: L4Proto,
    pub a: SocketAddr,
    pub b: SocketAddr,
}

impl FlowExtractor for FiveTuple {
    type Key = FiveTupleKey;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<FiveTupleKey>> {
        let parsed = parse::parse_eth(view.frame)?;
        let ip = parsed.ip?;
        let (src_port, dst_port, l4, tcp) = match parsed.l4? {
            ParsedL4::Tcp(t) => (
                t.src_port, t.dst_port,
                L4Proto::Tcp,
                Some(TcpInfo {
                    flags: t.flags, seq: t.seq, ack: t.ack,
                    payload_offset: t.payload_offset,
                    payload_len: t.payload.len(),
                }),
            ),
            ParsedL4::Udp(u) => (u.src_port, u.dst_port, L4Proto::Udp, None),
            ParsedL4::Other => (0, 0, L4Proto::Other(ip.proto), None),
        };
        let src = SocketAddr::new(ip.src, src_port);
        let dst = SocketAddr::new(ip.dst, dst_port);
        let (a, b, orientation) = if self.bidirectional && src > dst {
            (dst, src, Orientation::Reverse)
        } else {
            (src, dst, Orientation::Forward)
        };
        Some(Extracted {
            key: FiveTupleKey { proto: l4, a, b },
            orientation,
            l4: Some(l4),
            tcp,
        })
    }
}
```

### `netring-flow/src/extract/ip_pair.rs` and `mac_pair.rs`

Same shape, simpler keys:

```rust
pub struct IpPair;
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct IpPairKey { pub a: std::net::IpAddr, pub b: std::net::IpAddr }

pub struct MacPair;
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct MacPairKey { pub a: [u8; 6], pub b: [u8; 6] }
```

### `netring-flow/src/extract/encap_vlan.rs`

Etherparse already strips up to 3 link extensions, so `StripVlan`
is just a marker that delegates without extra work — but ship it
explicitly for documentation symmetry with the other combinators.

```rust
pub struct StripVlan<E>(pub E);

impl<E: FlowExtractor> FlowExtractor for StripVlan<E> {
    type Key = E::Key;
    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        // etherparse handles VLAN inline; our base parser already sees through it.
        self.0.extract(view)
    }
}
```

(Document that this combinator exists for clarity; the base parser
already does the work.)

### `netring-flow/src/extract/encap_mpls.rs`

We parse MPLS ourselves — 4 bytes per label, bottom-of-stack bit in
byte 2 bit 0:

```rust
pub struct StripMpls<E>(pub E);

impl<E: FlowExtractor> FlowExtractor for StripMpls<E> {
    type Key = E::Key;
    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        let inner = strip_mpls_labels(view.frame)?;
        // After MPLS, the protocol is determined by the first nibble of the inner:
        // 0x4 → IPv4, 0x6 → IPv6, otherwise unknown.
        self.0.extract(view.with_frame(inner))
    }
}

fn strip_mpls_labels(frame: &[u8]) -> Option<&[u8]>;  // see implementation step 6
```

### `netring-flow/src/extract/encap_vxlan.rs`

VXLAN: 8-byte header after UDP header (default port 4789). Inner is
an Ethernet frame. After we strip VXLAN, we re-feed the inner via
the base parser (which uses `parse_eth`).

```rust
pub struct InnerVxlan<E> {
    pub extractor: E,
    pub udp_port: u16,
}

impl<E> InnerVxlan<E> {
    pub fn new(extractor: E) -> Self {
        Self { extractor, udp_port: 4789 }
    }
}

impl<E: FlowExtractor> FlowExtractor for InnerVxlan<E> {
    type Key = E::Key;
    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        let inner = peel_vxlan(view.frame, self.udp_port)?;
        self.extractor.extract(view.with_frame(inner))
    }
}

fn peel_vxlan(frame: &[u8], expected_dst_port: u16) -> Option<&[u8]>;
```

### `netring-flow/src/extract/encap_gtp.rs`

GTP-U: 8-byte minimum header after UDP/2152, optional extensions if
the E flag is set. Inner is an IP datagram (not Ethernet).

```rust
pub struct InnerGtpU<E> {
    pub extractor: E,
    pub udp_port: u16,
}

impl<E> InnerGtpU<E> {
    pub fn new(extractor: E) -> Self {
        Self { extractor, udp_port: 2152 }
    }
}

impl<E: FlowExtractor> FlowExtractor for InnerGtpU<E> {
    type Key = E::Key;
    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        let inner = peel_gtp_u(view.frame, self.udp_port)?;
        // inner is an IP datagram — synthesize a fake Ethernet header
        // of len 0 so the inner extractor sees raw IP via parse_from_ip.
        // Easiest: treat the inner as already-IP and have the base
        // parser try `parse_eth` with a synthetic Ethernet wrapper, OR
        // expose a `FlowExtractor::extract_ip(view)` variant.
        // For v1: synthesize a 14-byte zeroed Ethernet header with
        // ethertype 0x0800/0x86dd and prepend.
        ...
    }
}
```

Implementation note on GTP-U: the inner datagram is bare IP, but our
base parser expects Ethernet. Two options:

(a) **Synthesize Ethernet wrapper** before delegating (clean: one
    parser path; cost: one stack-allocated 14-byte synthetic).
(b) **Add `parse_from_ip` path** to extractors via a separate trait
    method. (More invasive.)

**Decision: option (a)** for plan 01. Stack-buffer-then-prepend is
~10 LOC and keeps the trait simple. If perf benchmarks later show
the copy hurts, revisit.

### `netring/src/packet.rs` — `Packet::view()`

```rust
impl Packet<'_> {
    /// View this packet as a `netring_flow::PacketView`. Bridges the
    /// existing capture API to the source-agnostic flow tracking
    /// types.
    #[inline]
    pub fn view(&self) -> netring_flow::PacketView<'_> {
        netring_flow::PacketView::new(self.data(), self.timestamp())
    }
}
```

### Re-exports in `netring/src/lib.rs`

```rust
// Always available — needed by `Packet::view()` users.
pub use netring_flow::PacketView;

// When `parse` feature is enabled, surface the extractors under
// `netring::flow::extract::*` for convenience.
#[cfg(feature = "parse")]
pub mod flow {
    pub use netring_flow::{Extracted, FlowExtractor, L4Proto, Orientation, TcpFlags, TcpInfo};
    pub use netring_flow::extract;
}
```

---

## Cargo manifest changes

### `netring-flow/Cargo.toml`

```toml
[package]
# (workspace inheritance as in plan 00)

[dependencies]
bitflags   = { workspace = true }
etherparse = { workspace = true, optional = true }

[dev-dependencies]
pcap-file = { workspace = true }

[features]
default    = ["extractors"]
extractors = ["dep:etherparse"]
```

`extractors` is the only feature so far. Plan 02 adds `tracker`,
plan 03 adds `reassembler`.

### `netring/Cargo.toml`

Already depends on `netring-flow` from plan 00. No changes for
plan 01 — the new `Packet::view()` method uses only `PacketView`,
which is in `netring-flow` defaults-off. The re-exports under
`netring::flow::*` are gated by `parse` (which already pulls
etherparse and therefore activates `netring-flow/extractors`):

```toml
[features]
parse = ["dep:etherparse", "netring-flow/extractors"]
```

---

## Implementation steps

1. **Add deps to `netring-flow`.**
   - Update `netring-flow/Cargo.toml` per the manifest above.
   - `cargo build -p netring-flow --features extractors` succeeds.
2. **Land core types.**
   - `netring-flow/src/view.rs` — `PacketView`.
   - `netring-flow/src/extractor.rs` — trait + `Extracted` +
     `Orientation` + `L4Proto` + `TcpInfo` + `TcpFlags`.
   - Wire into `lib.rs`.
3. **Land internal parser helpers.**
   - `netring-flow/src/extract/parse.rs` — `parse_eth`,
     `parse_from_ip`, `ParsedFrame` etc.
   - Unit tests against synthetic frames (build SYN/ACK/FIN bytes by
     hand for each test).
4. **Land `FiveTuple`.**
   - Implement, test against synthetic IPv4-TCP, IPv4-UDP,
     IPv6-TCP, IPv4-ICMP frames.
   - Verify bidirectional canonicalization: feed two packets with
     swapped src/dst, assert same `FiveTupleKey`, distinct
     orientations.
5. **Land `IpPair` and `MacPair`.**
   - Mirror `FiveTuple` shape; tests against ICMP and ARP frames
     respectively.
6. **Land MPLS parser.**
   - 4-byte labels, bottom-of-stack bit at byte 2 bit 0.
   - `strip_mpls_labels` walks until BoS, returns the inner slice.
   - Wrap in `StripMpls<E>`.
   - Tests: synthetic IPv4-over-MPLS, multi-label stack, malformed.
7. **Land VXLAN parser.**
   - `peel_vxlan` parses Ethernet + IPv4/IPv6 + UDP using
     `etherparse`, checks UDP dst port, then expects 8 bytes of VXLAN
     (flags + 24-bit VNI + 24-bit reserved), returns the inner
     Ethernet slice.
   - Wrap in `InnerVxlan<E>`.
   - Tests: synthetic VXLAN-encapsulated IPv4-TCP frame, wrong UDP
     port (returns None), short VXLAN header (returns None).
8. **Land GTP-U parser.**
   - `peel_gtp_u` parses to UDP, checks port 2152, parses GTP-U
     header (1-byte flags, 1-byte msg type, 2-byte len, 4-byte TEID,
     optional 4 bytes if E/S/PN flags set).
   - Inner is bare IP. Synthesize 14-byte Ethernet wrapper:
     ```rust
     let ethertype: u16 = match inner_ip[0] >> 4 {
         4 => 0x0800,
         6 => 0x86dd,
         _ => return None,
     };
     let mut wrapped = [0u8; 14 + GTP_INNER_MAX];
     wrapped[12..14].copy_from_slice(&ethertype.to_be_bytes());
     wrapped[14..14 + inner_ip.len()].copy_from_slice(inner_ip);
     ```
     No, allocate-free approach via two-slice extractor would be
     cleaner — but for v1 this is fine.
   - **Better**: use a Cow or stack buffer; revisit perf if needed.
   - Wrap in `InnerGtpU<E>`.
   - Tests: synthetic GTP-U-encapsulated IPv4-TCP, GTP-U with E
     flag set (skip extensions), wrong UDP port.
9. **Land `StripVlan` for documentation symmetry.**
   - Pass-through wrapper since etherparse already does the work.
   - Test: VLAN-tagged IPv4-TCP, double-VLAN frame.
10. **Land `Packet::view()` bridge.**
    - One-line method addition.
    - Doctest in `netring/src/packet.rs` showing usage.
11. **Land re-exports in `netring`.**
    - `pub use netring_flow::PacketView;` (always).
    - `pub mod flow { pub use netring_flow::*; }` (gated by `parse`).
12. **Examples.**
    - `netring-flow/examples/pcap_flow_keys.rs`:
      ```rust
      // Read pcap, run FiveTuple over each frame, print keys.
      ```
    - `netring/examples/async_flow_keys.rs`:
      ```rust
      // Define an AppCookieExtractor (custom).
      // For plan 01: open AsyncCapture, recv() one packet,
      // construct a PacketView, run extractor, print result.
      // (Plan 02 will replace with cap.flow_stream(extractor).)
      ```
13. **Update justfile.**
    - Add `flow-keys *args:` recipe — `cargo run -p netring --example async_flow_keys --features tokio,parse -- {{args}}`.
14. **Update CHANGELOG.**
    - `0.7.0-alpha.1` (`netring`) and `0.1.0-alpha.1` (`netring-flow`).
    - Section: "Added — flow extractor + built-ins".

---

## Tests

### Unit (`netring-flow/src/**/tests`)

Each built-in extractor: ≥3 happy-path frames + ≥2 malformed/edge
frames. Helpers in `netring-flow/tests/common/synthetic.rs` build
canonical frames by hand:

- `synth_ipv4_tcp_syn(src, sport, dst, dport, seq, ack)`
- `synth_ipv4_udp(src, sport, dst, dport, payload)`
- `synth_ipv6_tcp(...)`
- `synth_vlan(inner, tci)`
- `synth_double_vlan(inner, outer_tci, inner_tci)`
- `synth_mpls(inner, labels)`
- `synth_vxlan(outer_ipv4_udp, vni, inner_eth)`
- `synth_gtp_u(outer_ipv4_udp, teid, inner_ip)`

### Integration (`netring-flow/tests/extractor_pcap.rs`)

- Read `tests/data/sample-tcp.pcap` (a small fixture, 100 packets).
- Run `FiveTuple::bidirectional()` over each frame.
- Assert: ≥1 unique flow seen, every TCP packet produced an
  `Extracted` with `tcp.is_some()`, every UDP packet produced
  `tcp.is_none()`.

### Doctest (`netring/src/packet.rs`)

```rust
/// ```no_run
/// use netring::AsyncCapture;
/// # async fn run() -> std::io::Result<()> {
/// let mut cap = AsyncCapture::open("eth0")?;
/// let pkt = cap.recv().await?;
/// let view = pkt.view();
/// // pass `view` to any FlowExtractor
/// # Ok(())
/// # }
/// ```
pub fn view(&self) -> netring_flow::PacketView<'_> { ... }
```

### Examples build

`cargo build --workspace --examples --all-features` includes
`pcap_flow_keys.rs` and `async_flow_keys.rs`.

---

## Acceptance criteria

- [ ] `FlowExtractor` trait + 6 supporting types compile in
      `netring-flow`.
- [ ] 3 built-in extractors (`FiveTuple`, `IpPair`, `MacPair`)
      compile and pass tests.
- [ ] 4 decap combinators (`StripVlan`, `StripMpls`, `InnerVxlan`,
      `InnerGtpU`) compile and pass tests.
- [ ] `cargo test -p netring-flow` passes (≥30 new tests).
- [ ] `cargo build -p netring-flow --no-default-features` succeeds
      with zero deps (only `bitflags` because it's mandatory now).
- [ ] `cargo build -p netring-flow --features extractors` pulls
      `etherparse`.
- [ ] `Packet::view()` method works — verified by doctest.
- [ ] `netring-flow/examples/pcap_flow_keys.rs` runs end-to-end on a
      sample pcap.
- [ ] `netring/examples/async_flow_keys.rs` builds (full runtime
      behavior gates on plan 02's `flow_stream`).
- [ ] No clippy warnings on workspace.
- [ ] `0.7.0-alpha.1` / `0.1.0-alpha.1` tagged on git.

---

## Risks

1. **GTP-U inner-IP re-wrapping**. Synthesizing an Ethernet header
   feels gross. If it's noticeably slow in benchmarks (plan 02 +
   later), refactor to a `parse_from_ip` extractor variant.
2. **VLAN already handled by etherparse**. `StripVlan` is a no-op in
   the trivial case. Document its purpose: explicit declaration of
   intent, plus future-proofing if etherparse changes behavior.
3. **`Send + Sync + 'static`** constraints on the trait. Custom
   extractors with internal `Cell`/`RefCell` won't work. Document.
4. **Bidirectional canonicalization with `SocketAddr` ordering**.
   `Ord` for `SocketAddr` compares IP first, then port. Make sure
   IPv4 < IPv6 ordering doesn't surprise users when we have a flow
   spanning both (impossible in practice — same-flow endpoints are
   same-family — but document).
5. **TCP `payload_offset`** must be measured from the *original*
   frame, not from the IP header. Decap combinators that swap
   `view.frame` make this tricky: the `payload_offset` returned by
   the *inner* extraction is relative to the inner frame, not the
   outer. **Decision**: document `tcp.payload_offset` as "relative
   to whatever frame was passed to the extractor that filled this
   field". For decap combinators, that's the inner frame. Reassembly
   layer (plan 03) reads the payload via `&view.frame[off..off+len]`
   using the same `view` it passed in.
6. **Test fixtures.** Need to create or check in a small pcap
   (`tests/data/sample-tcp.pcap`). Keep it under 50 KB; truly tiny
   capture (10–50 packets).

---

## Effort

- LOC: ~600 (design estimate). Breakdown:
  - Core types: ~150 LOC
  - `parse.rs` helpers: ~200 LOC
  - 3 simple extractors: ~150 LOC
  - 4 combinators: ~100 LOC
- Tests: ~400 LOC of synthetic-frame builders + assertions.
- Examples: ~150 LOC.
- Time: 2 days.
