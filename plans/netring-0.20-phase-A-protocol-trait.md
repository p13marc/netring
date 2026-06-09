# netring 0.20 — Phase A: Protocol trait + Event types + builtin markers

**Effort:** 2–3 days
**Predecessor:** netring 0.19.0 absorption (already shipped at `daf8557`)
**Successor:** [`Phase B`](./netring-0.20-phase-B-handler-trait.md) — Handler trait + dispatcher

## 1. Goal

Introduce a protocol-agnostic plugin layer. After this phase:

- A `Protocol` trait exists. Implementors declare `Message`, `NAME`, dispatch rule, and parser construction.
- Seven builtin marker types ship under `protocol::builtin`: `Tcp`, `Udp`, `Icmp`, `Http`, `Dns`, `Tls`, `TlsHandshake`.
- An `Event` trait + typed event marker structs (`FlowStarted<P>`, `FlowEnded<P>`, `FlowEstablished<P>`, `AnyFlowAnomaly`, `Tick`) exist.
- Third-party crates can implement `Protocol` for their own marker types — no edit to netring required.
- **No user-visible behavior change yet.** The existing `ProtocolMonitor` / `ProtocolEvent` / `ProtocolMessage` continue to work. The new types are *additions*; they get wired into a new `Monitor` builder in Phase B.

The phase is foundational — all subsequent phases build on the types defined here.

## 2. Scope

### In
- New `protocol::builtin` module with 7 marker types.
- `Protocol`, `ParserKind<M>`, `Dispatch`, `SignatureMatch`, `ProtocolInitError` types in `protocol::mod`.
- New `protocol::event_typed` module with `Event` trait + typed event structs.
- Unit tests for each.

### Out
- `Monitor` builder — Phase B.
- `Handler` trait — Phase B.
- Any change to the existing `ProtocolMonitorBuilder` user API — Phase G migration.
- Heuristic / signature routing wiring at the user level — Phase B (Monitor builder); the `Dispatch::Signature` variant lands here as a data type but is not yet consumed.

## 3. Dependencies

- netring 0.19.0 (flowscope 0.11.1 absorption) is shipped on master.
- flowscope 0.11.1 on crates.io; verify in `Cargo.lock`.
- No new external dependencies in this phase.

## 4. Module layout

```
src/
├── protocol/
│   ├── mod.rs                    M  — add `Protocol` trait, `Dispatch`, etc.; keep existing exports
│   ├── event.rs                  (unchanged from 0.19.0)
│   ├── monitor.rs                (unchanged from 0.19.0)
│   ├── builtin/                  A  — 7 marker types
│   │   ├── mod.rs                A
│   │   ├── tcp.rs                A  — `struct Tcp` lifecycle-only marker
│   │   ├── udp.rs                A  — `struct Udp` lifecycle-only marker
│   │   ├── icmp.rs               A  — `struct Icmp` datagram parser
│   │   ├── http.rs               A  — `struct Http` session parser
│   │   ├── dns.rs                A  — `struct Dns` datagram parser
│   │   ├── tls.rs                A  — `struct Tls` session parser
│   │   └── tls_handshake.rs      A  — `struct TlsHandshake` aggregator
│   └── event_typed.rs            A  — `Event` trait + FlowStarted<P>/etc. markers
│
├── lib.rs                        M  — `pub mod protocol::builtin;` re-export
```

No deletions. Modifications are additive.

**LoC estimates:** ~400 LoC new across these files (~30 LoC per builtin marker, ~100 LoC for `Protocol` trait surface, ~120 LoC for `Event` + typed event structs).

## 5. Detailed deliverables

### 5.1 `Protocol` trait + supporting types

`src/protocol/mod.rs` — add after existing items:

```rust
// ─── Plugin layer — landing in 0.20 (Phase A) ─────────────────

/// A protocol the monitor can observe.
///
/// Implementors are usually zero-sized marker types (`struct Http;`).
/// The marker is used as a type-level identifier; the runtime
/// dispatch key is its `TypeId`.
///
/// `'static` is required because dispatch is keyed by `TypeId`.
/// This forecloses lifetime-parameterized marker types — not a
/// real limitation since markers are typically ZSTs.
pub trait Protocol: Send + Sync + 'static {
    /// The typed message this protocol's parser emits. Must be
    /// `'static` (owning) — the framework downcasts via `Any`,
    /// which requires `'static`.
    type Message: Send + Sync + 'static;

    /// Stable identifier — used for metrics labels, log targets,
    /// and the `parser_kind` field on the low-level Stream API.
    /// Convention: lowercase, hyphenated. Examples: `"http/1"`,
    /// `"dns-udp"`, `"tls-handshake"`. Matches flowscope's
    /// `parser_kinds::*` constants where applicable.
    const NAME: &'static str;

    /// How packets get routed to this protocol's parser.
    fn dispatch() -> Dispatch;

    /// Construct the parser instance — a flowscope session or
    /// datagram parser ready to register against the typed
    /// `Driver<E>`. Called once at builder time.
    ///
    /// Lifecycle-only markers (`Tcp`, `Udp`) return `Err`; the
    /// builder treats `Dispatch::AllTcp` / `Dispatch::AllUdp` as
    /// "no parser slot to register; just record the marker for
    /// typed lifecycle event filtering."
    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError>;
}

/// flowscope 0.11 has two parser-trait flavors. A `Protocol` impl
/// declares which one it produces; the builder routes to the
/// matching `Driver<E>` registration method.
pub enum ParserKind<M> {
    /// TCP-shaped parser (HTTP, DNS-over-TCP, TLS).
    Session(Box<dyn flowscope::SessionParser<Message = M>>),
    /// UDP/ICMP-shaped parser (DNS-over-UDP, ICMP).
    Datagram(Box<dyn flowscope::DatagramParser<Message = M>>),
}

impl<M> std::fmt::Debug for ParserKind<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParserKind::Session(_) => f.write_str("ParserKind::Session(<flowscope::SessionParser>)"),
            ParserKind::Datagram(_) => f.write_str("ParserKind::Datagram(<flowscope::DatagramParser>)"),
        }
    }
}

/// How a protocol selects packets for its parser.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Dispatch {
    /// Match TCP flows on these ports.
    Tcp(Vec<u16>),
    /// Match UDP flows on these ports.
    Udp(Vec<u16>),
    /// Match all ICMP / ICMPv6 datagrams.
    Icmp,
    /// All TCP flows regardless of port — the L4-lifecycle case
    /// for the `Tcp` marker.
    AllTcp,
    /// All UDP flows regardless of port — the `Udp` marker case.
    AllUdp,
    /// Port-agnostic dispatch via a signature function over the
    /// first ≤64 payload bytes. The function returns whether the
    /// packet matches; matching flows pin to the parser.
    Signature(fn(&[u8]) -> SignatureMatch),
}

/// Result of a signature function. `Match` pins the flow to this
/// protocol's parser; `NoMatch` skips it; `MoreData` says "I need
/// more bytes" — the dispatcher keeps probing until budget runs out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMatch {
    Match,
    NoMatch,
    MoreData,
}

/// From flowscope's curated signature catalog.
impl From<flowscope::detect::signatures::SignatureMatch> for SignatureMatch {
    fn from(s: flowscope::detect::signatures::SignatureMatch) -> Self {
        use flowscope::detect::signatures::SignatureMatch as Fs;
        match s {
            Fs::Match => SignatureMatch::Match,
            Fs::NoMatch => SignatureMatch::NoMatch,
            Fs::MoreData => SignatureMatch::MoreData,
        }
    }
}

/// Error type for `Protocol::parser`. Most parsers are infallible
/// to construct; flowscope parsers that take config can fail.
#[derive(Debug, thiserror::Error)]
#[error("protocol parser init failed: {0}")]
pub struct ProtocolInitError(pub String);

pub use builtin::{Dns, Http, Icmp, Tcp, Tls, TlsHandshake, Udp};

pub mod builtin;
```

The `pub use builtin::*` re-export pulls the seven markers into `netring::protocol::*` so users write `use netring::protocol::Http;` rather than `use netring::protocol::builtin::Http;`.

### 5.2 The seven builtin markers

Each is ≤30 LoC. Template:

`src/protocol/builtin/http.rs`:

```rust
//! HTTP/1.x protocol marker.

use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

/// HTTP/1.x — RFC 7230 request/response over TCP.
/// Default ports: 80, 8080. Override with a custom `Protocol` impl
/// in your own crate.
#[derive(Debug)]
pub struct Http;

impl Protocol for Http {
    type Message = flowscope::http::HttpMessage;
    const NAME: &'static str = flowscope::parser_kinds::HTTP;

    fn dispatch() -> Dispatch { Dispatch::Tcp(vec![80, 8080]) }

    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError> {
        Ok(ParserKind::Session(Box::new(flowscope::http::HttpParser::default())))
    }
}
```

`src/protocol/builtin/dns.rs`:

```rust
//! DNS-over-UDP protocol marker. (DNS-over-TCP is a future
//! addition; `Protocol` lets a downstream crate ship its own
//! `DnsTcp` marker without touching netring.)

use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

/// DNS over UDP. Default port: 53.
#[derive(Debug)]
pub struct Dns;

impl Protocol for Dns {
    type Message = flowscope::dns::DnsMessage;
    const NAME: &'static str = flowscope::parser_kinds::DNS_UDP;

    fn dispatch() -> Dispatch { Dispatch::Udp(vec![53]) }

    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError> {
        Ok(ParserKind::Datagram(Box::new(
            flowscope::dns::DnsUdpParser::with_correlation(),
        )))
    }
}
```

`src/protocol/builtin/tls.rs`:

```rust
use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

/// TLS handshake observation at message granularity
/// (ClientHello / ServerHello / Alert).
#[derive(Debug)]
pub struct Tls;

impl Protocol for Tls {
    type Message = flowscope::tls::TlsMessage;
    const NAME: &'static str = flowscope::parser_kinds::TLS;
    fn dispatch() -> Dispatch { Dispatch::Tcp(vec![443, 8443]) }
    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError> {
        Ok(ParserKind::Session(Box::new(flowscope::tls::TlsParser::default())))
    }
}
```

`src/protocol/builtin/tls_handshake.rs`:

```rust
use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

/// TLS handshake aggregator — emits one event per observed
/// handshake (SNI/ALPN/JA3/JA4/outcome).
#[derive(Debug)]
pub struct TlsHandshake;

impl Protocol for TlsHandshake {
    type Message = flowscope::tls::TlsHandshake;
    const NAME: &'static str = flowscope::parser_kinds::TLS_HANDSHAKE;
    fn dispatch() -> Dispatch { Dispatch::Tcp(vec![443, 8443]) }
    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError> {
        Ok(ParserKind::Session(Box::new(flowscope::tls::TlsHandshakeParser::default())))
    }
}
```

`src/protocol/builtin/icmp.rs`:

```rust
use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

/// ICMPv4 + ICMPv6 message parser.
#[derive(Debug)]
pub struct Icmp;

impl Protocol for Icmp {
    type Message = flowscope::icmp::IcmpMessage;
    const NAME: &'static str = flowscope::parser_kinds::ICMP;
    fn dispatch() -> Dispatch { Dispatch::Icmp }
    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError> {
        Ok(ParserKind::Datagram(Box::new(flowscope::icmp::IcmpParser::new())))
    }
}
```

`src/protocol/builtin/tcp.rs`:

```rust
use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

/// TCP lifecycle marker. Registering this protocol enables
/// `FlowStarted<Tcp>`, `FlowEstablished<Tcp>`, `FlowEnded<Tcp>`
/// typed events — no parser slot registered on flowscope's side.
#[derive(Debug)]
pub struct Tcp;

impl Protocol for Tcp {
    type Message = ();
    const NAME: &'static str = "tcp";
    fn dispatch() -> Dispatch { Dispatch::AllTcp }
    fn parser() -> Result<ParserKind<()>, ProtocolInitError> {
        Err(ProtocolInitError(
            "Tcp marker is lifecycle-only — no parser; \
             handled by the central flow tracker"
                .into(),
        ))
    }
}
```

`src/protocol/builtin/udp.rs`: same shape with `NAME = "udp"`, `Dispatch::AllUdp`.

`src/protocol/builtin/mod.rs`:

```rust
//! Built-in `Protocol` marker types.
//!
//! These cover the protocols netring ships parsers for. Third-party
//! crates that implement [`crate::protocol::Protocol`] for their own
//! marker types compose seamlessly with these — no central enum to
//! edit.

mod tcp;
mod udp;
mod icmp;
mod http;
mod dns;
mod tls;
mod tls_handshake;

pub use tcp::Tcp;
pub use udp::Udp;
pub use icmp::Icmp;
pub use http::Http;
pub use dns::Dns;
pub use tls::Tls;
pub use tls_handshake::TlsHandshake;
```

Each marker is feature-gated where appropriate (`#[cfg(feature = "http")]` on the `pub use http::Http;` line etc.). The `Tcp`/`Udp` markers are always available (they don't need a parser).

### 5.3 `Event` trait + typed event structs

`src/protocol/event_typed.rs`:

```rust
//! Typed events for handler registration.
//!
//! These are the types a user passes to `Monitor::builder().on::<E>(handler)`
//! in Phase B. They re-package the existing `ProtocolEvent<K>` lifecycle
//! variants into per-`Protocol` typed structs, letting handlers scope
//! to a single L4 protocol (e.g. `FlowStarted<Tcp>`) without writing a
//! runtime filter.

use std::marker::PhantomData;

use flowscope::{AnomalyKind, EndReason, FlowStats, FlowSide, L4Proto, TcpInfo, Timestamp};

use crate::protocol::{FlowKey, Protocol};

/// Marker for types handlers can subscribe to.
///
/// `Payload` is the type the handler closure receives by reference.
/// For raw protocol messages, `Payload = P::Message`. For flow
/// lifecycle events, `Payload` is the typed event struct itself.
pub trait Event: Send + Sync + 'static {
    /// The handler-visible payload type.
    type Payload: Send + Sync + 'static;
}

// ─── Raw protocol message events ────────────────────────────────
//
// `Monitor::builder().on::<Http>(|msg: &HttpMessage, ctx| { ... })`
// dispatches whenever Http's parser emits an HttpMessage.

impl<P: Protocol> Event for P {
    type Payload = P::Message;
}

// ─── Flow lifecycle events, generic over the protocol marker ────

/// Emitted when a new flow begins. Scoped by `P` so a handler
/// for `FlowStarted<Tcp>` won't fire on UDP flow starts.
#[non_exhaustive]
pub struct FlowStarted<P: Protocol> {
    /// Flow key.
    pub key: FlowKey,
    /// L4 protocol (`Some(L4Proto::Tcp)` for `P = Tcp`, etc.).
    pub l4: Option<L4Proto>,
    /// Timestamp of the first packet.
    pub ts: Timestamp,
    _marker: PhantomData<fn() -> P>,
}

impl<P: Protocol> FlowStarted<P> {
    pub(crate) fn new(key: FlowKey, l4: Option<L4Proto>, ts: Timestamp) -> Self {
        Self { key, l4, ts, _marker: PhantomData }
    }
}

impl<P: Protocol> Event for FlowStarted<P> {
    type Payload = FlowStarted<P>;
}

/// Emitted when a flow ends.
#[non_exhaustive]
pub struct FlowEnded<P: Protocol> {
    pub key: FlowKey,
    pub reason: EndReason,
    pub stats: FlowStats,
    pub l4: Option<L4Proto>,
    pub ts: Timestamp,
    _marker: PhantomData<fn() -> P>,
}

impl<P: Protocol> FlowEnded<P> {
    pub(crate) fn new(
        key: FlowKey, reason: EndReason, stats: FlowStats,
        l4: Option<L4Proto>, ts: Timestamp,
    ) -> Self {
        Self { key, reason, stats, l4, ts, _marker: PhantomData }
    }
}

impl<P: Protocol> Event for FlowEnded<P> {
    type Payload = FlowEnded<P>;
}

/// Emitted at TCP 3-way-handshake completion. UDP/ICMP never fire.
#[non_exhaustive]
pub struct FlowEstablished<P: Protocol> {
    pub key: FlowKey,
    pub ts: Timestamp,
    _marker: PhantomData<fn() -> P>,
}

impl<P: Protocol> FlowEstablished<P> {
    pub(crate) fn new(key: FlowKey, ts: Timestamp) -> Self {
        Self { key, ts, _marker: PhantomData }
    }
}

impl<P: Protocol> Event for FlowEstablished<P> {
    type Payload = FlowEstablished<P>;
}

// ─── Cross-protocol events ──────────────────────────────────────

/// Catch-all for flowscope-side anomalies (TCP out-of-order,
/// reassembler watermark, parser poison, etc.).
#[non_exhaustive]
pub struct AnyFlowAnomaly {
    pub key: Option<FlowKey>,
    pub kind: AnomalyKind,
    pub ts: Timestamp,
}

impl Event for AnyFlowAnomaly {
    type Payload = AnyFlowAnomaly;
}

/// Periodic tick event.
#[non_exhaustive]
pub struct Tick {
    pub now: Timestamp,
    pub period: std::time::Duration,
}

impl Event for Tick {
    type Payload = Tick;
}

// Re-export FlowKey + FlowSide + TcpInfo so users can name them
// without a flowscope:: prefix.
pub use flowscope::FlowSide as Side;
pub use flowscope::TcpInfo;
```

The `PhantomData<fn() -> P>` (not `PhantomData<P>`) is intentional: it makes `FlowStarted<P>: Send + Sync` even when `P: !Sync`, matching `Protocol: Send + Sync + 'static` without forcing `Protocol: Send + Sync` on the phantom.

### 5.4 `FlowKey` re-export

Add to `src/protocol/mod.rs`:

```rust
/// Re-export from flowscope for convenience. Users name this
/// instead of `flowscope::extract::FiveTupleKey`.
pub type FlowKey = flowscope::extract::FiveTupleKey;
```

### 5.5 `lib.rs` exposure

`src/lib.rs` — under the existing `pub mod protocol;` declaration, the new sub-modules become available automatically. Add a single re-export for the marker convenience:

```rust
// Already there:
#[cfg(all(feature = "flow", feature = "tokio"))]
pub mod protocol;

// New top-level convenience re-exports (Phase A):
#[cfg(all(feature = "flow", feature = "tokio"))]
pub use protocol::{
    Dispatch, FlowKey, ParserKind, Protocol, ProtocolInitError, SignatureMatch,
};
```

No `pub use protocol::builtin::*;` at crate root — the markers stay namespaced under `netring::protocol::Http` etc.

## 6. Tests

### Unit tests (in each module)

`src/protocol/mod.rs`:

```rust
#[cfg(test)]
mod plugin_tests {
    use super::*;

    #[test]
    fn builtin_http_dispatch_is_tcp_80_8080() {
        let d = <crate::protocol::builtin::Http as Protocol>::dispatch();
        match d {
            Dispatch::Tcp(ref ports) => assert_eq!(ports, &vec![80, 8080]),
            _ => panic!("expected Dispatch::Tcp(...)"),
        }
        assert_eq!(<crate::protocol::builtin::Http as Protocol>::NAME, "http/1");
    }

    #[test]
    fn builtin_tcp_lifecycle_marker_has_no_parser() {
        let r = <crate::protocol::builtin::Tcp as Protocol>::parser();
        assert!(r.is_err(), "Tcp must return Err — it's lifecycle-only");
    }

    #[test]
    fn builtin_dns_uses_udp_53() {
        let d = <crate::protocol::builtin::Dns as Protocol>::dispatch();
        assert!(matches!(d, Dispatch::Udp(ref p) if p == &vec![53]));
    }

    #[test]
    fn builtin_icmp_uses_broadcast() {
        let d = <crate::protocol::builtin::Icmp as Protocol>::dispatch();
        assert!(matches!(d, Dispatch::Icmp));
    }

    #[test]
    fn signature_match_from_flowscope() {
        let m: SignatureMatch =
            flowscope::detect::signatures::SignatureMatch::Match.into();
        assert_eq!(m, SignatureMatch::Match);
    }
}
```

### Integration test

`tests/protocol_plugin.rs`:

```rust
//! Verify that a downstream-crate-equivalent custom `Protocol`
//! implementation compiles and reports correctly. This is the
//! agnosticism contract: third parties plug in new protocols
//! without editing netring.

use netring::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

struct MyCustomProtocol;

impl Protocol for MyCustomProtocol {
    type Message = ();
    const NAME: &'static str = "my-custom";
    fn dispatch() -> Dispatch { Dispatch::Tcp(vec![9999]) }
    fn parser() -> Result<ParserKind<()>, ProtocolInitError> {
        Err(ProtocolInitError("not real".into()))
    }
}

#[test]
fn custom_protocol_compiles_and_dispatches() {
    assert_eq!(<MyCustomProtocol as Protocol>::NAME, "my-custom");
    let d = <MyCustomProtocol as Protocol>::dispatch();
    assert!(matches!(d, Dispatch::Tcp(ref p) if p == &vec![9999]));
}
```

### Event-typed tests

`src/protocol/event_typed.rs` (inline):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::builtin::{Tcp, Udp};

    #[test]
    fn flow_started_typed_by_protocol() {
        // Distinct types — no implicit conversion.
        fn _assert_distinct() {
            fn _tcp(_: &FlowStarted<Tcp>) {}
            fn _udp(_: &FlowStarted<Udp>) {}
        }
    }

    #[test]
    fn flow_started_send_sync_with_send_sync_p() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<FlowStarted<Tcp>>();
        assert_sync::<FlowStarted<Tcp>>();
        assert_send::<FlowEnded<Tcp>>();
        assert_sync::<FlowEnded<Tcp>>();
    }
}
```

## 7. Acceptance criteria

- [ ] `cargo build -p netring --features tokio,channel,flow,parse,pcap,metrics,http,dns,tls,icmp,emit` succeeds.
- [ ] `cargo nextest run` — all existing 299 tests + new tests pass.
- [ ] `cargo +stable clippy --all-targets -- -D warnings` clean.
- [ ] `cargo fmt --check` clean.
- [ ] `cargo test --doc` passes.
- [ ] `tests/protocol_plugin.rs` compiles + runs.
- [ ] `use netring::protocol::Http;` works from a downstream crate (verified by the integration test above).
- [ ] Existing user code that imports `ProtocolMonitor` / `ProtocolEvent` / `ProtocolMessage` still compiles and runs unchanged.

## 8. Risks + mitigations

1. **`FlowKey` type alias might conflict with downstream user-defined extractors.**
   Mitigation: the existing `flowscope::FlowExtractor::Key` associated type is more general; `FlowKey` is a convenience alias for the canonical `FiveTupleKey`. Document that users with custom extractors should refer to `<MyExtractor as FlowExtractor>::Key` directly.

2. **`PhantomData<fn() -> P>` vs `PhantomData<P>` subtle.**
   The `fn()->P` form makes the phantom covariant in `P` and `Send + Sync` regardless of `P`'s bounds; the `PhantomData<P>` form would force `P: Send + Sync` on the phantom (we get those from the `Protocol` bound, but writing `PhantomData<P>` is brittle when `P: Sync` is omitted in the future). The test `flow_started_send_sync_with_send_sync_p` catches this.

3. **`parser_kinds::TLS_HANDSHAKE` import.**
   This is a flowscope 0.11+ export. The 0.19.0 absorption release already verified this works; Phase A just consumes it. If the constant moves, follow flowscope's CHANGELOG.

4. **Re-export conflicts at crate root.**
   `pub use protocol::Protocol` at `lib.rs` is generic enough to potentially shadow a future user import. We don't think this is real, but if a clippy complaint arises, namespace under `pub mod plugin { pub use crate::protocol::{Protocol, ...}; }` instead.

5. **`Tcp` / `Udp` markers' `Protocol::parser()` returning `Err` feels weird.**
   The Phase B `Monitor::builder().protocol::<Tcp>()` registration short-circuits on `Err` and treats the marker as "lifecycle-only" — no parser slot. The pattern works, but is documented prominently in the trait's doc comment and the builder's `protocol::<P>()` method.

## 9. Estimated effort + commit shape

**Total: 2–3 working days.** ~400 LoC new code + ~150 LoC tests.

**Commits (3):**

- `netring 0.20 (A.1): Protocol trait + Dispatch + ParserKind + SignatureMatch` — `src/protocol/mod.rs` additions, no builtin markers yet, but no behavior change. Tests for the surface compile but assert nothing yet.
- `netring 0.20 (A.2): 7 builtin protocol markers (Tcp/Udp/Icmp/Http/Dns/Tls/TlsHandshake)` — `src/protocol/builtin/*.rs`, full unit-test sweep, integration test for the agnosticism contract.
- `netring 0.20 (A.3): Event trait + typed FlowStarted<P>/FlowEnded<P>/etc. + crate-root re-exports` — `src/protocol/event_typed.rs`, send/sync proofs, doctests.

After A.3 the master branch should compile, test, lint clean. Open a draft PR for review.

## 10. Cross-phase notes

- Phase B's `Monitor::builder().protocol::<P>()` will route on `Dispatch::*` and call `P::parser()`. The handler-registration path in Phase B will use the `Event` trait defined here.
- Phase G's migration recipes will explain to users: `ProtocolMessage::Http(_)` pattern → `.on::<Http>(|msg, ...| ...)` — the `Http` marker name is the same.
- The existing `ProtocolEvent` / `ProtocolMessage` enums (defined in `protocol/event.rs`) stay verbatim through this phase; Phase G deletes them.
- This phase introduces no new dependencies. `bon`, `tower`, `arrayvec`, `compact_str`, `dhat`, `rustc-hash` are deferred to their respective phases.

Ready to execute.
