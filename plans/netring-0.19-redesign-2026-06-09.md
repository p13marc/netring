# netring 0.19 — detailed redesign

**Date:** 2026-06-09
**Status:** implementation spec — ready for execution
**Revision:** 2 (flowscope 0.11.1 landed; design tightened to use its typed `Driver<E>` + `SlotHandle<M, K>` directly)
**Supersedes:** none (additive to [`api-review-2026-06-09.md`](./api-review-2026-06-09.md))
**Dependencies resolved:** the six items in [`flowscope-deps-for-netring-0.19-2026-06-09.md`](./flowscope-deps-for-netring-0.19-2026-06-09.md) all shipped in flowscope 0.11.0/0.11.1.

This is the implementation-ready spec for netring 0.19. A developer should be able to start writing code from here without further design discussions. Where decisions could go either way, this document picks one and justifies it. Where genuinely open questions remain (e.g. exact `bon` v3 attribute spelling), they're called out as "verify before implementation" in §20.

The architectural principles — protocol-agnostic, Rust-idiomatic, zero-allocation hot path — come from the API review. This document doesn't re-litigate them; it specifies the types, files, and tests that implement them.

## 0. What flowscope 0.11.1 gave us

The dependency audit asked for six flowscope changes (plan 119 + plan 120 + plan 121 in flowscope's roadmap). All landed:

| # | Item | Landed in |
|---|---|---|
| 1 | `Driver::track_into(view, &mut Vec<Event>)` — zero-alloc | plan 119 |
| 2 | Parser scratch-buffer API — `feed_initiator(&mut self, bytes, ts, &mut Vec<M>)` | plan 119 |
| 3 | HTTP `method`/`path`/`reason`/headers fully `Bytes`-based | plan 120 |
| 4 | **Typed `Driver<E>` with `SlotHandle<M, K>` per parser** — the architectural one | plan 121 |
| 5 | `parser_kinds::TLS_HANDSHAKE` constant | plan 118 phase 4 |
| 6 | Multi-typed-slot dispatch — *implemented as typed handles, not TypeId-keyed callbacks* | plan 121 |
| bonus | `Driver::force_close(key, now)` for explicit flow termination | 0.11.1 |
| bonus | `Driver::sweep_into` / `finish_into` zero-alloc variants | plan 119 |

**The big shift from the previous design:** flowscope's `Driver<E>` (no `M` parameter) emits lifecycle `Event<K>` only — `FlowStarted`, `FlowEnded`, etc. **Per-parser typed messages flow through `SlotHandle<M, K>`** returned from each builder method. There is no `Box<dyn Any>` per message; netring's previously-planned `Erased` wrapper is gone. Each protocol gets a typed handle; the dispatcher drains them by going through netring's own type-erased handler table, not flowscope's.

This is **cleaner and faster** than the original plan. The redesign below has been tightened accordingly — Phase C (perf hardening) shrinks; the Dispatcher in §8 simplifies; the §20 open questions about flowscope close.

---

## 1. Scope

**In scope:**
- `netring::protocol` module: rebuilt around the `Protocol` trait + `TypeId` registry.
- `netring::anomaly` module: rebuilt around `Handler<E, M>` + `Sink`+`AnomalyWriter`.
- New `netring::ctx` module: `Ctx`, `FromCtx`, extractor types.
- New `netring::monitor` module: top-level `Monitor` builder.
- New `netring::layer` module: `Layer` + shipped middleware.
- `netring::correlate`: unchanged in shape; `TimeBucketedCounter` / `KeyIndexed` keep their APIs.
- `netring::prelude`: new module re-exporting the canonical surface.
- `benches/zero_alloc.rs`: new `dhat`-gated allocation regression test.
- `examples/`: all 13 anomaly examples rewritten; `examples/k8s_node_monitor.rs` added as the canonical multi-L4 example.
- `docs/MONITORING.md`: replaces `WRITING_DETECTORS.md`.
- `docs/performance.md`: new — documents the §7 contract from the API review.

**Out of scope:**
- AF_PACKET / AF_XDP capture surface (`Capture`, `AsyncCapture`, `BpfFilterBuilder`, `XdpSocket`): unchanged.
- PCAP read/write (`AsyncPcapSource`, `PcapTap`): unchanged.
- flowscope upstream changes: this spec assumes flowscope 0.11 ships `Bytes`-based payloads and a multi-message `Driver`. If those land later, the netring side falls back to per-event boxing — documented in §20.
- Plugin protocol discovery (`inventory` / `linkme` based): deferred to 0.20+.
- Columnar batch processing: deferred to 1.0.

**Migration story:**
- One breaking release (0.19.0).
- `netring-compat` companion crate ships `AnomalyRule` → `Handler` shim for one release.
- Detailed migration recipes in §16.

---

## 2. Module layout

The proposed `src/` tree, with **A**dded, **M**odified, **D**eleted markers:

```
src/
├── lib.rs                       M  — new module exports, prelude
├── prelude.rs                   A  — canonical re-exports (12–15 items)
├── error.rs                     M  — new error variants for build-time conflicts
│
├── protocol/                    M  — was protocol module, fully rebuilt
│   ├── mod.rs                   M  — Protocol trait, Dispatch enum, ProtocolParser trait
│   ├── builtin/                 A  — built-in protocol marker types
│   │   ├── mod.rs               A
│   │   ├── tcp.rs               A  — `struct Tcp` (L4 lifecycle)
│   │   ├── udp.rs               A  — `struct Udp` (L4 lifecycle)
│   │   ├── icmp.rs              A  — `struct Icmp` (message parser)
│   │   ├── http.rs              A  — `struct Http`
│   │   ├── dns.rs               A  — `struct Dns`
│   │   ├── tls.rs               A  — `struct Tls`
│   │   └── tls_handshake.rs     A  — `struct TlsHandshake`
│   ├── event.rs                 M  — Event trait, FlowStarted<P>, FlowEnded<P>, Tick, AnyFlowAnomaly
│   └── stream.rs                M  — renamed from monitor.rs; the low-level Stream API
│
├── anomaly/                     M  — was anomaly module, fully rebuilt
│   ├── mod.rs                   M  — re-exports
│   ├── sink.rs                  A  — AnomalySink trait + AnomalyWriter
│   ├── shipped_sinks.rs         A  — StdoutSink, StdoutJsonSink, TracingSink, ChannelSink
│   ├── severity.rs              M  — Severity enum (unchanged shape)
│   └── compat.rs                A  — AnomalyRule → Handler adapter for 0.18 → 0.19 migration
│
├── ctx/                         A  — context + extractor types
│   ├── mod.rs                   A  — Ctx<'a> struct
│   ├── from_ctx.rs              A  — FromCtx trait, GAT-based
│   ├── extractors.rs            A  — State<T>, Sink<A>, Counter<K>, Now
│   └── split.rs                 A  — disjoint-field projection helpers (unsafe inside)
│
├── monitor/                     A  — top-level Monitor builder
│   ├── mod.rs                   A  — Monitor + MonitorBuilder
│   ├── handler.rs               A  — Handler trait + blanket impls (macro-generated)
│   ├── dispatcher.rs            A  — type-erased dispatch table, no-alloc dispatch loop
│   ├── registry.rs              A  — HandlerRegistry, ProtocolRegistry, build-time slot indexing
│   ├── run.rs                   A  — run_until / run_for / run_until_signal terminators
│   └── shard.rs                 A  — per-CPU sharding (fanout_per_cpu, merge_state)
│
├── layer/                       A  — tower-style middleware
│   ├── mod.rs                   A  — Layer trait (re-export from tower, or hand-rolled)
│   ├── dedupe.rs                A  — DedupeAnomalies
│   ├── rate_limit.rs            A  — RateLimitAnomalies
│   ├── min_severity.rs          A  — MinSeverity
│   ├── sample.rs                A  — Sample
│   └── tee.rs                   A  — Tee<S2>
│
├── correlate/                   M  — minor: re-export of flowscope primitives
│   └── mod.rs                   M  — unchanged surface; just re-export polish
│
└── detector_macro.rs            A  — `detector!` macro_rules
```

Plus:

```
benches/
├── anomaly.rs                   M  — updated to new Handler shape
└── zero_alloc.rs                A  — dhat-gated allocation regression test

examples/
├── k8s_node_monitor.rs          A  — the canonical multi-L4 example from §8 of the review
└── anomaly/*                    M  — all 13 existing examples rewritten

tests/
├── anomaly_handler.rs           A  — Handler trait + blanket impls
├── ctx_borrow_disjoint.rs       A  — verify FromCtx borrow safety
├── dispatcher_no_alloc.rs       A  — non-bench allocation check on a small workload
├── protocol_registration.rs     A  — Protocol trait impls + dispatch
├── layer_composition.rs         A  — middleware ordering semantics
└── api_stability.rs             A  — snapshot of public API surface

docs/
├── MONITORING.md                A  — replaces WRITING_DETECTORS.md
├── performance.md               A  — §7 contract documented for users
└── migration-0.18-to-0.19.md    A  — mechanical migration recipes
```

**LoC estimates per new file:** see §19 phase checklists. Aggregate: ~3500 LoC new + ~600 modified + ~400 deleted; tests + benches add ~1800 LoC; docs ~600 lines.

---

## 3. Cargo.toml deltas

### Dependencies added

```toml
[dependencies]
# Bump flowscope to the 0.11 line — typed Driver<E> + SlotHandle.
flowscope = { version = "0.11", default-features = false }

# Type-erased handler dispatch + small inline storage:
fxhash = "0.2"          # FxHashMap for small key counts; faster than std HashMap
arrayvec = "0.7"        # ArrayVec for inline ≤8 observations/metrics
smallstr = "0.3"        # SmallString<[u8; 32]> for dedup keys

# Builder + middleware:
bon = "3"               # typestate-builder proc-macro
tower = { version = "0.5", features = ["util"] }  # Layer + ServiceBuilder

# Already direct deps; required for HTTP `method`/`path`/header payloads:
bytes = "1.7"

# Test-only:
[dev-dependencies]
dhat = "0.3"            # heap profiler for zero-alloc benches
serde_json = "1"        # for AnomalySink shipped impls
trybuild = "1"          # compile-fail tests for handler borrow conflicts
```

`tracing` already in deps; no version bump needed.
`futures` / `futures-core` already in deps for `Stream`.

### Features

```toml
[features]
default = []

# Foundation (unchanged):
tokio = ["dep:tokio", "dep:tokio-stream", "dep:futures-core"]
channel = ["dep:crossbeam-channel"]
parse = ["dep:etherparse", "flowscope/extractors"]
pcap = ["dep:pcap-file"]
metrics = ["dep:metrics"]
af-xdp = []
xdp-loader = ["af-xdp", "dep:aya"]
nightly = []

# Flow tracking (unchanged):
flow = ["parse", "flowscope/tracker", "flowscope/reassembler", "flowscope/session", "dep:bytes", "dep:ahash"]

# Protocol parsers (unchanged):
http = ["flow", "flowscope/http"]
dns = ["flow", "flowscope/dns"]
tls = ["flow", "flowscope/tls"]
icmp = ["flow", "flowscope/icmp"]
all-parsers = ["http", "dns", "tls", "icmp"]

# Output sinks (was `emit`, expanded):
emit = ["flow", "flowscope/emit"]

# Anomaly serialization (unchanged):
serde = ["dep:serde", "dep:serde_json", "flowscope/serde"]

# NEW: monitor umbrella for app users.
# This is the feature 90% of users want — pulls everything needed for a
# normal multi-protocol monitor without making the user think about it.
monitor = [
    "tokio", "channel", "flow", "parse", "metrics",
    "http", "dns", "tls", "icmp",
    "emit", "serde",
]

# NEW: dhat-gated allocation regression benchmark. Always-off by default;
# enable via `cargo bench --features bench-zero-alloc`.
bench-zero-alloc = ["dep:dhat"]
```

### `[[example]]` registrations

Add:
```toml
[[example]]
name = "k8s_node_monitor"
path = "examples/k8s_node_monitor.rs"
required-features = ["monitor"]
```

Remove (all 0.18 examples that get rewritten under the new API stay registered with their existing names; required-features collapse to just `["monitor"]` everywhere).

---

## 4. The `Protocol` trait + marker types

Full spec for `src/protocol/mod.rs`:

```rust
//! The Protocol trait — netring's protocol-agnostic core.
//!
//! User crates implement `Protocol` for marker types. Built-in
//! markers live in `protocol::builtin`. Adding a new protocol is
//! one trait impl in a downstream crate; no edits to netring.

use std::any::TypeId;

/// A protocol that the monitor can observe.
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
    /// `'static` because dispatch is keyed by `TypeId::of::<Self::Message>()`.
    type Message: Send + Sync + 'static;

    /// Stable identifier, used for metrics labels, log targets,
    /// and the `parser_kind` field on the low-level Stream API.
    /// Convention: lowercase, hyphenated. Examples: `"http/1"`,
    /// `"dns-udp"`, `"tls-handshake"`. Matches flowscope's own
    /// `parser_kinds::*` constants where applicable.
    const NAME: &'static str;

    /// How packets get routed to this protocol's parser.
    fn dispatch() -> Dispatch;

    /// Construct the parser instance — a flowscope session or
    /// datagram parser ready to register against the typed
    /// `Driver<E>`. Called once at `.build()`. Lifecycle-only
    /// markers (Tcp, Udp) return `Err` and the builder treats
    /// the `Dispatch::AllTcp` / `Dispatch::AllUdp` markers as
    /// "no slot to register; just record this for typed lifecycle
    /// event filtering."
    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError>;
}

/// flowscope 0.11 has two parser-trait flavors. A `Protocol` impl
/// declares which one it produces; netring's builder routes to
/// the matching `Driver<E>` registration method.
pub enum ParserKind<M> {
    /// TCP-shaped parser (HTTP, DNS-over-TCP, TLS).
    Session(Box<dyn flowscope::SessionParser<Message = M>>),
    /// UDP-shaped parser (DNS-over-UDP, ICMP).
    Datagram(Box<dyn flowscope::DatagramParser<Message = M>>),
}

/// How a protocol selects packets for its parser.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Dispatch {
    /// Match TCP flows on these ports.
    Tcp(Vec<u16>),
    /// Match UDP flows on these ports.
    Udp(Vec<u16>),
    /// Match all ICMP/ICMPv6 datagrams.
    Icmp,
    /// All TCP flows regardless of port — the L4-lifecycle case.
    AllTcp,
    /// All UDP flows regardless of port.
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
pub enum SignatureMatch { Match, NoMatch, MoreData }

// NOTE: netring does NOT define its own ProtocolParser trait.
// flowscope 0.11's `SessionParser` / `DatagramParser` already
// use the scratch-buffer signature we need (see flowscope plan
// 119). The Protocol::parser() method returns a constructed
// flowscope parser directly via `ParserKind<M>` (defined below).

/// Error type for `Protocol::parser`. Most parsers are infallible
/// to construct; flowscope parsers that take config can fail.
#[derive(Debug, thiserror::Error)]
#[error("protocol parser init failed: {0}")]
pub struct ProtocolInitError(pub String);

/// Re-export from flowscope for convenience.
pub type FlowKey = flowscope::extract::FiveTupleKey;
```

**The `ProtocolParser` trait deserves a note:** the spec above defines a netring-side `ProtocolParser` for the abstract "Protocol::parser()" return type, but the netring 0.19 implementation does **not** need a custom parser trait at all. flowscope 0.11's `SessionParser` / `DatagramParser` traits already use the scratch-buffer signature (`feed_initiator(&mut self, bytes, ts, &mut Vec<Self::Message>)`), already implement the per-protocol parsers we want (`HttpParser`, `DnsUdpParser`, `TlsParser`, `TlsHandshakeParser`, `IcmpParser`), and already plug into the typed `Driver<E>` via `session_on_ports`, `datagram_on_ports`, etc. — returning a `SlotHandle<M, K>` per registration.

So `Protocol::parser()` should return a constructed parser ready to feed into a flowscope builder method, not wrap into a netring-side trait:

```rust
/// What a Protocol's parser produces. flowscope 0.11 has two
/// trait flavors (SessionParser for TCP-shaped, DatagramParser
/// for UDP-shaped). The Protocol trait carries which one.
pub enum ParserKind<M> {
    Session(Box<dyn flowscope::SessionParser<Message = M>>),
    Datagram(Box<dyn flowscope::DatagramParser<Message = M>>),
}

pub trait Protocol: Send + Sync + 'static {
    type Message: Send + Sync + 'static;
    const NAME: &'static str;
    fn dispatch() -> Dispatch;
    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError>;
}
```

The `Monitor::builder().protocol::<P>()` builder reads the `Dispatch` discriminant + `ParserKind` and calls the appropriate flowscope builder method:

```rust
match (P::dispatch(), P::parser()?) {
    (Dispatch::Tcp(ports),  ParserKind::Session(p)) => {
        let handle = driver_builder.session_on_ports(p, ports);
        self.register_slot::<P>(handle);
    }
    (Dispatch::Udp(ports),  ParserKind::Datagram(p)) => {
        let handle = driver_builder.datagram_on_ports(p, ports);
        self.register_slot::<P>(handle);
    }
    (Dispatch::Icmp,        ParserKind::Datagram(p)) => {
        let handle = driver_builder.datagram_broadcast(p);
        self.register_slot::<P>(handle);
    }
    (Dispatch::Signature(sig), ParserKind::Session(p)) => {
        let handle = driver_builder.session_heuristic(p, sig);
        self.register_slot::<P>(handle);
    }
    (Dispatch::AllTcp,      ParserKind::Session(_)) => unreachable!("Tcp marker uses NoopParser; AllTcp means lifecycle-only"),
    // … (compile-time-checkable mismatches surface in tests)
}
```

The built-in markers in `src/protocol/builtin/*.rs` follow this template. Each is ≤20 LoC:

```rust
// src/protocol/builtin/http.rs

use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

/// HTTP/1.x — RFC 7230 request/response over TCP.
/// Default ports: 80, 8080. Override with a custom Protocol impl.
pub struct Http;

impl Protocol for Http {
    type Message = flowscope::http::HttpMessage;
    const NAME: &'static str = "http/1";

    fn dispatch() -> Dispatch { Dispatch::Tcp(vec![80, 8080]) }

    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError> {
        Ok(ParserKind::Session(Box::new(flowscope::http::HttpParser::default())))
    }
}
```

No adapter shim needed — we use flowscope's parser directly. Same pattern for `Dns`, `Tls`, `TlsHandshake`, `Icmp`.

The L4 markers `Tcp` and `Udp` are lifecycle-only — they don't register a parser slot. Their `Protocol` impl uses a marker `Dispatch::AllTcp` / `Dispatch::AllUdp` variant that the builder handles specially: register no parser slot, just record the marker so `FlowStarted<Tcp>` / `FlowEnded<Tcp>` typed events fire:

```rust
// src/protocol/builtin/tcp.rs

use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

/// TCP lifecycle marker. Registering this protocol enables
/// `FlowStarted<Tcp>`, `FlowEstablished<Tcp>`, `FlowEnded<Tcp>`
/// typed events — no parser slot registered on flowscope's side.
pub struct Tcp;

impl Protocol for Tcp {
    type Message = ();  // lifecycle-only marker
    const NAME: &'static str = "tcp";
    fn dispatch() -> Dispatch { Dispatch::AllTcp }
    fn parser() -> Result<ParserKind<()>, ProtocolInitError> {
        // The builder treats AllTcp/AllUdp specially — no slot
        // is registered. Returning an Err is the right shape.
        Err(ProtocolInitError("Tcp marker is lifecycle-only — no parser".into()))
    }
}

```

The L4 protocols look "trivial" because they are — their purpose is to make `.protocol::<Tcp>()` opt-in (so `FlowStarted<Tcp>` events fire only when registered). This keeps the API uniform.

---

## 5. The `Event` trait + event types

`src/protocol/event.rs`:

```rust
//! Event types — what handlers can register against.
//!
//! `Event` is a marker trait: any type implementing it can appear
//! after `.on::<E>(handler)`. The framework's dispatch table maps
//! `TypeId::of::<E>()` → `Vec<Handler>`.

use std::any::TypeId;
use crate::protocol::{Protocol, FlowKey};
use flowscope::{EndReason, FlowStats, FlowSide, Timestamp, L4Proto, AnomalyKind};

/// Marker for types handlers can subscribe to.
///
/// `Payload` is the type the handler closure receives by reference.
/// For raw protocol messages, `Payload = P::Message`. For flow
/// lifecycle events, `Payload` is the typed event struct.
pub trait Event: Send + Sync + 'static {
    type Payload: Send + Sync + 'static;
}

// ── Raw protocol message events ─────────────────────────────────
//
// `monitor.on::<Http>(|msg: &HttpMessage, ctx| ...)`
// dispatches whenever Http's parser emits an HttpMessage.

impl<P: Protocol> Event for P {
    type Payload = P::Message;
}

// ── Flow lifecycle events, typed by L4 protocol marker ──────────
//
// `monitor.on::<FlowStarted<Tcp>>(|evt, ctx| ...)`
// dispatches on every new TCP flow.

/// Emitted when a new flow begins. Generic over the L4 protocol
/// marker so handlers can scope to a single L4 trivially.
pub struct FlowStarted<P: Protocol> {
    pub key: FlowKey,
    pub l4: Option<L4Proto>,
    pub ts: Timestamp,
    _marker: std::marker::PhantomData<P>,
}

impl<P: Protocol + 'static> Event for FlowStarted<P> {
    type Payload = FlowStarted<P>;
}

/// Emitted when a flow ends (FIN, RST, idle timeout).
pub struct FlowEnded<P: Protocol> {
    pub key: FlowKey,
    pub reason: EndReason,
    pub stats: FlowStats,
    pub l4: Option<L4Proto>,
    pub ts: Timestamp,
    _marker: std::marker::PhantomData<P>,
}

impl<P: Protocol + 'static> Event for FlowEnded<P> {
    type Payload = FlowEnded<P>;
}

/// Emitted at TCP three-way-handshake completion. UDP/ICMP never
/// fire this event.
pub struct FlowEstablished<P: Protocol> {
    pub key: FlowKey,
    pub ts: Timestamp,
    _marker: std::marker::PhantomData<P>,
}

impl<P: Protocol + 'static> Event for FlowEstablished<P> {
    type Payload = FlowEstablished<P>;
}

// ── Cross-protocol events ───────────────────────────────────────

/// Any flowscope-side anomaly (TCP out-of-order, reassembler
/// watermark, parser poison, etc.) lifted into the handler
/// pipeline. Use for catch-all "all flow tracker anomalies"
/// handlers.
pub struct AnyFlowAnomaly {
    pub key: Option<FlowKey>,
    pub kind: AnomalyKind,
    pub ts: Timestamp,
}

impl Event for AnyFlowAnomaly {
    type Payload = AnyFlowAnomaly;
}

/// Periodic tick event. Fires at registered intervals; handlers
/// can scope to a tick by registering with `.tick(period, handler)`.
pub struct Tick {
    pub now: Timestamp,
    pub period: std::time::Duration,
}

impl Event for Tick {
    type Payload = Tick;
}
```

Why typed `FlowStarted<P>` rather than a plain `FlowStarted` carrying an `L4Proto` field? Two reasons:

1. **Type-driven dispatch**: `monitor.on::<FlowStarted<Tcp>>` lets the framework dispatch only when L4 is TCP. No runtime filter inside the handler.
2. **Plays with the agnostic `Protocol` trait**: third-party protocols can have their own `FlowStarted<Quic>` if they want (Quic isn't strictly L4 but its session lifecycle is logically equivalent).

The L4Proto field is still present for handlers that want it; this is convenience, not constraint.

---

## 6. The `Handler` trait + blanket impls

`src/monitor/handler.rs`. This is the most macro-heavy file in the redesign. ~400 LoC of mostly macro expansion.

### 6.1 The trait

```rust
//! The Handler trait. Functions implement it via blanket impls
//! over their signature shape. Users never name `Handler` —
//! they register closures via `Monitor::on::<E>(closure)`.

use std::marker::PhantomData;
use crate::ctx::Ctx;
use crate::error::Result;
use super::protocol::event::Event;

/// A handler is "something that can be called with `&E::Payload`
/// + extractors, producing a `Result<()>`".
///
/// The `M` type parameter is the **axum coherence marker** — it
/// lets one closure type `F` implement `Handler<E, (P1,)>` and
/// `Handler<E, (P1, P2)>` without overlap errors. Users never
/// name `M`.
pub trait Handler<E: Event, M>: Send + Sync + 'static {
    /// The framework calls this at dispatch time. The
    /// implementation downcasts erased extractors back to typed
    /// references and invokes the inner closure.
    fn call(&self, payload: &E::Payload, ctx: &mut Ctx<'_>) -> Result<()>;
}
```

### 6.2 The blanket impl macro

For ergonomics, blanket impls over `Fn(&Payload, P1, P2, ..., PN)` shapes are macro-generated for N = 0..8. The macro:

```rust
// Internal — never user-facing.
macro_rules! impl_handler {
    // 0 extractors:
    () => {
        impl<E, F> Handler<E, ()> for F
        where
            E: Event,
            F: Fn(&E::Payload) -> Result<()> + Send + Sync + 'static,
        {
            fn call(&self, p: &E::Payload, _ctx: &mut Ctx<'_>) -> Result<()> {
                self(p)
            }
        }
    };

    // N extractors:
    ( $($P:ident),+ ) => {
        impl<E, F, $($P),+> Handler<E, ($($P,)+)> for F
        where
            E: Event,
            F: for<'a> Fn(&'a E::Payload, $(<$P as FromCtx>::Target<'a>),+) -> Result<()> + Send + Sync + 'static,
            $($P: FromCtx),+
        {
            fn call(&self, p: &E::Payload, ctx: &mut Ctx<'_>) -> Result<()> {
                // Sequential extraction — Rust's borrow checker
                // tracks each Target<'_>'s lifetime separately.
                // For disjoint-field access, use `ctx.split_*`
                // helpers (see §7.3); this default path serializes
                // extractor calls.
                $(
                    let $P = <$P as FromCtx>::from_ctx(ctx);
                )+
                self(p, $($P),+)
            }
        }
    };
}

impl_handler!();
impl_handler!(P1);
impl_handler!(P1, P2);
impl_handler!(P1, P2, P3);
impl_handler!(P1, P2, P3, P4);
impl_handler!(P1, P2, P3, P4, P5);
impl_handler!(P1, P2, P3, P4, P5, P6);
impl_handler!(P1, P2, P3, P4, P5, P6, P7);
impl_handler!(P1, P2, P3, P4, P5, P6, P7, P8);
```

**Critical correctness note.** The sequential extraction `$( let $P = <$P as FromCtx>::from_ctx(ctx); )+` only compiles when each `Target<'_>` does not borrow conflictingly. For `Target<'a> = &'a mut T` where `T` is a sub-field of `Ctx`, Rust will reject *simultaneous* `&mut` projections to the same field. The framework provides two patterns to satisfy the borrow checker:

- **Pattern A — disjoint fields, distinct types**: `State<HttpStats>` and `Counter<IpAddr>` access different `Ctx` fields, so the borrow checker accepts both `&mut`s.
- **Pattern B — single mutable extractor**: at most one `&mut` extractor in the signature; other params are `Copy` types like `Now: Copy` and `&Sink`.

If a user writes a handler that requires simultaneous `&mut` access to the same field, the compile error is the standard "cannot borrow `*ctx` as mutable more than once" — what they expect from Rust. The escape hatch (§7.3, `ctx.split_state_sink::<T>()`) is documented but explicit.

### 6.3 The async escape hatch

`AsyncHandler` is a separate trait with separate registration. It pays one `Box::pin` per call but unblocks `.await`.

```rust
pub trait AsyncHandler<E: Event, M>: Send + Sync + 'static {
    fn call<'a>(
        &'a self,
        payload: &'a E::Payload,
        ctx: &'a mut Ctx<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

// Blanket impls similar to Handler but over AsyncFn.
// Generated by impl_async_handler! macro.
```

Registration is the explicit `.on_async::<E>(handler)` method on `MonitorBuilder`. Documentation says: "every event dispatched to an async handler costs one heap allocation (the boxed future). Prefer sync handlers wherever possible."

### 6.4 Tests

`tests/anomaly_handler.rs`:

- 0-extractor closure registration + call.
- 1-extractor with `State<T>`, `Now`, `Counter<K>`.
- 2-extractor disjoint fields (`State<A>` + `Counter<B>`).
- Compile-fail tests (via `trybuild`) for conflicting `&mut` borrows.
- Sync vs async dispatch — verify boxing only happens on `on_async`.

---

## 7. `Ctx` + `FromCtx` extractors

`src/ctx/mod.rs`:

```rust
//! Per-event context passed to handlers.
//!
//! `Ctx` lives on the dispatch stack — never heap-allocated.
//! Handlers borrow from it via the FromCtx trait; the borrow
//! lifetime is exactly the dispatch call.

use crate::anomaly::sink::AnomalySink;
use crate::correlate::CounterRegistry;
use crate::ctx::from_ctx::StateMap;
use flowscope::{Timestamp, extract::FiveTupleKey};

pub struct Ctx<'a> {
    /// The flow key for the current event, if any. Some events
    /// (e.g. `TrackerAnomaly`) have no key.
    pub flow: Option<&'a FiveTupleKey>,

    /// Timestamp of the current event. `Copy` — extract via `Now`.
    pub ts: Timestamp,

    /// Source-interface index for multi-interface monitors.
    pub source: SourceIdx,

    /// Per-monitor user state, keyed by TypeId.
    /// Extracted as `State<T>`; returns `&mut T`.
    pub(crate) state_map: &'a mut StateMap,

    /// The anomaly sink. Extracted as `Sink<()>`; returns
    /// `&mut dyn AnomalySink`.
    pub(crate) sink: &'a mut dyn AnomalySink,

    /// Per-monitor counter storage.
    /// Extracted as `Counter<K>`; returns `&mut TimeBucketedCounter<K>`.
    pub(crate) counters: &'a mut CounterRegistry,
}

/// Tag for which capture source this event came from.
/// `SourceIdx(0)` for single-interface monitors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceIdx(pub u8);
```

### 7.1 The `FromCtx` trait

`src/ctx/from_ctx.rs`:

```rust
use crate::ctx::Ctx;

/// Extract a typed view from `&mut Ctx<'_>`.
///
/// `Target<'a>` is the lifetime-bound view returned. For `State<T>`
/// this is `&'a mut T`; for `Sink<()>` it's `&'a mut dyn AnomalySink`;
/// for `Now` it's `Timestamp` (by value).
pub trait FromCtx {
    type Target<'a>;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> Self::Target<'a>;
}

/// Internal type-keyed state map. One slot per `T` registered
/// via `.state::<T>()`. Lazy-initialized via `T::default()` on
/// first access.
pub struct StateMap {
    by_type: fxhash::FxHashMap<std::any::TypeId, Box<dyn std::any::Any + Send>>,
}

impl StateMap {
    pub fn get_or_init_mut<T: Default + Send + 'static>(&mut self) -> &mut T {
        let id = std::any::TypeId::of::<T>();
        self.by_type
            .entry(id)
            .or_insert_with(|| Box::<T>::default())
            .downcast_mut::<T>()
            .expect("StateMap type invariant violated")
    }
}
```

### 7.2 The standard extractors

`src/ctx/extractors.rs`:

```rust
use std::marker::PhantomData;
use crate::ctx::{Ctx, FromCtx};
use crate::anomaly::sink::AnomalySink;
use crate::correlate::TimeBucketedCounter;
use flowscope::Timestamp;

/// Per-monitor shared user state. `T: Default` for lazy init.
pub struct State<T>(PhantomData<T>);

impl<T: Default + Send + 'static> FromCtx for State<T> {
    type Target<'a> = &'a mut T;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> &'a mut T {
        ctx.state_map.get_or_init_mut::<T>()
    }
}

/// The anomaly sink — writes go directly here, no `Anomaly` struct.
/// The `A` phantom is unused today; it's reserved for type-tagged
/// sinks (e.g. `Sink<MetricsSink>`) in a future revision.
pub struct Sink<A = ()>(PhantomData<A>);

impl<A: 'static> FromCtx for Sink<A> {
    type Target<'a> = &'a mut dyn AnomalySink;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> &'a mut dyn AnomalySink {
        ctx.sink
    }
}

/// Current event timestamp (Copy).
pub struct Now;

impl FromCtx for Now {
    type Target<'a> = Timestamp;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> Timestamp { ctx.ts }
}

/// Per-key sliding-window counter, pre-allocated by the framework.
pub struct Counter<K>(PhantomData<K>);

impl<K: Eq + std::hash::Hash + Send + 'static> FromCtx for Counter<K> {
    type Target<'a> = &'a mut TimeBucketedCounter<K>;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> &'a mut TimeBucketedCounter<K> {
        ctx.counters.get_mut::<K>()
    }
}
```

The `Counter<K>` extractor pulls from `CounterRegistry`, a typed map similar to `StateMap` but specialized for `TimeBucketedCounter<K>` instances. The counter is pre-allocated at registration time (window + bucket-width set via `.counter_config::<K>(window, bucket_width)` on the builder, with sensible defaults).

### 7.3 Disjoint-field projection (the explicit escape hatch)

For handlers that genuinely need simultaneous `&mut` access to multiple `Ctx` fields, `ctx` exposes split methods on `Ctx`:

```rust
impl<'a> Ctx<'a> {
    /// Borrow `(state, sink)` as disjoint mutable references.
    /// Use when a single handler must read state and emit to the
    /// sink in one expression, beyond what sequential FromCtx
    /// extractor calls support.
    pub fn split_state_sink<T: Default + Send + 'static>(
        &mut self,
    ) -> (&mut T, &mut dyn AnomalySink) {
        let state = self.state_map.get_or_init_mut::<T>();
        // SAFETY: state_map and sink are distinct fields of Ctx.
        // We never alias.
        let sink: &mut dyn AnomalySink = unsafe { &mut *(self.sink as *mut _) };
        (state, sink)
    }

    /// Same idea for state + counter.
    pub fn split_state_counter<T: Default + Send + 'static, K: Eq + Hash + Send + 'static>(
        &mut self,
    ) -> (&mut T, &mut TimeBucketedCounter<K>) { /* … */ }

    /// All three.
    pub fn split_state_sink_counter<T, K>(
        &mut self,
    ) -> (&mut T, &mut dyn AnomalySink, &mut TimeBucketedCounter<K>)
    where T: Default + Send + 'static, K: Eq + Hash + Send + 'static
    { /* … */ }
}
```

Each `split_*` method is ~10 LoC. The unsafe block is auditable line-by-line; each method has a comment justifying field disjointness. ~5 split methods cover the practical combinations; users beyond that write their own `split_*` extension or refactor.

**Why not magical axum-style multi-extractor?** Because axum's body extractor consumes the request — there's never two `&mut` extractors live simultaneously. netring's `State<T>` and `Sink` and `Counter<K>` are all `&mut` to different fields, and pretending the borrow checker doesn't notice would require either: (a) global unsafe, (b) `RefCell` interior mutability with runtime panics, (c) complex trait-level disjointness proofs. The explicit `split_*` is honest Rust.

### 7.4 Tests

`tests/ctx_borrow_disjoint.rs`:

- Sequential extractor access compiles + runs.
- Two `&mut` extractors of the same `Ctx` field fails to compile (`trybuild` test).
- `split_state_sink::<T>()` produces two independent `&mut` borrows.
- `StateMap` lazy-initializes via `Default` on first access.
- `CounterRegistry` pre-sized at build time, never reallocates.

---

## 8. Dispatcher — typed handles, zero-allocation

`src/monitor/dispatcher.rs`. The performance-critical core. Built on flowscope 0.11's typed `Driver<E>` + `SlotHandle<M, K>` shape — no `Box<dyn Any>` per parsed message.

The architecture in one diagram:

```text
                          netring::Monitor
                          ┌──────────────────────────────────────────┐
                          │                                          │
   ┌────────────────┐     │  ┌──────────────────────────────────┐    │
   │ AsyncCapture   ├─────┼─►│ flowscope::driver::Driver<E>     │    │
   └────────────────┘     │  │   (central FlowTracker)          │    │
                          │  └─────────┬────────────────────────┘    │
                          │            │ track_into(&mut events)     │
                          │            ▼                              │
                          │  ┌──────────────────────────────────┐    │
                          │  │ Vec<Event<K>>  (lifecycle only)  │    │
                          │  │   FlowStarted / FlowEnded / etc. │    │
                          │  └─────────┬────────────────────────┘    │
                          │            │                              │
                          │            ▼  per-protocol drain          │
                          │  ┌──────────────────────────────────┐    │
                          │  │ SlotHandle<HttpMessage, K>       │    │
                          │  │ SlotHandle<DnsMessage,  K>       │    │
                          │  │ SlotHandle<IcmpMessage, K>       │    │
                          │  └─────────┬────────────────────────┘    │
                          │            │                              │
                          │            ▼  TypeId-keyed dispatch       │
                          │  ┌──────────────────────────────────┐    │
                          │  │ HandlerRegistry                  │    │
                          │  │   TypeId::of::<HttpRequest>()    │    │
                          │  │     → Vec<HandlerSlot>           │    │
                          │  │   TypeId::of::<FlowStarted<Tcp>>()    │
                          │  │     → Vec<HandlerSlot>           │    │
                          │  └──────────────────────────────────┘    │
                          └──────────────────────────────────────────┘
```

There is **no per-message allocation**. Typed messages flow from flowscope's `SlotHandle::drain` directly into netring's handler-vec; the handler reads the typed payload through a single TypeId-keyed indirection.

### 8.1 The dispatcher types

```rust
//! Type-erased handler dispatch. The handler functions are
//! type-erased at registration (so we can store them in one Vec
//! per event type); the payloads stay typed all the way down to
//! the closure.

use std::any::TypeId;
use arrayvec::ArrayVec;
use crate::ctx::Ctx;
use crate::error::Result;

/// One registered handler, type-erased over its payload type.
/// At registration time we know the concrete `E::Payload`; here
/// we hold the boxed FnMut that takes a *typed pointer cast back*
/// from the dispatcher.
type BoxedHandler = Box<dyn FnMut(*const (), &mut Ctx<'_>) -> Result<()> + Send>;

struct HandlerSlot {
    handler: BoxedHandler,
}

/// The build-time-finalized dispatcher.
pub struct Dispatcher {
    /// `TypeId::of::<E>()` → u8 slot index. ≤16 entries in
    /// practice; linear scan beats hashing for this size.
    slot_by_type: ArrayVec<(TypeId, u8), 16>,

    /// Slot table — handlers grouped by event type. Indexed by
    /// the `u8` from `slot_by_type`. Each slot is usually 1–2
    /// handlers.
    slots: Box<[Vec<HandlerSlot>]>,
}

impl Dispatcher {
    /// Hot path. Called once per event from the monitor's main
    /// loop. Must not allocate.
    #[inline]
    pub fn dispatch<P: 'static>(
        &mut self,
        payload: &P,
        ctx: &mut Ctx<'_>,
    ) -> Result<()> {
        let Some(slot_idx) = self.slot_by_type.iter()
            .find(|(t, _)| *t == TypeId::of::<P>())
            .map(|(_, s)| *s as usize)
        else { return Ok(()) };

        // The handler was registered against this exact P. The
        // pointer cast is sound by the dispatch-table invariant:
        // the slot_idx for TypeId::of::<P>() only holds handlers
        // that expect P.
        let ptr = payload as *const P as *const ();
        for slot in &mut self.slots[slot_idx] {
            (slot.handler)(ptr, ctx)?;
        }
        Ok(())
    }
}
```

### 8.2 The handler registry (build side)

```rust
/// Handler-registration registry. Mutated during builder calls;
/// frozen into a `Dispatcher` at `.build()`.
#[derive(Default)]
pub struct HandlerRegistry {
    by_type: fxhash::FxHashMap<TypeId, Vec<BoxedHandler>>,
}

impl HandlerRegistry {
    pub fn register<E: Event, H: Handler<E, M>, M: 'static>(&mut self, handler: H) {
        // Type-erase the handler. The `*const ()` we receive at
        // dispatch time is a `*const E::Payload` cast by the
        // dispatcher; we cast it back here. Soundness invariant:
        // the dispatcher only ever calls this handler with
        // pointers to E::Payload values (enforced by the
        // TypeId-keyed table).
        let boxed: BoxedHandler = Box::new(move |ptr, ctx| {
            // SAFETY: dispatch table invariant — see above.
            let typed: &E::Payload = unsafe { &*(ptr as *const E::Payload) };
            handler.call(typed, ctx)
        });
        self.by_type
            .entry(TypeId::of::<E::Payload>())
            .or_default()
            .push(boxed);
    }

    /// Freeze into a Dispatcher. Assigns u8 indices to types.
    pub fn into_dispatcher(self) -> Result<Dispatcher, BuildError> {
        if self.by_type.len() > 16 {
            return Err(BuildError::TooManyEventTypes {
                limit: 16,
                actual: self.by_type.len(),
            });
        }

        let mut slot_by_type = ArrayVec::new();
        let mut slots = Vec::with_capacity(self.by_type.len());
        for (i, (type_id, handlers)) in self.by_type.into_iter().enumerate() {
            slot_by_type.push((type_id, i as u8));
            slots.push(handlers.into_iter().map(|h| HandlerSlot { handler: h }).collect());
        }
        Ok(Dispatcher {
            slot_by_type,
            slots: slots.into_boxed_slice(),
        })
    }
}
```

**The pointer cast is sound** because:
1. Registration keys handlers by `TypeId::of::<E::Payload>()`.
2. Dispatch only calls handlers in the slot for `TypeId::of::<P>()`.
3. The only handlers in that slot were registered with `E::Payload = P`.
4. So `*const () → *const P` round-trip is type-correct.

This is the same soundness argument `http::Extensions` / `tracing` span-data / `anymap` use. `miri` testing in `tests/ctx_split.rs` covers it.

**Why `u8` and 16-entry cap?** Linear scan over 16 entries fits in one cache line (16 × (8 bytes TypeId + 1 byte index) = ~150 bytes, well below 4 KiB L1). At 16 distinct event types, that's already an unusually large monitor; the cap is a sanity check that surfaces as a clean `BuildError`. Users with >16 event types split into multiple monitors.

### 8.3 Integration with flowscope's typed `Driver<E>`

flowscope 0.11's `Driver<E>` emits lifecycle `Event<K>` events with **no `M` parameter**. Per-parser typed messages flow through `SlotHandle<M, K>` returned at builder time. netring's `Monitor` stores both the central driver and the typed slot handles, with one **typed dispatch step** per protocol:

```rust
//! src/monitor/run.rs — the run loop.

/// Per-protocol slot wrapper. Type-erased at storage; typed at
/// dispatch via the `drain_and_dispatch` trait method.
trait ProtocolSlot: Send {
    fn drain_and_dispatch(
        &mut self,
        dispatcher: &mut Dispatcher,
        ctx: &mut Ctx<'_>,
    ) -> Result<()>;
}

/// One per registered protocol. Knows its concrete M at compile
/// time; uses generic dispatch with no `dyn Any`.
struct TypedProtocolSlot<P: Protocol> {
    handle: SlotHandle<P::Message, FlowKey>,
    scratch: Vec<SlotMessage<P::Message, FlowKey>>,  // pre-allocated; reused per drain
}

impl<P: Protocol> ProtocolSlot for TypedProtocolSlot<P> {
    fn drain_and_dispatch(
        &mut self,
        dispatcher: &mut Dispatcher,
        ctx: &mut Ctx<'_>,
    ) -> Result<()> {
        self.scratch.clear();
        self.handle.drain(&mut self.scratch);  // zero-alloc (cap reused)

        for slot_msg in self.scratch.drain(..) {
            ctx.flow = Some(&slot_msg.key);
            ctx.ts = slot_msg.ts;
            dispatcher.dispatch::<P::Message>(&slot_msg.message, ctx)?;
        }
        Ok(())
    }
}

/// Inside Monitor:
async fn run_loop(&mut self) -> Result<()> {
    let mut events: Vec<flowscope::driver::Event<FlowKey>> = Vec::with_capacity(64);
    let mut packet_stream = self.capture.into_stream();

    while let Some(packet) = packet_stream.next().await {
        let view = flowscope::PacketView::new(&packet.data, packet.timestamp);

        // (1) Central driver emits lifecycle events into our reused buffer.
        events.clear();
        self.driver.track_into(view, &mut events);

        // (2) Translate + dispatch each lifecycle event.
        for evt in events.drain(..) {
            let mut ctx = self.make_ctx(&evt);
            self.dispatch_lifecycle(evt, &mut ctx)?;
        }

        // (3) For each protocol, drain its typed slot and dispatch.
        for slot in &mut self.protocol_slots {
            let mut ctx = self.make_ctx_default();
            slot.drain_and_dispatch(&mut self.dispatcher, &mut ctx)?;
        }
    }
    Ok(())
}

/// Lifecycle dispatch: map flowscope::Event<K> → netring's typed
/// event payloads (FlowStarted<Tcp> / FlowEnded<Tcp> / etc.) and
/// invoke the dispatcher.
fn dispatch_lifecycle(
    &mut self,
    evt: flowscope::driver::Event<FlowKey>,
    ctx: &mut Ctx<'_>,
) -> Result<()> {
    use flowscope::driver::Event as FE;
    match evt {
        FE::FlowStarted { key, l4: Some(L4Proto::Tcp), ts } => {
            let p = FlowStarted::<Tcp> { key, l4: Some(L4Proto::Tcp), ts, _marker: PhantomData };
            self.dispatcher.dispatch::<FlowStarted<Tcp>>(&p, ctx)?;
        }
        FE::FlowStarted { key, l4: Some(L4Proto::Udp), ts } => {
            let p = FlowStarted::<Udp> { key, l4: Some(L4Proto::Udp), ts, _marker: PhantomData };
            self.dispatcher.dispatch::<FlowStarted<Udp>>(&p, ctx)?;
        }
        FE::FlowEnded { key, reason, stats, l4, ts, .. } => {
            // Same L4-keyed split as FlowStarted; macro-generate
            // these arms for the supported L4 set.
            match l4 {
                Some(L4Proto::Tcp) => {
                    let p = FlowEnded::<Tcp> { key, reason, stats, l4, ts, _marker: PhantomData };
                    self.dispatcher.dispatch::<FlowEnded<Tcp>>(&p, ctx)?;
                }
                /* … */
                _ => {}
            }
        }
        FE::FlowAnomaly { key, kind, ts } => {
            let p = AnyFlowAnomaly { key: Some(key), kind, ts };
            self.dispatcher.dispatch::<AnyFlowAnomaly>(&p, ctx)?;
        }
        FE::TrackerAnomaly { kind, ts } => {
            let p = AnyFlowAnomaly { key: None, kind, ts };
            self.dispatcher.dispatch::<AnyFlowAnomaly>(&p, ctx)?;
        }
        // … other variants
        _ => {}
    }
    Ok(())
}
```

**Why this is better than the original `Erased` design:**

| | Original (`Driver<E, Erased>`) | New (`Driver<E>` + `SlotHandle<M, K>`) |
|---|---|---|
| Per-message allocation | `Box::new(payload)` per parsed message | **None.** typed scratch Vec, capacity reused |
| Dispatch indirection | TypeId lookup + downcast | TypeId lookup + raw pointer cast |
| Type safety | Runtime downcast that can panic on invariant violation | Compile-time typed at the slot wrapper; raw cast is sound by construction |
| flowscope coupling | netring works around closed `M` parameter | netring uses flowscope's intended shape |
| LoC | ~250 LoC for `Erased` + boxing | ~100 LoC for `TypedProtocolSlot<P>` |

**The 0.11.1 `force_close` API** lets the monitor explicitly close stuck flows on shutdown:

```rust
impl Monitor {
    pub async fn shutdown(mut self) -> Result<()> {
        let now = current_timestamp();
        let mut events = Vec::new();

        // Force-close every flow the tracker knows about. Emits
        // FlowEnded events with reason = ForceClose for each.
        for key in self.driver.tracker().iter_keys().collect::<Vec<_>>() {
            self.driver.force_close_into(&key, now, &mut events);
        }

        // Drain remaining lifecycle + slot events.
        for evt in events.drain(..) { /* dispatch */ }
        for slot in &mut self.protocol_slots { /* drain_and_dispatch */ }

        self.sink_chain.flush()?;
        Ok(())
    }
}
```

This is a 0.19 deliverable — users running production daemons want clean shutdown, and `force_close` is what makes it possible without losing in-flight events.

---

## 9. `AnomalySink` + `AnomalyWriter`

`src/anomaly/sink.rs`:

```rust
//! AnomalySink — destination for anomaly emissions.
//!
//! Handlers do NOT construct an `Anomaly` struct. They use the
//! `AnomalyWriter` builder which writes directly into the sink's
//! pre-allocated buffer. The framework never materializes an
//! `Anomaly<K>` value on the hot path.

use std::borrow::Cow;
use std::fmt::Debug;
use arrayvec::ArrayVec;
use flowscope::Timestamp;
use super::severity::Severity;

/// The sink trait. Implementors decide what to do with anomalies:
/// print to stdout, write JSON to a file, forward to a tokio
/// channel, emit a tracing event, ship to a metrics endpoint.
pub trait AnomalySink: Send {
    /// Begin building an anomaly. The returned `AnomalyWriter`
    /// is filled via `.with_*` calls and finalized with `.emit()`.
    fn begin(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
    ) -> AnomalyWriter<'_>;

    /// Flush any internal buffering. Called on shutdown.
    /// Default: no-op.
    fn flush(&mut self) -> Result<(), std::io::Error> { Ok(()) }
}

/// Builder for a single anomaly. Lives on the stack; the inline
/// `ArrayVec` storage means zero heap allocation for ≤8 observations
/// + ≤8 metrics. Larger counts return `Err` from `with_*`.
pub struct AnomalyWriter<'sink> {
    sink: &'sink mut dyn AnomalySink,
    kind: &'static str,
    severity: Severity,
    ts: Timestamp,
    key_debug: Option<&'sink dyn Debug>,
    obs: ArrayVec<(&'static str, Cow<'sink, str>), 8>,
    metrics: ArrayVec<(&'static str, f64), 8>,
}

impl<'sink> AnomalyWriter<'sink> {
    /// Attach a key. The key is borrowed; the sink writes its
    /// `Debug` representation into the output. The handler does
    /// not pay a `Clone` cost; only sinks that need to retain the
    /// anomaly past the event clone.
    pub fn with_key<K: Debug>(mut self, key: &'sink K) -> Self {
        self.key_debug = Some(key);
        self
    }

    /// Attach an observation. `Cow<'static, str>` lets literal
    /// `&'static str` pass through with zero allocation; only
    /// user-built strings cost a clone. Returns `Err` if the
    /// inline buffer is full.
    pub fn with(
        mut self,
        label: &'static str,
        value: impl Into<Cow<'sink, str>>,
    ) -> Self {
        let _ = self.obs.try_push((label, value.into()));  // silent drop on full
        self
    }

    /// Attach a numeric metric.
    pub fn with_metric(mut self, label: &'static str, value: f64) -> Self {
        let _ = self.metrics.try_push((label, value));
        self
    }

    /// Emit. The sink consumes the writer and decides format /
    /// destination. After this call the writer is gone; the
    /// inline ArrayVecs are dropped without heap allocation.
    pub fn emit(self) {
        self.sink.write(
            self.kind,
            self.severity,
            self.ts,
            self.key_debug,
            &self.obs,
            &self.metrics,
        );
    }
}

/// Sink trait's serialization hook — called from `AnomalyWriter::emit`.
/// Implementors get all fields as borrowed references; they're
/// free to format into their own buffer.
pub trait AnomalySinkWrite: AnomalySink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Debug>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    );
}
```

The `Cow<'_, str>` lifetime story: most observations are `&'static str` literals (`"truncated"`, `"icmp_explained"`). Those pass through without allocation. User-built strings get a `Cow::Owned(String)` and pay one allocation per anomaly — rare in practice, and surfaceable via clippy.

### 9.1 Shipped sinks

`src/anomaly/shipped_sinks.rs`:

```rust
/// One line of human-readable text per anomaly to stdout.
/// Buffered with a configurable byte budget; flushes on `\n`.
pub struct StdoutSink {
    buf: Vec<u8>,  // pre-allocated; reused across anomalies
    capacity: usize,
}

impl StdoutSink {
    pub fn with_capacity(capacity: usize) -> Self {
        Self { buf: Vec::with_capacity(capacity), capacity }
    }
}

impl AnomalySink for StdoutSink { /* … */ }
impl AnomalySinkWrite for StdoutSink {
    fn write(&mut self, kind, severity, ts, key, obs, metrics) {
        self.buf.clear();
        // Format directly into pre-allocated buffer; no String::new.
        use std::io::Write;
        let _ = write!(&mut self.buf, "[{}] {} ts={}", severity, kind, ts);
        if let Some(k) = key {
            let _ = write!(&mut self.buf, " key={k:?}");
        }
        for (l, v) in obs { let _ = write!(&mut self.buf, " {l}={v}"); }
        for (l, v) in metrics { let _ = write!(&mut self.buf, " {l}={v:.2}"); }
        let _ = writeln!(&mut self.buf);
        let _ = std::io::stdout().write_all(&self.buf);
    }
}

/// One line of structured JSON per anomaly to stdout.
/// `serde_json::to_writer` into the buffer; reuses allocation.
pub struct StdoutJsonSink { /* … */ }

/// Emits each anomaly as a tracing event.
pub struct TracingSink { /* … */ }

/// Forwards to a tokio channel; useful for fan-out to downstream
/// processors.
pub struct ChannelSink {
    tx: tokio::sync::mpsc::UnboundedSender<OwnedAnomaly>,
    overflow_policy: OverflowPolicy,
}
```

`OwnedAnomaly` is the lazily-constructed anomaly struct — built only when the sink needs to *retain* the anomaly across the event lifetime. Sinks that immediately format and discard (StdoutSink, TracingSink) never construct it.

---

## 10. Layer / middleware

`src/layer/mod.rs`:

```rust
//! Middleware over anomaly emissions. Wraps the sink chain.
//!
//! Composition: layers stack from inside out. The first layer
//! registered wraps the sink directly; subsequent layers wrap
//! the previous. So `.layer(A).layer(B)` runs B before A.

// Re-export tower's Layer trait — same shape, fewer deps.
pub use tower::Layer;

mod dedupe;
mod rate_limit;
mod min_severity;
mod sample;
mod tee;

pub use dedupe::DedupeAnomalies;
pub use rate_limit::RateLimitAnomalies;
pub use min_severity::MinSeverity;
pub use sample::Sample;
pub use tee::Tee;
```

Each shipped layer is a wrapper around `AnomalySink`:

```rust
// src/layer/dedupe.rs

pub struct DedupeAnomalies<S> {
    inner: S,
    window: Duration,
    seen: fxhash::FxHashMap<DedupeKey, Instant>,  // pre-sized
}

/// `(kind, key_debug_string)` — what counts as "same anomaly."
type DedupeKey = (&'static str, smallstr::SmallString<[u8; 32]>);

impl<S: AnomalySinkWrite> AnomalySinkWrite for DedupeAnomalies<S> {
    fn write(&mut self, kind, severity, ts, key, obs, metrics) {
        let dedupe_key = (kind, format_compact_key(key));
        let now = Instant::now();
        if let Some(prev) = self.seen.get(&dedupe_key)
            && now.duration_since(*prev) < self.window
        { return }  // dropped — duplicate
        self.seen.insert(dedupe_key, now);
        self.inner.write(kind, severity, ts, key, obs, metrics);
    }
}

impl<S> DedupeAnomalies<S> {
    pub fn within(window: Duration) -> impl Layer<S, Service = DedupeAnomalies<S>> {
        // tower-compatible Layer; wraps inner sink.
        DedupeLayer { window }
    }
}
```

The `SmallString<[u8; 32]>` keeps dedup keys on the stack for the common case (most flow keys fit in 24–32 bytes when `Debug`-formatted as `10.0.0.1:55555 <-> 10.0.0.2:80 tcp`).

Tests `tests/layer_composition.rs`: dedup window correctness, rate-limit per-kind isolation, min-severity flooring, sample probability over a large N.

---

## 11. The `Monitor` builder

`src/monitor/mod.rs` — pulled together. ~250 LoC.

```rust
//! The top-level Monitor builder.

use bon::Builder;

#[derive(Builder)]
#[builder(start_fn = builder)]
pub struct Monitor {
    /// Capture sources. `[iface]` for single-interface monitors.
    #[builder(into, required)]
    interfaces: Vec<String>,

    /// Optional kernel BPF coarse filter. Applied to each capture.
    bpf: Option<BpfFilter>,

    /// Per-CPU fanout config. `None` = single-CPU; `Some(...)` =
    /// `AsyncMultiCapture` with PACKET_FANOUT.
    fanout: Option<FanoutConfig>,

    /// Internal: protocol registry, populated by `.protocol::<P>()`.
    #[builder(field, default)]
    protocols: ProtocolRegistry,

    /// Internal: handler registry, populated by `.on::<E>()`.
    #[builder(field, default)]
    handlers: HandlerRegistry,

    /// Layered sink chain.
    #[builder(field, default)]
    sink_chain: LayeredSink,

    /// Periodic tick handlers.
    #[builder(field, default)]
    ticks: Vec<TickRegistration>,

    /// Pre-allocated counter sizes, keyed by K.
    #[builder(field, default)]
    counter_configs: CounterConfigs,
}

// Builder-extension methods that aren't bon-generated:

impl<S: bon::__::IsUnset<Bp_protocols>> MonitorBuilder<S> {
    pub fn protocol<P: Protocol>(mut self) -> Self {
        self.protocols.register::<P>();
        self
    }

    pub fn on<E: Event, H: Handler<E, M>, M: 'static>(mut self, handler: H) -> Self {
        self.handlers.register::<E, H, M>(handler);
        self
    }

    pub fn on_async<E: Event, H: AsyncHandler<E, M>, M: 'static>(mut self, handler: H) -> Self {
        self.handlers.register_async::<E, H, M>(handler);
        self
    }

    pub fn state<T: Default + Send + 'static>(self) -> Self {
        // Force StateMap initialization slot for T. The actual T
        // is lazily created on first access.
        self
    }

    pub fn counter<K: Eq + Hash + Send + 'static>(
        mut self,
        window: Duration,
        bucket_width: Duration,
    ) -> Self {
        self.counter_configs.register::<K>(window, bucket_width);
        self
    }

    pub fn layer<L: Layer<LayeredSink>>(mut self, layer: L) -> Self {
        self.sink_chain = self.sink_chain.layered(layer);
        self
    }

    pub fn sink<S2: AnomalySinkWrite + 'static>(mut self, sink: S2) -> Self {
        self.sink_chain.set_terminal(Box::new(sink));
        self
    }

    pub fn tick<H, M>(mut self, period: Duration, handler: H) -> Self
    where H: Handler<Tick, M>, M: 'static
    {
        self.ticks.push(TickRegistration { period, handler: erase_tick(handler) });
        self
    }

    pub fn fanout_per_cpu(mut self, interface: impl Into<String>, mode: FanoutMode) -> Self {
        self.fanout = Some(FanoutConfig::PerCpu { interface: interface.into(), mode });
        self
    }
}

// Build + run:

impl Monitor {
    pub async fn run_until(self, deadline: Instant) -> Result<()> { /* … */ }
    pub async fn run_for(self, duration: Duration) -> Result<()> { /* … */ }
    pub async fn run_until_signal(self) -> Result<()> { /* … */ }
    pub fn into_stream(self) -> impl Stream<Item = Result<crate::protocol::Event>> { /* … */ }
    /// Force-close all in-flight flows, drain remaining slot
    /// events, flush the sink chain. Uses flowscope 0.11.1's
    /// `Driver::force_close_into` to emit `FlowEnded` events for
    /// every still-live flow before shutdown — handlers see clean
    /// lifecycle boundaries even on SIGTERM.
    pub async fn shutdown(self) -> Result<()> { /* … */ }
}
```

The `bon` `Builder` derive does the heavy lifting for required-vs-optional field tracking. The non-trivial builder methods (`protocol`, `on`, `layer`, etc.) extend the bon-generated `MonitorBuilder` via `impl` blocks on the typestate-parameterized struct.

The actual surface a user sees:

```rust
Monitor::builder()
    .interfaces(["eth0"])  // required — bon enforces at compile time
    .protocol::<Http>()    // builder extension
    .protocol::<Dns>()
    .state::<HttpStats>()
    .on::<HttpRequest>(|req, stats: State<HttpStats>| { ... })
    .layer(MinSeverity::warning())
    .sink(StdoutJsonSink::with_capacity(4096))
    .build()?              // bon-generated; returns Result
    .run_until_signal()
    .await
```

---

## 12. The `detector!` macro

`src/detector_macro.rs`. Pure `macro_rules!`, ~200 LoC.

```rust
/// Declarative stateless detector. Expands to a `Handler` impl.
///
/// ```ignore
/// let truncated_tls = detector! {
///     name: "TruncatedTls",
///     severity: Warning,
///     event: TlsHandshake,
///     // optional pattern guard:
///     matches: |hs| hs.outcome == HandshakeOutcome::Truncated,
///     // mandatory emission closure:
///     emit: |hs, sink: Sink<()>, ts: Now| {
///         sink.begin("TruncatedTls", Severity::Warning, ts)
///             .with("sni", hs.sni.as_deref().unwrap_or(""))
///             .emit();
///     },
/// };
///
/// monitor.detect(truncated_tls);
/// ```
#[macro_export]
macro_rules! detector {
    (
        name: $name:literal,
        severity: $sev:ident,
        event: $ev:ty,
        $( matches: $guard:expr, )?
        emit: $emit:expr,
    ) => {
        {
            // Expands to a Handler<E, (...)> closure.
            move |__evt: &<$ev as $crate::Event>::Payload, __ctx: &mut $crate::Ctx<'_>| {
                $( if !($guard)(__evt) { return Ok(()); } )?
                // Extract sink + ts from ctx for the user's emit closure.
                // The signature here is fixed to match $emit.
                let __sink: &mut dyn $crate::AnomalySink = __ctx.sink_mut();
                let __ts: $crate::Timestamp = __ctx.ts;
                ($emit)(__evt, __sink, __ts);
                Ok(())
            }
        }
    };
}
```

The macro's design constraint: keep it `macro_rules!` (not `proc-macro`). The user-facing grammar is small enough; proc-macros are reserved for `bon`.

---

## 13. Per-CPU sharding

`src/monitor/shard.rs`. Implements the `.fanout_per_cpu()` mode.

```rust
//! Per-CPU sharded monitor.
//!
//! Each shard has its own Dispatcher, StateMap, CounterRegistry,
//! Sink. Per-CPU state is merged at tick boundaries via user-
//! supplied merge closures.

pub struct ShardedMonitor {
    shards: Vec<MonitorShard>,
    merge_closures: HashMap<TypeId, Box<dyn Fn(&mut [BoxedAny])>>,
    tick_merge: Duration,
}

pub struct MonitorShard {
    cpu: usize,
    dispatcher: Dispatcher,
    state_map: StateMap,
    counters: CounterRegistry,
    sink: Box<dyn AnomalySink>,
}

impl MonitorBuilder {
    /// Register a merge closure for state of type T. Required when
    /// `fanout_per_cpu` is used with `state::<T>()` and T doesn't
    /// implement `AddAssign`.
    pub fn merge_state<T, F>(mut self, merge: F) -> Self
    where T: Default + Send + 'static, F: Fn(&mut T, &mut T) + Send + Sync + 'static {
        self.merge_closures.insert(TypeId::of::<T>(), Box::new(merge_fn(merge)));
        self
    }
}
```

The runtime: one `AsyncMultiCapture` with `FANOUT_CPU` mode opens one ring per CPU. Each ring's events feed an independent `MonitorShard`. At `tick_merge` intervals, the framework iterates shards and merges per-CPU state via the registered closures. The merge happens *only* at tick boundaries — never on the hot path.

Tests: `tests/sharded_monitor.rs`. Synthesize multi-CPU traffic via canned event vectors; verify merge correctness at tick boundaries.

---

## 14. Performance enforcement

`benches/zero_alloc.rs`. The teeth of the §7 contract.

```rust
//! dhat-gated allocation regression test.
//!
//! Asserts that the steady-state dispatch loop allocates within a
//! ≤1 KiB per 100k events tolerance. If a refactor introduces a
//! per-event allocation, CI fails with a precise call-graph.

#![cfg(feature = "bench-zero-alloc")]

use dhat::{Dhat, DhatAlloc};

#[global_allocator]
static ALLOC: DhatAlloc = DhatAlloc;

fn main() {
    let _dhat = Dhat::start_heap_profiling();

    // Construct monitor with the canonical 3-protocol setup.
    let monitor = build_test_monitor();

    // Warm up: 10k events.
    drive_events(&monitor, 10_000);

    // Measure steady state: 100k events.
    let stats_before = dhat::HeapStats::get();
    drive_events(&monitor, 100_000);
    let stats_after = dhat::HeapStats::get();

    let delta_bytes = stats_after.curr_bytes as i64 - stats_before.curr_bytes as i64;
    let delta_blocks = stats_after.curr_blocks as i64 - stats_before.curr_blocks as i64;

    println!("100k events: Δ {delta_bytes} bytes, Δ {delta_blocks} blocks");

    // Tolerance: <1 KiB or <100 blocks over 100k events.
    assert!(
        delta_bytes < 1024,
        "alloc regression: {delta_bytes} bytes (limit 1024). \
         Check dhat-heap.json for the offending call site."
    );
    assert!(
        delta_blocks < 100,
        "block regression: {delta_blocks} blocks (limit 100)"
    );
}
```

The `dhat-heap.json` file is emitted alongside; CI uploads it as an artifact on failure.

Tolerance rationale: tokio's scheduler may allocate occasionally (epoll registration changes, channel grows); pure-zero is too strict. 1 KiB / 100k events is well below the threshold of "the design has a leak."

CI integration: `.github/workflows/ci.yml` adds:

```yaml
zero-alloc:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v5
    - uses: dtolnay/rust-toolchain@stable
    - run: cargo bench --features bench-zero-alloc --bench zero_alloc
    - uses: actions/upload-artifact@v4
      if: failure()
      with: { name: dhat-heap, path: dhat-heap.json }
```

---

## 15. Migration shims

`src/anomaly/compat.rs`. Lets existing 0.18 `AnomalyRule` implementations plug into the new `Monitor`.

```rust
//! 0.18 → 0.19 migration shim. Adapts the old AnomalyRule trait
//! to the new Handler. Ships in `netring-compat` for one release,
//! deprecated in 0.20.

#[deprecated(note = "use Handler<E, M> directly; see migration guide")]
pub trait AnomalyRule<K>: Send {
    fn name(&self) -> &'static str;
    fn observe(&mut self, evt: &OldProtocolEvent<K>, emit: &mut Vec<Anomaly<K>>);
    fn on_tick(&mut self, _now: Timestamp, _emit: &mut Vec<Anomaly<K>>) {}
}

/// Convert a 0.18 AnomalyRule into a 0.19 Handler over the
/// catch-all `AnyEvent` type. The conversion costs one extra
/// indirection per event but lets old code work unmodified.
pub fn rule_as_handler<R: AnomalyRule<FlowKey> + 'static>(
    rule: R,
) -> impl Handler<AnyEvent, (Sink<()>,)> { /* … */ }
```

`AnyEvent` is a catch-all event type that fires for every event the monitor sees. It exists *only* for migration; new code should use typed events.

---

## 16. Migration recipes — 0.18 → 0.19

`docs/migration-0.18-to-0.19.md`. The mechanical mapping for every breaking change.

### 16.1 ProtocolMessage → Protocol marker

```rust
// 0.18:
ProtocolMessage::Http(HttpMessage::Request(req)) => { ... }

// 0.19:
.on::<HttpRequest>(|req| { ... })
```

### 16.2 AnomalyRule trait → closure handler

```rust
// 0.18 (~18 lines for TruncatedTls):
struct TruncatedTls;
impl AnomalyRule<FiveTupleKey> for TruncatedTls {
    fn name(&self) -> &'static str { "TruncatedTls" }
    fn observe(&mut self, evt, emit) { /* match + push */ }
}
monitor.with_rule(TruncatedTls);

// 0.19 (~5 lines):
.on::<TlsHandshake>(|hs, sink: Sink<()>, ts: Now| {
    if matches!(hs.outcome, HandshakeOutcome::Truncated) {
        sink.begin("TruncatedTls", Severity::Warning, ts).emit();
    }
    Ok(())
})
```

### 16.3 ProtocolMonitorBuilder → Monitor::builder

```rust
// 0.18:
let monitor = ProtocolMonitorBuilder::new()
    .interface("eth0")
    .flow()
    .http()
    .build(FiveTuple::bidirectional())?;
while let Some(evt) = monitor.next().await { match evt? { ... } }

// 0.19:
Monitor::builder()
    .interfaces(["eth0"])
    .protocol::<Http>()
    .on::<HttpRequest>(|req| { ... })
    .run_until_signal()
    .await?;
```

### 16.4 Per-detector recipes

The migration guide ships one recipe per existing detector:
- `dns_tunnel_detect` → §16.4.1
- `dns_query_burst` → §16.4.2
- `dns_resolved_no_connection` → §16.4.3
- `tls_to_unresolved_ip` → §16.4.4
- `lateral_movement` → §16.4.5
- `slow_tls_handshake` → §16.4.6
- `icmp_explained_drop` → §16.4.7 — the canonical multi-protocol case
- `syn_flood_burst` → §16.4.8
- `port_scan` → §16.4.9
- `pcap_replay*` → §16.4.10–11
- `anomaly_monitor_demo` → §16.4.12
- `full_monitor` → §16.4.13

Each recipe is 20–40 lines of side-by-side code. Total ~600 lines for the migration doc.

---

## 17. The low-level `Stream` API survives

`src/protocol/stream.rs` — renamed from the current `protocol/monitor.rs`. The `Stream<Item = Result<Event, Error>>` shape is preserved verbatim for power users who genuinely want exhaustive matching.

```rust
//! Lower-level: a Stream of typed events. Use when you need
//! exhaustive matching, custom event ordering, or interop with
//! `tokio_stream::StreamExt` adapters.
//!
//! The high-level `Monitor` (callbacks + middleware + sinks)
//! is built on top of this. Most users want Monitor.

pub struct ProtocolStream<K> { /* … */ }

impl<K> Stream for ProtocolStream<K> {
    type Item = Result<Event, Error>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> { /* … */ }
}
```

The relationship: `Monitor::into_stream()` returns a `ProtocolStream`; `ProtocolStream` can be built directly via `ProtocolStream::builder()` without any handler registration. Both share the same flowscope `Driver` machinery.

---

## 18. Tests

### 18.1 Unit tests (per-module)

| Module | Test file | Coverage |
|---|---|---|
| `protocol/mod.rs` | `tests/protocol_registration.rs` | Protocol trait impls; Dispatch enum variants; build-time conflict detection |
| `protocol/event.rs` | inline | FlowStarted<P>/FlowEnded<P> generic correctness |
| `monitor/handler.rs` | `tests/anomaly_handler.rs` | Blanket impls for 0..8 extractors; trybuild compile-fail for borrow conflicts |
| `monitor/dispatcher.rs` | `tests/dispatcher_no_alloc.rs` | 100k events, count_alloc(), assert zero |
| `monitor/registry.rs` | inline | Slot-index assignment, >16-types error |
| `ctx/from_ctx.rs` | `tests/ctx_borrow_disjoint.rs` | StateMap lazy init, get_or_init_mut |
| `ctx/extractors.rs` | inline | State/Sink/Counter/Now FromCtx impls |
| `ctx/split.rs` | `tests/ctx_split.rs` | Disjoint projection soundness via miri |
| `anomaly/sink.rs` | `tests/anomaly_sink.rs` | AnomalyWriter ArrayVec capacity; Cow vs String |
| `anomaly/shipped_sinks.rs` | inline | StdoutSink format; JsonSink schema |
| `layer/*` | `tests/layer_composition.rs` | Dedupe window, min-severity floor, sample probability |
| `detector_macro.rs` | `tests/detector_macro.rs` | Macro expansion correctness, gated case, emit closure |

### 18.2 Integration tests

| Test | Scenario |
|---|---|
| `tests/integration_basic.rs` | Single-protocol Http monitor on a synthesized event stream |
| `tests/integration_multi_proto.rs` | Tcp + Udp + Icmp combined (the §2 K8s scenario, simplified) |
| `tests/integration_layers.rs` | Dedupe + MinSeverity + Sample composition |
| `tests/integration_sharded.rs` | 4-shard per-CPU monitor with state merge |
| `tests/integration_compat.rs` | Old AnomalyRule via compat shim |

### 18.3 Public API stability snapshot

`tests/api_stability.rs`: a snapshot of `cargo public-api` output. Fails when the public surface changes; intentional breaks require committing the new snapshot. Prevents accidental API churn within the 0.19.x line.

### 18.4 Doctests

Every public type in `src/lib.rs` re-exports has a `# Example` doctest. The `MONITORING.md` tutorial is one giant doctest covering the §2 K8s scenario, broken into snippets.

---

## 19. Phase deliverable checklists

This is the order of operations for implementation. Each phase ships as one or more commits; the whole sequence ships as 0.19.0.

### Phase A — flowscope 0.11 bump + Protocol trait + registry (3–5 days)

**Deliverables:**
- [ ] Cargo.toml: `flowscope = { version = "0.11", default-features = false }`. Verify all feature passthroughs still build.
- [ ] `src/protocol/mod.rs`: `Protocol` trait, `Dispatch`, `ParserKind<M>`, `SignatureMatch`. No internal `ProtocolParser` trait — uses flowscope's directly.
- [ ] `src/protocol/builtin/{tcp,udp,icmp,http,dns,tls,tls_handshake}.rs`: 7 marker types, each ≤20 LoC.
- [ ] `src/protocol/event.rs`: `Event` trait, `FlowStarted<P>`, `FlowEnded<P>`, `FlowEstablished<P>`, `Tick`, `AnyFlowAnomaly`.
- [ ] `tests/protocol_registration.rs`: protocol impl correctness, dispatch enum routing.

**Shorter than the previous estimate (was 5–7 days)** because flowscope's typed `Driver<E>` ships the heavy lifting; netring's Protocol trait is mostly a thin shape over `Box<dyn flowscope::SessionParser>` / `Box<dyn flowscope::DatagramParser>`.

**Acceptance:** `cargo build -p netring --features monitor` succeeds. Old `ProtocolEvent` / `ProtocolMessage` deleted; old `ProtocolMonitorBuilder` renamed to `ProtocolStream::builder()`.

### Phase B — Handler trait + closure registration (4–6 days)

**Deliverables:**
- [ ] `src/monitor/handler.rs`: `Handler<E, M>` trait, `impl_handler!` macro for 0..8 extractors.
- [ ] `src/ctx/mod.rs`: `Ctx<'a>` struct.
- [ ] `src/ctx/from_ctx.rs`: `FromCtx` trait, `StateMap`.
- [ ] `src/ctx/extractors.rs`: `State<T>`, `Sink<A>`, `Now`, `Counter<K>`.
- [ ] `src/monitor/registry.rs`: `HandlerRegistry` + `TypedProtocolSlot<P>` wrapping flowscope `SlotHandle<M, K>`.
- [ ] `src/monitor/dispatcher.rs`: TypeId-keyed dispatcher with raw-pointer cast (sound by registration invariant — see §8.2).
- [ ] `src/monitor/run.rs`: the run loop with `Driver::track_into` + per-slot `drain_and_dispatch`.
- [ ] `tests/anomaly_handler.rs` + `tests/ctx_split.rs` (miri-tested): pass.

**Acceptance:** `.on::<E>(closure)` registration compiles + dispatches. The §7 K8s example compiles end-to-end with placeholder middleware.

### Phase C — Performance hardening (2–3 days)

**Note: shorter than the previous estimate (was 3–4 days)** because flowscope already shipped `track_into` + scratch-buffer parsers + `Bytes`-based HTTP payloads. The remaining netring work is the sink-side anomaly writer + the CI benchmark.

**Deliverables:**
- [ ] `src/anomaly/sink.rs`: `AnomalyWriter` with `ArrayVec` + `Cow<'static, str>`.
- [ ] `src/anomaly/shipped_sinks.rs`: `StdoutSink`, `StdoutJsonSink`, `TracingSink`, `ChannelSink`.
- [ ] `benches/zero_alloc.rs`: dhat-gated regression test (per netring §14 of this doc).
- [ ] CI: `bench-zero-alloc` job added to `.github/workflows/ci.yml`.

**Acceptance:** 100k events through the full monitor (capture → Driver::track_into → slot.drain_and_dispatch → handler → AnomalyWriter → sink) allocate **<512 bytes** delta (tighter than the original 1 KiB tolerance — flowscope's scratch-reuse + the typed-handle path together remove the slack that the original estimate budgeted for `Erased` boxing).

### Phase D — Async escape hatch + middleware (3–4 days)

**Deliverables:**
- [ ] `src/monitor/handler.rs`: `AsyncHandler<E, M>` trait + `impl_async_handler!` macro.
- [ ] `MonitorBuilder::on_async::<E>()` registration method.
- [ ] `src/layer/{dedupe,rate_limit,min_severity,sample,tee}.rs`: 5 layers.
- [ ] `tests/layer_composition.rs`: passes.

**Acceptance:** Async handlers work (one Box::pin per event, documented). Middleware composes; the K8s example's `DedupeAnomalies::within(60s) + MinSeverity::warning()` chain works.

### Phase E — detector! macro + prelude + multi-interface (3–4 days)

**Deliverables:**
- [ ] `src/detector_macro.rs`: `macro_rules!` `detector!`.
- [ ] `src/prelude.rs`: 12–15 re-exports.
- [ ] `MonitorBuilder::interfaces([...])` multi-interface support via `AsyncMultiCapture`.
- [ ] `Cargo.toml`: `monitor` umbrella feature.

**Acceptance:** `use netring::prelude::*;` brings everything needed; multi-interface monitor works with `SourceIdx` on events.

### Phase F — Per-CPU sharding (3–4 days)

**Deliverables:**
- [ ] `src/monitor/shard.rs`: `ShardedMonitor`, `MonitorShard`, `merge_state` registration.
- [ ] `MonitorBuilder::fanout_per_cpu()` + `merge_state::<T>(|a, b| ...)` methods.
- [ ] `tests/integration_sharded.rs`: passes with 4 simulated shards.
- [ ] `docs/scaling.md`: updated for new builder API.

**Acceptance:** 4-shard test passes; merge happens at tick boundary only.

### Phase G — Migration + docs (4–5 days)

**Deliverables:**
- [ ] All 13 existing examples rewritten in new API.
- [ ] `examples/k8s_node_monitor.rs`: the §8 scenario as a runnable file.
- [ ] `docs/MONITORING.md`: replaces WRITING_DETECTORS.md.
- [ ] `docs/performance.md`: §7 contract documented.
- [ ] `docs/migration-0.18-to-0.19.md`: 13 per-detector recipes + 4 cross-cutting recipes.
- [ ] `netring-compat` crate: ships `AnomalyRule` shim.
- [ ] CHANGELOG.md: 0.18 → 0.19 entry.
- [ ] Tag + ship 0.19.0.

**Acceptance:** all examples compile + run; migration guide validated by porting one external project (or the netring author's own).

**Phase totals: 22–30 days** (revised down from 25–34 in revision 1 because Phase A shrank by ~2 days — no `Erased` wrapper to design — and Phase C shrank by ~1–2 days — flowscope already ships `track_into` + scratch parsers).

Single breaking release as netring 0.19.0.

---

## 20. Open questions

Things to verify before or during implementation. Each has a fallback noted.

1. **`bon` v3 attribute spelling** for `#[builder(field, default)]` — the field-with-default pattern for builder-internal mutable state. May need to use `#[builder(skip)] + explicit method`. **Fallback:** hand-roll a typestate builder; ~150 LoC.

2. **`tower::Layer` import path** — `tower` 0.5 vs `tower-layer` 0.3. **Verify:** `cargo add tower --features util` resolves cleanly. **Fallback:** hand-roll a 30-LoC `Layer` trait; the wider tower ecosystem isn't load-bearing for netring's needs.

3. **`dhat` API stability** — `dhat::HeapStats::get()` interface. **Verify against latest docs.** **Fallback:** use `count-allocations` crate (simpler but less detailed).

4. ~~**`flowscope::driver_unified::Driver<E, M>` boxed-`M` path**~~ ✅ **RESOLVED** by flowscope 0.11.1 (plan 121): `Driver<E>` has no `M`; per-parser typed messages flow through `SlotHandle<M, K>`. No boxing required.

5. ~~**flowscope `Bytes` adoption**~~ ✅ **RESOLVED** by flowscope 0.11.0 (plan 120): `HttpRequest::{method, path, headers, body}` and `HttpResponse::{reason, headers, body}` all use `Bytes`. DNS rdata variants that contained `Vec<u8>` (the `Other` arm) are fine — they're the rare path. TLS handshake fields use `String` for SNI/ALPN (semantic strings, not byte payloads) — appropriate.

6. **The `M` coherence phantom** in `Handler<E, M>` — verify the blanket impls compile across all 8 arities. axum took several iterations to get this right. **Fallback:** if coherence fails for high N, cap at 4 extractors; users with more state use `&mut Ctx` directly via `Ctx::split_*`.

7. **`miri` coverage of the `unsafe` in `Ctx::split_*`** — needs to be added to the CI matrix. **Verify:** `cargo +nightly miri test --tests` passes on the split-projection tests.

8. **The `compat` crate shipping route** — same workspace as netring, or separate? Recommendation: same workspace as `netring-compat = "0.19"` published alongside, mark `#[deprecated]` from day 1, remove in 0.20.

9. **`tracing` features required for `TracingSink`** — verify minimum-features compile path. May need to gate `TracingSink` behind a `tracing-sink` feature.

10. **Public API stability test (`cargo public-api`)** — verify it works on Rust 1.95. Some semver tools lag stable releases.

These don't block the design but should be resolved by the start of the corresponding implementation phase.

---

## 21. What this redesign explicitly does *not* do

A summary of conscious non-goals, for posterity:

- **No `inventory` / `linkme` plugin discovery.** Explicit `.protocol::<P>()` registration. Auto-discovery is deferred to 0.20+ when there's a concrete plugin ecosystem.
- **No Bevy-style multi-extractor magic.** `Ctx` with explicit `split_*` methods, not unsafe field-disjoint trait magic.
- **No columnar batched dispatch.** Single-event dispatch is fine through ~2 Mpps; columnar is deferred to 1.0.
- **No further upstream flowscope changes required.** All six dependencies from [`flowscope-deps-for-netring-0.19-2026-06-09.md`](./flowscope-deps-for-netring-0.19-2026-06-09.md) shipped in flowscope 0.11.0/0.11.1. The typed `Driver<E>` + `SlotHandle<M, K>` lands the architecture and eliminates the per-message allocation outright.
- **No multi-monitor composition.** One `Monitor` per process; users who want two run them in two tasks.
- **No config-driven (TOML/YAML) pipeline construction.** netring is a Rust API for Rust developers; the config-DSL story (Vector-style) is out of scope.
- **No deprecation of `flowscope` direct usage.** Power users who reach past the prelude into `flowscope::*` continue to work; the prelude is convenience, not a wall.

---

## 22. Closing notes

This spec is approximately **10,500 words** of design + **3,000 LoC** of new Rust (down from 3,500 — no `Erased` wrapper, no `ProtocolParser` adapter shims) + **1,800 LoC** of new tests + **600 lines** of new docs. The implementation budget is **22–30 working days** across 7 phases, shipping as netring 0.19.0.

flowscope 0.11.1's typed `Driver<E>` + `SlotHandle<M, K>` is the foundation that makes the zero-alloc contract honestly achievable. Without it, netring 0.19 would have shipped with a per-parsed-message allocation and a footnoted perf headline. With it, the perf claim is unqualified.

The technical bets:

1. **Type-erased dispatch via `TypeId`** — well-trodden ground (axum, http, tracing all use this).
2. **Sync handlers by default** — the single biggest perf decision; backed by §7's allocation budget.
3. **`bon` for the builder** — community consensus, designed for evolution.
4. **`tower::Layer` for middleware** — same.
5. **`ArrayVec` + `Cow` for `AnomalyWriter`** — the inline-storage pattern Suricata and Vector both use.
6. **Per-CPU sharding for >2 Mpps** — Suricata-style; no `Arc<Mutex>` ever on the hot path.

The ergonomic bets:

1. **Closure handlers over trait impls** — bevy/axum/tower precedent.
2. **Sequential `FromCtx` extractors + explicit `split_*` escape hatch** — honest Rust over magical Rust.
3. **`detector!` macro for the stateless half** — closes the Suricata-DSL gap without proc-macros.
4. **`netring::prelude`** — convention compliance; every modern Rust crate ships one.
5. **`Monitor::run_until_signal()` as the default terminator** — production-shaped from day one.

If 0.19 ships with these in place, netring has a uniquely positioned design in the Rust ecosystem: zero-copy capture, unified L4+L7 dispatch, protocol-agnostic plugin model, zero-allocation hot path, modern Rust ergonomics. Nobody else has the four together. The 0.18 release proved the architecture; 0.19 brings the surface in line.

The spec is ready for execution. Begin with Phase A.
