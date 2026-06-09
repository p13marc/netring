# netring API review — multi-protocol monitoring + anomaly detection

**Date:** 2026-06-09 (post-0.18.0 release)
**Revision:** 2 (backward-compat lifted, protocol-agnosticism added as principle)
**Scope:** the user-facing `ProtocolMonitor` + `AnomalyMonitor` surface.
**Question on the table:** is the API good? can we do better? what are the pain points?

The 0.18 architecture is right. The user-facing surface is not. The fixes are not gentle polish — with backward compatibility off the table and protocol-agnosticism made a first-class principle, the right move is a coherent redesign in one cut. This revision proposes that redesign concretely, anchored on a real-world Kubernetes connectivity-monitor scenario that exercises ICMP + TCP + UDP together.

---

## 0. What changed in this revision

1. **Backward-compatibility is no longer a constraint.** The previous revision held back from breaking changes; that constraint is lifted. The redesign below assumes one breaking release.
2. **Protocol agnosticism is a first-class principle.** The library must not bake HTTP/DNS/TLS/ICMP into a closed enum. Users must be able to plug in a new protocol (QUIC, HTTP/2, an in-house RPC format) in their own crate with no edits to netring.
3. **Performance is a first-class constraint, not an afterthought.** netring is a packet library; the hot path runs at millions of events per second on saturated 10/25/100 GbE links. Per-event allocation, per-event boxing, per-event hashing are *each* fatal at line rate. Section 7 makes zero-allocation and zero-copy explicit design rules and forces the user-facing API in §6 to honour them.
4. **Real-world scenario added.** Section 2 walks an actual operational use case — a Kubernetes node-connectivity monitor that fuses ICMP, TCP, and UDP into one signal — and drives the design from concrete needs rather than abstract ergonomics.
5. **Three-level recommendation collapsed into one design.** With BC off the table, there's no reason to stage "conservative polish first, real changes later" — that was BC-driven. Section 6 is the design; section 9 is the implementation phasing.

---

## 1. The example, as a user experiences it today

`examples/l7/full_monitor.rs` is the canonical 0.18 entry point. The user-meaningful core, stripped of `#[cfg]` guards and per-match-arm printing:

```rust
let mut monitor = ProtocolMonitorBuilder::new()
    .interface(&iface)
    .flow()
    .http()
    .dns()
    .build(FiveTuple::bidirectional())?;

while Instant::now() < deadline
    && let Some(evt) = monitor.next().await
{
    match evt? {
        ProtocolEvent::FlowStarted { key, l4, .. }      => { /* print */ }
        ProtocolEvent::FlowEnded   { key, reason, .. }  => { /* print */ }
        ProtocolEvent::FlowEstablished { .. }
        | ProtocolEvent::FlowPacket { .. }
        | ProtocolEvent::FlowTick   { .. }
        | ProtocolEvent::FlowAnomaly{ .. }
        | ProtocolEvent::TrackerAnomaly{ .. }
        | ProtocolEvent::ParserClosed{ .. } => {}
        ProtocolEvent::Message { message: ProtocolMessage::Http(http), .. } => match http {
            HttpMessage::Request(req)  => { /* print */ }
            HttpMessage::Response(resp) => { /* print */ }
        },
        ProtocolEvent::Message { message: ProtocolMessage::Dns(dns), .. } => match dns {
            DnsMessage::Query(q)       => { /* print */ }
            DnsMessage::Response(r)    => { /* print */ }
            DnsMessage::Unanswered(q)  => { /* print */ }
            _ => {}
        },
        ProtocolEvent::Message { .. } => {}
        _ => {}
    }
}
```

The full file is 218 lines. ~110 are bookkeeping the user writes every time they want a monitor. The four-line builder declares intent; the rest is mechanism. That gap is the design target.

---

## 2. The motivating real-world scenario: a Kubernetes node connectivity monitor

A platform-engineering team runs a Kubernetes cluster with an overlay network (Calico, Cilium, take your pick). They want a daemon, one per node, that observes traffic on the host interface and emits structured events for the cluster-wide alerting pipeline. The detection surface mixes ICMP, TCP, and UDP because each L4 is the right tool for a different failure mode:

**TCP (L4 lifecycle)** — most service-to-service traffic. Signals:
- Half-open connections (SYN sent, no SYN-ACK) → pod CrashLooping or unreachable.
- RST on established flows → forced termination, often by a sidecar policy violation.
- Idle timeouts → connection-pool leaks.

**UDP (L4 lifecycle + L7 parse)** — DNS, NTP, Prometheus pushgateway, gossip protocols. Signals:
- DNS query bursts → CoreDNS resolution storm, often a CrashLoop signal.
- NTP unreachable → time-sync drift incoming.

**ICMP (L4 message parse)** — the diagnostic spine. Signals:
- `Destination Unreachable` referencing an inner TCP/UDP 5-tuple → confirms it was a network failure, not an app failure.
- `Fragmentation Needed` (DF set, MTU exceeded) → overlay MTU misconfiguration, one of the highest-impact silent failures in Kubernetes.
- `Time Exceeded` → routing loop.

**Cross-protocol correlation** — the actually-useful detector:

> "When a TCP flow terminates with `Rst` or `IdleTimeout`, and an ICMP error referencing the same 5-tuple arrived within the prior 5 seconds, classify it as a **network event** (label `network.icmp_explained`). When the same drop has no matching ICMP, classify it as **service event** (label `service.unexplained_close`)."

This is the kind of detector that separates network-team paging from service-team paging. It's a real production rule. It exists today as `examples/anomaly/icmp_explained_drop.rs` — ~260 LoC, all hand-rolled `match` and state.

What the user wants to write — and the design target for the rest of this report — is something like:

```rust
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    Monitor::builder()
        .interface("eth0")
        .protocol::<Tcp>()         // flow lifecycle (TCP-shaped)
        .protocol::<Udp>()         // flow lifecycle (UDP-shaped)
        .protocol::<Icmp>()        // ICMP message parser + inner-5tuple extraction
        .state::<DroppedFlows>()   // shared state: recently-RST/idle TCP flows
        .on::<FlowEnded<Tcp>>(|evt, mut dropped: State<DroppedFlows>| async move {
            if matches!(evt.reason, EndReason::Rst | EndReason::IdleTimeout) {
                dropped.insert(evt.key, evt.ts);
            }
        })
        .on::<Icmp>(|msg, ts, mut dropped: State<DroppedFlows>, sink: Sink<Anomaly>| async move {
            let Some((label, inner)) = msg.ty.error_inner() else { return };
            let key = key_from_inner(inner);
            if let Some(dropped_ts) = dropped.take_within(&key, ts, Duration::from_secs(5)) {
                sink.emit(Anomaly::network("icmp_explained", key, ts)
                    .with("delta_ms", (ts - dropped_ts).as_millis())
                    .with("icmp_kind", label));
            }
        })
        .layer(DedupeAnomalies::within(Duration::from_secs(60)))
        .layer(MinSeverity::warning())
        .sink(StdoutJsonSink)
        .tick(Duration::from_secs(10), |stats: Stats<L4Proto>| async move {
            for (l4, c) in stats.by_l4() { println!("{l4}: started={} ended={}", c.started, c.ended); }
        })
        .run_until_signal()
        .await
}
```

That's ~30 lines for a detector that's ~260 lines today. The design must justify this UX. Sections 3–6 explain how.

---

## 3. What works today (keep)

Before the redesign, the things that should survive verbatim:

1. **One unified event stream, one capture, one driver.** The 0.18 collapse of N-captures-with-N-BPF-filters into a single capture + `Driver<E, M>` is correct. Don't unwind it.
2. **`#[non_exhaustive]` on flow-lifecycle variants.** `FlowStarted` / `FlowEnded` / `FlowEstablished` etc. are exhaustively matchable AND extensible. Right call.
3. **flowscope as a separate crate.** Capture lives in netring, flow + parsers + correlate primitives live in flowscope. The seam is clean.
4. **The parser-kind discriminator.** Routing by `parser_kind: "tls-handshake"` works. It just shouldn't be the *user's* primary API — it should drive internal dispatch.
5. **Capture-side polish.** `AsyncCapture`, `BpfFilterBuilder`, `AsyncPcapSource`, `with_default_program()` for AF_XDP. These are competitive with the best in the ecosystem.
6. **Test ergonomics.** Synthesized `Vec<ProtocolEvent<K>>` driving a rule via `monitor.observe(&evt)` + `assert_eq!` is genuinely good. Keep.

The architecture is sound. The *user-facing layer* is what's stuck in 2022.

---

## 4. Pain points, reordered around the new constraints

### 4.1 `ProtocolMessage` bakes in 5 specific protocols — not protocol-agnostic

This is the #1 issue under the new constraints. The current definition:

```rust
#[non_exhaustive]
pub enum ProtocolMessage {
    #[cfg(feature = "http")] Http(HttpMessage),
    #[cfg(feature = "dns")]  Dns(DnsMessage),
    #[cfg(feature = "tls")]  Tls(TlsMessage),
    #[cfg(feature = "tls")]  TlsHandshake(TlsHandshake),
    #[cfg(feature = "icmp")] Icmp(IcmpMessage),
}
```

Five carved-out variants. To add QUIC, HTTP/2, AMQP, MQTT, a proprietary RPC format, a user must:
- Fork netring (impossible if their app is otherwise on stable releases), OR
- Wait for upstream to add the variant.

Every other constraint (closure handlers, declarative rules, middleware) is independent of the enum shape, but **agnosticism requires breaking this enum**. The replacement uses `TypeId`-keyed dispatch (§6.1) so a new protocol is a marker struct in a downstream crate.

### 4.2 No closure-based registration

Today every detector is a struct + `impl AnomalyRule`. For the 80% of detectors that are stateless or near-stateless, the trait impl adds zero value beyond what a closure with injected state would provide.

```rust
// Today: 18 lines for a one-shot detector
struct TruncatedTls;
impl AnomalyRule<FiveTupleKey> for TruncatedTls {
    fn name(&self) -> &'static str { "TruncatedTls" }
    fn observe(&mut self, evt: &ProtocolEvent<FiveTupleKey>, emit: &mut Vec<Anomaly<FiveTupleKey>>) {
        let ProtocolEvent::Message { parser_kind: "tls-handshake",
            message: ProtocolMessage::TlsHandshake(hs), key, ts, .. } = evt else { return };
        if matches!(hs.outcome, HandshakeOutcome::Truncated) {
            emit.push(Anomaly::new("TruncatedTls", Severity::Warning, *ts)
                .with_key(*key)
                .with_observation("sni", hs.sni.as_deref().unwrap_or("")));
        }
    }
}
monitor.with_rule(TruncatedTls);

// Tomorrow: 5 lines
monitor.on::<TlsHandshake>(|hs, key, ts, sink: Sink<Anomaly>| async move {
    if matches!(hs.outcome, HandshakeOutcome::Truncated) {
        sink.emit(Anomaly::warn("TruncatedTls", *ts).with_key(*key)
            .with("sni", hs.sni.as_deref().unwrap_or("")));
    }
});
```

Same compile-time guarantees, ~⅓ the LoC. Section 6.2 details how.

### 4.3 The event match is three levels deep

```rust
ProtocolEvent::Message {
    message: ProtocolMessage::Http(HttpMessage::Request(req)),
    ..
} => { use req }
```

Three pattern levels to bind one `req`. The protocol-agnostic redesign collapses this:

```rust
.on::<HttpRequest>(|req, key, ts, ctx| async move { use req })
```

Zero match boilerplate at the user site. The framework dispatches by `TypeId::of::<HttpRequest>()` internally.

### 4.4 No declarative DSL for the stateless half of detectors

Suricata writes "alert on TLS handshake with `outcome == Truncated`" in one line:

```
alert tls any any -> any 443 (msg:"truncated TLS"; tls.handshake.outcome:truncated; sid:3001;)
```

Rust will never beat that, but a `detector!` macro closes the gap — see §6.6.

### 4.5 No middleware / Layer composition

Dedupe, rate-limit, severity floor: all are reimplemented per rule. The tower `Layer` pattern is exactly the right composition primitive. See §6.4.

### 4.6 Output sinks are open-coded `println!`

Every example ends with `for a in alerts { println!("{a}"); }`. Production users need structured sinks (JSON to stdout/file, tracing, mpsc to a downstream task, Vector/Loki/etc.). §6.3 introduces a typed `Sink<A>` extractor.

### 4.7 No prelude

Five `#[cfg]`-gated `use` statements per detector. `axum::prelude`, `futures::prelude`, `tracing::prelude` all exist for this reason; netring needs one.

### 4.8 `AnomalyMonitor::observe` allocates on every call

```rust
self.scratch.clear();
for rule in &mut self.rules { rule.observe(evt, &mut self.scratch); }
std::mem::take(&mut self.scratch)  // new empty Vec, regardless of whether rules fired
```

`std::mem::take` defeats the scratch-buffer optimization on the no-alert path. Return `&[Anomaly]` instead — caller iterates and drops; zero alloc when nothing fires. With the new closure-driven API, this concern moves to the dispatcher (which can pass the sink by reference end-to-end and never allocate).

### 4.9 No multi-interface in the high-level builder

`AsyncMultiCapture` exists at the lower level. The high-level builder takes a single `String`. A user wanting two interfaces ends up with `tokio::select!` over two monitors — defeating the "one builder call replaces orchestration" pitch. §6.5 fixes via `.interfaces([...])`.

### 4.10 Feature flag explosion

```toml
features = ["tokio", "flow", "parse", "http", "dns", "tls", "icmp", "emit"]
```

Eight features for a typical monitor. `parse` leaks an implementation detail (etherparse). The redesign introduces a `monitor` umbrella feature for app users; the granular features stay for embedded.

### 4.11 `.flow()` is a no-op

Just delete it. Trivial. Already deprecated material.

---

## 5. Comparative anchors (condensed)

The 2026 ecosystem has converged on a few high-leverage patterns that netring should adopt directly:

- **axum** — `Handler` trait with blanket impls over function signatures; `FromRequestParts` extractors give per-handler typed parameter injection. Adding a parameter type just means adding an `impl FromRequestParts for MyType`. Zero macros at the user site.
- **bevy_ecs** — `IntoSystem` + `SystemParam`; "systems are just functions" with parameter-driven scheduling. The whole point of bevy's success: handlers are *functions, not trait impls*.
- **tower** — `Service<Req, Response, Error>` + `Layer<S>`; the canonical Rust middleware story. Used by hyper, axum, tonic, tower-http. Composable, type-safe, zero-cost in static-dispatch mode.
- **`bon` crate** — typestate builders without hand-writing typestate. Has overtaken `derive_builder` in mindshare. Designed for breaking-change avoidance — its explicit pitch.
- **`http::Extensions` / `tracing` span data** — `TypeMap` (`HashMap<TypeId, Box<dyn Any + Send + Sync>>`). The standard solution for "store a heterogeneous set of typed things and look them up by type." This is the right shape for the protocol registry.
- **Zeek scripts** — `event http_request(c: connection, method: string, uri: string) { … }`. One-level dispatch with auto-threaded connection record. The UX target.
- **Suricata rules** — declarative one-liners. The Rust analog is a `macro_rules!` detector DSL.

The pattern: **handlers as functions** (axum, bevy), **middleware as layers** (tower), **registries as TypeMaps** (http, tracing), **builders via `bon`**, and **a `detector!` macro for declarative cases**. None of these are research — they're shipped patterns netring just hasn't adopted yet.

---

## 6. The redesign

What follows is the proposed shape for netring 0.19. The principle: **the library is protocol-agnostic; users register typed handlers; the framework injects state extractor-style; middleware composes via Layer.**

### 6.1 The `Protocol` trait + marker types

Replace the closed `ProtocolMessage` enum with a trait:

```rust
/// A protocol the monitor can observe. Implementors are marker
/// types (`struct Http;` etc.) that bind a typed `Message` and a
/// stable `NAME` slug. `'static` is required for `TypeId`-keyed
/// dispatch.
pub trait Protocol: Send + Sync + 'static {
    /// The message type emitted by this protocol's parser.
    type Message: Send + Sync + 'static;

    /// Stable identifier — used for metrics labels, logging, and
    /// `parser_kind` in the lower-level stream API.
    const NAME: &'static str;

    /// How packets are routed to this protocol's parser.
    fn dispatch() -> Dispatch;

    /// Construct the parser instance.
    fn parser() -> Box<dyn ProtocolParser<Message = Self::Message>>;
}

/// How a protocol selects packets.
pub enum Dispatch {
    /// Match TCP flows on these ports (e.g. HTTP on 80, 8080).
    Tcp(Vec<u16>),
    /// Match UDP flows on these ports (e.g. DNS on 53).
    Udp(Vec<u16>),
    /// All ICMP/ICMPv6 packets.
    Icmp,
    /// All TCP flow events regardless of port (the L4 lifecycle).
    AllTcp,
    /// All UDP flow events regardless of port.
    AllUdp,
    /// Heuristic signature dispatch — port-agnostic protocol detection.
    Signature(fn(&[u8]) -> SignatureMatch),
}
```

Built-in protocols are marker structs in `netring::protocols::`:

```rust
pub struct Http;
impl Protocol for Http {
    type Message = HttpMessage;
    const NAME: &'static str = "http/1";
    fn dispatch() -> Dispatch { Dispatch::Tcp(vec![80, 8080]) }
    fn parser() -> Box<dyn ProtocolParser<Message = HttpMessage>> {
        Box::new(flowscope::http::HttpParser::default())
    }
}

pub struct Dns;
impl Protocol for Dns {
    type Message = DnsMessage;
    const NAME: &'static str = "dns-udp";
    fn dispatch() -> Dispatch { Dispatch::Udp(vec![53]) }
    fn parser() -> Box<dyn ProtocolParser<Message = DnsMessage>> {
        Box::new(flowscope::dns::DnsUdpParser::with_correlation())
    }
}

pub struct Tcp;
impl Protocol for Tcp {
    type Message = ();   // L4 lifecycle only; no parsed payload
    const NAME: &'static str = "tcp";
    fn dispatch() -> Dispatch { Dispatch::AllTcp }
    fn parser() -> Box<dyn ProtocolParser<Message = ()>> { Box::new(NoopParser) }
}

pub struct Udp;
impl Protocol for Udp {
    type Message = ();
    const NAME: &'static str = "udp";
    fn dispatch() -> Dispatch { Dispatch::AllUdp }
    fn parser() -> Box<dyn ProtocolParser<Message = ()>> { Box::new(NoopParser) }
}

pub struct Icmp;
impl Protocol for Icmp {
    type Message = IcmpMessage;
    const NAME: &'static str = "icmp";
    fn dispatch() -> Dispatch { Dispatch::Icmp }
    fn parser() -> Box<dyn ProtocolParser<Message = IcmpMessage>> {
        Box::new(flowscope::icmp::IcmpParser::new())
    }
}
```

`Tcp` and `Udp` are explicit protocol markers — that's how the API stays uniform across L4 and L7. The user opts in to TCP lifecycle the same way they opt in to HTTP messages: `.protocol::<Tcp>()`.

**A third-party crate** ships a new protocol by writing:

```rust
// in user-crate src/protocols.rs
pub struct Quic;
impl netring::Protocol for Quic {
    type Message = QuicInitial;
    const NAME: &'static str = "quic-initial";
    fn dispatch() -> netring::Dispatch {
        netring::Dispatch::Signature(quic_initial_signature)
    }
    fn parser() -> Box<dyn netring::ProtocolParser<Message = QuicInitial>> {
        Box::new(my_quic_parser::QuicInitialParser::new())
    }
}
```

Then `.protocol::<Quic>()` and `.on::<Quic>(|msg, _, _| ...)`. Zero edits to netring. This is the core agnosticism win.

### 6.2 Type-driven handler registration

Handlers are functions. The framework injects everything they need by type, axum-extractor-style. The single registration entry point:

```rust
impl MonitorBuilder {
    pub fn on<E, H, M>(self, handler: H) -> Self
    where
        E: Event,                      // Tcp / Udp / Http / Dns / FlowEnded<Tcp> / …
        H: Handler<E, M>,              // `M` is a coherence-marker phantom
    { /* TypeId::of::<E>() → handler stored in registry */ self }
}
```

`Event` is the trait that says "this type can fire from the monitor stream":

```rust
pub trait Event: Send + Sync + 'static {}

// Built-in events:
impl<P: Protocol> Event for P {}                  // raw protocol messages
impl<P: Protocol> Event for FlowStarted<P> {}     // typed flow start
impl<P: Protocol> Event for FlowEnded<P> {}       // typed flow end
impl Event for AnyFlowAnomaly {}                  // flowscope-side anomaly
impl Event for Tick {}                            // periodic
```

`Handler<E, M>` is the axum-blanket-impl trick over closures with N extractor parameters. **Critically, the default is synchronous** — most packet handlers don't `.await` anything (they bump counters, push to an in-memory sink) and forcing a per-event `Box::pin(async move { … })` on millions of events per second is fatal. Async is the explicit escape hatch via a second registration method.

```rust
pub trait Handler<E: Event, M>: Send + Sync + 'static {
    fn call(&self, evt: &E::Payload, ctx: &mut Ctx<'_>) -> Result<()>;
}

// 0-extractor blanket impl — sync, no allocation:
impl<E, F> Handler<E, (NoExtractor,)> for F
where
    E: Event,
    F: Fn(&E::Payload) -> Result<()> + Send + Sync + 'static,
{ fn call(&self, p: &E::Payload, _: &mut Ctx<'_>) -> Result<()> { self(p) } }

// N-extractor blanket impl, generated by macro for N=1..8 — sync, no allocation:
impl<E, F, P1, P2> Handler<E, (P1, P2)> for F
where
    E: Event,
    F: for<'a> Fn(&E::Payload, P1::Target<'a>, P2::Target<'a>) -> Result<()> + Send + Sync + 'static,
    P1: FromCtx, P2: FromCtx,
{
    fn call(&self, p: &E::Payload, ctx: &mut Ctx<'_>) -> Result<()> {
        let e1 = P1::from_ctx(ctx);
        let e2 = P2::from_ctx(ctx);
        self(p, e1, e2)
    }
}
```

The `M` phantom is the **axum coherence trick** — lets one function type `F` implement `Handler<E, (P1,)>` AND `Handler<E, (P1, P2)>` without overlap errors. The extractors are GATs over a lifetime so they can borrow from `Ctx` without an allocation. ~300 LoC of macro-generated blanket impls, no user-side macros.

The async escape hatch is a separate trait + registration method, never the default:

```rust
pub trait AsyncHandler<E: Event, M>: Send + Sync + 'static {
    fn call<'a>(&'a self, evt: &'a E::Payload, ctx: &'a mut Ctx<'a>)
        -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

// User-side:
.on::<HttpRequest>(|req, ctx: State<RequestStats>| { ctx.requests += 1; Ok(()) })  // sync, zero-alloc
.on_async::<HttpRequest>(|req, mut redis: State<RedisPool>| async move {            // async, one Box::pin per call
    redis.publish("requests", req.path.clone()).await?;
    Ok(())
})
```

The split is honest: the `on_async` registration costs a `Box::pin` per event. The plain `on` does not. Documentation says so plainly.

User experience:

```rust
// Zero extractors — just the event payload:
.on::<Http>(|msg: &HttpMessage| async move { /* … */ Ok(()) })

// One extractor — shared state:
.on::<Http>(|msg, state: State<RequestStats>| async move {
    state.lock().requests += 1;
    Ok(())
})

// Three extractors — state + sink + timestamp:
.on::<FlowEnded<Tcp>>(|evt, state: State<DropTracker>, sink: Sink<Anomaly>, ts: Now| async move {
    if matches!(evt.reason, EndReason::Rst) {
        state.lock().insert(evt.key, ts);
    }
    Ok(())
})
```

`State<T>`, `Sink<A>`, `Now`, `Counter<K>` all implement the framework's `FromCtx` trait. New extractors are written by users in ~10 LoC.

### 6.3 Injectable `Ctx` with extractor-style parameter binding

`Ctx` is the runtime-context object that lives on the stack of each dispatch call. The defaults assume a single-threaded async runtime (`tokio::current_thread`), which is the right shape for packet processing — one capture, one core, no cross-thread synchronization. Multi-threaded sharding is opt-in (one monitor per CPU via `AsyncMultiCapture`).

That assumption is load-bearing for performance: **single-threaded means no `Arc`, no `Mutex`, no atomic refcount traffic** in the hot path. Shared state is `&mut T`, not `Arc<Mutex<T>>`.

```rust
pub struct Ctx<'a> {
    pub flow:      Option<&'a FlowKey>,
    pub ts:        Timestamp,
    pub source:    SourceIdx,
    state_map:     &'a mut StateMap,     // type-keyed; &mut access for the duration of one event
    sink:          &'a mut dyn AnomalySink,
    counters:      &'a mut CounterRegistry,
}
```

Extractors are GATs that borrow from `&mut Ctx`. Their `Target<'a>` type carries the borrow:

```rust
pub trait FromCtx {
    type Target<'a>: 'a;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> Self::Target<'a>;
}

/// Shared user state keyed by type. `&'a mut T` borrowed from the
/// monitor's state map for the duration of one dispatch call.
/// `T: Default` for lazy initialization; never allocates beyond the
/// initial `Default::default()`.
pub struct State<T>(PhantomData<T>);
impl<T: Default + 'static> FromCtx for State<T> {
    type Target<'a> = &'a mut T;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> &'a mut T {
        ctx.state_map.get_or_init_mut::<T>()  // returns &mut T
    }
}

/// The anomaly sink. Borrowed; the handler writes directly to the
/// sink's pre-allocated buffer rather than constructing an
/// `Anomaly` struct that the framework then forwards.
pub struct Sink<A>(PhantomData<A>);
impl<A: 'static> FromCtx for Sink<A> {
    type Target<'a> = &'a mut dyn AnomalySink;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> &'a mut dyn AnomalySink { ctx.sink }
}

/// Current timestamp (`Copy`, no borrow).
pub struct Now;
impl FromCtx for Now {
    type Target<'a> = Timestamp;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> Timestamp { ctx.ts }
}

/// Per-key sliding-window counter. The counter's storage is
/// pre-allocated by the framework at registration; `bump` performs
/// at most one hash lookup on a pre-sized `FxHashMap` and one
/// in-place increment. No allocation on the hot path.
pub struct Counter<K>(PhantomData<K>);
impl<K: Eq + Hash + 'static> FromCtx for Counter<K> {
    type Target<'a> = &'a mut TimeBucketedCounter<K>;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> &'a mut TimeBucketedCounter<K> { ctx.counters.get_mut::<K>() }
}
```

A user adds a new extractor type by impl'ing `FromCtx` for it — say `SmallString` for stack-allocated tag values, or `RingBufWriter` for a custom output channel. The trait is small and the GAT carries the lifetime cleanly.

**The cross-extractor borrow rule:** an `&mut Ctx` can only project *one* `&mut`-extractor at a time without splitting. The Handler blanket impls handle this by calling `from_ctx` sequentially per parameter, releasing `&mut Ctx` between extractor calls. In practice this means **extractors should be designed to grab `&mut` to a field of `Ctx`, not to `Ctx` itself**. The `State<T>`, `Sink<A>`, `Counter<K>` extractors above all hit distinct `Ctx` fields, so they coexist in one handler signature without aliasing. This is enforced at compile time via field-disjoint `Ctx` projection; the macro generating the blanket impls verifies field non-overlap at registration. Errors here look like a "cannot borrow `*ctx` as mutable more than once" message, which is what the user expects from Rust.

### 6.4 Tower-style middleware

Anomalies pass through a `Service<Anomaly<K>>` pipeline before reaching the sink:

```rust
pub trait Layer<S> { type Service; fn layer(&self, inner: S) -> Self::Service; }

// Built-in layers, each ~30 LoC:
pub struct DedupeAnomalies { window: Duration, seen: HashMap<…, Instant> }
pub struct RateLimitAnomalies { per_kind: HashMap<&'static str, RateLimiter> }
pub struct MinSeverity { floor: Severity }
pub struct Sample { rate: f64 }
pub struct Tee<S2> { other: S2 }  // forward to a second sink

monitor.layer(DedupeAnomalies::within(Duration::from_secs(60)))
       .layer(MinSeverity::warning())
       .layer(Sample::probability(0.1))
       .sink(StdoutJsonSink);
```

Order is meaningful and explicit. New layers are ~50 LoC each. The user can write their own and plug it in.

### 6.5 Single-call builder, multi-interface, single tick loop

```rust
#[bon::builder]
pub struct Monitor {
    /// Multi-interface from the start. Pass `[iface]` for single.
    #[builder(into)]
    interfaces: Vec<String>,

    /// Optional kernel BPF coarse filter. Coexists with protocol slots.
    bpf: Option<BpfFilter>,

    /// Internal: built protocol registry.
    #[builder(default, with = |b| b.build())]
    protocols: ProtocolRegistry,

    /// Internal: built handler registry.
    #[builder(default, with = |b| b.build())]
    handlers: HandlerRegistry,

    /// Internal: layered sink.
    #[builder(default)]
    sink: BoxedSink,

    /// Periodic tick handlers.
    #[builder(default)]
    ticks: Vec<(Duration, TickHandler)>,
}

impl<S: Stage> MonitorBuilder<S> {
    pub fn protocol<P: Protocol>(mut self) -> Self { /* register */ self }
    pub fn on<E: Event, H, M>(mut self, handler: H) -> Self where H: Handler<E, M> { /* register */ self }
    pub fn layer<L: Layer<…>>(mut self, layer: L) -> Self { /* wrap sink */ self }
    pub fn sink<S2: AnomalySink>(mut self, sink: S2) -> Self { /* set */ self }
    pub fn state<T: Default + Send + Sync + 'static>(mut self) -> Self { /* register */ self }
    pub fn tick<H, M>(mut self, period: Duration, handler: H) -> Self where H: TickHandler<M> { /* register */ self }
}

impl Monitor {
    /// Run until a deadline.
    pub async fn run_until(self, deadline: Instant) -> Result<()> { /* … */ }
    /// Run for a duration.
    pub async fn run_for(self, d: Duration) -> Result<()> { /* … */ }
    /// Run until SIGINT/SIGTERM.
    pub async fn run_until_signal(self) -> Result<()> { /* … */ }
    /// Stream mode for power users who want the raw event stream.
    pub fn into_stream(self) -> impl Stream<Item = Result<Event>> { /* … */ }
}
```

Three terminators (`run_until` / `run_for` / `run_until_signal`) plus `into_stream` for the rare case where a user really does want a `Stream`. The 90% case never sees a `Stream`.

### 6.6 `detector!` macro for declarative stateless rules

For the long tail of "match this shape, emit this anomaly":

```rust
let truncated_tls = detector! {
    name: "TruncatedTls",
    severity: Warning,
    matches: <TlsHandshake>(hs) if hs.outcome == HandshakeOutcome::Truncated,
    emit: |hs, key, ts| Anomaly::warn("TruncatedTls", ts)
        .with_key(key)
        .with("sni", hs.sni.as_deref().unwrap_or("")),
};

monitor.detect(truncated_tls);
```

Expands to a `Handler<TlsHandshake, _>` implementing a `if let … {} else { return Ok(()) }` shape. ~150 LoC `macro_rules!`. Closes most of the Suricata terseness gap for stateless rules.

### 6.7 Internal: TypeId-keyed handler registry, type-erased dispatch

The implementation backbone — never user-facing:

```rust
struct HandlerRegistry {
    // Per protocol/event type, a list of erased handlers.
    by_type: HashMap<TypeId, Vec<BoxedHandler>>,
}

type BoxedHandler = Arc<dyn Fn(&dyn Any, &Ctx<'_>) -> BoxFuture<'_, Result<()>> + Send + Sync>;

impl<P: Protocol> Handler<P, …> for F where … {
    // Registration erases the concrete F into a BoxedHandler that
    // downcasts `&dyn Any` → `&P::Message` and calls F.
}
```

The downcast is sound: the key is `TypeId::of::<P>()`, the value can only contain handlers expecting `&P::Message`. No fallible unwrap user-facing.

The protocol-agnostic principle holds because **adding a new `Protocol` impl in a downstream crate just inserts a new (TypeId, parser, dispatch-rule) entry into the registry**. Nothing in netring's public surface needs to know `Quic` exists.

### 6.8 The lower-level Stream API survives unchanged

The redesigned `Monitor` lives at the top. Directly beneath it, `ProtocolStream` (the renamed flowscope-`Driver`-backed stream) is unchanged for power users:

```rust
let mut stream = ProtocolStream::builder()
    .interface("eth0")
    .protocol::<Http>()
    .build()?;

while let Some(evt) = stream.next().await {
    match evt? { /* exhaustive matching for users who genuinely need it */ }
}
```

Bevy did the same: `App::add_system(fn)` is the front door; `World::iter_entities()` is available for ECS power users. Two layers, both first-class, no lies.

---

## 7. Performance: zero-allocation, zero-copy where it matters

The ergonomic API in §6 must not bleed performance. The packet path runs at millions of events per second on a saturated 10 GbE link, tens of millions on 100 GbE; per-event allocation is fatal, per-event boxing is fatal, even per-event hashing matters at the high end. This section makes the performance contract explicit and shows how each piece of the §6 design honours it.

The cardinal rule, borrowed from DPDK, smoltcp, and Suricata in roughly that order: **allocate at startup, never on the hot path.** Every allocation visible during steady-state dispatch is a bug.

### 7.1 The performance budget by call site

For each call site in the dispatch loop, here's the allocation/copy contract and how the §6 design meets it:

| Site | Today (0.18) | Proposed (0.19) | How |
|---|---|---|---|
| `next_batch()` from capture | zero-copy (mmap ring) | zero-copy (mmap ring) | unchanged |
| flowscope parser → message | one struct move | one struct move | unchanged |
| message → handler dispatch | match arm | TypeId lookup or u8-slot index | one indirect call, no allocation |
| `&Ctx` construction | n/a | stack-allocated; reused per call | no heap |
| extractor binding (`State<T>`, `Sink<A>`, ...) | n/a | `&mut` to pre-allocated state | no heap |
| handler call | direct | one indirect call via `fn`-trait | no heap, no future allocation in sync path |
| anomaly emit | `Vec<Anomaly>` returned | write directly to sink's pre-allocated buffer | no heap |
| anomaly observations | `Vec<(&str, String)>` (allocates) | `Cow<'_, str>`, `&'static str`, or sink-side small buffer | no heap for the common case |
| anomaly metrics | `Vec<(&str, f64)>` (allocates) | `ArrayVec<(&'static str, f64), 8>` | no heap |
| dispatch table lookup | `match` over enum | `slots[u8 as usize]` after build | one array index, no hash |
| inter-handler state share | n/a | `&mut T` from `Ctx::state_map` | no heap, no atomics |

Three numbers worth pinning down: **a TypeId hash is ~3ns; a vtable indirect call is ~1ns; a `Box::pin` of an async future is ~50ns plus L2 cache traffic.** Run those over 10M events/sec and you get 30ms/s, 10ms/s, 500ms/s of overhead respectively. The `Box::pin` is the only one that's a problem — that's why sync is the default in §6.2.

### 7.2 Type-erased dispatch *without* heap allocation

The §6 design uses `TypeId`-keyed handler storage for *user-facing agnosticism*. The implementation must not allocate per dispatch. The trick is to separate registration-time work (allowed to allocate, runs once) from dispatch-time work (must not allocate).

**At registration:**

```rust
// User: monitor.protocol::<Http>().on::<HttpRequest>(handler).build()
// Internal at .build() time:

struct HandlerSlot {
    /// Stable index, assigned 0..N at build time. The dispatch
    /// table is `Box<[HandlerVec]>` indexed by this u8.
    index: u8,
    /// The actual sync handler. No async box, no Arc — a plain
    /// boxed closure with field-disjoint &mut Ctx access.
    handler: Box<dyn FnMut(&dyn Any, &mut Ctx<'_>) -> Result<()> + Send>,
}

struct Dispatcher {
    /// Indexed by TypeId-of-protocol → u8 slot at build time.
    /// After build, `parser_kind → slot_index` is a tiny
    /// `&'static [(TypeId, u8)]` scanned linearly (≤16 entries).
    slot_by_type: Box<[(TypeId, u8)]>,
    /// Slot table — flat array, no hashing on the hot path.
    slots: Box<[Vec<HandlerSlot>]>,
}
```

**At dispatch:**

```rust
impl Dispatcher {
    #[inline]
    fn dispatch(&mut self, msg_type: TypeId, msg: &dyn Any, ctx: &mut Ctx<'_>) -> Result<()> {
        // Linear scan ≤16 entries (well below the FxHashMap break-even).
        let slot = self.slot_by_type.iter()
            .find(|(t, _)| *t == msg_type)
            .map(|(_, s)| *s as usize);
        let Some(idx) = slot else { return Ok(()) };

        // Array index, no hash. Handler vec usually has 1-2 entries.
        for h in &mut self.slots[idx] {
            (h.handler)(msg, ctx)?;
        }
        Ok(())
    }
}
```

Linear scan up to 16 protocols beats `FxHashMap` by ~2x on cache locality. Slot lookup is one array index. Per-event cost: ~5–10ns total on a modern x86_64. **Zero allocation on the dispatch path.**

The "downcast" inside each handler is itself a `TypeId == TypeId` compare + `*const () as *const Msg`. ~1ns. The framework emits these unconditionally; the compiler hoists the comparison across all handlers in the same slot since they share the message type.

### 7.3 The "sync first, async opt-in" rule

`Box::pin(async { … })` on every event is the single biggest hidden cost in a naive design. Most packet handlers are arithmetic on counters, byte-slice peeking, and pushing to an in-memory ring — none of which `.await`s anything. The §6 design defaults to sync:

```rust
// Default — no future allocation:
.on::<HttpRequest>(|req, mut stats: State<HttpStats>| {
    stats.request_count += 1;
    if req.method == "POST" { stats.post_count += 1; }
    Ok(())
})

// Async opt-in — one Box::pin per event, documented cost:
.on_async::<HttpRequest>(|req, mut redis: State<RedisPool>| async move {
    redis.publish("requests", req.path.clone()).await?;
    Ok(())
})
```

The `on_async` registration is for handlers that genuinely need to `.await` something — opening a Redis connection, sending to a Kafka producer, awaiting a downstream `mpsc`. For those, the Box::pin is a real cost the user chose to pay.

A subtle but important rule: **the framework polls the event Stream sync-batched, then dispatches the batch synchronously, then yields once at the batch boundary.** That means: 1024 events come off the AF_PACKET ring → all 1024 dispatch synchronously (no `.await` between them, no per-event executor work) → one `yield_now()` at the end of the batch to keep tokio cooperative. The async event-loop overhead is amortized over the whole batch.

### 7.4 No `Anomaly` struct on the hot path

The current `Anomaly<K>` value type is honest but allocation-heavy:

```rust
pub struct Anomaly<K> {
    pub kind: &'static str,
    pub severity: Severity,
    pub key: Option<K>,
    pub ts: Timestamp,
    pub context: AnomalyContext,  // Vec<(&str, String)> + Vec<(&str, f64)>
}
```

Each `with_observation("sni", value.into())` calls `value.into() → String`, which usually allocates. Each `with_metric(...)` pushes to a `Vec`, which may grow. For high-rate detectors (e.g. a port scanner that fires once per anomalous flow), this dominates.

The redesign: handlers do **not** construct an `Anomaly` value. They write directly to a pre-allocated sink-side buffer:

```rust
pub trait AnomalySink {
    /// The handler writes anomaly fields into this builder; the
    /// sink decides what to do with them at the end of the event.
    /// No `Anomaly` struct is materialized.
    fn begin(&mut self, kind: &'static str, severity: Severity, ts: Timestamp) -> AnomalyWriter<'_>;
}

pub struct AnomalyWriter<'sink> {
    sink: &'sink mut dyn AnomalySink,
    // small inline buffers; no allocation up to 8 obs + 8 metrics
    obs: ArrayVec<(&'static str, Cow<'static, str>), 8>,
    metrics: ArrayVec<(&'static str, f64), 8>,
    key: Option<&'sink (dyn Debug + 'sink)>,
}

impl<'a> AnomalyWriter<'a> {
    pub fn with_key<K: Debug>(mut self, k: &'a K) -> Self { self.key = Some(k); self }
    pub fn with(mut self, label: &'static str, value: impl Into<Cow<'static, str>>) -> Self {
        self.obs.push((label, value.into())); self
    }
    pub fn with_metric(mut self, label: &'static str, value: f64) -> Self {
        self.metrics.push((label, value)); self
    }
    pub fn emit(self) {
        self.sink.write(self.kind, self.severity, self.ts, self.key, &self.obs, &self.metrics);
    }
}
```

The user-facing API is the same builder shape:

```rust
sink.begin("icmp_explained", Severity::Warning, ts)
    .with_key(&key)
    .with("icmp_kind", label)                    // label is &'static str — zero alloc
    .with_metric("delta_ms", delta_ms)
    .emit();
```

`Cow<'static, str>` lets `&'static str` literals pass through with zero allocation; only user-built `String` values (which are rare in detectors) cost an allocation. `ArrayVec<_, 8>` inlines up to 8 observations and 8 metrics on the stack — exceeds 8 is an explicit `Result::Err` rather than a silent grow.

A subtle point: the `with_key` taking `&K` rather than `K` avoids cloning the flow key. Sinks that need to *retain* the anomaly past the event (e.g. an mpsc forwarder) clone explicitly via `key.cloned()`.

### 7.5 Per-CPU sharding for >2 Mpps

Single-core dispatch tops out around 2–3 Mpps on commodity hardware. Above that, the only answer is per-CPU sharding via `PACKET_FANOUT_CPU` (already supported by `AsyncMultiCapture`). The §6 design treats this as the default for multi-Mpps workloads:

```rust
Monitor::builder()
    .fanout_per_cpu("eth0", FanoutMode::Cpu)  // one capture ring per CPU
    .protocol::<Tcp>()
    .protocol::<Http>()
    .on::<HttpRequest>(|req, mut stats: State<HttpStats>| { ... })  // runs once per CPU
    .merge_state::<HttpStats>(|a, b| a.merge(b))                   // merges shard state at tick
    .run_until_signal()
    .await
```

Each shard has its own `Ctx`, its own `State<HttpStats>`, its own counters. Nothing crosses cores during the hot path. State is merged at tick boundaries via user-supplied `merge_state` closures — a Suricata-style design that scales linearly to 32+ cores in practice.

The trade-off: shared state needs an explicit merge closure. That's *more* code than `Arc<Mutex<HttpStats>>`, but it's also the only design that scales. The lock-based alternative caps at ~5 Mpps no matter how many cores you throw at it.

### 7.6 Zero-copy payload sharing via `Bytes`

Where parsers emit byte-slice payloads (HTTP request body, DNS rdata, TLS handshake bytes), the redesign uses `bytes::Bytes` throughout. This is already the convention in flowscope 0.10 and `tokio`/`hyper`/`tonic`. Properties that matter:

- `Bytes::clone()` is a ref-count bump (~3ns), not a memcpy.
- A handler that needs to hold the bytes past the event lifetime calls `payload.clone()` and pays one atomic — never a copy.
- A handler that just inspects bytes uses `&[u8]` borrowed from the `Bytes`; zero cost.

Where flowscope currently returns `Vec<u8>` for some payloads (legacy carry-overs from pre-0.8), the upgrade is straightforward and already on flowscope's roadmap.

### 7.7 `tracing` overhead on the hot path

`tracing::info!()` looks free but isn't — even when the level filter drops the event, there's a stack frame, an atomic load on the filter, a few hundred bytes of stack-allocated `Event`. Multiplied by 10M events/sec, that's noticeable.

The redesign uses two patterns:

1. `tracing::Span` opened once per *flow* (not per event), with handlers calling `span.record("bytes", n)` which is ~5ns.
2. Per-event `tracing::trace!()` only behind `#[cfg(feature = "trace-events")]` — off in production.

The default monitor uses zero `tracing` calls on the hot path. Sinks may opt into `tracing` output explicitly via `TracingSink`, but the default is direct sink writes.

### 7.8 Allocation audit — the verifier

This contract isn't enforceable by the type system; it needs a regression test. The redesign ships a benchmark that:

1. Generates 10M synthetic events from a pre-allocated `Vec<ProtocolEvent>`.
2. Runs them through a monitor with 3 protocols + 5 handlers + 2 middleware layers + an `Anomaly`-emitting sink.
3. Asserts `dhat::HeapStats` shows zero net allocation during the dispatch loop (after warm-up).

`dhat` (the Rust heap profiler — Valgrind-DHAT compatible) is the standard tool. The benchmark lives in `benches/zero_alloc.rs` and runs in CI. If a future change introduces an allocation, CI fails with a precise call-graph telling you where.

Suricata, Vector, and tokio's own benchmarks all do this. It's the only way to keep a zero-allocation invariant honest.

### 7.9 What about really high rates — 25/100 GbE saturation?

At 10–14 Mpps (line-rate 25 GbE with 60-byte packets), even the design above starts to hurt. Two further moves are available, not in 0.19 but worth knowing:

1. **Columnar batched events.** Instead of `&ProtocolEvent`, the dispatch path receives `&ProtocolEventBatch` — a struct of arrays (keys, timestamps, payloads in parallel `Vec`s). Handlers vectorize over the batch. This trades the trait-object indirection for SIMD-friendly tight loops. Typical 3–5x throughput win. Real work; defer to 1.0.

2. **AF_XDP zero-copy busy-polling, single-CPU.** Pin the monitor to one CPU, busy-poll the XDP ring (no `wait_readable()`), bypass tokio entirely. 200 ns/packet end-to-end is achievable. The trade-off is one core burning at 100% even when there's no traffic. Already supported via `XdpSocketBuilder::busy_poll`; the high-level `Monitor` builder should expose it as `.busy_poll_mode()`.

Neither is needed for the 90% case — a Kubernetes monitor on a 1 GbE service interface handles 100k pps with the standard design and never breaks a sweat. The 25/100 GbE deep end is documented in `docs/scaling.md` and reserved for genuine line-rate users.

### 7.10 Summary of the performance contract

The 0.19 design must hold these invariants:

1. **No allocation during steady-state dispatch.** Verified by `dhat`-based benchmark in CI.
2. **No atomic operations during sync handler dispatch** (per-CPU sharding, no Arc/Mutex by default).
3. **No future boxing in the sync handler path.** `Box::pin` is only paid by handlers explicitly registered via `on_async`.
4. **Payload sharing is `Bytes`, not `Vec<u8>` copies.**
5. **Dispatch table is array-indexed**, not hashed, after `.build()`.
6. **Anomaly observations are `Cow<'static, str>`** so literals stay free.
7. **State is `&mut T`** by default; cross-CPU sharing requires explicit merge.

These aren't aspirational — they're enforceable in CI. If 0.19 ships without the allocation-audit benchmark, the design failed. If 0.20 introduces a `tracing` call on the hot path, CI catches it.

---

## 8. The Kubernetes monitor, rewritten

The detector from §2, in the proposed API. **All closures are sync — no `async move`, no `Box::pin` on the hot path.** State is `&mut T`, not `Arc<Mutex<T>>`. Anomalies are emitted via the sink writer (§7.4), not by constructing `Anomaly` structs. This is the *whole* program — not a sketch.

```rust
use netring::prelude::*;
use std::collections::HashMap;
use std::time::Duration;

/// Shared state: recently-RST or idle-timed-out TCP flows, waiting
/// for a possible ICMP error to correlate. Pre-sized at startup to
/// avoid HashMap growth allocations during steady state.
struct DroppedFlows {
    inner: FxHashMap<FlowKey, Timestamp>,
}

impl Default for DroppedFlows {
    fn default() -> Self {
        Self { inner: FxHashMap::with_capacity_and_hasher(1024, Default::default()) }
    }
}

impl DroppedFlows {
    fn insert(&mut self, key: FlowKey, ts: Timestamp) {
        self.inner.insert(key, ts);
    }
    fn take_within(&mut self, key: &FlowKey, now: Timestamp, ttl: Duration) -> Option<Timestamp> {
        let ts = self.inner.get(key)?;
        if (now - *ts) < ttl {
            self.inner.remove(key)
        } else {
            None
        }
    }
    fn evict_expired(&mut self, now: Timestamp, ttl: Duration) {
        self.inner.retain(|_, ts| (now - *ts) < ttl);
    }
}

#[tokio::main(flavor = "current_thread")]  // single-threaded — no Arc/Mutex on the hot path
async fn main() -> netring::Result<()> {
    let iface = std::env::var("IFACE").unwrap_or_else(|_| "eth0".into());

    Monitor::builder()
        .interface(iface)
        .protocol::<Tcp>()
        .protocol::<Udp>()
        .protocol::<Icmp>()
        .state::<DroppedFlows>()  // registers + Default-initializes; never reallocates after build

        // Stash any RST / idle-timeout TCP flow for correlation.
        // Sync handler — &mut DroppedFlows borrowed from Ctx; no Arc, no future allocation.
        .on::<FlowEnded<Tcp>>(|evt, dropped: State<DroppedFlows>| {
            if matches!(evt.reason, EndReason::Rst | EndReason::IdleTimeout) {
                dropped.insert(evt.key, evt.ts);
            }
            Ok(())
        })

        // ICMP error: look up matching dropped TCP/UDP flow, classify.
        // Writes directly to sink via AnomalyWriter — no Anomaly struct materialized.
        .on::<Icmp>(|msg, ts: Now, dropped: State<DroppedFlows>, sink: Sink<()>| {
            let Some((kind_label, inner)) = msg.ty.error_inner() else { return Ok(()) };
            let inner_key = key_from_inner(inner);
            if let Some(dropped_ts) = dropped.take_within(&inner_key, ts, Duration::from_secs(5)) {
                sink.begin("icmp_explained", Severity::Warning, ts)
                    .with_key(&inner_key)
                    .with("icmp_kind", kind_label)          // &'static str — zero alloc
                    .with_metric("delta_ms", (ts - dropped_ts).as_millis() as f64)
                    .emit();
            } else {
                sink.begin("icmp_orphan", Severity::Info, ts)
                    .with_key(&inner_key)
                    .with("icmp_kind", kind_label)
                    .emit();
            }
            Ok(())
        })

        // UDP DNS query burst: tag CoreDNS resolution storms.
        // Counter<IpAddr> is pre-allocated; bump is one hash lookup + atomic increment.
        .on::<FlowStarted<Udp>>(|evt, counts: Counter<IpAddr>, sink: Sink<()>| {
            if evt.key.b.port() == 53 {
                let src = evt.key.a.ip();
                counts.bump_in_window(src, evt.ts, Duration::from_secs(10));
                let n = counts.in_window(&src, evt.ts, Duration::from_secs(10));
                if n > 100 {
                    sink.begin("dns_query_burst", Severity::Warning, evt.ts)
                        .with_key(&evt.key)
                        .with_metric("queries_10s", n as f64)
                        .emit();
                }
            }
            Ok(())
        })

        // Periodic L4 totals — printed every 10 seconds.
        // Tick handlers can be sync too; they run on the tokio interval timer.
        .tick(Duration::from_secs(10), |stats: Stats<L4Proto>| {
            for (l4, c) in stats.by_l4() {
                println!("[10s] {l4}: started={} ended={}", c.started, c.ended);
            }
            Ok(())
        })

        // Periodic cleanup of the dropped-flows cache.
        .tick(Duration::from_secs(30), |dropped: State<DroppedFlows>, ts: Now| {
            dropped.evict_expired(ts, Duration::from_secs(60));
            Ok(())
        })

        // Middleware: dedupe identical anomalies within 60s,
        // suppress sub-Warning noise.
        .layer(DedupeAnomalies::within(Duration::from_secs(60)))
        .layer(MinSeverity::warning())

        // Structured JSON sink — writes one line per anomaly to stdout.
        // Sink-side buffer is pre-allocated; no per-anomaly allocation.
        .sink(StdoutJsonSink::with_capacity(4096))

        .build()?
        .run_until_signal()
        .await
}

fn key_from_inner(i: &IcmpInner) -> FlowKey {
    FlowKey::from_5tuple(i.src, i.dst, i.src_port, i.dst_port, i.proto)
}
```

That's ~90 lines including the helper struct, fully implementing the §2 scenario. The equivalent today is ~260 lines (`icmp_explained_drop.rs` + manual L4 counters + manual DNS burst tracker + manual sink).

**Allocation profile of the loop above, under load:**

- Each event: zero allocation. Dispatch is array-indexed; extractors borrow from `Ctx`; handlers call sync; sink writer uses `ArrayVec` inlined on the stack; `StdoutJsonSink` writes into a pre-allocated 4 KiB buffer it owns.
- Each anomaly emit: zero allocation when observations are `&'static str` literals (the common case). `Cow` makes user-built strings only-allocate when actually needed.
- Each tick: zero allocation. The println! formatting goes through a stack buffer; only the eventual stdout write touches the kernel.
- Each batch of 1024 events: one `yield_now()` to the executor. No batch-level allocation.

A `dhat` baseline on this program at 1 Mpps should show **zero net heap delta after warm-up** — exactly the contract from §7.10.

Read top to bottom: it's a sequence of declarations. *"For TCP flow ends, remember the dropped ones. For ICMP errors, correlate. For UDP DNS bursts, alert. Tick every 10s, every 30s. Dedupe, floor at Warning, output JSON, run forever."* Every line carries weight; nothing is bookkeeping.

This is the design target.

---

## 9. Implementation phases

With BC off the table, the redesign can ship as one big release — but it doesn't have to ship all at once. A reasonable phasing:

### Phase A — `Protocol` trait + `TypeId` registry (5–7 days)

Foundation. Refactor `ProtocolMessage` from a closed enum to a `TypeId`-keyed registry. Add `pub trait Protocol`, define `struct Tcp`, `struct Udp`, `struct Icmp`, `struct Http`, `struct Dns`, `struct Tls`, `struct TlsHandshake` as markers. Update the internal driver to dispatch by TypeId. The Stream API still exists; it now yields a richer `Event` enum that includes typed messages via downcast helpers.

**No user-facing API change yet** — the Stream still works, just internally restructured. Tests still pass.

### Phase B — `Handler` trait + sync closure registration (4–6 days)

Add `Monitor::builder()` with `bon`. Add `Handler<E, M>` blanket impls for plain `Fn` with 0..8 extractor parameters (**sync default**, see §7.3). Implement `FromCtx` for `State<T>`, `Sink<A>`, `Now`, `Counter<K>` as borrows from `Ctx` (no `Arc<Mutex<T>>`, see §7.1 row "inter-handler state share"). The closure-based `.on::<E>(handler)` lands. The Stream API stays alongside.

### Phase C — Performance hardening (3–4 days)

Three deliverables that pin down the perf contract before more features land on top:

1. **Allocation-audit benchmark** (`benches/zero_alloc.rs`). 10M synthetic events, 3 protocols, 5 handlers, 2 layers; `dhat` heap profiler asserts zero net delta during steady-state dispatch. Wired into CI.
2. **`AnomalyWriter` sink-side API** (§7.4). Replaces `Anomaly<K>` construction with `sink.begin(...).with(...).emit()`. `ArrayVec`-backed inline storage, `Cow<'static, str>` observations.
3. **Array-indexed dispatch table** (§7.2). Slot indexes computed at `.build()`; runtime dispatch is `slots[u8 as usize]` after a ≤16-entry linear `TypeId` scan. Replaces the naive `HashMap<TypeId, _>` first sketch.

Without this phase, phases D/E/F risk locking in allocations the user-facing API can never escape.

### Phase D — Async escape hatch + middleware (3–4 days)

`on_async::<E>(handler)` separate registration (§6.2). Implement `Layer` + the five shipped layers: `DedupeAnomalies`, `RateLimitAnomalies`, `MinSeverity`, `Sample`, `Tee`. Wire `Monitor::builder().layer(...).sink(...)` through `tower::ServiceBuilder`. The five layers are themselves zero-alloc on the no-fire path.

### Phase E — `detector!` macro + prelude + multi-interface (3–4 days)

- `macro_rules!` `detector!` for the stateless half.
- `netring::prelude` re-exporting the canonical 12 types.
- New umbrella `monitor` Cargo feature.
- `.interfaces([...])` constructor variant via `AsyncMultiCapture`. Events tagged with `source: SourceIdx`.

### Phase F — Per-CPU sharding (3–4 days)

`.fanout_per_cpu("eth0", FanoutMode::Cpu)` builder method (§7.5). One monitor instance per core, per-CPU `State<T>` and `Counter<K>` instances, `merge_state::<T>(|a, b| ...)` for tick-time merging. The high-PPS deep-end answer; only needed for users above ~2 Mpps but landing it in 0.19 means the API never has to reshape for it later.

### Phase G — Migration + docs (4–5 days)

- Rewrite all 13 anomaly examples in the new API.
- New `WRITING_DETECTORS.md` (or rename to `MONITORING.md`).
- Migration guide: 0.18 → 0.19 with mechanical recipes.
- `docs/performance.md` documenting the §7 contract for users.
- Tag and ship 0.19.0.

**Total: 25–34 days of focused work.** Ships as netring 0.19.0. The 0.18 → 0.19 migration guide does the hand-holding.

---

## 10. What we explicitly don't break

The redesign is large but bounded. Things that stay verbatim:

- **AF_PACKET / AF_XDP capture surface**: `Capture`, `CaptureBuilder`, `AsyncCapture`, `BpfFilterBuilder`, `XdpSocket`. All unchanged.
- **flowscope as the engine**: no upstream changes required for 0.19. (Phase A could optionally push the TypeId-keyed slot registry into flowscope itself for 0.20+, but doesn't have to.)
- **PCAP/PCAP-NG read/write**: `AsyncPcapSource`, `PcapTap` unchanged.
- **Flow extraction shape**: `FiveTupleKey`, `FlowEvent`, `EndReason`, `FlowStats`. The new event types are *layered on top* of these; they're not replaced.
- **The Stream API**: `ProtocolStream` (renamed from `ProtocolMonitor`) keeps the `Stream<Item = Result<Event, Error>>` shape for power users.
- **Correlation primitives**: `KeyIndexed`, `TimeBucketedCounter`, `BurstDetector`, etc. — these are in flowscope and survive untouched.
- **Anomaly value type**: `Anomaly<K>`, `Severity`, `AnomalyContext`. The shape is right; only the *registration* pattern changes.

The "redesign" is **only** the user-facing event-handling layer. Everything else stays.

---

## 11. Comparison: today vs proposed, side by side

The same simple "watch HTTP" requirement in each API:

```rust
// netring 0.18 (the world today)
use netring::flow::extract::FiveTuple;
use netring::protocol::{ProtocolEvent, ProtocolMessage, ProtocolMonitorBuilder};
use flowscope::http::HttpMessage;
use futures::StreamExt;

let mut monitor = ProtocolMonitorBuilder::new()
    .interface("eth0")
    .flow()
    .http()
    .build(FiveTuple::bidirectional())?;
while let Some(evt) = monitor.next().await {
    if let Ok(ProtocolEvent::Message {
        message: ProtocolMessage::Http(HttpMessage::Request(req)), ..
    }) = evt { println!("{} {}", req.method, req.path); }
}
```

```rust
// netring 0.19 (proposed) — sync handler, zero alloc per request
use netring::prelude::*;

Monitor::builder()
    .interface("eth0")
    .protocol::<Http>()
    .on::<HttpRequest>(|req| { println!("{} {}", req.method, req.path); Ok(()) })
    .run_until_signal()
    .await?;
```

The proposed version has:
- No `Result` matching boilerplate at the user site.
- No nested pattern unwrapping.
- No `use flowscope::...` — flowscope is an implementation detail.
- Typed dispatch: `HttpRequest` IS the type the closure receives; no `HttpMessage::Request(req)` ceremony.
- Single terminator (`run_until_signal()`) — no `while let`, no deadline arithmetic for the trivial case.
- **Sync closure — zero `Box::pin` per request.** The whole hot path of this program is allocation-free under steady state.

This is the standard the rest of the API should meet.

---

## 12. Risks and what to watch

The redesign is bold but not reckless. The real risks:

1. **The `Fn`-blanket-impl coherence is fragile.** axum has hit and fixed several coherence issues over the years; netring should expect to hit them too. Mitigate by locking the handler signature to `(payload, extractor_1, ..., extractor_n)` for the public API; never accept variant shapes (no `Fn(&Payload)` *and* `Fn(payload)`). Lock it down once, never change it.
2. **`TypeId`-keyed downcasts forbid lifetime-parameterized messages.** `HttpMessage<'pkt>` would not work. Mitigate: messages are owning, like they already are today. This is a constraint not a regression.
3. **`bon` builders explode compile times.** Worth a baseline benchmark before committing. Fallback: hand-write the typestate for `MonitorBuilder` (its surface is small enough — ~6 stages).
4. **The middleware story risks user confusion about ordering.** `DedupeAnomalies` after `MinSeverity` behaves differently from before. Mitigate: write a "common middleware orderings" doc; ship a `RecommendedLayers` convenience that bundles dedupe + min-severity in the operationally-correct order.
5. **Third-party `Protocol` impls might dispatch to overlapping ports.** Two crates each registering `.protocol::<Http>()` and `.protocol::<MyHttp>()` on port 80. Mitigate: dispatch conflict detection at `.build()` time, return a typed `BuildError::DispatchConflict { ports, protocols }`.
6. **Long-tail users who built complex `AnomalyRule` types lose them.** Need a migration shim: `AnomalyRule::as_handler<P>()` adapter that lets old rules plug into the new monitor for one release. Ship in `netring-compat` if helpful.

The performance-specific risks (§7) deserve their own callouts:

7. **The sync-handler-by-default rule will frustrate users who reflexively reach for `async`.** Mitigate with crystal-clear `on` vs `on_async` documentation; the migration guide includes explicit recipes for "I have an async detector — what do I do?" The `on_async` registration is genuinely available, just opt-in.
8. **The single-threaded-runtime assumption rules out `tokio::main` with default flavor.** Users who put `#[tokio::main]` without `flavor = "current_thread"` will silently lose perf to atomic refcount traffic on `Sink` and `State` projection. Mitigate: detect multi-threaded runtime at `.build()` time and emit a `tracing::warn!` once, plus document `current_thread` as the default in every example.
9. **The allocation-audit benchmark will be brittle.** `dhat` reports change with rustc versions; some allocations come from `tokio`'s scheduler, not netring. Mitigate: gate the assertion to a tolerance window (`net allocation delta < 1 KiB after 100k events`) rather than absolute zero; document the methodology in `docs/performance.md` so future maintainers don't paper over real regressions.
10. **`ArrayVec<_, 8>` for observations + metrics is a hard cap.** Detectors that produce 9+ observations fail at runtime. Mitigate: explicit `Result::Err(AnomalyError::TooManyObservations)` from the writer, plus a documented `AnomalyWriter::overflow_into_heap()` escape hatch for the genuine outlier case.
11. **The "merge per CPU" state model demands user merge closures.** Forgetting to register `merge_state::<HttpStats>(|a, b| a.merge(b))` for sharded state means the daemon reports per-CPU partial counts only. Mitigate: `.build()` rejects sharded configurations whose registered `State<T>` lacks a merge function unless `T: Default + AddAssign` (auto-merged) or the user explicitly opts in to `per_cpu_only::<T>()`.

None of these are fatal. All are tractable with the engineering budget already estimated in §9.

---

## 13. Closing

The 0.18 release shipped the right architecture. The 0.19 release should ship the right *user-facing surface for that architecture* — protocol-agnostic, Rust-idiomatic, **and zero-allocation on the hot path.** The three constraints are mutually reinforcing once you understand they're not in tension: type-erased dispatch can be free with the right registration-time work; closure handlers can be sync by default; state injection can be `&mut T` instead of `Arc<Mutex<T>>`. Ergonomics and performance are the same problem solved twice.

The principles, restated:

1. **The library is protocol-agnostic.** HTTP, DNS, TLS, ICMP are plugins on equal footing with anything a downstream user wants to add. The framework doesn't carve out special cases. Dispatch is type-driven via `TypeId`; third parties register new protocols in their own crates.
2. **Handlers are functions, not trait impls.** Stateless handlers are 3-line closures; stateful ones get extractor-injected state via the axum-style `FromCtx` GAT trait.
3. **The hot path allocates nothing.** Sync handlers by default, `&mut T` state, `Cow<'static, str>` observations, `ArrayVec` inline storage, array-indexed dispatch slots. Verified by a `dhat`-gated CI benchmark.
4. **Async and multi-threaded are opt-in, never default.** `on_async` for handlers that genuinely `.await`; `fanout_per_cpu` for users above 2 Mpps; everyone else stays on the zero-cost path.

What this revision adds over the previous ones:

1. **The `Protocol` trait + TypeId registry** as the agnosticism mechanism — third parties plug in new protocols without forking. (Revision 2)
2. **`Handler<E, M>` blanket impls** as the registration mechanism — handlers are functions, not trait impls. Stateless handlers are 3-line closures; stateful ones get extractor-injected state. (Revision 2)
3. **The Kubernetes ICMP+TCP+UDP scenario** as the litmus test — a real production rule that goes from 260 LoC of bookkeeping to ~90 LoC of declarations. (Revision 2)
4. **The performance contract** (§7) as an enforceable invariant — sync-first handlers, sink-side anomaly writers with `ArrayVec`/`Cow`, array-indexed dispatch slots, `&mut T` state, per-CPU sharding for the high-PPS deep end, plus a `dhat`-gated CI benchmark. (Revision 3 — this one)
5. **Concrete phasing** — seven phases, 25–34 working days, one breaking release. Phase C is now the perf-hardening phase explicitly, sandwiched between the bare-bones registration in Phase B and the feature surface in D/E/F/G.

The library has a real wedge today: nobody else in Rust combines zero-copy AF_PACKET/AF_XDP capture, a unified L4+L7 event stream, a stateful detector framework, *and* a zero-allocation hot path, in one crate. The 0.19 redesign is the opportunity to make that wedge feel *modern* — to make netring read like 2026 axum at the API layer and like 2026 DPDK at the perf layer, rather than 2022 trait-and-builder-and-match plus 2022 `Box`-everywhere.

The architecture is already there. The grammar is what's left to write — *and the grammar has to honour the perf budget*.
