# netring 0.20 — unified-`Driver<E, M>` refactor (closes N5 + N6)

**Date:** 2026-06-07
**Author:** netring maintainer
**Status:** 📝 drafted; await 0.17 (= 0.19 plan file) lockstep bump
**Predecessor:** [`netring-0.19-flowscope-0.10-bump-2026-06-07.md`](./netring-0.19-flowscope-0.10-bump-2026-06-07.md)

**Driven by:** flowscope 0.10's centerpiece plan 116 — unified
`Driver<E, M>` + `Event<K, M>` + `driver_unified::Pipeline`.
Also closes the long-deferred netring items:

- **N5** (driver refactor) from
  [`netring-0.16-roadmap-2026-05-29.md`](./netring-0.16-roadmap-2026-05-29.md)
  — netring's hand-rolled session/datagram stream state machines
- **N6** (single-ring fan-out) from the same roadmap — the
  "ProtocolMonitor opens N captures" memory cost
- **O2** (driver refactor) and **O1** (broadcast(n)) from
  [`netring-0.18-roadmap-2026-06-03.md`](./netring-0.18-roadmap-2026-06-03.md)

flowscope 0.10 shipped both halves of the long-blocked work: the
multi-parser driver (closes N6/O1) **and** the migration
recipe to drop netring's bespoke session/datagram drivers in
favour of flowscope's (closes N5/O2). One refactor cycle in
netring absorbs all four.

**Scope rule:** internal refactor; the public
`ProtocolMonitor` / `ProtocolEvent` / `AnomalyMonitor` /
`AnomalyRule` API stays compatible for end-user code where
possible. Pre-1.0, so breaking changes on `ProtocolEvent` /
`ProtocolMessage` are acceptable if the win justifies it.

---

## TL;DR — what changes

| What | Before | After |
|---|---|---|
| **Ring count** for an N-protocol monitor | N `AsyncCapture`s + N kernel BPF filters | **1** `AsyncCapture` + N user-side parser slots |
| **netring's session_stream.rs** | ~880 LoC hand-rolled state machine | ~30 LoC wrapper around `flowscope::driver_unified::Driver` |
| **netring's datagram_stream.rs** | ~505 LoC hand-rolled state machine | ~30 LoC wrapper |
| **ProtocolMonitor's internal wiring** | `Vec<BoxedEventStream<K>>` + round-robin polling | One driver, one event stream |
| **netring::ProtocolEvent\<K\>** | Custom sum-type wrapping FlowEvent + ProtocolMessage | Re-export / thin wrapper around `flowscope::driver_unified::Event<K, M>` |
| **netring::ProtocolMessage** | netring-owned enum | Either kept (light) or replaced by `M` parameter wired in |

**Net code change:** ~1300 LoC deleted, ~400 LoC added.
**Net memory cost** for a 5-protocol monitor (flow + http + dns +
tls + icmp): 5× ring → 1× ring. Linux kernel `tpacket_v3`
ring is typically 16-32 MiB per capture; 5× becomes 1×. For
embedded / dense multi-tenant boxes, this is the win.

---

## At a glance — work breakdown

| # | Item | Tier | Touch points |
|---|---|---|---|
| **U1** | Adopt `flowscope::driver_unified::Driver<E, M>` internally in `ProtocolMonitor` | **High** | `protocol/monitor.rs` rewrite |
| **U2** | Migrate `netring::ProtocolEvent<K>` to wrap `flowscope::Event<K, M>` | **High** | `protocol/event.rs` rewrite + ~50 consumer sites in examples/tests |
| **U3** | Migrate `netring::ProtocolMessage` to a small "lift" enum over the parser outputs | **High** | `protocol/event.rs` |
| **U4** | Delete `netring/src/async_adapters/session_stream.rs` (~880 LoC) | **Med** | Source deletion + acceptance tests pass |
| **U5** | Delete `netring/src/async_adapters/datagram_stream.rs` (~505 LoC) | **Med** | Same |
| **U6** | Replace netring's `flow_stream` / `session_stream` / `datagram_stream` constructors with wrappers around `flowscope::driver_unified::Driver` | **High** | `lib.rs` re-exports + `async_adapters/` glue |
| **U7** | Update `pcap_flow.rs` (`PcapFlowStream` / `PcapSessionStream` / `PcapDatagramStream`) similarly | **Med** | `pcap_flow.rs` |
| **U8** | Switch `AnomalyMonitor` API surface to `flowscope::Event<K, M>` directly (collapse `ProtocolEvent`) **or** keep `ProtocolEvent` as a thin alias for backwards compat | **High** | `anomaly/*.rs` + every example detector |
| **U9** | Heuristic routing: `ProtocolMonitorBuilder::heuristic()` exposes flowscope's signature-based dispatch | **Med** | `protocol/monitor.rs` |
| **U10** | Update `WRITING_DETECTORS.md` to reflect the new shape | Polish | `docs/WRITING_DETECTORS.md` |
| **U11** | CHANGELOG + version bump 0.17 → 0.18 | **High** | `CHANGELOG.md` + `Cargo.toml` |

---

## U1. Adopt `Driver<E, M>` internally

flowscope 0.10's centerpiece is:

```rust
let driver = Driver::builder(FiveTuple::bidirectional())
    .session_on_ports(HttpParser::default(), &[80, 8080], |m| MyMsg::Http(m))
    .session_on_ports(TlsParser::default(),  &[443],      |m| MyMsg::Tls(m))
    .datagram_on_ports(DnsUdpParser::with_correlation(), &[53], |m| MyMsg::Dns(m))
    .datagram_broadcast(IcmpParser::default(), |m| MyMsg::Icmp(m))
    .build();

while let Some(view) = source.next() {
    for ev in driver.track(&view)? {
        match ev {
            Event::FlowStarted { key, .. } => …,
            Event::Message { key, message, parser_kind, .. } => match message {
                MyMsg::Http(http) => …,
                MyMsg::Dns(dns) => …,
                MyMsg::Tls(tls) => …,
                MyMsg::Icmp(icmp) => …,
            },
            Event::FlowEnded { key, reason, l4, .. } => …,
            _ => {}
        }
    }
}
```

`ProtocolMonitor` becomes a tokio adapter over exactly this
shape:

```rust
pub struct ProtocolMonitor<K> {
    inner_capture: AsyncCapture,           // ONE ring, no filter
    driver: Driver<E, M>,                  // owns the per-parser slots + tracker
    pending: VecDeque<Event<K, M>>,        // batch buffer
}
```

Each `poll_next` either drains `pending` or pulls a new batch
from `inner_capture` and calls `driver.track(&view)` for each
packet.

### Acceptance gate

`tests/anomaly_monitor_smoke.rs` passes — no rule needs to
change. `tests/anomaly_pcap_replay.rs` passes — likewise. The
existing rules just iterate `Event<K, M>` instead of
`ProtocolEvent<K>` (or `ProtocolEvent<K>` becomes a type alias).

## U2 + U3. Collapse `ProtocolEvent` / `ProtocolMessage` onto flowscope's `Event<K, M>`

Two paths:

### Path A — type aliases (lightweight, backward-compat)

```rust
pub type ProtocolEvent<K> = flowscope::driver_unified::Event<K, ProtocolMessage>;

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum ProtocolMessage {
    #[cfg(feature = "http")]
    Http(flowscope::http::HttpMessage),
    #[cfg(feature = "dns")]
    Dns(flowscope::dns::DnsMessage),
    #[cfg(feature = "tls")]
    Tls(flowscope::tls::TlsMessage),
    #[cfg(feature = "tls")]
    TlsHandshake(flowscope::tls::TlsHandshake),
    #[cfg(feature = "icmp")]
    Icmp(flowscope::icmp::IcmpMessage),
}
```

netring users keep writing `ProtocolEvent<K>` and
`ProtocolMessage::Dns(_)`. The match shapes change slightly
because `Event<K, M>` has different variant names — see the
flowscope migration mapping table:

| Old (netring `ProtocolEvent`) | New (`Event<K, M>`) |
|---|---|
| `ProtocolEvent::Flow(FlowEvent::Started { … })` | `Event::FlowStarted { … }` |
| `ProtocolEvent::Flow(FlowEvent::Ended { … })` | `Event::FlowEnded { … }` |
| `ProtocolEvent::Message { kind: "dns-udp", message: ProtocolMessage::Dns(_), … }` | `Event::Message { parser_kind: DNS_UDP, message: ProtocolMessage::Dns(_), … }` |

Detector code needs to be touched but mechanically. Acceptable.

### Path B — drop the alias, expose `Event<K, M>` directly

```rust
pub use flowscope::driver_unified::Event as ProtocolEvent;
```

Users write `Event<K, M>` (or `ProtocolEvent` via the alias).
Slightly cleaner; same migration burden for detectors.

**Recommend Path A** — the alias keeps existing code paths
discoverable and gives us flexibility to add netring-side
fields later (e.g. capture metadata) without forcing another
breaking change.

## U4 + U5. Delete `session_stream.rs` and `datagram_stream.rs`

These are ~1400 LoC of hand-rolled state machine that duplicate
what `FlowSessionDriver` / `FlowDatagramDriver` (and now the
unified `Driver`) handle. flowscope 0.10's migration recipe
covers the exact replacement.

### Preservation work

Any tests in `session_stream.rs` / `datagram_stream.rs` that
exercise scenarios not already covered by flowscope's own
driver tests should be lifted into `tests/`:

- The FIN-with-residual-bytes drain semantics
- The RST-drops-reassembler semantics
- The BufferOverflow vs Application event ordering

flowscope's `tests/session_driver_*.rs` already cover most of
these; verify before deleting netring's.

### Public-API impact

`netring/src/lib.rs` re-exports:

```diff
- pub use async_adapters::session_stream::SessionStream;
- pub use async_adapters::datagram_stream::DatagramStream;
+ pub use protocol::{ProtocolStream};  // new — wraps Driver<E, M>
```

`SessionStream` / `DatagramStream` users (if any external; we
control all current consumers) need to migrate. The new
`ProtocolStream<E, M>` is the unified replacement.

### Backwards compat

Keep `SessionStream<S, E, F>` and `DatagramStream<S, E, P>` as
**type aliases** to `ProtocolStream` shapes for one release.
Document as deprecated. Remove in the *next* release after.

## U6. `flow_stream` / `session_stream` / `datagram_stream` wrappers

The user-facing entry points stay:

```rust
let stream = cap.flow_stream(FiveTuple::bidirectional());
let stream = cap.session_stream(FiveTuple::bidirectional(), HttpParser::default());
let stream = cap.datagram_stream(FiveTuple::bidirectional(), DnsUdpParser::with_correlation());
```

Internally, each constructs a `Driver` with one slot configured
and wraps it.

Multi-parser entry: `cap.protocol_monitor_builder()` returns a
`ProtocolMonitorBuilder` that mirrors flowscope's
`Driver::builder` API but stays in netring's idiom (less
flowscope-coupling visible to users):

```rust
let monitor = cap.protocol_monitor()
    .flow()
    .http()           // → driver.session_on_ports(HttpParser, [80, 8080], lift)
    .dns()            // → driver.datagram_on_ports(DnsUdpParser, [53], lift)
    .tls_handshake()  // → driver.session_on_ports(TlsHandshakeParser, [443], lift)
    .icmp()           // → driver.datagram_broadcast(IcmpParser, lift)
    .build();
```

The `lift` closure is internal to the builder.

## U7. Pcap stream wrappers

Same shape for the pcap-side wrappers:

```rust
let stream = source.flow_events(FiveTuple::bidirectional());
let stream = source.sessions(FiveTuple::bidirectional(), HttpParser::default());
let stream = source.datagrams(FiveTuple::bidirectional(), DnsUdpParser::with_correlation());
```

These constructors stay; internals adopt the unified driver.

`AsyncPcapSource::protocol_monitor()` ships as a new builder
entry for multi-protocol pcap replay — fulfills the deferred
`netring-0.18-roadmap` O9 (`ProtocolMonitorBuilder::pcap(path)`)
and supersedes the manual "open twice + merge by timestamp"
pattern in `examples/anomaly/pcap_replay_multi.rs`.

The old example can be reduced to a comment pointing at
`ProtocolMonitorBuilder::pcap(...)` or rewritten to use it.

## U8. `AnomalyRule` over `Event<K, M>`

`AnomalyRule<K>` today is:

```rust
pub trait AnomalyRule<K>: Send {
    fn name(&self) -> &'static str;
    fn observe(&mut self, evt: &ProtocolEvent<K>, emit: &mut Vec<Anomaly<K>>);
    fn on_tick(&mut self, now: Timestamp, emit: &mut Vec<Anomaly<K>>) {}
}
```

If `ProtocolEvent<K>` is a type alias for `Event<K, M>` (path A
above), the trait signature is unchanged. If we expose
`Event<K, M>` directly, the trait gains an `M` generic:

```rust
pub trait AnomalyRule<K, M>: Send {
    fn name(&self) -> &'static str;
    fn observe(&mut self, evt: &Event<K, M>, emit: &mut Vec<Anomaly<K>>);
    fn on_tick(&mut self, now: Timestamp, emit: &mut Vec<Anomaly<K>>) {}
}
```

This adds a generic that detectors then have to thread through
their `impl` block. Mild inconvenience. Sticks with Path A.

### Detector migration

Each rule body needs the variant-name shift (Started →
FlowStarted, etc.) and the `kind` → `parser_kind` field rename.
Per-example diff:

```diff
- ProtocolEvent::Flow(FlowEvent::Started { key, l4, ts, .. }) => {
+ Event::FlowStarted { key, l4, ts, .. } => {
      // … unchanged …
  }
- ProtocolEvent::Flow(FlowEvent::Ended { key, reason, stats, l4, .. }) => {
+ Event::FlowEnded { key, reason, stats, l4, .. } => {
      // … unchanged …
  }
- ProtocolEvent::Message { kind: "dns-udp", message: ProtocolMessage::Dns(DnsMessage::Query(_)), key, ts, .. } => {
+ Event::Message { parser_kind: DNS_UDP, message: ProtocolMessage::Dns(DnsMessage::Query(_)), key, ts, .. } => {
      // … unchanged …
  }
```

Field-rename `kind` → `parser_kind` is mechanical: ~30 sites
across the 8 reference detectors.

## U9. Heuristic routing

flowscope 0.10 ships heuristic dispatch on the unified Driver
(plan 116 PR 2b + plan 113 sub-B). Each heuristic slot is a
signature function over the first 64 bytes per side, with
`Probing` → `Pinned` → `GaveUp` state per flow.

netring exposes it via:

```rust
let monitor = cap.protocol_monitor()
    .flow()
    .heuristic(http_request_signature, HttpParser::default(), |m| ProtocolMessage::Http(m))
    .heuristic(tls_client_hello_signature, TlsHandshakeParser::default(), |m| ProtocolMessage::TlsHandshake(m))
    .dns()
    .build();
```

Useful for port-randomized C2 detection and protocols on
non-standard ports.

`flowscope::detect::signatures::{http_request, http_response,
tls_client_hello, tls_server_hello, dns_message, ssh_banner,
smtp_banner, ftp_banner, irc_message, redis_resp, mqtt_connect,
postgres_startup}` are the curated set; their slugs align
with `parser_kinds::*` so dispatch round-trips cleanly.

## U10. `WRITING_DETECTORS.md` update

The tutorial gets:

- Section 1 (anatomy) — Update variant names: `Event::FlowStarted`
  vs old `ProtocolEvent::Flow(FlowEvent::Started)`. Field-rename
  `kind` → `parser_kind`.
- Section 4 (observe/on_tick) — unchanged.
- Section 5 (cross-protocol) — update the `tls_to_unresolved_ip`
  pattern to use `Event::Message` shape.
- Section 8 (production deployment) — mention
  `flowscope::emit::FlowEventNdjsonWriter` as an alternative to
  `to_json_line()` when shipping flow-lifecycle events.

## U11. CHANGELOG + version bump

netring 0.17 → 0.18. CHANGELOG headline:

> Centerpiece architectural refactor: ProtocolMonitor now
> collapses N captures + N kernel BPF filters down to ONE
> capture + flowscope's unified Driver<E, M>. Memory
> savings scale linearly with the protocol count.

Breaking changes section:
- `ProtocolEvent<K>` variant rename: `Flow(FlowEvent::Started)`
  → `FlowStarted`, etc. Type alias if Path A; otherwise full
  rename.
- `kind` field renamed to `parser_kind` on `Message` arm
- `SessionStream` / `DatagramStream` deprecated (aliases stay
  one release; deletion in 0.19)

---

## Effort summary

| Phase | LoC delta | Days | Risk |
|---|---|---|---|
| U1 (ProtocolMonitor adopts Driver) | +200 / -500 | 1 | Med |
| U2 + U3 (Event/ProtocolEvent collapse) | +50 / -150 | 0.5 | Med (semver) |
| U4 (delete session_stream.rs) | -880 | 0.3 | Low (covered by flowscope) |
| U5 (delete datagram_stream.rs) | -505 | 0.3 | Low |
| U6 (flow/session/datagram stream wrappers) | +200 / -100 | 0.5 | Low |
| U7 (pcap stream wrappers) | +100 / -50 | 0.3 | Low |
| U8 (AnomalyRule + 8 detector example migrations) | ~100 site touches | 0.5 | None |
| U9 (heuristic routing) | +80 + builder | 0.3 | Low |
| U10 (WRITING_DETECTORS update) | +50 prose | 0.2 | None |
| U11 (CHANGELOG + version) | +100 doc | 0.2 | None |

**Total: ~4 days.** Substantially less than the 5-day estimate
in the 0.18 roadmap because flowscope 0.10 already shipped the
heavy lifting (unified Driver). netring just has to point at it.

Ship as **2 ship-commits**:
- **Commit A** — U1 + U4 + U5 + U6 + U7 (the refactor proper).
  Includes converting all detector examples in one go because
  the variant-name shift is mechanical.
- **Commit B** — U2 + U3 + U8 (`ProtocolEvent` alias finalization,
  detector signatures stable) + U9 + U10 + U11.

Each commit must pass the same gates as 0.17.

---

## Open design questions

### Q1. Path A (alias) vs Path B (drop netring's ProtocolEvent)?

**Recommend Path A.** Keeps the surface discoverable for
existing tutorial readers; the alias is zero-cost; gives us
escape hatch to add netring-side fields later.

### Q2. Should `ProtocolMonitorBuilder` keep its current shape or move to a literal flowscope `Driver::builder` wrapping?

```rust
// Today (and Path A — keep)
let monitor = cap.protocol_monitor()
    .flow()
    .http().dns().tls().icmp()
    .build();

// Path B — expose flowscope's builder directly
let monitor = AsyncCapture::open("eth0")?
    .into_driver(FiveTuple::bidirectional())
    .session_on_ports(HttpParser::default(), &[80, 8080], lift_http)
    .datagram_on_ports(DnsUdpParser::with_correlation(), &[53], lift_dns)
    .build();
```

**Recommend Path A.** Keep the netring-flavored builder for
discoverability; rich users who want full flowscope flexibility
already have direct access via the `Driver::builder` they can
construct from the underlying source. Document the escape hatch.

### Q3. Does the `ProtocolMonitor` constant-overhead benchmark match the existing one after the refactor?

Run the existing `cargo bench --bench anomaly` and confirm:
- `bench_observe_no_op_rule`: still ≤ 10 ns/event
- `bench_full_pipeline_dns_burst`: still ≤ 100 ns/event

A 2× regression on the no-op rule would be acceptable (we're
going through one more layer); 10× would not be. Compare against
the baseline pinned in commit `fb9bdc0`.

### Q4. Will pcap-replay throughput change?

Should improve modestly: one driver replacing the
SessionStream/DatagramStream state machine. Re-run
`tests/anomaly_pcap_replay.rs` with a 10× larger synthesized
pcap and confirm no regressions.

---

## What 0.18 success looks like

1. `ProtocolMonitor` opens 1 `AsyncCapture` regardless of how
   many parsers are enabled. Memory savings linearly proportional
   to N.
2. `session_stream.rs` and `datagram_stream.rs` are deleted
   (~1400 LoC). The shape of `cap.session_stream(...)` /
   `.datagram_stream(...)` is unchanged for users.
3. All 8 reference detector examples migrate to the new variant
   names (mechanical) and continue to pass tests + pcap-replay
   integration tests.
4. New `cap.protocol_monitor()` exposes the unified-Driver
   builder including the new heuristic-routing slots.
5. CHANGELOG documents the breaking renames.
6. The next pcap-replay-multi example collapses to "use
   `ProtocolMonitorBuilder::pcap(path)`."
7. Per-event overhead in benchmarks regresses by < 2×; the
   harness floor stays ≤ 20 ns/event.

---

## Out of scope

- **Public `AsyncCapture::broadcast(n)` for non-`ProtocolMonitor`
  use cases.** The unified Driver gives us the multi-parser case;
  general broadcast (for fanning packets to user-defined sinks)
  is a separate motivation. Defer.
- **Async-trait `AnomalyRule`.** flowscope drivers are sync;
  netring's `AnomalyRule` stays sync. Users that want async I/O
  should fan events to a channel and process there.
- **`PacketBackend` unification** (AF_PACKET + AF_XDP). Unchanged.
  Tracked in `upstream-tracking.md`.
- **Removing the legacy `SessionStream` / `DatagramStream`
  aliases.** Keep them in 0.18 as deprecated aliases; delete in
  0.19 (gives one release for downstream consumers to migrate).
