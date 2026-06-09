# Flowscope dependencies for netring 0.19

**Date:** 2026-06-09
**Status:** ✅ **RESOLVED — all six items shipped in flowscope 0.11.0/0.11.1.**
**Companion to:** [`netring-0.19-redesign-2026-06-09.md`](./netring-0.19-redesign-2026-06-09.md)
**Original question:** "Do we have to improve or add features to flowscope first?"

**Short answer (historical):** Yes. Six concrete flowscope work items — three required for the zero-allocation contract, one required for the architectural design, two highly desirable.

**Outcome (2026-06-09 evening):** flowscope 0.11.0 + 0.11.1 shipped all six. Mapping:

| netring ask | flowscope plan | flowscope version |
|---|---|---|
| 3.1 `Driver::track_into` | plan 119 | 0.11.0 |
| 3.2 Parser scratch-buffer API | plan 119 | 0.11.0 |
| 3.3 HTTP `Bytes` payloads | plan 120 | 0.11.0 |
| 3.4 Multi-typed-slot Driver | plan 121 (typed `Driver<E>` + `SlotHandle<M, K>`) | 0.11.0 |
| 3.5 `parser_kinds::TLS_HANDSHAKE` constant | plan 118 phase 4 | 0.11.0 |
| 3.6 `Driver::slot_by_kind` | subsumed by plan 121 | 0.11.0 |
| (bonus) `Driver::force_close` | 0.11.1 release | 0.11.1 |
| (bonus) `sweep_into` / `finish_into` zero-alloc variants | plan 119 | 0.11.0 |

**Implication for netring 0.19:** the redesign spec ([`netring-0.19-redesign-2026-06-09.md`](./netring-0.19-redesign-2026-06-09.md)) has been updated to use flowscope 0.11's typed shape directly. The `Erased` wrapper that the original spec budgeted for is gone; `Driver<E>` emits lifecycle `Event<K>` only and each protocol's typed messages flow through `SlotHandle<P::Message, K>`. The `Box<dyn Any>` per parsed message disappears entirely.

**Phase impact:** netring 0.19 implementation budget revised down from 25–34 days to **22–30 days** (Phase A −2d, Phase C −1–2d). The zero-alloc CI gate tightens from "<1 KiB delta per 100k events" to "<512 bytes delta per 100k events."

The rest of this document is **historical** — kept for the audit trail and to document the original analysis that drove flowscope plan 119/120/121. The §3.x items below describe what netring needed and what flowscope shipped to meet each need. The §5 sequencing recommendation (Option α — flowscope first) was followed; netring 0.19 implementation can now begin against flowscope 0.11.1.

---

Below is the full audit as originally written: what netring 0.19 needs, what flowscope 0.10 already provided, what was missing, and the recommended sequencing.

---

## 1. Audit methodology

For each touchpoint where netring 0.19 reaches into flowscope, the audit answers three questions:

1. **Does the API exist in flowscope 0.10?** Checked against `/var/home/mpardo/git/flowscope/src` at `0.10.1`.
2. **If it exists, does it meet netring 0.19's contract?** Particularly the zero-allocation rule from `api-review-2026-06-09.md` §7.
3. **If not, what's the smallest flowscope change that makes it work?**

Touchpoints come from `netring-0.19-redesign-2026-06-09.md`:

- §4 `Protocol::parser()` wraps flowscope `SessionParser`/`DatagramParser`.
- §5 Event payload types pull from `flowscope::{Timestamp, FlowSide, L4Proto, EndReason, FlowStats, AnomalyKind}`.
- §7 `Counter<K>` reuses `flowscope::correlate::TimeBucketedCounter`.
- §8 Dispatcher integrates with `flowscope::driver_unified::Driver<E, M>`.
- §9 `AnomalyWriter` uses `flowscope::Timestamp`.
- §15 migration shim wraps `flowscope::SessionEvent` translation.

Each is graded:
- ✅ **Ready** — works as-is.
- 🟡 **Needs verification** — exists but should be checked at implementation time.
- 🔴 **Needs change** — flowscope work required.

---

## 2. What flowscope 0.10 already provides (ready, no change)

These are confirmed working at the netring 0.19 contract level by reading flowscope source:

| Touchpoint | Status | Notes |
|---|---|---|
| `Driver<E, M>` accepts custom `M` | ✅ | Bounds are `M: Send + 'static` only. netring's `Erased` wrapper fits. (`driver_unified/mod.rs:106`) |
| `Driver` lift closures (`session_on_ports`, etc.) | ✅ | `F: Fn(P::Message) -> M` — works for `lift = \|m\| Erased::wrap(m)`. (`driver_unified/mod.rs:316–500`) |
| `HttpRequest::body: Bytes` | ✅ | Already `bytes::Bytes` since 0.6. (`http/types.rs:15`) |
| `HttpResponse::body: Bytes` | ✅ | Same. (`http/types.rs:26`) |
| `IcmpType::error_inner()` | ✅ | Returns `Option<(&'static str, &IcmpInner)>` — used by `icmp_explained_drop`. Shipped 0.8. |
| `parser_kinds::*` constants | ✅ | `HTTP`, `DNS_UDP`, `DNS_TCP`, `TLS`, `ICMP`. (`lib.rs:197–208`) |
| `FlowStats::total_bytes` / `total_packets` / `duration` | ✅ | Shipped 0.10. (`event.rs:194–235`) |
| `EndReason::as_str()` | ✅ | Zero-alloc string slug. Shipped 0.10. (`event.rs:83`) |
| `well_known::protocol_label(L4Proto, src_port, dst_port)` | ✅ | ~70 services covered. Shipped 0.10. |
| `flowscope::detect::signatures::{http_request, tls_client_hello, dns_message, …}` | ✅ | Shipped 0.10. Required for netring's `Dispatch::Signature(fn)`. |
| `SignatureMatch::{Match, NoMatch, MoreData}` | ✅ | Used in heuristic routing. |
| Correlate primitives (`BurstDetector`, `TimeBucketedSet`, `TopK`, `Ewma`, `TimeBucketedCounter`, `KeyIndexed`) | ✅ | All shipped 0.10. netring's `Counter<K>` wraps `TimeBucketedCounter`. |
| `DnsResolutionCache` | ✅ | Used by netring's `tls_to_unresolved_ip` detector. |
| `TlsHandshakeParser` aggregator | ✅ | Shipped 0.9. Emits one `TlsHandshake` per completed handshake. |
| `From<flowscope::Severity> for netring::Severity` | ✅ | Already in netring 0.17+. |
| `Severity`, `AnomalyKind::severity()`, `AnomalyKind::short_kind()` | ✅ | All shipped 0.10. |
| `FiveTupleKey` + `FlowExtractor` trait | ✅ | Unchanged shape. |
| `PacketView`, `Timestamp` | ✅ | Unchanged. |

The bulk of netring 0.19's flowscope dependencies are already met. The gap is concentrated in two areas: per-event allocation inside parsers/driver, and the closed-`M` shape of `Driver<E, M>`.

---

## 3. The gaps — required flowscope work

### 3.1 🔴 CAT-1 — `Driver::track_into(&mut self, view, &mut buf)`: scratch-buffer reuse

**Today (flowscope 0.10):**

```rust
// driver_unified/mod.rs around line 200
pub fn track<'v>(&mut self, view: impl Into<PacketView<'v>>) -> Vec<Event<E::Key, M>> {
    let view: PacketView<'v> = view.into();
    let ts = view.timestamp;
    let mut out: Vec<Event<E::Key, M>> = Vec::new();   // ← allocates every call
    // …
    out
}
```

**Why it matters:** netring's dispatch loop calls `track()` once per packet. At 1 Mpps that's 1M `Vec::new()` calls per second — even when no events fire (most packets just feed the flow tracker without producing an event). The Vec is freed immediately after netring iterates it. That's the textbook allocate-and-free-per-event pattern netring 0.19 §7 explicitly forbids.

**Required change:**

```rust
/// Same as `track`, but appends into a caller-supplied buffer.
/// Reuses the buffer's capacity across calls — zero allocation
/// in steady state.
pub fn track_into<'v>(
    &mut self,
    view: impl Into<PacketView<'v>>,
    out: &mut Vec<Event<E::Key, M>>,
) {
    let view: PacketView<'v> = view.into();
    // … (existing track() body, but append to `out` instead of a fresh Vec) …
}

/// Backwards-compat wrapper.
pub fn track<'v>(&mut self, view: impl Into<PacketView<'v>>) -> Vec<Event<E::Key, M>> {
    let mut out = Vec::new();
    self.track_into(view, &mut out);
    out
}
```

**Effort:** ~1 day. The body of `track` mostly already accumulates into a local `out`; the refactor is to take `&mut Vec<Event>` instead.

**netring 0.19 use:** the dispatcher in `monitor/dispatcher.rs` holds one persistent `Vec<Event<E::Key, Erased>>` scratch buffer, `clear()`s it before each `track_into` call, then iterates the events and dispatches each.

---

### 3.2 🔴 CAT-1 — `SessionParser::feed_*` / `DatagramParser::parse`: scratch-buffer reuse

**Today (flowscope 0.10):**

```rust
// session.rs:506
fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
fn fin_initiator(&mut self) -> Vec<Self::Message> { Vec::new() }
fn fin_responder(&mut self) -> Vec<Self::Message> { Vec::new() }
fn on_tick(&mut self, _now: Timestamp) -> Vec<Self::Message> { Vec::new() }
// Same pattern for DatagramParser::parse (session.rs:642).
```

**Why it matters:** Each parser call allocates a fresh `Vec<Self::Message>`. Even for the common case of "this packet contributed no complete message" the parser returns `Vec::new()` — which is a zero-cost empty vec on stable Rust today, but the moment a single message lands in the Vec, it allocates. Multiplied by parser-feed-per-packet × packets/sec, this is a serious chunk of the allocation budget.

**Two possible required changes:**

**Option A — scratch buffer in signature:**

```rust
fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp, out: &mut Vec<Self::Message>);
// (same for the other five methods)
```

Drops a fresh `Vec` per call to zero; caller's buffer is reused across all parsers.

**Option B — `SmallVec` return:**

```rust
fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp) -> smallvec::SmallVec<[Self::Message; 4]>;
```

≤4 messages per call (the overwhelming common case) stays on the stack; only the rare 5+-message packet allocates.

**Recommendation:** Option A. It's a wider signature change but it composes with §3.1 (`Driver::track_into`) cleanly — flowscope holds one persistent scratch `SmallVec<[M; 4]>` per parser-slot internally, and the Driver appends parser output into the user's `out` via `out.extend(parser_scratch.drain(..))`.

**Effort:** ~2 days. Mechanical breaking change across 5 shipped parsers (Http, DnsUdp, DnsTcp, Tls, TlsHandshake, Icmp) + ~3 internal helpers. Each parser already has an internal `messages: Vec<_>` field; the change is "drain into caller buffer, don't return new Vec."

**netring 0.19 use:** netring's `ProtocolParser::parse` (which wraps flowscope's parser) takes `&mut ArrayVec<M, 4>` in `ParseResult`. The adapter calls `parser.feed_initiator(bytes, ts, &mut scratch)` and drains scratch into the ArrayVec.

---

### 3.3 🔴 CAT-1 — HTTP header values as `Bytes`

**Today (flowscope 0.10):**

```rust
// http/types.rs:12, 25
pub headers: Vec<(String, Vec<u8>)>,
```

Each parsed HTTP request/response allocates one `String` per header name + one `Vec<u8>` per header value + one outer `Vec`. For a request with 10 headers, that's 21 allocations per HTTP message.

**Why it matters:** HTTP is the most-common L7 protocol netring users observe. Headers are the bulk of an HTTP request's allocation footprint. Even if request bodies are already `Bytes` (✅), the header layer dominates.

**Required change:**

```rust
pub headers: Vec<(HeaderName, Bytes)>,

// Where HeaderName is a small wrapper that lower-cases the name
// without copying, or just uses Bytes for both:
pub headers: Vec<(Bytes, Bytes)>,
```

The simplest version is `Vec<(Bytes, Bytes)>` — names and values both reference the parsed-buffer arena. Header lookup helpers (`.host()`, `.user_agent()`) compare via `eq_ignore_ascii_case` over `&[u8]`, which is what they do today anyway.

**Effort:** ~1.5 days. Touches `http/types.rs`, `http/parser.rs`, and the existing header accessor methods. All cargo-doc-able with a deprecation note for users that match against `headers` directly.

**Alternative (smaller):** keep `String` for names (typically small fixed set: ~30 common names; intern via `compact_str` or just leave them), change values to `Bytes`. Cuts the allocation count by half. Effort: ~0.5 day.

**Recommendation:** ship the smaller alternative in flowscope 0.11, full `Bytes`-both in 0.12. Don't block netring on the bigger change.

---

### 3.4 🔴 CAT-2 — multi-typed-slot `Driver` (the architectural change)

**Today (flowscope 0.10):**

```rust
pub struct Driver<E, M> { /* one M for all slots */ }

impl<E, M> Driver<E, M> {
    pub fn session_on_ports<P, F>(self, parser: P, ports: Vec<u16>, lift: F) -> Self
    where F: Fn(P::Message) -> M
    { … }
    // All slots' P::Message values lift into the single M.
}
```

**Why it matters (architecturally):** netring 0.19 wants protocol agnosticism — `monitor.protocol::<Http>()` registers Http and the parser emits typed `HttpMessage`; `monitor.protocol::<Dns>()` registers Dns and the parser emits typed `DnsMessage`. They have *different message types*. Today, both have to lift into a unified `M = Erased` wrapper that boxes the typed message via `Box<dyn Any>` — exactly the per-event allocation netring 0.19 §7 forbids.

**Why it matters (numerically):** at 1 Mpps of which ~10% is parsed L7 traffic = 100k parsed messages/sec = 100k `Box<dyn Any>` allocations/sec = ~5 MiB/sec of heap traffic on the hot path. Each `Box` is a malloc + a refcount-style dec at the consumer end. Not fatal at 100k, fatal at 10M.

**Required change — pick one:**

**Option (a) — typed channels per slot (recommended):**

```rust
pub struct Driver<E> {
    central: FlowTracker<E, ()>,
    slots: Vec<Box<dyn DriverSlot<E::Key>>>,  // each slot owns its M_i internally
    // … events written to a per-driver buffer keyed by TypeId
}

trait DriverSlot<K> {
    fn parser_kind(&self) -> &'static str;
    fn message_type_id(&self) -> TypeId;
    fn feed(&mut self, … , out: &mut TypedEventBuf);
}

pub struct TypedEventBuf {
    by_type: HashMap<TypeId, Vec<Box<dyn Any + Send>>>,
}
```

Hmm, that still uses `Any`. Let me think again.

**Option (a) revised — driver emits via typed callback registration:**

```rust
pub struct Driver<E> {
    slots: Vec<Box<dyn DriverSlot<E::Key>>>,
    callbacks_by_type: HashMap<TypeId, Box<dyn FnMut(&dyn Any, &EventMeta)>>,
}

impl<E> Driver<E> {
    /// Register a typed callback. Stored keyed by TypeId::of::<M>().
    pub fn on<M: Send + 'static>(
        &mut self,
        cb: impl FnMut(&M, &EventMeta) + Send + 'static,
    ) {
        let erased: Box<dyn FnMut(&dyn Any, &EventMeta)> = Box::new(move |any, meta| {
            let m = any.downcast_ref::<M>().expect("type-id keyed dispatch invariant");
            cb(m, meta);
        });
        self.callbacks_by_type.insert(TypeId::of::<M>(), erased);
    }

    /// Inside the driver, each slot calls callbacks_by_type for its message
    /// type. The Box<dyn Any> is constructed *only* in the dispatch path
    /// where the callback is registered. No callback registered = no box.
    fn dispatch_message<M: Send + 'static>(&mut self, msg: &M, meta: &EventMeta) {
        if let Some(cb) = self.callbacks_by_type.get_mut(&TypeId::of::<M>()) {
            cb(msg as &dyn Any, meta);
        }
    }
}
```

This is the right shape: parser emits a typed `M` by reference, the driver downcasts via `&dyn Any` (zero-cost — just a TypeId match + a pointer cast), no `Box` per message. netring's `monitor.on::<Http>(handler)` registers its callback through this; flowscope's driver dispatches without ever owning a typed message past the parse call.

**Option (b) — keep `Driver<E, M>` but make `M` a sum type generated by macro:**

```rust
flowscope_message_sum! {
    pub enum Messages {
        Http(HttpMessage),
        Dns(DnsMessage),
        // user-extensible via inventory or linkme
    }
}
```

Hostile to third-party protocols (the marketing-feature of netring 0.19), so no.

**Option (c) — separate streams per slot:**

```rust
pub struct Driver<E> { … }
pub struct DriverSlot<M> { rx: tokio::sync::mpsc::UnboundedReceiver<Event<E::Key, M>> }

let (driver, slots) = Driver::builder(extractor)
    .session_on_ports::<HttpParser>(…)  // returns DriverSlot<HttpMessage>
    .session_on_ports::<DnsUdpParser>(…)  // returns DriverSlot<DnsMessage>
    .build();
```

Each slot polled independently. netring would `tokio::select!` over them. Eliminates erasure but adds N tasks; complicates the single-loop dispatch model from netring 0.19 §8.1.

**Recommendation:** Option (a) revised — typed callbacks via `TypeId`-keyed dispatch internal to the driver. Closest fit to netring's `on::<E>(handler)` registration; preserves the single-`track_into` loop; zero allocation per parsed message; sound via the `&dyn Any` + TypeId-keyed downcast invariant (same as `http::Extensions`).

**Effort:** ~5–7 days. Real design work but achievable. The driver's internal slot management is already structured around per-slot trait objects (look at `driver_unified/mod.rs:115`-ish); adding the typed-callback layer is incremental.

**netring 0.19 use:** `Monitor::builder().on::<Http>(handler)` calls down into `flowscope::driver_unified::Driver::on::<HttpMessage>(handler_wrapped)`. The `Erased` wrapper from the netring 0.19 redesign §8.1 disappears entirely. Zero allocation per parsed message.

---

### 3.5 🟡 CAT-3 — `parser_kinds::TLS_HANDSHAKE` constant

**Today (flowscope 0.10):**

```rust
// lib.rs:197
pub mod parser_kinds {
    #[cfg(feature = "dns")] pub use crate::dns::PARSER_KIND_TCP as DNS_TCP;
    #[cfg(feature = "dns")] pub use crate::dns::PARSER_KIND_UDP as DNS_UDP;
    #[cfg(feature = "http")] pub use crate::http::PARSER_KIND as HTTP;
    #[cfg(feature = "icmp")] pub use crate::icmp::PARSER_KIND as ICMP;
    #[cfg(feature = "tls")]  pub use crate::tls::PARSER_KIND as TLS;
}
```

Missing: `TLS_HANDSHAKE` (the `"tls-handshake"` slug emitted by `TlsHandshakeParser`).

**Why it matters:** netring 0.19 examples and detector code reference `parser_kinds::TLS_HANDSHAKE` for stable routing. Today users have to write the magic string `"tls-handshake"` directly (which netring 0.18 already does in `slow_tls_handshake.rs`).

**Required change:**

```rust
#[cfg(feature = "tls")] pub use crate::tls::handshake::PARSER_KIND as TLS_HANDSHAKE;
```

**Effort:** ~5 minutes. Add a `pub const PARSER_KIND: &str = "tls-handshake";` to `tls/handshake.rs` if not present, and re-export it.

---

### 3.6 🟡 CAT-3 — `Driver` exposes `parser_kind → TypeId` map at build time

**Today:** the driver internally knows which slot a given `parser_kind` maps to, but doesn't expose it externally. netring's translation layer (the §8.1 `run_loop` in the redesign) needs this lookup for the `Event::Message { parser_kind, .. }` → dispatcher routing path.

**Why it matters:** if §3.4 lands as option (a), then the dispatcher inside `Driver` already keys callbacks by `TypeId`, so netring never sees `parser_kind` strings. The need for this lookup disappears.

**If §3.4 doesn't land for 0.11:** netring needs a `Driver::slot_by_kind(parser_kind: &str) -> Option<SlotInfo>` accessor to do the routing.

**Effort:** ~0.5 day if needed; superseded by §3.4 if it lands.

---

## 4. Summary table

| # | Category | Item | Effort | Blocks netring 0.19? |
|---|---|---|---|---|
| 3.1 | 🔴 CAT-1 | `Driver::track_into` | 1 d | **Yes** — zero-alloc contract |
| 3.2 | 🔴 CAT-1 | `Parser::feed_*` scratch reuse | 2 d | **Yes** — zero-alloc contract |
| 3.3 | 🔴 CAT-1 | HTTP header values as `Bytes` (partial) | 0.5–1.5 d | Mostly — perf claim degrades without it |
| 3.4 | 🔴 CAT-2 | Multi-typed-slot `Driver` (option a) | 5–7 d | **Yes** — architecture / zero-alloc |
| 3.5 | 🟡 CAT-3 | `parser_kinds::TLS_HANDSHAKE` constant | 5 min | No |
| 3.6 | 🟡 CAT-3 | `Driver::slot_by_kind` accessor | 0.5 d | No if 3.4 lands; small lift otherwise |

**Total flowscope-side effort:** ~9–12 working days for CAT-1 + CAT-2; ~1 day more for CAT-3.

---

## 5. Recommended sequencing

### Option α — flowscope 0.11 first, then netring 0.19 (recommended)

```
Week 1-2:   flowscope 0.11 — items 3.1, 3.2, 3.3, 3.5, 3.6
Week 2-3:   flowscope 0.11 — item 3.4 (multi-typed-slot Driver)
Week 4:     flowscope 0.11 release + crates.io publish
Week 5-9:   netring 0.19 — phases A through G
Week 10:    netring 0.19 release
```

**Pros:**
- netring 0.19 ships against final flowscope API; no churn.
- Zero-allocation claim is honest at release time.
- The `Erased` wrapper from the redesign §8.1 disappears — netring code is simpler.

**Cons:**
- 2-week dependency on flowscope work before netring code starts.
- flowscope users who don't care about netring still get a (mostly additive) update.

### Option β — netring 0.19 with Erased wrapper, flowscope 0.11 after, netring 0.20 to collect benefits

```
Week 1-5:   netring 0.19 — phases A through G, against flowscope 0.10
Week 6:     netring 0.19 release with documented allocation per parsed message
Week 7-9:   flowscope 0.11 — all six items
Week 10-12: netring 0.20 — drop Erased, simplify, re-bench
```

**Pros:**
- netring code starts now.
- flowscope work parallelized.

**Cons:**
- netring 0.19 ships with an asterisk on the zero-allocation claim ("zero-alloc for sync handler dispatch path; one allocation per parsed L7 message awaiting flowscope 0.11").
- The benchmark in §14 of the redesign would need a tolerance of "~100k bytes / 100k events" (the `Box<dyn Any>` traffic), not the planned <1 KiB.
- netring 0.20 has to do the `Driver` re-integration twice — once with `Erased`, once without. ~3 days of throwaway work.

### Option γ — co-development with daily sync (risky)

Flowscope and netring authors are the same person; co-development is possible but invites integration churn. **Not recommended** — the 2-week dependency in Option α is honest signaling that the foundation matters.

### Recommendation

**Option α.** The zero-allocation contract is the load-bearing claim of netring 0.19. Shipping it with known allocations on the hot path turns the perf headline into a footnote. The ~2 weeks of flowscope work is small in absolute terms (one developer, ~10 days) and buys netring 0.19 a clean architecture rather than a workaround it later has to remove.

---

## 6. Concrete flowscope 0.11 work plan

If Option α is the path, flowscope 0.11 ships seven items in this order:

### Phase 1 — Low-risk infrastructure (3 days)

- [ ] **3.5** — Add `parser_kinds::TLS_HANDSHAKE` constant. (5 minutes)
- [ ] **3.1** — `Driver::track_into(view, &mut Vec<Event>)`. Keep `track` as wrapper. (1 day)
- [ ] **3.6** — `Driver::slot_by_kind(&str) -> Option<SlotInfo>` if not subsumed by 3.4. (0.5 day)
- [ ] **3.3** (partial — values only) — HTTP header values to `Bytes`, keep names as `String`. (0.5 day)

**Outcome:** one allocation per packet removed from the hot path (`track_into`). HTTP value allocation halved.

### Phase 2 — Parser scratch reuse (2 days)

- [ ] **3.2** — `SessionParser::feed_*` / `DatagramParser::parse` take `&mut Vec<Self::Message>` scratch. **Breaking** trait change.

**Outcome:** zero allocation in the parse path under steady state. This is the big perf win for netring.

**Migration:** every implementor (5 in flowscope + any user implementations) gets a 5-line diff. Documented in flowscope CHANGELOG with `before/after` recipe.

### Phase 3 — Multi-typed-slot Driver (5–7 days)

- [ ] **3.4** — `Driver::on::<M>(callback)` API with TypeId-keyed dispatch. Parser slots emit typed messages; the driver downcasts to callback type at registration boundary.

**Outcome:** netring's `Erased` wrapper goes away. Zero allocation per parsed L7 message.

**Migration:** the closed `Driver<E, M>` shape is replaced by `Driver<E>`. Existing flowscope examples that name `Driver<E, ProtocolMessage>` get migrated to `Driver<E>` with explicit `.on::<HttpMessage>(…)` calls. ~30-line diff per example.

### Phase 4 — Release (1 day)

- [ ] CHANGELOG, version bump 0.10.1 → 0.11.0, publish.
- [ ] Migration guide in `flowscope/docs/migration-0.10-to-0.11.md`.

---

## 7. What flowscope explicitly does NOT need to change for netring 0.19

For posterity — items I considered and rejected:

- **`SessionParser::feed_*` returning `&[Message]` instead of `Vec`**: would force the parser to hold messages internally until next call. Bad lifetime story; messes with `is_done()` semantics. The scratch-Vec API (§3.2) is cleaner.
- **A second-level `FlowAnomaly` channel**: netring 0.19 lifts these into `AnyFlowAnomaly` events already. No flowscope change needed.
- **Sync `Driver::track`**: already sync today. Good.
- **`tracker_mut()` exposing the internal `FlowTracker`**: already exposed; netring uses it for `iter_active`.
- **Built-in `Bytes` arena**: an optimization further than needed; defer to flowscope 0.12+.
- **`async fn` in `SessionParser`**: hostile to netring's sync hot path. Don't add.
- **`AnomalySink` upstream in flowscope**: netring's `AnomalySink` is netring-flavored (its `Severity` is netring's, not flowscope's `event::Severity`). Keep separate.
- **`tower::Layer` integration in flowscope**: middleware is netring's concern. Don't pollute flowscope's surface.
- **Per-CPU sharding helpers in flowscope**: netring's `AsyncMultiCapture` is the right home. Flowscope is shared by single-monitor users too.
- **Columnar batch events**: defer to flowscope 0.12+/netring 1.0.

---

## 8. Risks and mitigations

### Risk 1: flowscope 0.11 takes longer than estimated.

**Mitigation:** ship the CAT-1 items (3.1, 3.2, 3.3) as flowscope 0.10.2 (no breaking changes since 3.2 is a trait change but additive via a new `feed_initiator_into` method alongside the old `feed_initiator`). Then ship CAT-2 (3.4) as 0.11 with the breaking-change announcement. netring can start against 0.10.2 with the `Erased` wrapper only for un-converted parsers.

### Risk 2: the multi-typed-slot Driver (3.4) design needs more iteration.

**Mitigation:** prototype it first. The three options outlined in §3.4 (typed callbacks, sum-type macro, per-slot streams) should be benchmarked against the canonical netring 0.19 K8s monitor before committing. Allocate 1–2 days for prototyping.

### Risk 3: HTTP header migration (3.3) breaks user code.

**Mitigation:** keep the partial migration (values only, names stay `String`). Full `Bytes`-both deferred to flowscope 0.12. Document the value change clearly.

### Risk 4: scratch-buffer parser API (3.2) ergonomics surprise users.

**Mitigation:** ship `SmallVec<[M; 4]>` as the user-facing return type via a small helper:

```rust
pub trait SessionParserExt: SessionParser {
    fn feed_initiator_small(&mut self, bytes: &[u8], ts: Timestamp)
        -> smallvec::SmallVec<[Self::Message; 4]>;
}
```

Users who don't care about zero-alloc keep using the new `feed_initiator_into`; the trait-method wrapper for ad-hoc use cases is one line.

### Risk 5: third-party parsers (e.g. netring users who shipped a custom `SessionParser`) break on 3.2.

**Mitigation:** the breaking-change announcement is in the flowscope 0.11 CHANGELOG. Migration shim provided. There's no avoiding the breakage — the scratch-buffer pattern is the perf-correct shape long-term.

---

## 9. Closing

netring 0.19 cannot honestly meet its zero-allocation contract against flowscope 0.10. The two CAT-1 items (3.1 `track_into` and 3.2 parser scratch) eliminate ~3 allocations per packet on the hot path; the CAT-2 item (3.4 multi-typed-slot Driver) eliminates the per-parsed-message `Box`.

Total flowscope effort: **~9–12 working days**, spread across two phases that can ship independently (3.1/3.2/3.3 as a 0.10.2 minor; 3.4 as 0.11 with breaking changes). netring 0.19 should not start implementation until at least flowscope 0.10.2 is published, and **should not release** until flowscope 0.11 is published.

The good news: the netring 0.19 redesign was honest about these dependencies — §20.4 and §20.5 already flagged them as "open questions." This document promotes them from open questions to actionable work items with effort estimates and a sequencing plan.

If you'd like the same level of detail-down-to-line-numbers for the flowscope 0.11 implementation itself, that's a separate document in `flowscope/plans/`. The skeleton would mirror this one's §3.x sections, scoped to "what code changes in `flowscope/src/`."

The architecture is right, the surface design is right, and the perf contract is achievable — but only if flowscope ships first.
