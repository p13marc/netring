# Feedback from `des-rs` — wishlist for an upcoming netring release

**Date:** 2026-05-09
**From:** `des-rs` (a Rust DES protocol discovery server federating across
sites via Zenoh — <https://github.com/p13marc/des-rs>). Specifically, the
team rewriting `tools/des_capture/` (a 3,600-LoC AF_PACKET DES protocol
decoder) on top of `netring` + `flowscope`.
**Background:** the rewrite plan and the per-API verification are written
up in `des-rs`'s repo at
`des-discovery/reports/des-capture-rewrite-analysis-2026-05-09.md`. This
document is the netring-shaped subset of the wishlist that came out of
that analysis. flowscope-side items already shipped in flowscope 0.2.0
(see flowscope's `plans/42-reassembly-observability.md` and
`plans/25-binary-protocol-example.md`).

## TL;DR

| # | Item | Severity for `des-rs` | Notes |
|---|---|---|---|
| **F1** | Bump `flowscope` dep from `"0.1"` to `"0.2"` and handle the breaking changes inside netring's adapters | **Blocker** for the live-capture rewrite | The offline path (`des-pcap-decode`) doesn't need netring at all and can ship today on flowscope 0.2 directly. The live path can't, until netring sees flowscope 0.2's new types. |
| **F2** | Add `AsyncCapture::flow_stream_with_config(extractor, FlowTrackerConfig)` (or equivalent setter on `FlowStream`) | **Major** for the live-capture rewrite | Without this, async users can't enable flowscope 0.2's `OverflowPolicy::DropFlow` + 1 MiB buffer cap from a single config call — which is the whole point of consolidating `tcp_stream.rs`'s hand-rolled limits into the upstream. |
| **F3** | `AsyncCapture::open_in_netns(iface, ns_path)` — capture inside a Linux netns from a process outside it | Nice to have | Workaround exists (`nlink-lab spawn` inside the target netns), so this is QoL-only. Original W3 from the rewrite analysis. |
| **F4** | Confirm or harden `Dedup::loopback()` exactness at sub-millisecond same-side cadence (5–500 Hz on a single TCP flow) | Verify | Documented as 1 ms / 256-entry / xxh3-64 + direction-aware. For our DES traffic shapes the false-positive risk is theoretical, but a one-line stress-test fixture would close the question. |
| **F5** | Confirm `CaptureWriter` nanosecond pcap timestamps survive a write-read-write-read round-trip (mostly a documentation ask) | Verify | Reading `netring/src/pcap.rs:59-72` shows pcapng + `ts_resolution = NanoSecond` hardcoded; just want it confirmed end-to-end. |

F1 is the only true blocker. F2 makes the live-capture rewrite ergonomic.
F3-F5 can ride along.

---

## F1 — Bump `flowscope` dep to 0.2

### Why

`netring/Cargo.toml:26` currently pins `flowscope = { version = "0.1",
default-features = false }`. flowscope 0.2.0 (released 2026-05-09) adds
the four types `des-rs` needs to drop its hand-rolled
`tools/des_capture/src/tcp_stream.rs`:

- `OverflowPolicy::{SlidingWindow, DropFlow}`
- `FlowStats::reassembly_dropped_ooo_*` and `reassembly_bytes_dropped_oversize_*`
  (four new fields)
- `FlowEvent::Anomaly { kind: AnomalyKind, .. }` and `AnomalyKind::{BufferOverflow, OutOfOrderSegment, FlowTableEvictionPressure}`
- `FlowSessionDriver<E, P, S>` — sync mirror of netring's `session_stream`
  (we use this in `des-pcap-decode`, so technically not blocking netring;
  flagging because some users will reach for the *async* sync-driver
  parallel and find nothing)

Until netring re-exports these (or at least lets `flowscope = "0.2"`
in `Cargo.lock`), every async-stream consumer is stuck on flowscope
0.1's surface.

### Breaking changes in flowscope 0.2 to handle inside netring

The flowscope 0.2 release notes flag these — they need audit-and-fix
inside `netring/src/async_adapters/`:

1. **`FlowEvent::key()`** now returns `Option<&K>` (was `&K`).
   - Greppable: `event.key()` callers across `netring/src/async_adapters/*.rs`.
   - For non-`Anomaly` events the value is always `Some(_)` — most
     call sites can `event.key().expect("non-anomaly")` or pattern-match.
2. **`EndReason::BufferOverflow`** is a new variant.
   - Greppable: `match … { EndReason::Fin | EndReason::Rst | … }` —
     anywhere that exhausts the enum needs a new arm. Treat
     `BufferOverflow` like `Rst` for cleanup semantics (the flow's
     reassembler is poisoned; emit close).
3. **`#[non_exhaustive]`** project-wide on `FlowStats`,
   `FlowTrackerConfig`, `AnomalyKind`, `OverflowPolicy`.
   - Affects netring only if it constructs these via struct literals.
     A grep for `FlowTrackerConfig {` / `FlowStats {` will flush them
     out; replace with `Default::default()` + `..Default::default()`.

### API delta (none)

This is purely a Cargo.toml + internal-fixup change. No new public API on
netring.

### Effort

- Cargo.toml dep bump: 1 line.
- `cargo check` reveals the broken match arms / struct literals.
  Likely <50 LoC of fix-ups across async adapters. CHANGELOG entry.
- Estimate: half a day, dominated by adding test coverage for the new
  `FlowEvent::Anomaly` variant flowing through `flow_stream` and
  `session_stream` (assert it propagates verbatim — no manual variant
  rewrap).

---

## F2 — `AsyncCapture::flow_stream_with_config(extractor, config)`

### Why

flowscope 0.2's `FlowTrackerConfig` gained two fields that *every* DES
consumer needs:

```rust
pub max_reassembler_buffer: Option<usize>,   // 0.2.0
pub overflow_policy: OverflowPolicy,         // 0.2.0
```

The sync `FlowDriver::with_config(extractor, config)` already reads
these and propagates them into the default `BufferedReassemblerFactory`.
The async path (`AsyncCapture::flow_stream(extractor)`) takes only the
extractor and uses `FlowTrackerConfig::default()` — no way to pass the
buffer cap.

### Sketch

```rust
impl<S> AsyncCapture<S> where S: PacketSource + Unpin {
    /// Like [`flow_stream`], but with explicit tracker config so
    /// the per-side reassembler buffer cap and overflow policy can
    /// be set at stream construction time.
    pub fn flow_stream_with_config<E>(self, extractor: E, config: FlowTrackerConfig)
        -> FlowStream<E, S, ()>
    where
        E: FlowExtractor,
        E::Key: Hash + Eq + Clone + Send + 'static,
    {
        // Same body as flow_stream, but threads `config` into the
        // FlowTracker constructor.
    }
}
```

Or, if the existing `FlowStream` builder pattern is preferred:

```rust
let s = cap.flow_stream(FiveTuple::bidirectional())
    .with_config(FlowTrackerConfig {
        max_reassembler_buffer: Some(1 << 20),
        overflow_policy: OverflowPolicy::DropFlow,
        ..Default::default()
    });
```

Either shape works; the builder is more flexible if you expect more
config knobs over time.

### Use case

```rust
let cfg = FlowTrackerConfig {
    idle_timeout_tcp: Duration::from_secs(60),
    max_reassembler_buffer: Some(1 << 20),       // 1 MiB per side
    overflow_policy: OverflowPolicy::DropFlow,    // poison + EndReason::BufferOverflow
    ..Default::default()
};

let mut s = AsyncCapture::open(iface)?
    .dedup_stream(Dedup::loopback())
    .flow_stream_with_config(FiveTuple::bidirectional(), cfg)
    .session_stream(DesSessionParser::default());
```

Without F2 the user has to construct a custom `BufferedReassemblerFactory`
and feed it through some other pathway — there's no obvious one for
`session_stream`'s default reassembler. Workable but ugly.

### Effort

- ~30 LoC of duplication + test.
- Estimate: 1 hour.

---

## F3 — `AsyncCapture::open_in_netns(iface, ns_path)`

### Why

`des-rs`'s test fleet runs each site inside a Linux network namespace
(via `nlink-lab`). Today every `tools/des_capture/` invocation has to
be launched *inside* the netns via `nlink-lab spawn`, which is fine for
automation but awkward for one-off debugging from a host shell.

A first-class netns API would let a debugger run from outside the netns
and pick which one to capture in:

```rust
let cap = AsyncCapture::open_in_netns("eth0", "/var/run/netns/site_a")?;
```

### Sketch

The standard recipe is:

1. `let ns_fd = open(ns_path, O_RDONLY | O_CLOEXEC)?;`
2. `let cur_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC)?;`
3. `setns(ns_fd, CLONE_NEWNET)?;`
4. Open the socket as usual.
5. `setns(cur_fd, CLONE_NEWNET)?;` — restore.

The fiddly part is RAII restoration in the face of panics — usually a
`scopeguard`-style helper or a `nix::sched::setns` call wrapped in a
custom `Drop` does it. Or: fork a child process that lives in the netns
and pipe captured packets back; safer but heavier.

### Workaround for `des-rs`

`nlink-lab spawn <lab> <node> -- des-capture …` is the existing shape
of every `des-test-harness` scenario, so this is QoL only. Punt unless
demand from other downstream users surfaces.

### Effort

- ~80 LoC + a `nix` dep (already a transitive of `tokio`?) or a manual
  syscall wrapper.
- Estimate: half a day, dominated by the RAII-restore design + tests.

### Decision (netring side, 2026-05-09): WONTFIX in netring

[`nlink`](https://github.com/p13marc/nlink) already exposes the
exact API this would build:

- `nlink::netlink::namespace::execute_in(name, |closure| …)` —
  closure-in-netns helper (RAII restore)
- `nlink::netlink::namespace::enter_path(path) -> Result<NamespaceGuard>`
- `nlink::netlink::socket::new_in_namespace_path(protocol, path)` for
  low-level use

Recommended one-off-debug recipe from a host shell:

```rust
use nlink::netlink::namespace;
let cap = namespace::execute_in("site_a", || AsyncCapture::open("eth0"))?;
```

Reasons not to duplicate this in netring:

1. nlink already has the `NamespaceGuard` with RAII restore. Adding
   the same primitive to netring splits maintenance across two
   crates for one logical concern.
2. Privilege boundary: keeping `setns` out of netring means netring
   stays at `CAP_NET_RAW`. Users who need netns capture pay the
   `CAP_SYS_ADMIN` cost in their own code via nlink, where the
   privilege escalation stays visible.
3. `des-rs` is already in the nlink ecosystem (`nlink-lab spawn` is
   the existing workaround). Pointing at `namespace::execute_in` is
   a smaller behavior change than landing a new netring constructor.

If composition through nlink turns out to have an ergonomic gap that
can't be fixed in nlink (unlikely — the existing API covers the
shape), revisit then.

---

## F4 — Verify `Dedup::loopback()` exactness at high cadence

### Why

`tools/des_capture/` today filters loopback duplicates at the kernel
level: `if from_addr.sll_pkttype == PACKET_OUTGOING { skip }`. Exact,
zero false positives, zero CPU.

netring's `Dedup::loopback()` is a 1 ms / 256-entry / xxh3-64 ring with
direction-aware pairing (`Outgoing ↔ Host` only). For typical traffic
this is functionally equivalent. The theoretical concern is sub-
millisecond same-direction retransmits with hash collisions:

- DES test flows can spike to 500 Hz on a single TCP connection
  (two packets within < 2 ms).
- xxh3-64 collision probability for two 1500-byte packets in the same
  1 ms window is astronomical for *random* bytes, but DES packets
  have heavy structural similarity (same headers, similar body
  prefixes) — birthday-problem-style collision rates on such inputs
  may be higher than a uniform-distribution analysis suggests.
- Direction-awareness mitigates the *cross-direction* false positive
  but not the *same-direction sub-millisecond retransmit* one.

### What we want

Two options, in order of preference:

1. **Documentation answer**: a benchmark or unit test in
   `netring/tests/dedup_*` that drives 10 k same-direction packets at
   1 kHz with realistic-looking (structured, header-heavy) payloads,
   asserts `dedup.dropped() == 0`. Once that exists, we trust
   `Dedup::loopback()` as-is.

2. **API answer (only if (1) shows real false positives)**: an
   exact-mode dedup that uses `sll_pkttype` directly — i.e. a
   `Dedup::loopback_exact()` constructor that drops only
   `PacketDirection::Outgoing` and ignores content hashing entirely.
   Equivalent to our current kernel-level filter; the function would
   collapse to a one-line predicate over `Packet::direction()`. Useful
   for any user where false positives are unacceptable (capture-as-
   evidence pipelines, legal/audit recording).

### Workaround for `des-rs`

We can replicate the exact filter at user-level using netring's already-
exposed `PacketDirection`:

```rust
let mut s = AsyncCapture::open(iface)?
    .into_stream()
    .filter_map(|res| async move {
        match res {
            Ok(pkt) if pkt.direction() == PacketDirection::Outgoing => None,
            other => Some(other),
        }
    });
```

So this is a "make sure we don't get bitten" verification more than a
new-feature ask.

### Effort

- Option 1 (test): ~50 LoC fixture + assertion, ~1 hour.
- Option 2 (API): ~30 LoC + tests, half a day.

---

## F5 — Confirm `CaptureWriter` nanosecond pcap round-trip

### Why

`tools/des-test-harness/src/pcap_decode.rs` and the cross-site
forensic analysis at
`des-rs/des-discovery/reports/multisite-bundle-analysis-2026-05-07.md`
rely on **nanosecond precision** for ordering events across sites.

`netring/src/pcap.rs:59-72` shows the writer is hardcoded to pcapng
with `ts_resolution = NanoSecond`. We just want a sanity round-trip:

```rust
let mut w = CaptureWriter::new(File::create(path)?, …)?;
let ts_in = Timestamp::new(1700000000, 123_456_789);
w.write_packet_with_ts(ts_in, &payload)?;
drop(w);

let mut r = pcap_file::pcapng::PcapNgReader::new(File::open(path)?)?;
let block = r.next_block().unwrap()?;
let ts_out = block.enhanced_packet().unwrap().timestamp;
assert_eq!(ts_out.as_nanos(), 1_700_000_000_123_456_789u128);
```

A test fixture that does this explicitly would close the question
permanently.

### Effort

- ~30 LoC test, ~1 hour.

---

## Recommended ship order

If you're cutting one netring release that addresses multiple items:

1. **F1** alone is a netring 0.8.1 / 0.9.0 (whichever signals breaking
   changes correctly — flowscope 0.2's `FlowEvent::key()` widening
   probably warrants 0.9.0). This unblocks `des-rs` Phase 2 of the
   `des-capture` rewrite.
2. **F2** ships with F1 — same release, since it's flowscope-0.2-aware.
3. **F4** test (option 1) ships in the same release as a hardening note.
4. **F5** ships in the same release as a hardening note.
5. **F3** can defer to a subsequent minor.

Total estimated effort: 1.5 days (F1 + F2 + F4-test + F5-test) for one
combined release.

---

## What `des-rs` is doing in the meantime

- **Phase 1 of the `des-capture` rewrite** (offline-only `des-pcap-decode`
  on `flowscope::FlowSessionDriver` + `flowscope::PcapFlowSource`)
  has no netring dependency and proceeds today.
- **Phase 2 (live `des-capture` on `AsyncCapture` + `flow_stream` +
  `session_stream`)** waits on F1 + F2.
- **No fork or vendoring of netring is planned.** We'd rather wait for
  an upstream release than carry a patch.

If you want a separate netring-side plan-document equivalent for any
of F1-F5 (in the same shape as flowscope's
`plans/42-reassembly-observability.md`), happy to draft it.
