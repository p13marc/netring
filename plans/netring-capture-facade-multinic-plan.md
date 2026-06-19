# netring — Declarative capture facade + multi-NIC / tap merge (plan)

> **Status:** plan, 2026-06-16. Candidate feature; no fixed release slot.
> Addresses **issue #11** (AsyncMultiCapture for AF_XDP). Minor flowscope touch
> (source-agnostic key option). Additive surface.

## 1. Why

Two gaps the multi-queue work (0.26) exposed:
1. **Choice overload.** Users now hand-pick AF_PACKET vs `xdp_interface_loaded`
   vs `xdp_queues` vs `XdpShardedRunner`. The capstone is a **policy-driven facade**
   that picks the right backend + queue strategy + threading automatically.
2. **No multi-NIC AF_XDP merge** (issue #11). AF_PACKET has `AsyncMultiCapture`
   (open N interfaces → unified `TaggedEvent` stream); AF_XDP has no equivalent.
   The motivating case — a **network tap that splits TX/RX across two NICs** — also
   needs the two legs tracked as **one bidirectional flow**, which today's
   per-`source_idx` keying does *not* do.

## 2. Design

### A. `AsyncXdpMultiCapture` (issue #11)
- Open N AF_XDP interfaces, each multi-queue via `XdpCapture`/`AsyncXdpCapture`,
  and present a unified merged stream — **reuse the existing `multi_streams`
  round-robin select** + `TaggedEvent { source_idx, event }`. Composes N NICs × M
  queues with no new merge machinery.
- Mirror the `AsyncMultiCapture` surface: `open(["eth0","eth1"])`,
  `flow_stream(extractor)`, `label(i)`, aggregated + per-source `capture_stats`.

### B. Tap / source-agnostic merge (the part that matters for taps)
- A TAP feeds direction A on `eth0`, direction B on `eth1`; both legs belong to
  the same flows. Today multi-interface keys flows per `source_idx` → **two
  half-flows**. Add a **merge mode** that feeds *one* tracker keyed by the
  bidirectional 5-tuple, **ignoring source**, so the legs reconstruct whole flows.
  - `AsyncXdpMultiCapture::merged_flow_stream(FiveTuple::bidirectional())` — single
    tracker, source dropped from the key. `AsyncMultiCapture` gets the same option
    (AF_PACKET taps exist too).
  - **flowscope:** the tracker already supports bidirectional keys; the change is a
    `merge_sources: bool` (or a `MergedKey` wrapper) so the source isn't folded
    into the flow key. Small, additive.
  - Document the trade-off vs the existing "two distinct flows" anti-pattern
    (scaling.md) — *merge* is correct for a tap, *distinct* is correct for a
    routing gateway. Make it an explicit opt-in, not a default.

### C. `Backend::Auto` facade
- `enum Backend { Auto, AfPacket, AfXdp { queues, sharded }, Pcap }`.
- `Monitor::builder().capture("eth0", Backend::Auto)` / a top-level
  `Capture::auto("eth0")` probes and picks: AF_XDP DRV-mode if the driver supports
  it → `Queues::Auto` → single-reactor vs `XdpShardedRunner` by core count; else
  AF_PACKET (+ fanout if N cores requested); on non-Linux or no perms, **`Pcap`
  fallback** (we already have a pcap source — promote it to a live-capture
  `AnyBackend::Pcap` arm for dev/macOS adoption without touching the fast path).
- Everything overridable — `Auto` is a smart default, not a black box. Surfaces the
  chosen plan via a log + a `CaptureHealth`-style field so operators can see it.

## 3. flowscope side
A `merge_sources` / source-agnostic key option on the tracker (additive). Nothing
else — the merge reuses existing bidirectional keying.

## 4. Milestones
- **M1** `AsyncXdpMultiCapture` + `TaggedEvent` (reuse `multi_streams`) — closes #11.
- **M2** source-agnostic `merged_flow_stream` (tap mode) on both
  `AsyncXdpMultiCapture` and `AsyncMultiCapture`; flowscope key option.
- **M3** `Backend::Auto` probe + facade + the chosen-plan introspection.
- **M4** `AnyBackend::Pcap` live arm (non-Linux fallback) behind `Backend::Auto`.
- **M5** docs (tap recipe, the merge-vs-distinct decision) + a `tap_capture` example.

## 5. Testing
- Cap-free: the merge-key logic (two synthetic feeds, same 5-tuple opposite
  directions → one flow under merge, two without); `Backend::Auto` probe decisions
  with a mocked capability source.
- Root-gated `lo`: two AF_XDP "interfaces" (lo + a `veth` pair) → `TaggedEvent`
  tags both; merged mode collapses a loopback flow seen on both into one.
- A real TX/RX-split tap is topology-gated — example-documented.

## 6. Risks & open decisions
- **Tap clock skew / reordering.** The two legs arrive on independent NIC queues;
  merged flow stats (RTT, ordering) can be skewed without HW timestamps — pairs
  naturally with the **AF_XDP RX-metadata/timestamp** plan (use `hw_timestamp` to
  re-order across legs). Note the dependency.
- **`Backend::Auto` surprise.** Auto-selection must be observable + overridable, or
  it becomes a debugging black box. Always log the chosen plan.
- **pcap fallback scope.** Live `AnyBackend::Pcap` widens adoption (dev/macOS) but
  must stay clearly second-tier (no zero-copy, lower rate) — gate + document so it
  never masquerades as the fast path.
- **Open:** does `Backend::Auto` belong on `Monitor::builder` only, or also a
  standalone `Capture::auto` for the stream API? Recommend both (thin wrapper).
