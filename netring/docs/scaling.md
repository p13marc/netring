# Scaling capture across cores

A working recipe for fan-out capture on busy interfaces, plus the
common anti-patterns that trip people up. Targets readers who've
hit the per-core capture ceiling and need to spread the work.

## When you need it

Single-core capture peaks somewhere around 1-5 Mpps depending on
NIC + frame size + downstream processing. On a busy DES mediator
doing 50-100 k msg/s with full TCP reassembly, the bottleneck is
the user-space stream — not the kernel ring. Fan-out moves that
bottleneck to "first available core" rather than "the one core
running your single capture loop".

## Decision matrix

| `FanoutMode`    | Distribution                       | Per-flow ordering  | Best for                                          |
|---|---|---|---|
| `Cpu`           | RX CPU (set by RSS / RPS)          | preserved          | RSS-capable NICs with skewed flow distributions   |
| `Hash`          | 5-tuple hash modulo N              | preserved          | uniformly-distributed flows (NOT skewed traffic)  |
| `LoadBalance`   | round-robin                        | **broken**          | stateless pipelines, header-only inspection      |
| `Rollover`      | first non-full socket              | preserved          | failover; primary worker can drain alone         |
| `Random`        | random                             | **broken**          | rarely the right answer; mostly historical       |
| `QueueMapping`  | RX queue (set by NIC steering)     | preserved          | tightest cache-locality when NIC RSS is tuned    |
| `Ebpf`          | caller-supplied eBPF program       | up to the program  | custom distribution (load-aware, content-aware)  |

**Default recommendation: `FanoutMode::Cpu`**. Combined with NIC
RSS (default on most multi-queue NICs), it gives you N-way
parallelism with per-flow ordering preserved, while keeping each
flow on a single core for cache-locality.

## Recipe — `AsyncMultiCapture::open_workers`

The headline shape:

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures::StreamExt;
use netring::{AsyncMultiCapture, flow::extract::FiveTuple};

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let n_workers: usize = 4;
    let group_id: u16 = 0xDE57;  // unique per process

    // 4 captures, fanned out by RX CPU on eth0.
    let multi = AsyncMultiCapture::open_workers("eth0", n_workers, group_id)?;

    // Pin each underlying capture to a CPU (one task per worker).
    let cpus = core_affinity::get_core_ids().unwrap_or_default();
    let (captures, labels) = multi.into_captures();
    let total = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::with_capacity(n_workers);
    for (i, cap) in captures.into_iter().enumerate() {
        let label = labels[i].clone();
        let total = total.clone();
        let core = cpus.get(i % cpus.len()).copied();
        handles.push(tokio::task::spawn_blocking(move || {
            if let Some(c) = core {
                core_affinity::set_for_current(c);
            }
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap();
            rt.block_on(async move {
                let mut stream = cap.flow_stream(FiveTuple::bidirectional());
                while let Some(evt) = stream.next().await {
                    if evt.is_ok() {
                        total.fetch_add(1, Ordering::Relaxed);
                    }
                }
                eprintln!("{label} exited; events seen ≈ unknown");
            });
        }));
    }
    for h in handles { h.await?; }
    Ok(())
}
```

If you don't want to pin threads or want all events merged into
one stream (with per-worker tagging), drop `.into_captures()` and
use the merged stream:

```rust
let mut stream = multi.flow_stream(FiveTuple::bidirectional());
while let Some(tagged) = stream.next().await {
    let evt = tagged?;
    println!("worker {} → {:?}", evt.source_idx, evt.event);
}
```

## Recipe — multi-interface gateway

```rust
use netring::AsyncMultiCapture;
use netring::flow::extract::FiveTuple;

let multi = AsyncMultiCapture::open(["eth0", "eth1"])?;
let mut stream = multi.flow_stream(FiveTuple::bidirectional());
while let Some(tagged) = stream.next().await {
    let evt = tagged?;
    let iface = stream.label(evt.source_idx).unwrap_or("?");
    println!("[{iface}] {:?}", evt.event);
}
```

The same TCP flow appearing on both interfaces (e.g. on a routing
gateway) yields **two distinct flows** with the same `FiveTuple`
but different `source_idx`. That's intentional for a gateway — for a
**tap** (where the two directions are two legs of *one* flow), use
`merged_flow_stream` instead (next recipe).

## Recipe — tap merge (`merged_flow_stream`)

A network **tap** splits a flow's two directions across two NICs: TX
on `eth0`, RX on `eth1`. Both legs are **one** bidirectional flow. Feed
them into a single shared tracker with `merged_flow_stream`:

```rust
use netring::AsyncMultiCapture;
use netring::flow::extract::FiveTuple;

let multi = AsyncMultiCapture::open(["eth0", "eth1"])?;        // TX leg, RX leg
let mut stream = multi.merged_flow_stream(FiveTuple::bidirectional());
while let Some(evt) = stream.next().await {
    let evt = evt?;                                            // plain FlowEvent — no source_idx envelope
    if let FlowEvent::Ended { stats, .. } = &evt {
        // Which physical leg each canonical direction arrived on
        // (RFC 5103 biflow); `capture_leg_inconsistent` flags a
        // tap-miswire / asymmetric route.
        let _ = (stats.source_idx_forward, stats.source_idx_reverse);
        assert!(!stats.capture_leg_inconsistent);
    }
}
```

`merged_flow_stream` is **one** `FlowTracker` fed by all sources, keyed
by the bare bidirectional 5-tuple, so the `a→b` and `b→a` legs coalesce
by construction. Each source's packets are stamped `source_idx = i + 1`
so flowscope binds `FlowStats::source_idx_{forward,reverse}` without
splitting the flow. For race-robust TCP roles across the legs, pair with
`MultiStreamConfig::with_infer_tcp_initiator(true)` via
`merged_flow_stream_with`.

### merge vs distinct — pick by topology

| Topology | Method | Result |
|---|---|---|
| **Tap** (TX/RX split across NICs) | `merged_flow_stream` | one bidirectional flow, legs bound |
| **Routing gateway** (flow transits two NICs) | `flow_stream` | two distinct `TaggedEvent` flows |

**Caveat — clock skew across legs.** The two legs arrive on independent
NIC queues; without hardware RX timestamps, merged ordering can skew and
a TCP state machine may see SYN/ACK before data (the Suricata
`copy-iface` failure mode). `infer_tcp_initiator` corrects the *role*
axis; cross-leg reordering pairs with AF_XDP RX hardware timestamps
(#13).

**AF_XDP tap merge.** `AsyncXdpMultiCapture` exposes the same
`merged_flow_stream` / `merged_flow_stream_with` (issue #105 Phase B over
AF_XDP, built on the `AsyncFlowSource` generalization #104) — kernel-bypass
tap reconstruction with identical capture-leg semantics:

```rust
use netring::AsyncXdpMultiCapture;
use netring::flow::extract::FiveTuple;

let multi = AsyncXdpMultiCapture::open(["eth0", "eth1"])?;     // TX leg, RX leg
let mut stream = multi.merged_flow_stream(FiveTuple::bidirectional());
// …identical FlowEvent loop as the AF_PACKET recipe above.
```

## Recipe — heterogeneous setups

Per-source different config (buffer sizes, filters, fanout
groups):

```rust
use netring::{AsyncCapture, AsyncMultiCapture, BpfFilter, CaptureBuilder};

// Worker pool on eth0 with a port-443 filter.
let workers_filter = BpfFilter::builder().tcp().dst_port(443).build()?;
let workers = AsyncMultiCapture::open_with_filter(
    std::iter::repeat("eth0").take(4),
    workers_filter,
)?;
// Wait — this won't quite work because each worker needs its own
// fanout-group socket. Use this shape only for distinct interfaces.
//
// For heterogeneous *worker pools*, build manually + from_captures:
let mut captures = Vec::new();
let mut labels = Vec::new();
for i in 0..4 {
    let rx = CaptureBuilder::default()
        .interface("eth0")
        .fanout(netring::FanoutMode::Cpu, 0xDE57)
        // ...additional per-worker tuning...
        .build()?;
    captures.push(AsyncCapture::new(rx)?);
    labels.push(format!("eth0-worker-{i}"));
}
let multi = AsyncMultiCapture::from_captures(captures, Some(labels))?;
```

## Aggregating stats across sources

```rust
// One snapshot, all sources summed:
let agg = stream.capture_stats();
println!("packets={} drops={} freeze={}",
         agg.packets, agg.drops, agg.freeze_count);

// Per-source breakdown:
for (label, stats) in stream.per_source_capture_stats() {
    match stats {
        Some(Ok(s)) => println!("[{label}] {s:?}"),
        Some(Err(e)) => eprintln!("[{label}] error: {e}"),
        None => eprintln!("[{label}] exhausted"),
    }
}
```

## AF_XDP: one socket per RX queue

The fanout above is the **AF_PACKET** scaling model (`PACKET_FANOUT` — the kernel
load-balances one logical capture across N worker sockets). **AF_XDP is
different**: an `XdpSocket` binds to a *single* RX queue (`queue_id`), and the
NIC's RSS hashing spreads inbound traffic across all its queues. So:

- **Yes — full-NIC AF_XDP capture means N `XdpSocket`s, one per queue.** A single
  socket on queue 0 only ever sees the traffic RSS hashed to queue 0, **even in
  promiscuous mode** (promisc lifts the MAC filter; it does not collapse RSS).
- Check the queue count with `ethtool -l <iface>` (the *Combined* row).

Two ways to capture everything:

| Approach | How | Trade-off |
|---|---|---|
| **One socket per queue** | `XdpCapture` opens one socket per `queue_id`, loads one redirect program, registers each in its XSKMAP, and drains them round-robin | full line-rate; the canonical pattern |
| **Collapse to one queue** | `ethtool -L <iface> combined 1`, then a single `XdpSocket` | simplest; caps throughput at one core's worth |

The high-level [`XdpCapture`](../docs/API_OVERVIEW.md#xdpcapture--full-nic-multi-queue-capture-issue-6-feature-xdp-loader)
handle does the one-socket-per-queue orchestration for you:

```rust
use netring::xdp::{XdpCapture, Queues};
let mut cap = XdpCapture::builder()
    .interface("eth0").queues(Queues::Auto).promiscuous(true).build()?;
while let Some((queue_id, batch)) = cap.next_batch_blocking(timeout)? { /* … */ }
// or cap.into_parts() → one socket per worker thread (Suricata model)
```

It enables **promiscuous mode once** (interface-global, reference-counted — a
single `PACKET_MR_PROMISC` guard covers every queue) and gives each socket its
**own UMEM** — the safe default, since sharing a UMEM across per-CPU sockets
races on the FILL queue. Runnable: `examples/xdp/xdp_multiqueue.rs`.

Two Monitor tiers, mirroring plain-Monitor ↔ `ShardedRunner` on the AF_PACKET side:

- **Single-reactor** — `MonitorBuilder::xdp_queues(Queues::Auto)`: one socket per
  queue behind a single program, drained through a unified round-robin
  (`AnyBackend::XdpMq`) on **one core**. Captures the whole NIC instead of just
  queue 0; the simplest fix, fine up to a core's worth of traffic.
- **Sharded (line rate)** — `XdpShardedRunner`: **one `Monitor` per RX queue**,
  each on its own core, ideally busy-polled. The AF_XDP analogue of
  `ShardedRunner`; this is Suricata's `threads: auto`.

```rust
use netring::monitor::XdpShardedRunner;
use netring::xdp::Queues;
use netring::prelude::*;

XdpShardedRunner::new("eth0", Queues::Auto, |queue, builder| {
    builder.protocol::<Tcp>().on::<FlowStarted<Tcp>>(move |_e| Ok(()))
})
.promiscuous(true)
.busy_poll(50)        // µs — one busy-polled socket per core
.pin_cpus(true)
.run_for(std::time::Duration::from_secs(60))?;
```

Pair `pin_cpus(true)` with NIC IRQ affinity (queue `i`'s interrupt on core `i`)
and the netdev NAPI knobs (`napi-defer-hard-irqs`, `gro-flush-timeout`) so
busy-poll is effective. Runnable: `examples/xdp/xdp_sharded.rs`.

> Some NICs (notably Mellanox) require you to create **twice** as many AF_XDP
> queues as `ethtool -L combined` reports to be sure of receiving every packet.

## Anti-patterns

### 1. `FanoutMode::Hash` on skewed traffic

`Hash` distributes by 5-tuple. DES traffic — and many industrial
protocol traces — has one large mediator flow plus many small
short-lived flows. Under `Hash`, the mediator's flow always hits
the same worker, swamping it while the others idle.

**Symptom**: one worker at 100% CPU, the rest at 5% even though
total throughput is well below the multi-worker ceiling.

**Fix**: use `FanoutMode::Cpu`. Verify the NIC has RSS enabled
(`ethtool -X eth0` shows the indirection table).

### 2. More workers than RX queues

If your NIC has 4 RX queues and you spin up 16 workers with
`FanoutMode::Cpu`, 12 of them will see zero traffic — `Cpu` routes
by the RX CPU, and only 4 CPUs are receiving anything.

**Symptom**: `capture_stats().packets` near zero on most workers.

**Fix**: either reduce worker count to RX-queue count, or
`ethtool -L eth0 combined 16` (driver permitting).

### 3. Reading `PACKET_STATISTICS` from only one worker

Each fanout socket has its own statistics counters. Reading one
worker's stats and assuming they represent the group → 75% of
traffic invisible.

**Fix**: `multi_stream.capture_stats()` (aggregated) or
`multi_stream.per_source_capture_stats()` (per-worker).

### 4. Mixed fanout modes in the same group

The kernel rejects this at `setsockopt(PACKET_FANOUT)` with
`Invalid argument`. All sockets in a group must share the same
mode.

**Symptom**: builder returns `Error::SockOpt` on the second
worker.

**Fix**: pick one mode for the whole group; build separate groups
for different distribution strategies.

### 5. Identical `group_id` across processes

Two unrelated programs picking the same `group_id` on the same
interface land in the same fanout group → packets bounce between
processes unpredictably.

**Fix**: choose a deliberate 16-bit constant per process. Hash
your binary name, derive from PID modulo 0x10000, or just pick a
project-specific magic (e.g. `0xDE57` for DES).

### 6. Using `flow_stream` for a tap (wrong tool)

Same TCP flow appearing on `eth0` (inbound) and `eth1` (outbound) is
**two distinct flows** under `flow_stream` —  `(source_idx=0, key)` and
`(source_idx=1, key)`. Correct for a **routing gateway**; wrong for a
**tap**, where the two directions are one flow. For a tap, use
[`merged_flow_stream`](#recipe--tap-merge-merged_flow_stream) — one
shared tracker that coalesces the legs and binds
`source_idx_{forward,reverse}`. (Don't hand-roll the merge from two
`source_idx` fields; the bare bidirectional key already canonicalizes
both legs to the same flow.)

### 7. PACKET_FANOUT on `lo`

`lo` has no RSS, so all RX happens on whichever CPU originated
the traffic. `FanoutMode::Cpu` then collapses to "one worker gets
everything". Use `FanoutMode::LoadBalance` for testing
multi-worker shapes on `lo`.

## Troubleshooting

### "Invalid argument" on fanout setsockopt

- Different `FanoutMode` than other sockets in the same group.
  See anti-pattern #4.
- `FanoutFlags::DEFRAG` requested but kernel lacks defrag support
  in fanout. Drop the flag.
- `group_id == 0` on some kernels — pick a non-zero value.

### Uneven distribution

```
# Inspect RSS indirection:
ethtool -X eth0

# Inspect per-queue interrupts:
cat /proc/interrupts | grep eth0

# Check RX queue count:
ethtool -L eth0
```

If RSS is producing skew, set explicit `--rxhash` weights or move
to `FanoutMode::QueueMapping` with hand-picked queue affinities.

### Wrong queue count

```
# Set 8 combined queues (driver permitting):
ethtool -L eth0 combined 8
```

Match worker count to queue count for `FanoutMode::Cpu`.

## Cross-shard state aggregation (0.22)

Each shard's `Monitor` owns private state — no cross-shard locking on
the hot path. For a **global** view, register a merge on the runner:

```rust
ShardedRunner::new("eth0", FanoutMode::Cpu, 42, num_cpus, build_shard)
    .state_auto_merge::<ConnCount>(Duration::from_secs(1))  // T: AddAssign
    .on_merge::<ConnCount, _>(|total| println!("global: {}", total.0));
```

A merge-worker thread probes each shard on the cadence, `mem::take`s its
`T` slot (the shard re-creates `T::default()` lazily, so each interval
folds the delta), and folds into a persistent primary — the running
grand total handed to `on_merge`. Use `.merge_state(period, |p, t| …)`
for a custom fold. This replaces the older "route per-shard anomalies
through `Tee + ChannelSink` to a single collator task" workaround.

Per-shard secondary sink layers: `.layer(spec)` mints one independent
layer instance per shard (a `DedupeAnomalies` table / `Sample` RNG isn't
shared) — cloneable config layers pass directly, `Tee` via
`LayerFactory(|| …)`. See `examples/monitor/sharded_runner.rs`.

## Cross-references

- [`packet(7)`](https://man7.org/linux/man-pages/man7/packet.7.html)
  — kernel documentation for AF_PACKET fanout.
- [Enabling Packet Fan-Out in libpcap (TMA 2017)](https://dl.ifip.org/db/conf/tma/tma2017/tma2017_paper65.pdf)
  — the canonical paper on AF_PACKET fanout in practice.
- [Suricata AF-PACKET docs](https://docs.securityonion.net/en/2.4/af-packet.html)
  — operational guide for production deployments.
- AF_XDP multi-queue capture (XSKMAP) — different model, see
  `XdpSocketBuilder::with_program` and plan 12 follow-ups.
- [The trouble with multiple capture interfaces (Packet-Foo)](https://blog.packet-foo.com/2014/08/the-trouble-with-multiple-capture-interfaces/)
  — context on cross-interface timestamp ordering.
