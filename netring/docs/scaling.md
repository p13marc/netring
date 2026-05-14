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
but different `source_idx`. That's intentional — see the "cross-
interface flow merging" anti-pattern below.

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

### 6. Cross-interface flow merging

Same TCP flow appearing on `eth0` (inbound) and `eth1` (outbound)
on a routing gateway is **two distinct flows** under
`AsyncMultiCapture::open` — `(source_idx=0, key)` and
`(source_idx=1, key)`. If you need a unified view of the routed
flow, do the merging in your application using both `source_idx`
fields.

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
