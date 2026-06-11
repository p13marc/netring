# netring 0.21 Phase E — Pcap source + offline replay

## 1. Summary

`MonitorBuilder::pcap_source(path)` opens a pcap file instead of an AF_PACKET ring. Uses flowscope 0.13.0's `DeferredDriverBuilder<E>` so protocols can be registered before the source is chosen. `Monitor::replay()` drives the run loop until pcap EOF. `with_speed_factor(f)` paces replay for time-realistic behavior. `MonitorBuilder::run_until_idle(window)` provides an idle-window stop condition.

## 2. Status

Not started. Depends on Phase H.1 (flowscope 0.13.0).

## 3. Prerequisites

- Phase H.1 — flowscope 0.13.0 dep bump for `DeferredDriverBuilder` and `PcapFlowSource::with_speed_factor`.

## 4. Out of scope

- Multi-file pcap merge / glob-based replay. Downstream tools (or a follow-up) handle it.
- Real-time pcap capture (live `tcpdump`-style sniffing into a pcap). The `pcap` feature is for offline files only.

## 5. Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/monitor/mod.rs` | `MonitorBuilder::pcap_source(path)` + `pcap_speed_factor(f)`; `Monitor::replay()`; `run_until_idle(window)` |
| Modify | `src/monitor/run.rs` | New `Source::Pcap(PcapFlowSource)` variant alongside the existing AF_PACKET stream branch |
| Modify | `Cargo.toml` | Feature gate `pcap` already exists; thread through to flowscope |
| New | `examples/monitor/pcap_replay.rs` | Demo: replay a pcap at 2× speed, dispatch handlers, write to StdoutSink |

## 6. API

### E.1 — `pcap_source` + `replay()`

```rust
// src/monitor/mod.rs
impl MonitorBuilder {
    /// Use a pcap file as the packet source instead of a live interface.
    /// Mutually exclusive with `.interface()` / `.interfaces()` / `.fanout_per_cpu()`.
    pub fn pcap_source(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.source = Source::Pcap(path.into());
        self
    }

    /// Pace pcap replay. `1.0` = real-time, `2.0` = double speed,
    /// `f64::INFINITY` (default) = as-fast-as-possible.
    pub fn pcap_speed_factor(mut self, factor: f64) -> Self {
        self.pcap_speed_factor = Some(factor);
        self
    }
}

impl Monitor {
    /// Drive the run loop until the pcap source is exhausted.
    /// Returns an error if the source is a live interface (use `run_for`/`run_until_signal`).
    pub async fn replay(self) -> Result<()> { … }
}
```

The pcap source path uses flowscope's `PcapFlowSource::open(path)?.with_speed_factor(f)`. Per flowscope's tokio caveat, replay calls `tokio::task::spawn_blocking` for the sleep-bounded pcap iterator (the blocking sleep would otherwise monopolize the runtime worker).

### E.2 — `run_until_idle`

```rust
impl MonitorBuilder {
    /// Stop the run loop after `window` consecutive seconds with no event activity.
    /// Useful for pcap replay (auto-stop after EOF + grace) and one-shot scans.
    pub fn idle_timeout(mut self, window: Duration) -> Self { … }
}

impl Monitor {
    pub async fn run_until_idle(self, window: Duration) -> Result<()> { … }
}
```

Implemented via a `tokio::time::Instant`-based last-event timestamp in the run loop; the timeout branch in `tokio::select!` fires after `window` of inactivity.

### E.3 — `examples/monitor/pcap_replay.rs`

```rust
use std::time::Duration;
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pcap = std::env::args().nth(1).expect("usage: pcap_replay <path>");

    Monitor::builder()
        .pcap_source(pcap)
        .pcap_speed_factor(2.0)
        .protocol::<Tcp>()
        .protocol::<Http>()
        .on_ctx::<Http>(|msg, ctx| {
            ctx.emit("Http", Severity::Info).emit();
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .replay()
        .await?;

    Ok(())
}
```

## 7. Implementation steps

1. **E.1** — add `Source` enum (`Iface(Vec<String>)` | `Pcap(PathBuf)`). Update `MonitorBuilder` to use `DeferredDriverBuilder<FiveTuple>` so protocols register before the source decision. `MonitorBuilder::build()` materializes the driver via `build_with(FiveTuple::bidirectional())`.
2. **E.2** — pcap branch in `run.rs`: open via `PcapFlowSource::open(path).with_speed_factor(factor)`, wrap in `spawn_blocking` task feeding a `mpsc::Receiver<OwnedPacket>` that the main run loop consumes.
3. **E.3** — `run_until_idle` stop condition.
4. **E.4** — example + matching test (synthetic 5-flow pcap).

## 8. Tests

- `tests/pcap_replay::reads_synthetic_pcap_and_dispatches` — generate a 5-flow pcap with `flowscope::test_helpers::events` + a synthetic pcap writer, run `Monitor::replay()`, assert handlers fired N times.
- `tests/pcap_replay::speed_factor_2x_halves_replay_duration` — replay a 10-second pcap with `speed_factor = 2.0`; assert elapsed is ~5s ± tolerance.
- `tests/run_until_idle::no_events_triggers_stop` — fake source with no events, idle window 200ms; run loop exits within 250ms.
- Doctest on `MonitorBuilder::pcap_source`.

## 9. Acceptance criteria

- `cargo build --example monitor_pcap_replay --features "tokio,flow,pcap,http"` builds.
- `cargo run --example monitor_pcap_replay -- tests/fixtures/sample.pcap` replays + emits to stdout.
- `pcap_source` + `interface` returns `BuildError::SourceAlreadySet`.
- `run_until_idle` exits within the window plus the run-loop polling jitter.

## 10. Risks

- **R1 — `spawn_blocking` propagation.** The pcap iterator's `std::thread::sleep` (for `with_speed_factor`) blocks the spawned task. `tokio::task::spawn_blocking` is the canonical fix; the iterator runs on a dedicated thread, packets flow through an `mpsc::Receiver` back to the main run loop. Documented.
- **R2 — Pcap reader EOF semantics.** flowscope's `PcapFlowSource` returns `None` at EOF; the run loop needs to distinguish "EOF" from "no events this poll." Use `Option::Option::is_none` after the spawn-blocking task channel closes.

## 11. Effort

- LoC delta: +350 (pcap branch ~200, run_until_idle ~50, example ~50, tests ~50).
- Time estimate: **~1.5 days**.

## 12. Provenance

- §4.2 (`MonitorBuilder::pcap_source`) → E.1.
- §4.4 (`run_until_idle`) → E.2.
- §3.8 (pcap example for new API) → E.3.
- flowscope 0.13.0 plan 152 (`with_speed_factor`) + plan 124 (`DeferredDriverBuilder`) ship the upstream foundation.
