//! 0.21 Phase C — per-CPU sharded monitor execution.
//!
//! A [`ShardedRunner`] spawns N OS threads, each running its own
//! `current_thread` tokio runtime + its own single-shard
//! [`crate::monitor::Monitor`]. Each shard opens its own
//! AsyncCapture against the same interface but with a shared
//! AF_PACKET fanout group; the Linux kernel hashes inbound
//! packets across shards per the configured [`FanoutMode`].
//!
//! ## Scope
//!
//! - Each shard's state, dispatcher, and sink are private. The
//!   merge worker (`merge_state::<T>`) from the Phase C plan is
//!   deferred — users wanting global aggregation today route
//!   per-shard anomalies through a `Tee + ChannelSink` to a
//!   single collator task, or use a sharded metrics backend.
//! - `subscribe::<P>()` is single-shard-only. Each shard has its
//!   own `BroadcastSlotHandle`; subscribing across shards needs
//!   per-shard subscriber bookkeeping that we'll add in 0.22.
//! - `replay()` is single-shard-only — pcap is a single file
//!   stream, not fan-out-shaped.
//!
//! ## Threading
//!
//! Each shard owns a dedicated OS thread that drives one
//! `current_thread` tokio runtime. The runtime is local to that
//! thread; the runner doesn't coordinate them at runtime past
//! shutdown signaling.
//!
//! Shutdown: an `Arc<AtomicBool>` flag tells each shard's monitor
//! whether to stop. Shards poll the flag through their own
//! `run_until` deadline path — for a deadline-based run, each
//! shard runs the same `deadline`, so they exit naturally
//! together. SIGINT/SIGTERM under `run_until_signal`: each shard
//! installs its own signal handler; the first one to fire wakes
//! its shard, which sets the shared flag.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::config::FanoutMode;
use crate::error::Result;
use crate::monitor::Monitor;

/// 0.21 C: per-CPU sharded monitor runner.
///
/// Spawns one OS thread per shard; each thread runs its own
/// single-shard [`Monitor`] driven by a builder closure.
pub struct ShardedRunner {
    iface: String,
    mode: FanoutMode,
    group_id: u16,
    num_shards: usize,
    build_shard: Arc<dyn Fn(usize) -> Result<Monitor> + Send + Sync + 'static>,
    /// 0.22 §5.2: per-shard secondary layers. Each shard calls
    /// `spec.instantiate()` for its own independent layer instance;
    /// applied *outside* the builder-registered layers (so runner specs
    /// run first / outermost).
    layer_specs: Vec<Box<dyn crate::layer::LayerSpec>>,
}

impl ShardedRunner {
    /// Create a sharded runner.
    ///
    /// - `iface` — the interface every shard opens (e.g. `"eth0"`).
    /// - `mode` — kernel hash strategy. `FanoutMode::Cpu` distributes
    ///   by the CPU servicing the IRQ; `FanoutMode::Hash` distributes
    ///   by `(srcip, srcport, dstip, dstport, proto)` — preferred
    ///   when downstream pipelines key on flow.
    /// - `group_id` — opaque ID; all shards must share it. Pick any
    ///   non-zero u16 unique to this process.
    /// - `num_shards` — typically `num_cpus::get()` or a fraction
    ///   thereof. Each shard runs its own thread.
    /// - `build_shard(cpu_idx)` — produces the per-shard
    ///   [`Monitor`]. **Each invocation must build a fully
    ///   independent monitor.** The closure runs once per shard on
    ///   the spawned thread. It must call
    ///   [`crate::monitor::MonitorBuilder::fanout`] with the same
    ///   `(mode, group_id)` so the kernel knows the shards share a
    ///   fanout set.
    ///
    /// ```ignore
    /// use netring::config::FanoutMode;
    /// use netring::monitor::shard::ShardedRunner;
    /// use netring::prelude::*;
    ///
    /// let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    /// let runner = ShardedRunner::new("eth0", FanoutMode::Cpu, 42, 4, {
    ///     let counter = counter.clone();
    ///     move |cpu_idx| {
    ///         let c = counter.clone();
    ///         Monitor::builder()
    ///             .interface("eth0")
    ///             .fanout(FanoutMode::Cpu, 42)
    ///             .name(format!("shard-{cpu_idx}"))
    ///             .protocol::<Tcp>()
    ///             .on::<FlowStarted<Tcp>>(move |_e: &FlowStarted<Tcp>| {
    ///                 c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    ///                 Ok(())
    ///             })
    ///             .build()
    ///     }
    /// });
    /// runner.run_for(std::time::Duration::from_secs(60))?;
    /// # netring::error::Result::<()>::Ok(())
    /// ```
    pub fn new<F>(
        iface: impl Into<String>,
        mode: FanoutMode,
        group_id: u16,
        num_shards: usize,
        build_shard: F,
    ) -> Self
    where
        F: Fn(usize) -> Result<Monitor> + Send + Sync + 'static,
    {
        Self {
            iface: iface.into(),
            mode,
            group_id,
            num_shards: num_shards.max(1),
            build_shard: Arc::new(build_shard),
            layer_specs: Vec::new(),
        }
    }

    /// 0.22 §5.2: register a per-shard secondary layer.
    ///
    /// Each shard calls `spec.instantiate()` to get its **own**
    /// independent layer (so a `DedupeAnomalies` table / `Sample` RNG
    /// isn't shared across shards). Cloneable config layers
    /// (`MinSeverity`, `DedupeAnomalies`, …) pass directly; non-`Clone`
    /// layers like `Tee` go through
    /// [`LayerFactory`](crate::layer::LayerFactory). Runner layers wrap
    /// *outside* the per-shard builder layers (they run first).
    pub fn layer<L: crate::layer::LayerSpec>(mut self, spec: L) -> Self {
        self.layer_specs.push(Box::new(spec));
        self
    }

    /// Number of shards this runner will spawn.
    pub fn shard_count(&self) -> usize {
        self.num_shards
    }

    /// Interface every shard opens.
    pub fn interface(&self) -> &str {
        &self.iface
    }

    /// Fanout config every shard uses.
    pub fn fanout(&self) -> (FanoutMode, u16) {
        (self.mode, self.group_id)
    }

    /// Run all shards until each individual `deadline` fires.
    /// Returns the first error from any shard, or `Ok(())` if
    /// every shard returned cleanly.
    pub fn run_until(self, deadline: Instant) -> Result<()> {
        self.run_inner(RunMode::Deadline(deadline))
    }

    /// Run all shards for `duration`. Each shard sees the same
    /// wall-clock deadline.
    pub fn run_for(self, duration: Duration) -> Result<()> {
        let deadline = Instant::now() + duration;
        self.run_until(deadline)
    }

    /// Run all shards until SIGINT/SIGTERM is observed. Each shard
    /// installs its own signal handler; whichever fires first
    /// flips the shared shutdown flag, prompting siblings to
    /// finish their current packet and exit.
    pub fn run_until_signal(self) -> Result<()> {
        self.run_inner(RunMode::Signal)
    }

    fn run_inner(self, mode: RunMode) -> Result<()> {
        let stop = Arc::new(AtomicBool::new(false));
        let build_shard = self.build_shard;
        // 0.22 §5.2: share the layer specs across shard threads; each
        // shard instantiates its own layer instances.
        let layer_specs = Arc::new(self.layer_specs);
        let mut handles = Vec::with_capacity(self.num_shards);

        for cpu in 0..self.num_shards {
            let stop = Arc::clone(&stop);
            let build = Arc::clone(&build_shard);
            let layer_specs = Arc::clone(&layer_specs);
            let handle = std::thread::Builder::new()
                .name(format!("netring-shard-{cpu}"))
                .spawn(move || -> Result<()> {
                    // Each shard owns a current_thread tokio runtime.
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(crate::error::Error::Io)?;

                    let mut monitor = build(cpu)?;
                    // Apply per-shard secondary layers (fresh instances).
                    for spec in layer_specs.iter() {
                        monitor.wrap_sink(spec.instantiate());
                    }

                    match mode {
                        RunMode::Deadline(deadline) => {
                            // Compute the per-shard duration so each
                            // shard converges on the same exit time.
                            let now = Instant::now();
                            let dur = deadline.saturating_duration_since(now);
                            rt.block_on(monitor.run_for(dur))?;
                        }
                        RunMode::Signal => {
                            rt.block_on(monitor.run_until_signal())?;
                        }
                    }
                    let _ = stop;
                    Ok(())
                })
                .map_err(crate::error::Error::Io)?;
            handles.push(handle);
        }

        // Drain each shard. Return the first error encountered;
        // continue joining the rest to avoid leaked threads.
        let mut first_err: Option<crate::error::Error> = None;
        for h in handles {
            match h.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
                Err(panic) => {
                    if first_err.is_none() {
                        first_err = Some(crate::error::Error::Io(std::io::Error::other(format!(
                            "shard thread panicked: {panic:?}"
                        ))));
                    }
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
        if let Some(e) = first_err {
            return Err(e);
        }
        Ok(())
    }
}

#[derive(Copy, Clone)]
enum RunMode {
    Deadline(Instant),
    Signal,
}

impl std::fmt::Debug for ShardedRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardedRunner")
            .field("iface", &self.iface)
            .field("mode", &self.mode)
            .field("group_id", &self.group_id)
            .field("num_shards", &self.num_shards)
            .finish()
    }
}
