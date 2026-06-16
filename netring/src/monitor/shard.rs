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
    /// 0.22 §5.1: cross-shard state merges. Registered via
    /// [`Self::merge_state`] / [`Self::state_auto_merge`] /
    /// [`Self::on_merge`]; driven by the merge-worker thread.
    merges: Vec<crate::monitor::merge::MergeSpec>,
    /// 0.25 C1: pin each shard's OS thread to CPU `shard_index % n_cores`.
    /// Off by default. See [`Self::pin_cpus`].
    pin_cpus: bool,
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
            merges: Vec::new(),
            pin_cpus: false,
        }
    }

    /// 0.25 C1: pin each shard's OS thread to a dedicated CPU core (shard `i`
    /// → core `i % num_cores`) via `sched_setaffinity`.
    ///
    /// With one shard per core and the kernel steering each flow to a fixed
    /// shard (`FanoutMode::Cpu`, or a symmetric hash), pinning keeps a flow's
    /// state, its socket's RX ring, and the worker on the same core — fewer
    /// cross-core cache bounces and no scheduler migration of the busy capture
    /// thread. Best paired with `num_shards == num_cores` and IRQ affinity set
    /// so the NIC queue for core `i` also lands on core `i`.
    ///
    /// No-op if affinity can't be set (logged at `warn`); never fails the run.
    pub fn pin_cpus(mut self, on: bool) -> Self {
        self.pin_cpus = on;
        self
    }

    /// 0.22 §5.1: periodically fold each shard's `T` state slot into a
    /// single primary via `merge(&mut primary, shard_value)`.
    ///
    /// Every `period`, a merge-worker thread probes each shard for its
    /// `T` (removing it — the shard re-creates `T::default()` lazily, so
    /// each interval folds the delta since the last probe), folds into a
    /// persistent primary (the running grand total), and hands it to any
    /// [`Self::on_merge`] observer. Pairs with `MonitorBuilder::state::<T>()`
    /// in `build_shard`. **flowscope follow-up:** `RollingRate::merge_into`
    /// would let a sharded `bandwidth_by_app` merge globally (0.15 wishlist).
    pub fn merge_state<T, F>(mut self, period: Duration, merge: F) -> Self
    where
        T: Default + Send + 'static,
        F: FnMut(&mut T, T) + Send + 'static,
    {
        self.merges
            .push(crate::monitor::merge::MergeSpec::new::<T, F>(period, merge));
        self
    }

    /// 0.22 §5.1: [`Self::merge_state`] with `AddAssign` as the fold —
    /// the common "sum a per-shard counter into a global total" case.
    pub fn state_auto_merge<T>(mut self, period: Duration) -> Self
    where
        T: std::ops::AddAssign + Default + Send + 'static,
    {
        self.merges
            .push(crate::monitor::merge::MergeSpec::new::<T, _>(
                period,
                |p: &mut T, t: T| *p += t,
            ));
        self
    }

    /// 0.22 §5.1: observe the merged primary `T` after each interval's
    /// fold (e.g. print / emit a global view). **Call after**
    /// [`Self::merge_state`] / [`Self::state_auto_merge`] for the same
    /// `T` — it attaches to that spec; with no matching spec it is a
    /// silent no-op.
    pub fn on_merge<T, G>(mut self, observe: G) -> Self
    where
        T: 'static,
        G: Fn(&T) + Send + 'static,
    {
        let tid = std::any::TypeId::of::<T>();
        if let Some(spec) = self.merges.iter_mut().find(|s| s.type_id() == tid) {
            spec.set_observe::<T, G>(observe);
        }
        self
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
        let pin_cpus = self.pin_cpus;
        // 0.22 §5.2: share the layer specs across shard threads; each
        // shard instantiates its own layer instances.
        let layer_specs = Arc::new(self.layer_specs);
        let mut handles = Vec::with_capacity(self.num_shards);

        // 0.22 §5.1: if any merge is registered, create one request
        // channel per shard — the shard run loop owns the receiver, the
        // merge worker holds all senders.
        let merges = self.merges;
        let (merge_txs, mut merge_rxs): (Vec<_>, Vec<Option<_>>) = if merges.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            (0..self.num_shards)
                .map(|_| {
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                    (tx, Some(rx))
                })
                .unzip()
        };

        for cpu in 0..self.num_shards {
            let stop = Arc::clone(&stop);
            let build = Arc::clone(&build_shard);
            let layer_specs = Arc::clone(&layer_specs);
            let merge_rx = merge_rxs.get_mut(cpu).and_then(Option::take);
            let handle = std::thread::Builder::new()
                .name(format!("netring-shard-{cpu}"))
                .spawn(move || -> Result<()> {
                    // 0.25 C1: pin this shard's thread to its core before doing
                    // any work, so the runtime + capture ring stay core-local.
                    if pin_cpus && !pin_current_thread_to_core(cpu) {
                        tracing::warn!(shard = cpu, "could not set CPU affinity for shard");
                    }
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
                    // 0.22 §5.1: wire the merge-request receiver.
                    if let Some(rx) = merge_rx {
                        monitor.set_merge_rx(rx);
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

        // 0.22 §5.1: spawn the merge worker (one extra OS thread, no
        // runtime). It probes shards on each spec's cadence while they
        // run, and exits when `stop` flips.
        let merge_handle = if merges.is_empty() {
            None
        } else {
            let stop = Arc::clone(&stop);
            let handle = std::thread::Builder::new()
                .name("netring-merge".to_string())
                .spawn(move || crate::monitor::merge::merge_worker(merge_txs, merges, stop))
                .map_err(crate::error::Error::Io)?;
            Some(handle)
        };

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
        // Join the merge worker (it sees `stop`, does a final best-effort
        // pass, and exits).
        if let Some(h) = merge_handle {
            let _ = h.join();
        }
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

/// 0.25 C1: pin the calling OS thread to a single CPU core via
/// `sched_setaffinity`. `index` is taken modulo the number of online cores, so
/// `num_shards > cores` wraps instead of failing. Returns `false` if the
/// syscall fails (e.g. a restricted cgroup cpuset) — callers treat that as a
/// best-effort no-op.
pub(crate) fn pin_current_thread_to_core(index: usize) -> bool {
    let n = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1);
    let core = index % n;
    // SAFETY: `cpu_set_t` is a POD bitmask; we zero it, set exactly one bit, and
    // pass its byte size. pid `0` targets the calling thread only.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) == 0
    }
}

impl std::fmt::Debug for ShardedRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardedRunner")
            .field("iface", &self.iface)
            .field("mode", &self.mode)
            .field("group_id", &self.group_id)
            .field("num_shards", &self.num_shards)
            .field("pin_cpus", &self.pin_cpus)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    /// 0.25 C1: pinning the current thread restricts its affinity to a single
    /// core. Cap-free — `sched_setaffinity` on the calling thread needs no
    /// privileges. Restores all-core affinity afterwards so it doesn't pin the
    /// test runner.
    #[test]
    fn pin_current_thread_sets_single_core_affinity() {
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        if n < 2 {
            return; // single visible core → trivially "pinned"
        }
        if !super::pin_current_thread_to_core(0) {
            return; // restricted cpuset (e.g. locked-down CI) → skip
        }
        // SAFETY: same POD-bitmask contract as the helper; pid 0 = this thread.
        unsafe {
            let mut got: libc::cpu_set_t = std::mem::zeroed();
            let r = libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut got);
            assert_eq!(r, 0, "sched_getaffinity failed");
            assert!(libc::CPU_ISSET(0, &got), "core 0 should be set");
            assert_eq!(
                libc::CPU_COUNT(&got),
                1,
                "affinity should be pinned to exactly one core"
            );
            // Restore affinity to all cores so the test thread isn't left pinned.
            let mut all: libc::cpu_set_t = std::mem::zeroed();
            for c in 0..n {
                libc::CPU_SET(c, &mut all);
            }
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &all);
        }
    }
}
