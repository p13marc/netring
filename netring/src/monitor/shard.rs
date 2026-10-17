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
//! Shutdown: the shards share a stop signal. For a deadline-based
//! run each shard runs the same `deadline`, so they exit naturally
//! together; SIGINT/SIGTERM under `run_until_signal` reach every
//! shard's own signal handler. Whenever a shard's run ends — its stop
//! condition, or an error (failing to build or open its capture) — it
//! sets the shared stop and its siblings' run loops stop too, so the
//! runner returns that error instead of running on without the shard.
//! A shard thread that can't even be spawned stops (and joins) the ones
//! already running before the runner returns its error (#224).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// A [`ShardedRunner`]'s shared stop: set when any shard's run ends,
/// awaited by every shard's run loop (beside its own stop condition).
/// Runtime-agnostic — each shard runs its own runtime.
#[derive(Default)]
pub(crate) struct ShardStop {
    stopped: AtomicBool,
    notify: tokio::sync::Notify,
}

impl ShardStop {
    /// Stop every shard.
    pub(crate) fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Resolves once [`Self::stop`] was called (before or after).
    pub(crate) async fn stopped(&self) {
        loop {
            let notified = self.notify.notified();
            let mut notified = std::pin::pin!(notified);
            // Register before checking the flag, so a `stop` between the
            // two isn't missed.
            notified.as_mut().enable();
            if self.stopped.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

/// Sets the [`ShardStop`] when dropped: a shard thread holds one, so any
/// way its run ends (including a panic) stops its siblings.
struct StopOnExit(Arc<ShardStop>);

impl Drop for StopOnExit {
    fn drop(&mut self) {
        self.0.stop();
    }
}

use crate::config::FanoutMode;
use crate::error::{Error, Result};
use crate::monitor::Monitor;

/// One shard thread's work: `(shard index, the shared stop)` → its result.
/// Shared by every thread, hence `Fn` behind an `Arc`.
pub(crate) type ShardBody = Arc<dyn Fn(usize, Arc<ShardStop>) -> Result<()> + Send + Sync>;

/// A spawned shard thread's handle.
type ShardHandle = std::thread::JoinHandle<Result<()>>;

/// Run `n` shard threads named `{name}-{i}`, each `body(i, stop)`, and wait
/// for all of them — the spawn/join routine of both sharded runners
/// (#213, #224).
///
/// Every thread shares one [`ShardStop`]: when any shard's run ends (its
/// stop condition, an error, a panic) the others stop too. A thread that
/// can't be spawned stops the ones already running; they are joined before
/// the spawn error is returned — none is left running detached. Otherwise
/// the result is the first shard error (a panic counts as one).
///
/// `pin`: the CPUs to pin shard `i` to, `cpu_for_shard(pin, i)` (see
/// [`allowed_cpus`]); `None` leaves the threads unpinned.
pub(crate) fn run_shard_threads(
    n: usize,
    name: &str,
    pin: Option<Vec<usize>>,
    body: ShardBody,
) -> Result<()> {
    run_shard_threads_with(n, name, pin, body, |name, f| {
        std::thread::Builder::new().name(name).spawn(f)
    })
}

/// [`run_shard_threads`] with the thread spawn injected (tests).
pub(crate) fn run_shard_threads_with<S>(
    n: usize,
    name: &str,
    pin: Option<Vec<usize>>,
    body: ShardBody,
    mut spawn: S,
) -> Result<()>
where
    S: FnMut(String, Box<dyn FnOnce() -> Result<()> + Send>) -> std::io::Result<ShardHandle>,
{
    let stop = Arc::new(ShardStop::default());
    let mut handles: Vec<ShardHandle> = Vec::with_capacity(n);
    let mut first_err: Option<Error> = None;
    for i in 0..n {
        let cpu = pin.as_deref().and_then(|cpus| cpu_for_shard(cpus, i));
        let stop_i = Arc::clone(&stop);
        let body_i = Arc::clone(&body);
        let thread_body: Box<dyn FnOnce() -> Result<()> + Send> = Box::new(move || {
            // However this shard's run ends, its siblings stop too.
            let _stop_siblings = StopOnExit(Arc::clone(&stop_i));
            // Pin before doing any work, so the runtime + capture ring stay
            // core-local.
            if let Some(cpu) = cpu
                && !pin_current_thread_to_cpu(cpu)
            {
                tracing::warn!(shard = i, cpu, "could not set CPU affinity for shard");
            }
            body_i(i, stop_i)
        });
        match spawn(format!("{name}-{i}"), thread_body) {
            Ok(h) => handles.push(h),
            Err(e) => {
                // Don't leave the started shards running detached.
                stop.stop();
                first_err = Some(Error::Io(e));
                break;
            }
        }
    }
    for h in handles {
        let res = match h.join() {
            Ok(res) => res,
            Err(panic) => Err(Error::Io(std::io::Error::other(format!(
                "{name} thread panicked: {}",
                panic_message(panic.as_ref())
            )))),
        };
        if let Err(e) = res
            && first_err.is_none()
        {
            first_err = Some(e);
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// A panic payload's message, when it has one.
fn panic_message(panic: &(dyn std::any::Any + Send)) -> &str {
    panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

/// The CPUs this thread may run on — its affinity mask
/// (`sched_getaffinity`), so a `taskset` / cpuset restriction is honoured
/// — in ascending order. Empty if the mask can't be read.
pub(crate) fn allowed_cpus() -> Vec<usize> {
    // SAFETY: `cpu_set_t` is a POD bitmask: zeroed is a valid empty set, and
    // sched_getaffinity writes at most its size. pid 0 = the calling thread.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) != 0 {
            return Vec::new();
        }
        (0..libc::CPU_SETSIZE as usize)
            .filter(|&cpu| libc::CPU_ISSET(cpu, &set))
            .collect()
    }
}

/// The CPU for shard `i`: the `i`-th allowed one, wrapping when there are
/// more shards than CPUs. `None` with no allowed CPU.
pub(crate) fn cpu_for_shard(allowed: &[usize], i: usize) -> Option<usize> {
    (!allowed.is_empty()).then(|| allowed[i % allowed.len()])
}

/// Pin the calling OS thread to `cpu` (`sched_setaffinity`). `false` if the
/// kernel refuses (a CPU outside the cpuset, an offline one) — callers
/// treat that as a best-effort no-op.
pub(crate) fn pin_current_thread_to_cpu(cpu: usize) -> bool {
    if cpu >= libc::CPU_SETSIZE as usize {
        return false;
    }
    // SAFETY: `cpu_set_t` is a POD bitmask; we zero it, set exactly one bit
    // (in range, checked above), and pass its byte size. pid `0` targets the
    // calling thread only.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) == 0
    }
}

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
    /// 0.25 C1: pin each shard's OS thread to its own CPU. Off by default.
    /// See [`Self::pin_cpus`].
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

    /// 0.25 C1: pin each shard's OS thread to a dedicated CPU via
    /// `sched_setaffinity`: shard `i` → the `i`-th CPU this process may run
    /// on (its affinity mask, so `taskset` and cpusets are honoured),
    /// wrapping when there are more shards than CPUs.
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
    /// One merge per state type: a second `merge_state` /
    /// [`Self::state_auto_merge`] for the same `T` makes the run fail with
    /// [`BuildError::DuplicateMergeState`](crate::error::BuildError::DuplicateMergeState)
    /// before any shard starts (a shard's delta is taken once, so only one
    /// fold could ever see it).
    ///
    /// Every `period`, a merge-worker thread probes each shard for its
    /// `T` — taking it and re-seeding the slot the way it was registered
    /// (`T::default()` for `MonitorBuilder::state::<T>()`, the factory for
    /// `state_init`), so each interval folds the delta since the last
    /// probe — folds it into a persistent primary (the running grand
    /// total), and hands it to any [`Self::on_merge`] observer. A shard
    /// that answers late is folded at the next probe; when the run ends,
    /// every shard hands over its last delta and the primary is observed
    /// once more, so the grand total covers the whole run (#216).
    ///
    /// Register `T` in `build_shard` with `MonitorBuilder::state::<T>()` or
    /// `state_init`: a `state_with(value)` slot can't be re-seeded.
    /// **flowscope follow-up:** `RollingRate::merge_into` would let a
    /// sharded `bandwidth_by_app` merge globally (0.15 wishlist).
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
        self.run_until(deadline_after(duration))
    }

    /// Run all shards until SIGINT/SIGTERM is observed. Each shard
    /// installs its own signal handler; whichever fires first
    /// flips the shared shutdown flag, prompting siblings to
    /// finish their current packet and exit.
    pub fn run_until_signal(self) -> Result<()> {
        self.run_inner(RunMode::Signal)
    }

    fn run_inner(self, mode: RunMode) -> Result<()> {
        // A zero period, or a second merge for one state type (#227).
        crate::monitor::merge::validate(&self.merges)?;
        let build_shard = self.build_shard;
        // 0.22 §5.2: share the layer specs across shard threads; each
        // shard instantiates its own layer instances.
        let layer_specs = Arc::new(self.layer_specs);

        // 0.22 §5.1: if any merge is registered, create one request
        // channel per shard — the shard run loop owns the receiver, the
        // merge worker holds all senders — and one reply channel every
        // shard shares (#216: it outlives each probe, so a late reply is
        // folded at the next pass instead of lost). Each shard takes its
        // request receiver from its slot.
        let merges = self.merges;
        let merge_types: Arc<[std::any::TypeId]> = merges.iter().map(|m| m.type_id()).collect();
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let (merge_txs, merge_rxs): (Vec<_>, Vec<_>) = if merges.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            (0..self.num_shards)
                .map(|_| {
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                    (tx, std::sync::Mutex::new(Some(rx)))
                })
                .unzip()
        };
        let merge_rxs = Arc::new(merge_rxs);

        // 0.22 §5.1: the merge worker (one extra OS thread, no runtime)
        // probes shards on each spec's cadence while they run. Started
        // first: if it can't be, no shard is running yet. It is stopped
        // only after every shard was joined, so it folds their final
        // pushes (#216: the last partial interval used to be lost).
        let stop = Arc::new(AtomicBool::new(false));
        let merge_handle = if merges.is_empty() {
            None
        } else {
            let stop = Arc::clone(&stop);
            let handle = std::thread::Builder::new()
                .name("netring-merge".to_string())
                .spawn(move || {
                    crate::monitor::merge::merge_worker(merge_txs, reply_rx, merges, stop)
                })
                .map_err(Error::Io)?;
            Some(handle)
        };

        let body: ShardBody = Arc::new(move |i, shard_stop| {
            // Each shard owns a current_thread tokio runtime.
            let rt = shard_runtime()?;
            let mut monitor = build_shard(i)?;
            // Apply per-shard secondary layers (fresh instances).
            for spec in layer_specs.iter() {
                monitor.wrap_sink(spec.instantiate());
            }
            // 0.22 §5.1: wire the merge channels.
            if let Some(requests) = merge_rxs
                .get(i)
                .and_then(|slot| slot.lock().ok().and_then(|mut rx| rx.take()))
            {
                monitor.set_merge_link(crate::monitor::merge::MergeLink {
                    requests,
                    replies: reply_tx.clone(),
                    types: Arc::clone(&merge_types),
                });
            }
            monitor.set_shard_stop(shard_stop);
            rt.block_on(mode.run(monitor))
        });
        let pin = self.pin_cpus.then(allowed_cpus);
        let res = run_shard_threads(self.num_shards, "netring-shard", pin, body);

        // Every shard was joined: their final deltas are queued. Join the
        // merge worker (it sees `stop` — or every reply sender gone — folds
        // what is queued, observes once more, and exits).
        stop.store(true, Ordering::Relaxed);
        if let Some(h) = merge_handle {
            let _ = h.join();
        }
        res
    }
}

/// How long the sharded runners run: until a shared deadline, or until
/// SIGINT/SIGTERM.
#[derive(Copy, Clone)]
pub(crate) enum RunMode {
    Deadline(Instant),
    Signal,
}

impl RunMode {
    /// Run one shard's monitor in this mode.
    pub(crate) async fn run(self, monitor: Monitor) -> Result<()> {
        match self {
            RunMode::Deadline(deadline) => monitor.run_until(deadline).await,
            RunMode::Signal => monitor.run_until_signal().await,
        }
    }
}

/// A shard's own `current_thread` tokio runtime.
pub(crate) fn shard_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Error::Io)
}

/// `now + duration` for the runners' shared deadline. A duration too long
/// to represent as an `Instant` (e.g. `Duration::MAX`) means "never" —
/// 30 years out, tokio's own far future — instead of an overflow panic.
pub(crate) fn deadline_after(duration: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(duration)
        .unwrap_or_else(|| now + Duration::from_secs(86_400 * 365 * 30))
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// A zero merge period would re-probe the shards back to back: it is
    /// rejected before any shard is built.
    #[test]
    fn zero_merge_period_is_a_build_error() {
        let built = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let b = built.clone();
        let runner =
            super::ShardedRunner::new("lo", crate::config::FanoutMode::Hash, 1, 2, move |_| {
                b.store(true, std::sync::atomic::Ordering::Relaxed);
                Err(crate::error::Error::Config("not reached".into()))
            })
            .state_auto_merge::<u64>(Duration::ZERO);
        let err = runner.run_for(Duration::from_millis(10)).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::Error::Build(crate::error::BuildError::ZeroPeriod { .. })
            ),
            "{err:?}"
        );
        assert!(!built.load(std::sync::atomic::Ordering::Relaxed));
    }

    /// #227: two merges for the same state type are a build error — a
    /// shard's delta can be taken once, so only one of them could ever
    /// fold it. Rejected before any shard is built.
    #[test]
    fn duplicate_merge_for_a_type_is_a_build_error() {
        let built = Arc::new(AtomicBool::new(false));
        let b = Arc::clone(&built);
        let runner =
            super::ShardedRunner::new("lo", crate::config::FanoutMode::Hash, 1, 2, move |_| {
                b.store(true, Ordering::Relaxed);
                Err(crate::error::Error::Config("not reached".into()))
            })
            .state_auto_merge::<u64>(Duration::from_secs(1))
            .merge_state::<u64, _>(Duration::from_secs(5), |p: &mut u64, t: u64| {
                *p = (*p).max(t)
            });
        let err = runner.run_for(Duration::from_millis(10)).unwrap_err();
        assert!(
            matches!(
                &err,
                crate::error::Error::Build(crate::error::BuildError::DuplicateMergeState { type_name })
                    if type_name.contains("u64")
            ),
            "{err:?}"
        );
        assert!(!built.load(Ordering::Relaxed));
    }

    /// The calling thread's affinity mask, as CPU ids.
    fn current_affinity() -> Vec<usize> {
        // SAFETY: POD bitmask out-buffer of the right size; pid 0 = this thread.
        unsafe {
            let mut got: libc::cpu_set_t = std::mem::zeroed();
            let r = libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut got);
            assert_eq!(r, 0, "sched_getaffinity failed");
            (0..libc::CPU_SETSIZE as usize)
                .filter(|&c| libc::CPU_ISSET(c, &got))
                .collect()
        }
    }

    /// Restrict the calling thread to `cpus`; `false` if the kernel refuses.
    fn restrict_to(cpus: &[usize]) -> bool {
        // SAFETY: as in `pin_current_thread_to_cpu`.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            for &c in cpus {
                libc::CPU_SET(c, &mut set);
            }
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) == 0
        }
    }

    /// 0.25 C1: pinning restricts the calling thread to that one CPU.
    /// Cap-free. Runs on its own thread so the test runner isn't left
    /// pinned.
    #[test]
    fn pin_current_thread_sets_single_cpu_affinity() {
        std::thread::spawn(|| {
            let allowed = super::allowed_cpus();
            let Some(&cpu) = allowed.last() else { return };
            if !super::pin_current_thread_to_cpu(cpu) {
                return; // restricted cpuset (e.g. locked-down CI) → skip
            }
            assert_eq!(current_affinity(), vec![cpu]);
        })
        .join()
        .unwrap();
    }

    /// #216: shard `i` goes to the `i`-th CPU of the affinity mask,
    /// wrapping — not to CPU `i % cpu_count`.
    #[test]
    fn cpu_for_shard_uses_nth_allowed_cpu() {
        let allowed = [2, 3, 5];
        let picked: Vec<_> = (0..5).map(|i| super::cpu_for_shard(&allowed, i)).collect();
        assert_eq!(picked, [Some(2), Some(3), Some(5), Some(2), Some(3)]);
        assert_eq!(super::cpu_for_shard(&[], 0), None);
    }

    /// #216: under `taskset -c 2,3,5`, the shards land on CPUs 2, 3 and 5.
    /// (0.31 pinned shard 0 to CPU 0, outside the allowed set — or failed
    /// silently under a cpuset.)
    #[test]
    fn pinned_shards_stay_inside_the_affinity_mask() {
        std::thread::spawn(|| {
            let mask = [2, 3, 5];
            if !mask.iter().all(|c| super::allowed_cpus().contains(c)) || !restrict_to(&mask) {
                eprintln!("skip: CPUs 2, 3 and 5 are not all available");
                return;
            }
            let landed = Arc::new(std::sync::Mutex::new(vec![None; 3]));
            let l = Arc::clone(&landed);
            let body: super::ShardBody = Arc::new(move |i, _stop| {
                l.lock().unwrap()[i] = Some(current_affinity());
                Ok(())
            });
            super::run_shard_threads(3, "pin-test", Some(super::allowed_cpus()), body).unwrap();
            assert_eq!(
                *landed.lock().unwrap(),
                vec![Some(vec![2]), Some(vec![3]), Some(vec![5])]
            );
        })
        .join()
        .unwrap();
    }

    /// #224 / #213: a shard thread that can't be spawned stops the shards
    /// already running, which are joined before the error is returned —
    /// none is left running detached.
    #[test]
    fn spawn_failure_stops_and_joins_started() {
        let finished = Arc::new([AtomicBool::new(false), AtomicBool::new(false)]);
        let f = Arc::clone(&finished);
        let body: super::ShardBody = Arc::new(move |i, stop| {
            // Runs until its siblings stop.
            futures::executor::block_on(stop.stopped());
            f[i].store(true, Ordering::SeqCst);
            Ok(())
        });
        let res = super::run_shard_threads_with(4, "spawn-test", None, body, |name, f| {
            if name == "spawn-test-2" {
                return Err(std::io::Error::other("no more threads"));
            }
            std::thread::Builder::new().name(name).spawn(f)
        });
        let err = res.expect_err("the spawn failure is returned");
        assert!(err.to_string().contains("no more threads"), "{err}");
        // Both started shards stopped and were joined before the return.
        assert!(finished[0].load(Ordering::SeqCst));
        assert!(finished[1].load(Ordering::SeqCst));
    }

    /// A shard whose run fails stops its siblings; the runner returns the
    /// failure.
    #[test]
    fn one_shard_error_stops_siblings() {
        let body: super::ShardBody = Arc::new(|i, stop| {
            if i == 1 {
                std::thread::sleep(Duration::from_millis(20));
                return Err(crate::error::Error::Config("shard 1 failed".into()));
            }
            futures::executor::block_on(stop.stopped());
            Ok(())
        });
        let start = std::time::Instant::now();
        let err = super::run_shard_threads(3, "error-test", None, body).unwrap_err();
        assert!(matches!(&err, crate::error::Error::Config(m) if m == "shard 1 failed"));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    /// A panicking shard stops its siblings too, and is reported.
    #[test]
    fn panicking_shard_stops_siblings() {
        let body: super::ShardBody = Arc::new(|i, stop| {
            if i == 0 {
                panic!("shard 0 panicked");
            }
            futures::executor::block_on(stop.stopped());
            Ok(())
        });
        let err = super::run_shard_threads(2, "panic-test", None, body).unwrap_err();
        assert!(err.to_string().contains("shard 0 panicked"), "{err}");
    }
}
