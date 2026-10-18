//! Tier 2 AF_XDP capture: one Monitor (worker) per RX queue (issue #6 M5).
//!
//! The line-rate multi-queue model — the AF_XDP analogue of [`ShardedRunner`]
//! (which shards AF_PACKET via `PACKET_FANOUT`). The kernel ABI is one socket
//! per queue, and RSS spreads traffic across queues, so the performant shape is
//! **one socket per core, busy-polled** (Suricata `threads: auto`).
//!
//! Unlike AF_PACKET fanout, the program is *shared* setup, not per-worker:
//! [`XdpShardedRunner`] builds one [`XdpCapture`] up front (one attached
//! program, one socket per queue, one promiscuous guard), then hands each shard
//! its socket via [`MonitorBuilder::inject_xdp_backend`]. Each shard runs an
//! independent single-shard [`Monitor`] on its own OS thread + `current_thread`
//! runtime, so every queue gets full flow tracking on its own core. The shared
//! program/promiscuous guard is held on the calling thread for the run's
//! duration, so it outlives every shard. As with [`ShardedRunner`], the shards
//! share a stop: when one shard's run ends (an error, a panic, a signal) the
//! others stop too, and a shard thread that can't be spawned stops and joins
//! the ones already running (#213).
//!
//! For the single-core convenience tier (one reactor draining every queue), use
//! [`MonitorBuilder::xdp_queues`](crate::monitor::MonitorBuilder::xdp_queues)
//! instead.
//!
//! [`ShardedRunner`]: crate::monitor::shard::ShardedRunner
//! [`MonitorBuilder::inject_xdp_backend`]: crate::monitor::MonitorBuilder

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::XdpSocket;
use crate::error::{Error, Result};
use crate::monitor::shard::{RunMode, ShardBody, allowed_cpus, run_shard_threads, shard_runtime};
use crate::monitor::{Monitor, MonitorBuilder};
use crate::xdp::{Queues, XdpCapture, XdpFlags};

/// Per-queue sharded AF_XDP capture runner — one [`Monitor`] per RX queue.
///
/// ```ignore
/// use netring::monitor::xdp_shard::XdpShardedRunner;
/// use netring::xdp::Queues;
/// use netring::prelude::*;
///
/// XdpShardedRunner::new("eth0", Queues::Auto, |queue, builder| {
///     builder
///         .protocol::<Tcp>()
///         .on::<FlowStarted<Tcp>>(move |_e: &FlowStarted<Tcp>| Ok(()))
///         .sink(StdoutJsonSink::default())
/// })
/// .promiscuous(true)
/// .busy_poll(50)        // µs — one busy-polled socket per core
/// .pin_cpus(true)
/// .run_for(std::time::Duration::from_secs(60))?;
/// # netring::error::Result::<()>::Ok(())
/// ```
pub struct XdpShardedRunner {
    iface: String,
    queues: Queues,
    promiscuous: bool,
    busy_poll_us: Option<u32>,
    pin_cpus: bool,
    numa_auto: bool,
    attach_flags: XdpFlags,
    build_shard: Arc<dyn Fn(usize, MonitorBuilder) -> MonitorBuilder + Send + Sync + 'static>,
}

impl XdpShardedRunner {
    /// Create a runner. `build_shard(queue_id, builder)` configures the
    /// per-shard [`Monitor`] (protocols, handlers, sinks) — the runner injects
    /// the queue's socket and builds + runs it. The closure is called once per
    /// queue on its own thread, so each invocation must build independent state
    /// (capture `Arc`s for anything shared).
    pub fn new<F>(iface: impl Into<String>, queues: Queues, build_shard: F) -> Self
    where
        F: Fn(usize, MonitorBuilder) -> MonitorBuilder + Send + Sync + 'static,
    {
        Self {
            iface: iface.into(),
            queues,
            promiscuous: false,
            busy_poll_us: None,
            pin_cpus: false,
            numa_auto: false,
            attach_flags: XdpFlags::SKB_MODE,
            build_shard: Arc::new(build_shard),
        }
    }

    /// Auto-bind every queue's UMEM to the NIC's NUMA node (issue #6 F3). Best
    /// paired with [`Self::pin_cpus`] so worker, ring, and DMA stay node-local.
    pub fn numa_auto(mut self, on: bool) -> Self {
        self.numa_auto = on;
        self
    }

    /// Put the interface into promiscuous mode for the run (one shared guard).
    pub fn promiscuous(mut self, enable: bool) -> Self {
        self.promiscuous = enable;
        self
    }

    /// Busy-poll every per-queue socket for `us` microseconds (`SO_BUSY_POLL`).
    /// The performance lever for this model — pair with [`Self::pin_cpus`].
    pub fn busy_poll(mut self, us: u32) -> Self {
        self.busy_poll_us = Some(us);
        self
    }

    /// Pin shard `i`'s thread to the `i`-th CPU this process may run on (its
    /// affinity mask, so `taskset` and cpusets are honoured; wrapping when
    /// there are more shards than CPUs) via `sched_setaffinity`. With
    /// [`Self::numa_auto`], the CPUs of the NIC's NUMA node come first.
    /// Best with `Queues::Auto`, NIC IRQ affinity aligned, and one core per queue.
    pub fn pin_cpus(mut self, on: bool) -> Self {
        self.pin_cpus = on;
        self
    }

    /// XDP attach mode. Default `SKB_MODE`; use `DRV_MODE` for native zero-copy.
    pub fn attach_flags(mut self, flags: XdpFlags) -> Self {
        self.attach_flags = flags;
        self
    }

    /// Run every shard until `deadline`. Returns the first shard error.
    pub fn run_until(self, deadline: Instant) -> Result<()> {
        self.run_inner(RunMode::Deadline(deadline))
    }

    /// Run every shard for `duration` (shared deadline).
    pub fn run_for(self, duration: Duration) -> Result<()> {
        self.run_until(crate::monitor::shard::deadline_after(duration))
    }

    /// Run every shard until SIGINT/SIGTERM. Returns the first shard error.
    pub fn run_until_signal(self) -> Result<()> {
        self.run_inner(RunMode::Signal)
    }

    fn run_inner(self, mode: RunMode) -> Result<()> {
        // Build the shared capture on the calling thread (one program + N
        // sockets + one promiscuous guard).
        let mut b = XdpCapture::builder()
            .interface(&self.iface)
            .queues(self.queues.clone())
            .promiscuous(self.promiscuous)
            .attach_flags(self.attach_flags);
        if let Some(us) = self.busy_poll_us {
            b = b.busy_poll(us).prefer_busy_poll(true);
        }
        if self.numa_auto {
            b = b.numa_auto(true);
        }
        let capture = b.build()?;
        let n = capture.socket_count();
        // Socket `i` serves `queue_ids[i]` — what `build_shard` is given.
        let queue_ids: Arc<[u32]> = capture.queue_ids().into();
        let pin = self.pin_cpus.then(|| self.shard_cpus());
        // The guard (attached program + promiscuous) stays on *this* thread for
        // the whole run, so it outlives every shard's socket.
        let (sockets, guard) = capture.into_parts();
        // Shard `i` takes socket `i` out of its slot.
        let slots: Arc<[Mutex<Option<XdpSocket>>]> =
            sockets.into_iter().map(|s| Mutex::new(Some(s))).collect();

        let build_shard = self.build_shard;
        let body: ShardBody = Arc::new(move |i, shard_stop| {
            let socket = slots[i]
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
                .ok_or_else(|| Error::Config(format!("xdp shard {i}: socket already taken")))?;
            let queue = queue_ids[i];
            let rt = shard_runtime()?;
            rt.block_on(async {
                // AsyncFd must be created inside the runtime context.
                let async_sock = crate::AsyncXdpSocket::new(socket)?;
                let mut monitor = build_shard(queue as usize, Monitor::builder())
                    .inject_xdp_backend(async_sock)
                    .build()?;
                monitor.set_shard_stop(shard_stop);
                mode.run(monitor).await
            })
        });
        let res = run_shard_threads(n, "netring-xdp-shard", pin, body);
        // Program detaches + promiscuity drops only now that every shard has
        // stopped — on an error too.
        drop(guard);
        res
    }

    /// The CPUs shards are pinned to: the affinity mask — with
    /// [`Self::numa_auto`], only its CPUs on the NIC's NUMA node, when that
    /// leaves any.
    fn shard_cpus(&self) -> Vec<usize> {
        let allowed = allowed_cpus();
        if self.numa_auto
            && let Some(node) = crate::xdp::interface_numa_node(&self.iface)
            && let Some(local) = node_cpus(node)
        {
            let local: Vec<usize> = allowed
                .iter()
                .copied()
                .filter(|c| local.contains(c))
                .collect();
            if !local.is_empty() {
                return local;
            }
        }
        allowed
    }

    /// Number of queues (shards) this runner will resolve `queues` to is
    /// determined at [`run_until`](Self::run_until) time; use
    /// [`queue_count`](crate::xdp::queue_count) to size a thread pool ahead.
    pub fn interface(&self) -> &str {
        &self.iface
    }
}

/// NUMA node `node`'s CPUs (`/sys/devices/system/node/node{node}/cpulist`).
fn node_cpus(node: u32) -> Option<Vec<usize>> {
    let list =
        std::fs::read_to_string(format!("/sys/devices/system/node/node{node}/cpulist")).ok()?;
    parse_cpulist(&list)
}

/// Parse a kernel CPU list (`/sys/devices/system/node/node0/cpulist`):
/// comma-separated CPUs and inclusive ranges, e.g. `0-3,8,10-11`. `None`
/// on malformed input.
fn parse_cpulist(s: &str) -> Option<Vec<usize>> {
    let mut cpus = Vec::new();
    for part in s.trim().split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((lo, hi)) => {
                let (lo, hi): (usize, usize) = (lo.parse().ok()?, hi.parse().ok()?);
                if lo > hi {
                    return None;
                }
                cpus.extend(lo..=hi);
            }
            None => cpus.push(part.parse().ok()?),
        }
    }
    Some(cpus)
}

impl std::fmt::Debug for XdpShardedRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdpShardedRunner")
            .field("iface", &self.iface)
            .field("queues", &self.queues)
            .field("promiscuous", &self.promiscuous)
            .field("busy_poll_us", &self.busy_poll_us)
            .field("pin_cpus", &self.pin_cpus)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults_and_setters() {
        // Construction is cap-free; running needs root (covered by the lo live
        // test). Assert the knobs plumb in.
        let r = XdpShardedRunner::new("eth0", Queues::Auto, |_q, b| b)
            .promiscuous(true)
            .busy_poll(50)
            .pin_cpus(true);
        assert_eq!(r.interface(), "eth0");
        assert!(r.promiscuous);
        assert_eq!(r.busy_poll_us, Some(50));
        assert!(r.pin_cpus);
        assert!(matches!(r.queues, Queues::Auto));
    }

    #[test]
    fn parse_cpulist_reads_ranges_and_singles() {
        assert_eq!(
            parse_cpulist("0-3,8,10-11\n"),
            Some(vec![0, 1, 2, 3, 8, 10, 11])
        );
        assert_eq!(parse_cpulist("5"), Some(vec![5]));
        assert_eq!(parse_cpulist(""), Some(vec![]));
        assert_eq!(parse_cpulist("3-1"), None);
        assert_eq!(parse_cpulist("a-b"), None);
    }

    /// Node 0 always exists where sysfs exposes NUMA at all.
    #[test]
    fn node_cpus_reads_sysfs() {
        if let Some(cpus) = node_cpus(0) {
            assert!(!cpus.is_empty());
        }
    }
}
