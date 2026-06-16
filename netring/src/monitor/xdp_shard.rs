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
//! duration, so it outlives every shard.
//!
//! For the single-core convenience tier (one reactor draining every queue), use
//! [`MonitorBuilder::xdp_queues`](crate::monitor::MonitorBuilder::xdp_queues)
//! instead.
//!
//! [`ShardedRunner`]: crate::monitor::shard::ShardedRunner
//! [`MonitorBuilder::inject_xdp_backend`]: crate::monitor::MonitorBuilder

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
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
            attach_flags: XdpFlags::SKB_MODE,
            build_shard: Arc::new(build_shard),
        }
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

    /// Pin shard `i`'s thread to core `i % num_cores` (`sched_setaffinity`).
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
        let capture = b.build()?;
        let n = capture.socket_count();
        // The guard (attached program + promiscuous) stays on *this* thread for
        // the whole run, so it outlives every shard's socket.
        let (sockets, _guard) = capture.into_parts();

        let build_shard = self.build_shard;
        let pin_cpus = self.pin_cpus;
        let mut handles = Vec::with_capacity(n);
        for (i, socket) in sockets.into_iter().enumerate() {
            let build = Arc::clone(&build_shard);
            let handle = std::thread::Builder::new()
                .name(format!("netring-xdp-shard-{i}"))
                .spawn(move || -> Result<()> {
                    if pin_cpus && !crate::monitor::shard::pin_current_thread_to_core(i) {
                        tracing::warn!(shard = i, "could not set CPU affinity for xdp shard");
                    }
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(Error::Io)?;
                    rt.block_on(async move {
                        // AsyncFd must be created inside the runtime context.
                        let async_sock = crate::AsyncXdpSocket::new(socket)?;
                        let monitor = build(i, Monitor::builder())
                            .inject_xdp_backend(async_sock)
                            .build()?;
                        let dur = deadline.saturating_duration_since(Instant::now());
                        monitor.run_for(dur).await
                    })
                })
                .map_err(Error::Io)?;
            handles.push(handle);
        }

        // Join all shards (keeping `_guard` alive), collecting the first error.
        let mut first_err: Option<Error> = None;
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
                        first_err = Some(Error::Io(std::io::Error::other(format!(
                            "xdp shard thread panicked: {panic:?}"
                        ))));
                    }
                }
            }
        }
        // Program detaches + promiscuity drops now that every shard has stopped.
        drop(_guard);
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Run every shard for `duration` (shared deadline).
    pub fn run_for(self, duration: Duration) -> Result<()> {
        let deadline = Instant::now() + duration;
        self.run_until(deadline)
    }

    /// Number of queues (shards) this runner will resolve `queues` to is
    /// determined at [`run_until`](Self::run_until) time; use
    /// [`queue_count`](crate::xdp::queue_count) to size a thread pool ahead.
    pub fn interface(&self) -> &str {
        &self.iface
    }
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
}
