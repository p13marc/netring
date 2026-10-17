//! Bidirectional packet bridge between two interfaces (IPS mode).
//!
//! Forwards packets from interface A to B and vice versa through an optional
//! filter callback. Designed for IPS (Intrusion Prevention System) and
//! transparent tap use cases.
//!
//! # Examples
//!
//! ```no_run
//! use netring::bridge::{Bridge, BridgeAction, BridgeDirection};
//!
//! let mut bridge = Bridge::builder()
//!     .interface_a("eth0")
//!     .interface_b("eth1")
//!     .build()
//!     .unwrap();
//!
//! // Forward all packets (transparent bridge)
//! bridge.run(|_pkt, _dir| BridgeAction::Forward).unwrap();
//! ```

use std::os::fd::AsFd;
use std::time::Duration;

use crate::afpacket::rx::{Capture, CaptureBuilder};
use crate::afpacket::tx::{Injector, InjectorBuilder};
use crate::config::RingProfile;
use crate::error::Error;
use crate::packet::{Packet, PacketDirection};
use crate::stats::CaptureStats;

/// Action returned by a bridge filter callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BridgeAction {
    /// Forward the packet to the other interface.
    Forward,
    /// Drop the packet (do not forward).
    Drop,
}

/// Direction of packet flow through the bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BridgeDirection {
    /// Packet from interface A heading to interface B.
    AtoB,
    /// Packet from interface B heading to interface A.
    BtoA,
}

/// The async loops' idle health check: every
/// [`LIVENESS_PROBE`](crate::async_adapters::registered::LIVENESS_PROBE),
/// on a timerfd (no tokio time driver needed).
#[cfg(feature = "tokio")]
fn liveness_probe() -> Result<crate::async_adapters::registered::ProbeTimer, Error> {
    use crate::async_adapters::registered::{LIVENESS_PROBE, ProbeTimer};
    ProbeTimer::new(LIVENESS_PROBE).map_err(Error::Io)
}

/// Forwarding statistics for both directions, plus per-cause drop counters.
///
/// The drop counters track packets that were dropped *by the bridge itself*
/// (TX ring full, packet too large for the TX frame). Kernel-side drops
/// (RX ring full) are reflected in `a_to_b.drops` / `b_to_a.drops`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BridgeStats {
    /// Ring statistics of the capture on A (the A→B direction): totals
    /// since the bridge was created.
    pub a_to_b: CaptureStats,
    /// Ring statistics of the capture on B (the B→A direction): totals
    /// since the bridge was created.
    pub b_to_a: CaptureStats,
    /// A→B packets dropped because the TX frame was too small.
    pub a_to_b_dropped_too_large: u64,
    /// A→B packets dropped because the TX ring was full.
    pub a_to_b_dropped_ring_full: u64,
    /// B→A packets dropped because the TX frame was too small.
    pub b_to_a_dropped_too_large: u64,
    /// B→A packets dropped because the TX ring was full.
    pub b_to_a_dropped_ring_full: u64,
}

impl std::fmt::Display for BridgeStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "A→B: {} dropped(too_large={}, ring_full={}) | B→A: {} dropped(too_large={}, ring_full={})",
            self.a_to_b,
            self.a_to_b_dropped_too_large,
            self.a_to_b_dropped_ring_full,
            self.b_to_a,
            self.b_to_a_dropped_too_large,
            self.b_to_a_dropped_ring_full,
        )
    }
}

/// Bidirectional packet bridge between two interfaces.
///
/// Creates paired RX+TX handles on each interface and forwards packets
/// between them, passing each through a user-supplied filter callback.
///
/// # Architecture
///
/// ```text
/// Interface A ──RX──→ filter ──TX──→ Interface B
/// Interface B ──RX──→ filter ──TX──→ Interface A
/// ```
///
/// The bridge waits via `poll(2)` on both RX fds before draining each direction,
/// so it does not consume CPU while idle.
///
/// Only frames *arriving* on an interface are bridged. Frames leaving it —
/// the bridge's own forwards and anything the host itself sends there — are
/// skipped (and not shown to the filter), so the two directions cannot
/// bounce a frame back and forth.
///
/// VLAN tags are forwarded (0.32, #209): the receiving kernel strips a
/// frame's outer 802.1Q / 802.1ad tag before the capture sees it, and the
/// RX captures re-insert it ([`CaptureBuilder::vlan_reinsert`], on by
/// default), so the frame leaves the other side tagged, as it arrived.
/// Before 0.32 the bridge forwarded every tagged frame untagged.
#[must_use]
pub struct Bridge {
    rx_a: Capture,
    tx_b: Injector,
    rx_b: Capture,
    tx_a: Injector,
    poll_timeout: Duration,
    /// Per-direction drop counters maintained by the bridge itself
    /// (kernel-side drops live in stats()).
    drops: DropCounters,
}

#[derive(Debug, Default, Clone, Copy)]
struct DropCounters {
    a_to_b_too_large: u64,
    a_to_b_ring_full: u64,
    b_to_a_too_large: u64,
    b_to_a_ring_full: u64,
}

impl Bridge {
    /// Start building a new bridge.
    pub fn builder() -> BridgeBuilder {
        BridgeBuilder::default()
    }

    /// Open a bridge between two interfaces with default settings.
    ///
    /// One-liner shortcut for
    /// `Bridge::builder().interface_a(a).interface_b(b).build()`.
    /// Defaults match the builder: promiscuous + qdisc_bypass on, 100 ms
    /// poll timeout, [`RingProfile::Default`].
    pub fn open_pair(interface_a: &str, interface_b: &str) -> Result<Self, Error> {
        Self::builder()
            .interface_a(interface_a)
            .interface_b(interface_b)
            .build()
    }

    /// Run the bridge loop, forwarding packets through the filter.
    ///
    /// Blocks forever (until I/O error). The bridge waits on `poll(2)` for
    /// both RX fds before draining whichever directions became readable, so
    /// idle interfaces do not consume CPU. The callback receives each packet
    /// and its direction, and returns [`BridgeAction::Forward`] or
    /// [`BridgeAction::Drop`].
    ///
    /// For maximum throughput, the callback should be fast — avoid
    /// allocations or heavy processing. Copy interesting packets via
    /// [`Packet::to_owned()`] and process them elsewhere.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if `poll(2)` or a `flush()` syscall fails, or
    /// with `ENETDOWN` when either interface is removed. A side that is
    /// merely down is waited out (with a warning) and forwarding resumes
    /// when it comes back up.
    pub fn run<F>(&mut self, mut filter: F) -> Result<(), Error>
    where
        F: FnMut(&Packet<'_>, BridgeDirection) -> BridgeAction,
    {
        loop {
            let [a_ready, b_ready] = self.poll_both(self.poll_timeout)?;
            if a_ready {
                self.drain_direction(&mut filter, BridgeDirection::AtoB, Kick::Wait)?;
            }
            if b_ready {
                self.drain_direction(&mut filter, BridgeDirection::BtoA, Kick::Wait)?;
            }
        }
    }

    /// Run the bridge for a limited number of poll iterations (for testing).
    ///
    /// Each iteration waits up to [`poll_timeout`](BridgeBuilder::poll_timeout)
    /// on both RX fds, then drains any direction that became readable.
    pub fn run_iterations<F>(&mut self, iterations: usize, mut filter: F) -> Result<(), Error>
    where
        F: FnMut(&Packet<'_>, BridgeDirection) -> BridgeAction,
    {
        for _ in 0..iterations {
            let [a_ready, b_ready] = self.poll_both(self.poll_timeout)?;
            if a_ready {
                self.drain_direction(&mut filter, BridgeDirection::AtoB, Kick::Wait)?;
            }
            if b_ready {
                self.drain_direction(&mut filter, BridgeDirection::BtoA, Kick::Wait)?;
            }
        }
        Ok(())
    }

    /// Wait for either RX socket to become readable.
    ///
    /// Returns `[a_ready, b_ready]`. Both `false` indicates the timeout
    /// elapsed with no traffic. EINTR is handled by [`crate::syscall::poll_eintr_safe`].
    /// A socket error is read (clearing it) rather than left to make every
    /// poll return at once; a removed interface is returned as an error.
    fn poll_both(&self, timeout: Duration) -> Result<[bool; 2], Error> {
        use nix::poll::{PollFd, PollFlags};

        let mut pfds = [
            PollFd::new(self.rx_a.as_fd(), PollFlags::POLLIN),
            PollFd::new(self.rx_b.as_fd(), PollFlags::POLLIN),
        ];
        crate::syscall::poll_eintr_safe(&mut pfds, timeout).map_err(Error::Io)?;
        crate::afpacket::socket::poll_error(self.rx_a.as_fd(), pfds[0].revents())?;
        crate::afpacket::socket::poll_error(self.rx_b.as_fd(), pfds[1].revents())?;
        Ok([
            pfds[0]
                .revents()
                .is_some_and(|r| r.contains(PollFlags::POLLIN)),
            pfds[1]
                .revents()
                .is_some_and(|r| r.contains(PollFlags::POLLIN)),
        ])
    }

    /// Async version of [`run`](Self::run) for users with a tokio runtime.
    ///
    /// Uses [`tokio::io::unix::AsyncFd`] on each RX fd and `tokio::select!`
    /// to wait for readability — no manual `poll(2)` syscall, EINTR handled
    /// by tokio's reactor.
    ///
    /// Prefer this over [`run`](Self::run) when you already have a tokio
    /// runtime: it avoids the bridge's own poll loop and reuses the runtime's
    /// epoll registration.
    ///
    /// The TX rings are kicked without waiting for the device (`MSG_DONTWAIT`,
    /// 0.32 #228): [`run`](Self::run)'s kick waits until every frame it handed
    /// over is transmitted, which on a device that holds frames (a qdisc that
    /// queues or shapes, with [`qdisc_bypass`](BridgeBuilder::qdisc_bypass)
    /// off) would block the runtime thread. Frames a full TX ring can't take
    /// are dropped and counted, as in `run`; frames a kick could not hand over
    /// (the socket's send buffer full) are kicked again on the next batch or
    /// within a second.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "tokio")]
    /// # async fn _ex() -> Result<(), netring::Error> {
    /// use netring::bridge::{Bridge, BridgeAction};
    ///
    /// let mut bridge = Bridge::builder()
    ///     .interface_a("veth0")
    ///     .interface_b("veth1")
    ///     .build()?;
    ///
    /// bridge.run_async(|_pkt, _dir| BridgeAction::Forward).await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if `AsyncFd` registration or a TX kick fails,
    /// or with `ENETDOWN` when either interface is removed (noticed on the
    /// kernel's error event, or within a second when the interface was
    /// already down). A side that is merely down is waited out, as with
    /// [`run`](Self::run).
    #[cfg(feature = "tokio")]
    pub async fn run_async<F>(&mut self, mut filter: F) -> Result<(), Error>
    where
        F: FnMut(&Packet<'_>, BridgeDirection) -> BridgeAction,
    {
        use crate::async_adapters::registered::register_dup;
        use tokio::io::Interest;

        // Register dups of the RX fds: an `AsyncFd` must own what it
        // registers, and owning a dup keeps it from borrowing `self`, which
        // the drain below needs mutably. `ERROR` too: a side whose
        // interface goes down or away raises only an error event (#212).
        let interest = Interest::READABLE | Interest::ERROR;
        let async_a = register_dup(self.rx_a.as_fd(), interest).map_err(Error::Io)?;
        let async_b = register_dup(self.rx_b.as_fd(), interest).map_err(Error::Io)?;
        let probe = liveness_probe()?;

        loop {
            tokio::select! {
                result = async_a.ready(interest) => {
                    let mut guard = result.map_err(Error::Io)?;
                    self.serve_ready(&mut guard, &mut filter, BridgeDirection::AtoB)?;
                }
                result = async_b.ready(interest) => {
                    let mut guard = result.map_err(Error::Io)?;
                    self.serve_ready(&mut guard, &mut filter, BridgeDirection::BtoA)?;
                }
                tick = probe.tick() => {
                    tick.map_err(Error::Io)?;
                    self.check_health()?;
                    self.kick_queued()?;
                }
            }
        }
    }

    /// Async version of [`run_iterations`](Self::run_iterations) for tokio runtimes.
    ///
    /// # Errors
    ///
    /// As [`run_async`](Self::run_async).
    #[cfg(feature = "tokio")]
    pub async fn run_iterations_async<F>(
        &mut self,
        iterations: usize,
        mut filter: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&Packet<'_>, BridgeDirection) -> BridgeAction,
    {
        use crate::async_adapters::registered::register_dup;
        use tokio::io::Interest;

        let interest = Interest::READABLE | Interest::ERROR;
        let async_a = register_dup(self.rx_a.as_fd(), interest).map_err(Error::Io)?;
        let async_b = register_dup(self.rx_b.as_fd(), interest).map_err(Error::Io)?;
        let probe = liveness_probe()?;

        for _ in 0..iterations {
            // Bound each iteration with poll_timeout so a quiet bridge still
            // returns control eventually (mirrors run_iterations semantics).
            tokio::select! {
                result = async_a.ready(interest) => {
                    let mut guard = result.map_err(Error::Io)?;
                    self.serve_ready(&mut guard, &mut filter, BridgeDirection::AtoB)?;
                }
                result = async_b.ready(interest) => {
                    let mut guard = result.map_err(Error::Io)?;
                    self.serve_ready(&mut guard, &mut filter, BridgeDirection::BtoA)?;
                }
                tick = probe.tick() => {
                    tick.map_err(Error::Io)?;
                    self.check_health()?;
                    self.kick_queued()?;
                }
                _ = tokio::time::sleep(self.poll_timeout) => {
                    // Idle iteration — fall through to next loop pass.
                }
            }
        }
        Ok(())
    }

    /// Serve one readiness event of the async loops on side `direction`'s
    /// RX socket: an error event is checked (a removed interface ends the
    /// run with `ENETDOWN`, a down one is waited out), then ready frames
    /// are forwarded. Each readiness bit is cleared only once handled, so
    /// the next wait re-arms via epoll.
    #[cfg(feature = "tokio")]
    fn serve_ready<F>(
        &mut self,
        guard: &mut tokio::io::unix::AsyncFdReadyGuard<'_, std::os::fd::OwnedFd>,
        filter: &mut F,
        direction: BridgeDirection,
    ) -> Result<(), Error>
    where
        F: FnMut(&Packet<'_>, BridgeDirection) -> BridgeAction,
    {
        use tokio::io::Ready;

        let ready = guard.ready();
        if ready.is_error() {
            guard.clear_ready_matching(Ready::ERROR);
            let rx = match direction {
                BridgeDirection::AtoB => &self.rx_a,
                BridgeDirection::BtoA => &self.rx_b,
            };
            crate::afpacket::socket::check_health(rx.as_fd())?;
        }
        // Re-arm the read readiness only once the ring is empty; a capped
        // drain leaves it set so the backlog is resumed (epoll is
        // edge-triggered: no new edge would come).
        if (ready.is_readable() || ready.is_read_closed())
            && self.drain_direction(filter, direction, Kick::NoWait)?
        {
            guard.clear_ready_matching(Ready::READABLE | Ready::READ_CLOSED);
        }
        Ok(())
    }

    /// Both sides still usable? A removed interface raises no event when it
    /// was already down, so the async loops ask once a second.
    #[cfg(feature = "tokio")]
    fn check_health(&self) -> Result<(), Error> {
        crate::afpacket::socket::check_health(self.rx_a.as_fd())?;
        crate::afpacket::socket::check_health(self.rx_b.as_fd())
    }

    /// Kick frames a non-blocking kick left queued (it stops when the
    /// socket's send buffer is full) — the async loops do this once a
    /// second, so a backlog doesn't wait for the next forwarded batch.
    #[cfg(feature = "tokio")]
    fn kick_queued(&mut self) -> Result<(), Error> {
        self.tx_a.flush_nonblocking()?;
        self.tx_b.flush_nonblocking()?;
        Ok(())
    }

    /// Drain retired blocks from one direction, forwarding through the filter.
    ///
    /// Takes up to [`DRAIN_BATCHES`] blocks, then returns so the other
    /// direction gets its turn: draining until empty never ends while one
    /// side is under sustained load, starving the other. Returns `true` when
    /// the direction had nothing more retired. The leftover backlog keeps
    /// the RX fd readable, so the next `poll(2)` returns at once. `kick`
    /// says whether handing frames to the kernel waits for the device.
    fn drain_direction<F>(
        &mut self,
        filter: &mut F,
        direction: BridgeDirection,
        kick: Kick,
    ) -> Result<bool, Error>
    where
        F: FnMut(&Packet<'_>, BridgeDirection) -> BridgeAction,
    {
        let (rx, tx, too_large, ring_full) = match direction {
            BridgeDirection::AtoB => (
                &mut self.rx_a,
                &mut self.tx_b,
                &mut self.drops.a_to_b_too_large,
                &mut self.drops.a_to_b_ring_full,
            ),
            BridgeDirection::BtoA => (
                &mut self.rx_b,
                &mut self.tx_a,
                &mut self.drops.b_to_a_too_large,
                &mut self.drops.b_to_a_ring_full,
            ),
        };

        let tx_capacity = tx.frame_capacity();

        for _ in 0..DRAIN_BATCHES {
            let Some(batch) = rx.next_batch() else {
                return Ok(true);
            };
            for pkt in &batch {
                // Frames leaving this interface are not bridged: without
                // qdisc bypass the other direction's own forwards pass the
                // packet taps here (dev_queue_xmit_nit() skips only the
                // sending socket), and sending them back would bounce every
                // frame between the two sides forever.
                if pkt.direction() == PacketDirection::Outgoing {
                    continue;
                }
                if filter(&pkt, direction) != BridgeAction::Forward {
                    continue;
                }
                if pkt.len() > tx_capacity {
                    *too_large += 1;
                    tracing::warn!(
                        pkt_len = pkt.len(),
                        tx_capacity,
                        "Bridge: dropping packet — exceeds TX frame capacity"
                    );
                    continue;
                }
                if !queue_frame(tx, pkt.data(), kick)? {
                    *ring_full += 1;
                    tracing::debug!(
                        pkt_len = pkt.len(),
                        "Bridge: dropping packet — TX ring full"
                    );
                }
            }
            kick.kick(tx)?;
        }
        Ok(false)
    }

    /// Forwarding statistics for both directions: each side's ring totals
    /// since the bridge was created, plus the bridge's own drop counters.
    ///
    /// `a_to_b` is the capture on interface A (what was received for
    /// forwarding to B), `b_to_a` the one on B. Reading never resets
    /// anything — see [`Capture::stats`]; the counts of a window are
    /// `later.a_to_b.delta_since(&earlier.a_to_b)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SockOpt`] if stats retrieval fails.
    pub fn stats(&self) -> Result<BridgeStats, Error> {
        Ok(BridgeStats {
            a_to_b: self.rx_a.stats()?,
            b_to_a: self.rx_b.stats()?,
            a_to_b_dropped_too_large: self.drops.a_to_b_too_large,
            a_to_b_dropped_ring_full: self.drops.a_to_b_ring_full,
            b_to_a_dropped_too_large: self.drops.b_to_a_too_large,
            b_to_a_dropped_ring_full: self.drops.b_to_a_ring_full,
        })
    }

    /// Decompose into the four backend handles: `(rx_a, tx_b, rx_b, tx_a)`.
    ///
    /// After this call, the bridge no longer drives forwarding — the caller
    /// is responsible for any further packet movement. Useful for advanced
    /// patterns: attaching eBPF programs to one side, taking a custom
    /// forwarding path, or shutting down a single direction.
    pub fn into_inner(self) -> BridgeHandles {
        BridgeHandles {
            rx_a: self.rx_a,
            tx_b: self.tx_b,
            rx_b: self.rx_b,
            tx_a: self.tx_a,
        }
    }

    /// Borrow the four backend handles for inspection (e.g., extracting fds).
    pub fn handles(&self) -> (&Capture, &Injector, &Capture, &Injector) {
        (&self.rx_a, &self.tx_b, &self.rx_b, &self.tx_a)
    }
}

/// Blocks one direction forwards before the other gets its turn.
const DRAIN_BATCHES: usize = 4;

/// How a drain hands its queued frames to the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kick {
    /// [`Injector::flush`]: wait until the device completed every frame —
    /// the blocking loops' backpressure.
    Wait,
    /// [`Injector::flush_nonblocking`]: return once they are handed over.
    /// The async loops must not block the runtime thread on a device that
    /// holds frames (#228).
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    NoWait,
}

impl Kick {
    fn kick(self, tx: &mut Injector) -> Result<(), Error> {
        match self {
            Kick::Wait => tx.flush()?,
            Kick::NoWait => tx.flush_nonblocking()?,
        };
        Ok(())
    }
}

/// Copy `data` into a TX slot and queue it. A batch can hold more packets
/// than the TX ring has frames, and queued frames only leave the ring on a
/// kick (`tpacket_snd()` runs from `sendto()`), so a full ring is kicked
/// and the allocation retried once. `false`: still no free frame (with
/// [`Kick::NoWait`], the frames handed over may not be transmitted yet).
fn queue_frame(tx: &mut Injector, data: &[u8], kick: Kick) -> Result<bool, Error> {
    for attempt in 0..2 {
        if let Some(mut slot) = tx.allocate(data.len()) {
            slot.data_mut()[..data.len()].copy_from_slice(data);
            slot.set_len(data.len());
            slot.send();
            return Ok(true);
        }
        if attempt == 0 {
            kick.kick(tx)?;
        }
    }
    Ok(false)
}

/// The four backend handles that make up a [`Bridge`].
///
/// Returned by [`Bridge::into_inner`].
#[derive(Debug)]
pub struct BridgeHandles {
    /// RX on interface A.
    pub rx_a: Capture,
    /// TX on interface B (forwards A→B).
    pub tx_b: Injector,
    /// RX on interface B.
    pub rx_b: Capture,
    /// TX on interface A (forwards B→A).
    pub tx_a: Injector,
}

impl std::fmt::Debug for Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridge")
            .field("rx_a", &self.rx_a)
            .field("rx_b", &self.rx_b)
            .finish()
    }
}

// ── Builder ────────────────────────────────────────────────────────────────

/// Builder for [`Bridge`].
///
/// Creates paired RX+TX handles on two interfaces. By default both sides
/// inherit a single [`RingProfile`] and share `promiscuous` / `qdisc_bypass`
/// flags. Per-direction overrides exist for asymmetric setups (e.g., capture
/// jumbo on A, retransmit standard MTU on B).
///
/// Promiscuous mode and qdisc bypass are enabled by default (optimal for
/// transparent bridging).
#[must_use]
pub struct BridgeBuilder {
    interface_a: Option<String>,
    interface_b: Option<String>,
    profile: RingProfile,
    promiscuous: bool,
    qdisc_bypass: bool,
    poll_timeout: Duration,
    // Per-direction overrides; None = inherit from profile / global setting.
    a_block_size: Option<usize>,
    a_block_count: Option<usize>,
    a_frame_size: Option<usize>,
    a_block_timeout_ms: Option<u32>,
    b_block_size: Option<usize>,
    b_block_count: Option<usize>,
    b_frame_size: Option<usize>,
    b_block_timeout_ms: Option<u32>,
    tx_a_frame_size: Option<usize>,
    tx_b_frame_size: Option<usize>,
    tx_a_frame_count: Option<usize>,
    tx_b_frame_count: Option<usize>,
}

impl Default for BridgeBuilder {
    fn default() -> Self {
        Self {
            interface_a: None,
            interface_b: None,
            profile: RingProfile::Default,
            promiscuous: true,
            qdisc_bypass: true,
            poll_timeout: Duration::from_millis(100),
            a_block_size: None,
            a_block_count: None,
            a_frame_size: None,
            a_block_timeout_ms: None,
            b_block_size: None,
            b_block_count: None,
            b_frame_size: None,
            b_block_timeout_ms: None,
            tx_a_frame_size: None,
            tx_b_frame_size: None,
            tx_a_frame_count: None,
            tx_b_frame_count: None,
        }
    }
}

impl BridgeBuilder {
    /// Set interface A (required).
    pub fn interface_a(mut self, name: &str) -> Self {
        self.interface_a = Some(name.to_string());
        self
    }

    /// Set interface B (required).
    pub fn interface_b(mut self, name: &str) -> Self {
        self.interface_b = Some(name.to_string());
        self
    }

    /// Set the ring buffer profile for both interfaces. Default: [`RingProfile::Default`].
    pub fn profile(mut self, profile: RingProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Enable promiscuous mode on both interfaces. Default: true.
    pub fn promiscuous(mut self, enable: bool) -> Self {
        self.promiscuous = enable;
        self
    }

    /// Bypass qdisc for TX on both interfaces. Default: true.
    pub fn qdisc_bypass(mut self, enable: bool) -> Self {
        self.qdisc_bypass = enable;
        self
    }

    /// Maximum time the bridge waits in `poll(2)` between iterations.
    ///
    /// Smaller values reduce shutdown latency at the cost of more frequent
    /// syscalls when traffic is sparse. Default: 100 ms.
    pub fn poll_timeout(mut self, timeout: Duration) -> Self {
        self.poll_timeout = timeout;
        self
    }

    // ── Per-direction RX overrides ──────────────────────────────────────

    /// Override RX block size on interface A. None = inherit from profile.
    pub fn a_block_size(mut self, bytes: usize) -> Self {
        self.a_block_size = Some(bytes);
        self
    }
    /// Override RX block count on interface A.
    pub fn a_block_count(mut self, n: usize) -> Self {
        self.a_block_count = Some(n);
        self
    }
    /// Override RX frame size on interface A.
    pub fn a_frame_size(mut self, bytes: usize) -> Self {
        self.a_frame_size = Some(bytes);
        self
    }
    /// Override RX block-retire timeout on interface A.
    pub fn a_block_timeout_ms(mut self, ms: u32) -> Self {
        self.a_block_timeout_ms = Some(ms);
        self
    }
    /// Override RX block size on interface B.
    pub fn b_block_size(mut self, bytes: usize) -> Self {
        self.b_block_size = Some(bytes);
        self
    }
    /// Override RX block count on interface B.
    pub fn b_block_count(mut self, n: usize) -> Self {
        self.b_block_count = Some(n);
        self
    }
    /// Override RX frame size on interface B.
    pub fn b_frame_size(mut self, bytes: usize) -> Self {
        self.b_frame_size = Some(bytes);
        self
    }
    /// Override RX block-retire timeout on interface B.
    pub fn b_block_timeout_ms(mut self, ms: u32) -> Self {
        self.b_block_timeout_ms = Some(ms);
        self
    }

    // ── Per-direction TX overrides ──────────────────────────────────────

    /// Override TX frame size on interface A (B→A direction). None = inherit RX frame_size.
    pub fn tx_a_frame_size(mut self, bytes: usize) -> Self {
        self.tx_a_frame_size = Some(bytes);
        self
    }
    /// Override TX frame size on interface B (A→B direction). None = inherit RX frame_size.
    pub fn tx_b_frame_size(mut self, bytes: usize) -> Self {
        self.tx_b_frame_size = Some(bytes);
        self
    }
    /// Override TX frame count on interface A.
    pub fn tx_a_frame_count(mut self, n: usize) -> Self {
        self.tx_a_frame_count = Some(n);
        self
    }
    /// Override TX frame count on interface B.
    pub fn tx_b_frame_count(mut self, n: usize) -> Self {
        self.tx_b_frame_count = Some(n);
        self
    }

    /// Validate and create the [`Bridge`].
    ///
    /// Creates 4 handles: RX on A, TX on B, RX on B, TX on A.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if interface names are missing,
    /// [`Error::PermissionDenied`] without `CAP_NET_RAW`, or other
    /// socket/mmap errors.
    pub fn build(self) -> Result<Bridge, Error> {
        let iface_a = self
            .interface_a
            .ok_or_else(|| Error::Config("interface_a is required".into()))?;
        let iface_b = self
            .interface_b
            .ok_or_else(|| Error::Config("interface_b is required".into()))?;

        let (bs, bc, fs, timeout) = self.profile.params();

        // Per-direction effective values (override or inherit from profile).
        let a_bs = self.a_block_size.unwrap_or(bs);
        let a_bc = self.a_block_count.unwrap_or(bc);
        let a_fs = self.a_frame_size.unwrap_or(fs);
        let a_to = self.a_block_timeout_ms.unwrap_or(timeout);
        let b_bs = self.b_block_size.unwrap_or(bs);
        let b_bc = self.b_block_count.unwrap_or(bc);
        let b_fs = self.b_frame_size.unwrap_or(fs);
        let b_to = self.b_block_timeout_ms.unwrap_or(timeout);

        // TX frame_size defaults to the RX frame_size on the *destination*
        // side so a captured packet is guaranteed to fit:
        //   A→B: TX on B, defaults to b_fs (matches what A receives & resends)
        //   B→A: TX on A, defaults to a_fs
        // Users with asymmetric needs use tx_*_frame_size to override.
        let tx_b_fs = self.tx_b_frame_size.unwrap_or(b_fs);
        let tx_a_fs = self.tx_a_frame_size.unwrap_or(a_fs);

        let rx_a = CaptureBuilder::default()
            .interface(&iface_a)
            .block_size(a_bs)
            .block_count(a_bc)
            .frame_size(a_fs)
            .block_timeout_ms(a_to)
            .promiscuous(self.promiscuous)
            .build()?;

        let mut tx_b_builder = InjectorBuilder::default()
            .interface(&iface_b)
            .frame_size(tx_b_fs)
            .qdisc_bypass(self.qdisc_bypass);
        if let Some(n) = self.tx_b_frame_count {
            tx_b_builder = tx_b_builder.frame_count(n);
        }
        let tx_b = tx_b_builder.build()?;

        let rx_b = CaptureBuilder::default()
            .interface(&iface_b)
            .block_size(b_bs)
            .block_count(b_bc)
            .frame_size(b_fs)
            .block_timeout_ms(b_to)
            .promiscuous(self.promiscuous)
            .build()?;

        let mut tx_a_builder = InjectorBuilder::default()
            .interface(&iface_a)
            .frame_size(tx_a_fs)
            .qdisc_bypass(self.qdisc_bypass);
        if let Some(n) = self.tx_a_frame_count {
            tx_a_builder = tx_a_builder.frame_count(n);
        }
        let tx_a = tx_a_builder.build()?;

        Ok(Bridge {
            rx_a,
            tx_b,
            rx_b,
            tx_a,
            poll_timeout: self.poll_timeout,
            drops: DropCounters::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_missing_a() {
        let err = BridgeBuilder::default()
            .interface_b("lo")
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_rejects_missing_b() {
        let err = BridgeBuilder::default()
            .interface_a("lo")
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_defaults() {
        let b = BridgeBuilder::default();
        assert!(b.promiscuous);
        assert!(b.qdisc_bypass);
        assert_eq!(b.profile, RingProfile::Default);
        assert_eq!(b.poll_timeout, Duration::from_millis(100));
    }

    #[test]
    fn builder_poll_timeout_setter() {
        let b = BridgeBuilder::default().poll_timeout(Duration::from_millis(25));
        assert_eq!(b.poll_timeout, Duration::from_millis(25));
    }

    #[test]
    fn builder_per_direction_overrides_stored() {
        let b = BridgeBuilder::default()
            .a_block_size(1 << 20)
            .a_block_count(8)
            .a_frame_size(4096)
            .a_block_timeout_ms(20)
            .b_block_size(1 << 21)
            .b_frame_size(8192)
            .tx_a_frame_size(2048)
            .tx_b_frame_size(65536)
            .tx_b_frame_count(512);
        assert_eq!(b.a_block_size, Some(1 << 20));
        assert_eq!(b.a_block_count, Some(8));
        assert_eq!(b.a_frame_size, Some(4096));
        assert_eq!(b.a_block_timeout_ms, Some(20));
        assert_eq!(b.b_block_size, Some(1 << 21));
        assert_eq!(b.b_frame_size, Some(8192));
        assert_eq!(b.tx_a_frame_size, Some(2048));
        assert_eq!(b.tx_b_frame_size, Some(65536));
        assert_eq!(b.tx_b_frame_count, Some(512));
    }

    #[test]
    fn bridge_action_eq() {
        assert_eq!(BridgeAction::Forward, BridgeAction::Forward);
        assert_ne!(BridgeAction::Forward, BridgeAction::Drop);
    }

    #[test]
    fn bridge_direction_eq() {
        assert_ne!(BridgeDirection::AtoB, BridgeDirection::BtoA);
    }

    #[test]
    fn bridge_stats_display() {
        let stats = BridgeStats::default();
        let s = stats.to_string();
        assert!(s.contains("A→B"));
        assert!(s.contains("B→A"));
        assert!(s.contains("too_large=0"));
        assert!(s.contains("ring_full=0"));
    }

    #[test]
    fn bridge_stats_drop_counters_display() {
        let stats = BridgeStats {
            a_to_b_dropped_too_large: 7,
            b_to_a_dropped_ring_full: 13,
            ..BridgeStats::default()
        };
        let s = stats.to_string();
        assert!(s.contains("too_large=7"));
        assert!(s.contains("ring_full=13"));
    }
}
