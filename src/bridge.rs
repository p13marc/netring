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

use crate::afpacket::rx::{AfPacketRx, AfPacketRxBuilder};
use crate::afpacket::tx::{AfPacketTx, AfPacketTxBuilder};
use crate::config::RingProfile;
use crate::error::Error;
use crate::packet::Packet;
use crate::stats::CaptureStats;
use crate::traits::PacketSource;

/// Action returned by a bridge filter callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// Forwarding statistics for both directions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BridgeStats {
    /// Statistics for A→B direction.
    pub a_to_b: CaptureStats,
    /// Statistics for B→A direction.
    pub b_to_a: CaptureStats,
}

impl std::fmt::Display for BridgeStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "A→B: {} | B→A: {}", self.a_to_b, self.b_to_a)
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
#[must_use]
pub struct Bridge {
    rx_a: AfPacketRx,
    tx_b: AfPacketTx,
    rx_b: AfPacketRx,
    tx_a: AfPacketTx,
    poll_timeout: Duration,
}

impl Bridge {
    /// Start building a new bridge.
    pub fn builder() -> BridgeBuilder {
        BridgeBuilder::default()
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
    /// Returns [`Error::Io`] if `poll(2)` or a `flush()` syscall fails.
    pub fn run<F>(&mut self, mut filter: F) -> Result<(), Error>
    where
        F: FnMut(&Packet<'_>, BridgeDirection) -> BridgeAction,
    {
        loop {
            let [a_ready, b_ready] = self.poll_both(self.poll_timeout)?;
            if a_ready {
                self.drain_direction(&mut filter, BridgeDirection::AtoB)?;
            }
            if b_ready {
                self.drain_direction(&mut filter, BridgeDirection::BtoA)?;
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
                self.drain_direction(&mut filter, BridgeDirection::AtoB)?;
            }
            if b_ready {
                self.drain_direction(&mut filter, BridgeDirection::BtoA)?;
            }
        }
        Ok(())
    }

    /// Wait for either RX socket to become readable.
    ///
    /// Returns `[a_ready, b_ready]`. Both `false` indicates the timeout
    /// elapsed with no traffic. EINTR is handled by [`crate::syscall::poll_eintr_safe`].
    fn poll_both(&self, timeout: Duration) -> Result<[bool; 2], Error> {
        use nix::poll::{PollFd, PollFlags};

        let mut pfds = [
            PollFd::new(self.rx_a.as_fd(), PollFlags::POLLIN),
            PollFd::new(self.rx_b.as_fd(), PollFlags::POLLIN),
        ];
        crate::syscall::poll_eintr_safe(&mut pfds, timeout).map_err(Error::Io)?;
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
    /// Returns [`Error::Io`] if `AsyncFd` registration or a `flush()` fails.
    #[cfg(feature = "tokio")]
    pub async fn run_async<F>(&mut self, mut filter: F) -> Result<(), Error>
    where
        F: FnMut(&Packet<'_>, BridgeDirection) -> BridgeAction,
    {
        use std::os::fd::{AsRawFd, RawFd};
        use tokio::io::Interest;
        use tokio::io::unix::AsyncFd;

        // Tokio's AsyncFd needs T: AsRawFd by value. Wrap the raw fd in a
        // POD holder so AsyncFd doesn't borrow from `self`. AsyncFd's Drop
        // deregisters from epoll without closing — `self.rx_*` retain
        // ownership of the underlying fd.
        struct FdHolder(RawFd);
        impl AsRawFd for FdHolder {
            fn as_raw_fd(&self) -> RawFd {
                self.0
            }
        }

        let async_a = AsyncFd::with_interest(
            FdHolder(self.rx_a.as_fd().as_raw_fd()),
            Interest::READABLE,
        )
        .map_err(Error::Io)?;
        let async_b = AsyncFd::with_interest(
            FdHolder(self.rx_b.as_fd().as_raw_fd()),
            Interest::READABLE,
        )
        .map_err(Error::Io)?;

        loop {
            tokio::select! {
                result = async_a.readable() => {
                    let mut guard = result.map_err(Error::Io)?;
                    self.drain_direction(&mut filter, BridgeDirection::AtoB)?;
                    // We've drained until next_batch returned None — re-arm
                    // tokio's readiness so the next iteration awaits epoll.
                    guard.clear_ready();
                }
                result = async_b.readable() => {
                    let mut guard = result.map_err(Error::Io)?;
                    self.drain_direction(&mut filter, BridgeDirection::BtoA)?;
                    guard.clear_ready();
                }
            }
        }
    }

    /// Async version of [`run_iterations`](Self::run_iterations) for tokio runtimes.
    #[cfg(feature = "tokio")]
    pub async fn run_iterations_async<F>(
        &mut self,
        iterations: usize,
        mut filter: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&Packet<'_>, BridgeDirection) -> BridgeAction,
    {
        use std::os::fd::{AsRawFd, RawFd};
        use tokio::io::Interest;
        use tokio::io::unix::AsyncFd;

        struct FdHolder(RawFd);
        impl AsRawFd for FdHolder {
            fn as_raw_fd(&self) -> RawFd {
                self.0
            }
        }

        let async_a = AsyncFd::with_interest(
            FdHolder(self.rx_a.as_fd().as_raw_fd()),
            Interest::READABLE,
        )
        .map_err(Error::Io)?;
        let async_b = AsyncFd::with_interest(
            FdHolder(self.rx_b.as_fd().as_raw_fd()),
            Interest::READABLE,
        )
        .map_err(Error::Io)?;

        for _ in 0..iterations {
            // Bound each iteration with poll_timeout so a quiet bridge still
            // returns control eventually (mirrors run_iterations semantics).
            tokio::select! {
                result = async_a.readable() => {
                    let mut guard = result.map_err(Error::Io)?;
                    self.drain_direction(&mut filter, BridgeDirection::AtoB)?;
                    guard.clear_ready();
                }
                result = async_b.readable() => {
                    let mut guard = result.map_err(Error::Io)?;
                    self.drain_direction(&mut filter, BridgeDirection::BtoA)?;
                    guard.clear_ready();
                }
                _ = tokio::time::sleep(self.poll_timeout) => {
                    // Idle iteration — fall through to next loop pass.
                }
            }
        }
        Ok(())
    }

    /// Drain every retired block from one direction, forwarding through the filter.
    ///
    /// Continues until `next_batch()` reports nothing more is currently retired,
    /// so a single readability wakeup empties the backlog (otherwise blocks
    /// pile up until the next poll cycle).
    fn drain_direction<F>(
        &mut self,
        filter: &mut F,
        direction: BridgeDirection,
    ) -> Result<(), Error>
    where
        F: FnMut(&Packet<'_>, BridgeDirection) -> BridgeAction,
    {
        let (rx, tx) = match direction {
            BridgeDirection::AtoB => (&mut self.rx_a, &mut self.tx_b),
            BridgeDirection::BtoA => (&mut self.rx_b, &mut self.tx_a),
        };

        while let Some(batch) = rx.next_batch() {
            for pkt in &batch {
                if filter(&pkt, direction) == BridgeAction::Forward {
                    if let Some(mut slot) = tx.allocate(pkt.len()) {
                        slot.data_mut()[..pkt.len()].copy_from_slice(pkt.data());
                        slot.set_len(pkt.len());
                        slot.send();
                    } else {
                        tracing::debug!(pkt_len = pkt.len(), "TX ring full, dropping packet");
                    }
                }
            }
            tx.flush()?;
        }
        Ok(())
    }

    /// Get forwarding statistics for both directions.
    ///
    /// # Reads are destructive
    ///
    /// Each call invokes [`AfPacketRx::stats()`] on both RX sockets, which
    /// performs a `getsockopt(PACKET_STATISTICS)` — a destructive read that
    /// resets kernel counters. To accumulate over time, sum the result of
    /// periodic calls.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SockOpt`] if stats retrieval fails.
    pub fn stats(&self) -> Result<BridgeStats, Error> {
        Ok(BridgeStats {
            a_to_b: self.rx_a.stats()?,
            b_to_a: self.rx_b.stats()?,
        })
    }

    /// Accumulated forwarding statistics since this bridge was created.
    ///
    /// Each direction's counters are monotonically non-decreasing across
    /// calls (deltas accumulated via the underlying [`AfPacketRx::cumulative_stats`]).
    /// **Do not mix with [`stats()`](Self::stats)** — see that method's
    /// docstring for the reason.
    pub fn cumulative_stats(&self) -> Result<BridgeStats, Error> {
        Ok(BridgeStats {
            a_to_b: self.rx_a.cumulative_stats()?,
            b_to_a: self.rx_b.cumulative_stats()?,
        })
    }
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
/// Creates paired RX+TX handles on two interfaces with matching configuration.
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

        let rx_a = AfPacketRxBuilder::default()
            .interface(&iface_a)
            .block_size(bs)
            .block_count(bc)
            .frame_size(fs)
            .block_timeout_ms(timeout)
            .promiscuous(self.promiscuous)
            .build()?;

        let tx_b = AfPacketTxBuilder::default()
            .interface(&iface_b)
            .frame_size(fs)
            .qdisc_bypass(self.qdisc_bypass)
            .build()?;

        let rx_b = AfPacketRxBuilder::default()
            .interface(&iface_b)
            .block_size(bs)
            .block_count(bc)
            .frame_size(fs)
            .block_timeout_ms(timeout)
            .promiscuous(self.promiscuous)
            .build()?;

        let tx_a = AfPacketTxBuilder::default()
            .interface(&iface_a)
            .frame_size(fs)
            .qdisc_bypass(self.qdisc_bypass)
            .build()?;

        Ok(Bridge {
            rx_a,
            tx_b,
            rx_b,
            tx_a,
            poll_timeout: self.poll_timeout,
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
    }
}
