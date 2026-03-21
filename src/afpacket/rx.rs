//! AF_PACKET TPACKET_V3 RX path.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::time::Duration;

use crate::afpacket::ring::MmapRing;
use crate::afpacket::{fanout, ffi, filter, ring, socket};
use crate::config::{BpfFilter, BpfInsn, FanoutFlags, FanoutMode, RingProfile, TimestampSource};
use crate::error::Error;
use crate::packet::PacketBatch;
use crate::stats::CaptureStats;
use crate::traits::PacketSource;

/// AF_PACKET TPACKET_V3 receive ring.
///
/// Implements [`PacketSource`] and [`AsFd`].
/// Use [`AfPacketRx::builder()`] to construct.
pub struct AfPacketRx {
    // Drop order: ring (munmap) before fd (close).
    ring: MmapRing,
    fd: OwnedFd,
    current_block: usize,
    expected_seq: u64,
}

impl AfPacketRx {
    /// Start building a new RX capture.
    pub fn builder() -> AfPacketRxBuilder {
        AfPacketRxBuilder::default()
    }

    /// Expose the mmap base pointer for advanced use (e.g., `madvise`).
    ///
    /// # Safety
    ///
    /// The caller must not write to the returned pointer region or
    /// interfere with block status fields.
    pub unsafe fn ring_ptr(&self) -> *const u8 {
        self.ring.base().as_ptr()
    }

    /// Total size of the mmap region in bytes.
    pub fn ring_len(&self) -> usize {
        self.ring.size()
    }

    /// Attach an eBPF socket filter program.
    ///
    /// Replaces any existing filter (classic BPF or eBPF). The program
    /// must be `BPF_PROG_TYPE_SOCKET_FILTER`. Packets not accepted by
    /// the program are dropped before reaching the ring.
    ///
    /// `prog_fd` is the fd of a loaded eBPF program (e.g., from `aya`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::SockOpt`] if the program attachment fails.
    pub fn attach_ebpf_filter(&self, prog_fd: std::os::fd::RawFd) -> Result<(), Error> {
        filter::attach_ebpf_socket_filter(self.fd.as_fd(), prog_fd)
    }

    /// Detach any attached BPF/eBPF filter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SockOpt`] if detachment fails.
    pub fn detach_filter(&self) -> Result<(), Error> {
        filter::detach_bpf_filter(self.fd.as_fd())
    }
}

impl PacketSource for AfPacketRx {
    fn next_batch(&mut self) -> Option<PacketBatch<'_>> {
        let bd = self.ring.block_ptr(self.current_block);

        // SAFETY: bd points to a valid block descriptor in our mmap region.
        let status = unsafe { ring::read_block_status(bd) };

        if status & ffi::TP_STATUS_USER == 0 {
            return None;
        }

        // Read sequence number for gap detection
        // SAFETY: block is user-owned (Acquire fence done in read_block_status).
        let seq = unsafe { (*bd.as_ptr()).hdr.bh1.seq_num };
        if seq != self.expected_seq && self.expected_seq != 0 {
            tracing::warn!(
                expected = self.expected_seq,
                actual = seq,
                dropped = seq.saturating_sub(self.expected_seq),
                "block sequence gap"
            );
        }
        self.expected_seq = seq + 1;

        // SAFETY: block is user-owned, bd is valid, block_size is correct.
        let batch = unsafe { PacketBatch::new(bd) };
        self.current_block = (self.current_block + 1) % self.ring.block_count();
        Some(batch)
    }

    fn next_batch_blocking(&mut self, timeout: Duration) -> Result<Option<PacketBatch<'_>>, Error> {
        // Check if a batch is already available (non-blocking).
        // We inline the status check rather than calling next_batch() to
        // avoid a borrow conflict with the poll() call below.
        {
            let bd = self.ring.block_ptr(self.current_block);
            let status = unsafe { ring::read_block_status(bd) };
            if status & ffi::TP_STATUS_USER != 0 {
                return Ok(self.next_batch());
            }
        }

        // No batch ready — block on poll(2).
        let pfd = nix::poll::PollFd::new(self.fd.as_fd(), nix::poll::PollFlags::POLLIN);
        let poll_timeout =
            nix::poll::PollTimeout::try_from(timeout).unwrap_or(nix::poll::PollTimeout::MAX);
        nix::poll::poll(&mut [pfd], poll_timeout).map_err(|e| Error::Io(e.into()))?;

        Ok(self.next_batch())
    }

    fn stats(&self) -> Result<CaptureStats, Error> {
        let raw = socket::get_packet_stats(self.fd.as_fd())?;
        Ok(CaptureStats::from(raw))
    }
}

impl std::fmt::Debug for AfPacketRx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfPacketRx")
            .field("ring_size", &self.ring.size())
            .field("block_count", &self.ring.block_count())
            .field("current_block", &self.current_block)
            .finish()
    }
}

impl AsFd for AfPacketRx {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for AfPacketRx {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

// SAFETY: AfPacketRx owns its fd and ring exclusively. Safe to move across threads.
unsafe impl Send for AfPacketRx {}

// ── Builder ────────────────────────────────────────────────────────────────

/// Builder for [`AfPacketRx`].
#[must_use]
pub struct AfPacketRxBuilder {
    interface: Option<String>,
    block_size: usize,
    block_count: usize,
    frame_size: usize,
    block_timeout_ms: u32,
    fill_rxhash: bool,
    promiscuous: bool,
    ignore_outgoing: bool,
    busy_poll_us: Option<u32>,
    timestamp_source: TimestampSource,
    fanout: Option<(FanoutMode, u16)>,
    fanout_flags: FanoutFlags,
    bpf_filter: Option<Vec<BpfInsn>>,
}

impl Default for AfPacketRxBuilder {
    fn default() -> Self {
        Self {
            interface: None,
            block_size: 1 << 22, // 4 MiB
            block_count: 64,
            frame_size: 2048,
            block_timeout_ms: 60,
            fill_rxhash: true,
            promiscuous: false,
            ignore_outgoing: false,
            busy_poll_us: None,
            timestamp_source: TimestampSource::default(),
            fanout: None,
            fanout_flags: FanoutFlags::empty(),
            bpf_filter: None,
        }
    }
}

impl AfPacketRxBuilder {
    /// Set the network interface name (required).
    pub fn interface(mut self, name: &str) -> Self {
        self.interface = Some(name.to_string());
        self
    }

    /// Apply a ring buffer profile.
    pub fn profile(mut self, profile: RingProfile) -> Self {
        let (bs, bc, fs, timeout) = profile.params();
        self.block_size = bs;
        self.block_count = bc;
        self.frame_size = fs;
        self.block_timeout_ms = timeout;
        self
    }

    /// Block size in bytes (must be power of 2 and multiple of PAGE_SIZE). Default: 4 MiB.
    pub fn block_size(mut self, bytes: usize) -> Self {
        self.block_size = bytes;
        self
    }

    /// Number of blocks. Default: 64.
    pub fn block_count(mut self, n: usize) -> Self {
        self.block_count = n;
        self
    }

    /// Minimum frame size (multiple of 16, >= 68). Default: 2048.
    pub fn frame_size(mut self, bytes: usize) -> Self {
        self.frame_size = bytes;
        self
    }

    /// Block retirement timeout in milliseconds. Default: 60.
    pub fn block_timeout_ms(mut self, ms: u32) -> Self {
        self.block_timeout_ms = ms;
        self
    }

    /// Enable promiscuous mode. Default: false.
    pub fn promiscuous(mut self, enable: bool) -> Self {
        self.promiscuous = enable;
        self
    }

    /// Ignore outgoing packets. Default: false.
    pub fn ignore_outgoing(mut self, enable: bool) -> Self {
        self.ignore_outgoing = enable;
        self
    }

    /// Enable SO_BUSY_POLL with the given microsecond timeout.
    pub fn busy_poll_us(mut self, us: u32) -> Self {
        self.busy_poll_us = Some(us);
        self
    }

    /// Set the kernel timestamp source.
    pub fn timestamp_source(mut self, source: TimestampSource) -> Self {
        self.timestamp_source = source;
        self
    }

    /// Join a fanout group.
    pub fn fanout(mut self, mode: FanoutMode, group_id: u16) -> Self {
        self.fanout = Some((mode, group_id));
        self
    }

    /// Set fanout flags.
    pub fn fanout_flags(mut self, flags: FanoutFlags) -> Self {
        self.fanout_flags = flags;
        self
    }

    /// Attach a classic BPF filter.
    pub fn bpf_filter(mut self, insns: Vec<BpfInsn>) -> Self {
        self.bpf_filter = Some(insns);
        self
    }

    /// Validate configuration and create the [`AfPacketRx`].
    ///
    /// # Errors
    ///
    /// - [`Error::Config`] if parameters are invalid (block_size not power of 2,
    ///   frame_size not aligned, etc.)
    /// - [`Error::PermissionDenied`] without `CAP_NET_RAW`
    /// - [`Error::InterfaceNotFound`] if the interface doesn't exist
    /// - [`Error::SockOpt`] if a socket option fails
    /// - [`Error::Mmap`] if ring buffer mmap fails
    pub fn build(self) -> Result<AfPacketRx, Error> {
        // Validate
        let interface = self
            .interface
            .ok_or_else(|| Error::Config("interface is required".into()))?;

        if !self.block_size.is_power_of_two() {
            return Err(Error::Config(format!(
                "block_size {} is not a power of 2",
                self.block_size
            )));
        }

        let page_size = 4096usize; // standard on all Linux platforms
        if self.block_size % page_size != 0 {
            return Err(Error::Config(format!(
                "block_size {} is not a multiple of PAGE_SIZE ({})",
                self.block_size, page_size
            )));
        }

        crate::afpacket::validate_frame_size(self.frame_size)?;

        if self.frame_size > self.block_size {
            return Err(Error::Config(format!(
                "frame_size {} exceeds block_size {}",
                self.frame_size, self.block_size
            )));
        }

        if self.block_count == 0 {
            return Err(Error::Config("block_count must be > 0".into()));
        }

        let frame_nr = (self.block_size / self.frame_size) * self.block_count;

        // Create socket
        let fd = socket::create_packet_socket()?;

        // Set TPACKET_V3
        socket::set_packet_version(fd.as_fd())?;

        // Configure RX ring
        let mut req: ffi::tpacket_req3 = unsafe { std::mem::zeroed() };
        req.tp_block_size = self.block_size as u32;
        req.tp_block_nr = self.block_count as u32;
        req.tp_frame_size = self.frame_size as u32;
        req.tp_frame_nr = frame_nr as u32;
        req.tp_retire_blk_tov = self.block_timeout_ms;
        req.tp_sizeof_priv = 0;
        req.tp_feature_req_word = if self.fill_rxhash {
            ffi::TP_FT_REQ_FILL_RXHASH
        } else {
            0
        };

        socket::set_rx_ring(fd.as_fd(), &req)?;

        // mmap
        let ring_size = self.block_size * self.block_count;
        let ring = MmapRing::new(fd.as_fd(), ring_size, self.block_size, self.block_count)?;

        // Bind to interface
        let ifindex = socket::resolve_interface(&interface)?;
        socket::bind_to_interface(fd.as_fd(), ifindex)?;

        // Optional: promiscuous mode
        if self.promiscuous {
            socket::set_promiscuous(fd.as_fd(), ifindex)?;
        }

        // Optional: ignore outgoing
        if self.ignore_outgoing {
            socket::set_ignore_outgoing(fd.as_fd())?;
        }

        // Optional: busy poll
        if let Some(us) = self.busy_poll_us {
            socket::set_busy_poll(fd.as_fd(), us)?;
        }

        // Optional: timestamp source
        if self.timestamp_source != TimestampSource::Software {
            socket::set_timestamp_source(fd.as_fd(), self.timestamp_source)?;
        }

        // Optional: fanout (must be after bind)
        if let Some((mode, group_id)) = self.fanout {
            fanout::join_fanout(fd.as_fd(), group_id, mode, self.fanout_flags)?;
        }

        // Optional: BPF filter
        if let Some(insns) = &self.bpf_filter {
            let filt = BpfFilter::new(insns.clone());
            filter::attach_bpf_filter(fd.as_fd(), &filt)?;
        }

        Ok(AfPacketRx {
            ring,
            fd,
            current_block: 0,
            expected_seq: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_missing_interface() {
        let err = AfPacketRxBuilder::default().build().unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_rejects_bad_block_size() {
        let err = AfPacketRxBuilder::default()
            .interface("lo")
            .block_size(3000) // not power of 2
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_rejects_bad_frame_size() {
        let err = AfPacketRxBuilder::default()
            .interface("lo")
            .frame_size(100) // not multiple of 16
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_rejects_small_frame_size() {
        let err = AfPacketRxBuilder::default()
            .interface("lo")
            .frame_size(32) // < TPACKET3_HDRLEN (68)
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_rejects_zero_block_count() {
        let err = AfPacketRxBuilder::default()
            .interface("lo")
            .block_count(0)
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_defaults() {
        let b = AfPacketRxBuilder::default();
        assert_eq!(b.block_size, 1 << 22);
        assert_eq!(b.block_count, 64);
        assert_eq!(b.frame_size, 2048);
        assert_eq!(b.block_timeout_ms, 60);
        assert!(b.fill_rxhash);
        assert!(!b.promiscuous);
        assert!(!b.ignore_outgoing);
    }
}
