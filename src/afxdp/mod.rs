//! AF_XDP backend for kernel-bypass packet I/O.
//!
//! Provides high-throughput packet I/O via XDP sockets with shared UMEM memory.
//! Uses direct `libc` syscalls (same pure Rust approach as AF_PACKET — no C
//! library dependencies beyond libc).
//!
//! # Ring model
//!
//! AF_XDP uses 4 shared rings over a UMEM region:
//! - **Fill ring**: userspace gives empty frame addrs to kernel for RX
//! - **RX ring**: kernel delivers received packet descriptors to userspace
//! - **TX ring**: userspace submits packet descriptors for transmission
//! - **Completion ring**: kernel returns transmitted frame addrs to userspace
//!
//! # Requirements
//!
//! - Linux 5.4+
//! - `CAP_NET_RAW` (or root) for socket creation
//! - XDP-capable NIC driver for zero-copy mode
//! - An external XDP BPF program (e.g. via `aya`) for RX — not needed for TX-only
//!
//! # Standalone API
//!
//! AF_XDP uses different ring semantics than AF_PACKET (block-based mmap).
//! This module provides a standalone API that does **not** implement
//! [`PacketSource`](crate::traits::PacketSource). A unified trait-based API
//! is planned for a future version using GATs.
//!
//! # Feature gate
//!
//! Requires the `af-xdp` feature. Without it, only the builder types are
//! available (for downstream crates to compile against).

pub(crate) mod ffi;
#[cfg(feature = "af-xdp")]
mod ring;
#[cfg(feature = "af-xdp")]
mod socket;
#[cfg(feature = "af-xdp")]
mod umem;

#[cfg(feature = "af-xdp")]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
#[cfg(feature = "af-xdp")]
use std::time::Duration;

#[cfg(feature = "af-xdp")]
use ring::{CompletionRing, FillRing, RxRing, TxRing};
#[cfg(feature = "af-xdp")]
use umem::Umem;

use crate::error::Error;
#[cfg(feature = "af-xdp")]
use crate::packet::{OwnedPacket, Timestamp};

// ── XdpMode ──────────────────────────────────────────────────────────────

/// Operating mode for an AF_XDP socket.
///
/// Controls how UMEM frames are partitioned between the fill ring (for kernel
/// RX) and the free list (available for TX allocation). The wrong split breaks
/// either RX (kernel can't enqueue packets — `rx_dropped` counter rises) or TX
/// (`send()` can never allocate a frame).
///
/// Pick the mode that matches your traffic direction. For asymmetric splits or
/// shared-UMEM setups, use [`XdpMode::Custom`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum XdpMode {
    /// Receive only. All UMEM frames are pre-staged to the fill ring; `send()`
    /// will always return `Ok(false)` because no frames are reachable from the
    /// free list.
    Rx,
    /// Transmit only. No prefill — every UMEM frame stays in the free list and
    /// is available for `send()` allocation. RX descriptors will not arrive
    /// (the fill ring is empty) but stats are unaffected.
    Tx,
    /// Bidirectional. Half the frames prefilled to the fill ring (RX), half
    /// retained in the free list (TX). For uneven traffic patterns prefer
    /// [`XdpMode::Custom`] to control the split explicitly.
    #[default]
    RxTx,
    /// Custom prefill: pre-stage exactly `prefill` frames in the fill ring; the
    /// remaining `frame_count - prefill` stay in the free list for TX.
    ///
    /// `prefill` is clamped to `min(frame_count, ring_size)`. Use `0` to skip
    /// prefill entirely (equivalent to [`XdpMode::Tx`]); use `frame_count` to
    /// prefill everything (equivalent to [`XdpMode::Rx`]).
    Custom {
        /// Number of frames to pre-stage in the fill ring at construction.
        prefill: u32,
    },
}

// ── XdpSocketBuilder ─────────────────────────────────────────────────────

/// Builder for AF_XDP sockets.
///
/// For TX-only workloads, set [`XdpMode::Tx`] — by default the builder
/// pre-stages half the UMEM into the fill ring (RxTx mode), which leaves only
/// half available for `send()`.
///
/// # Examples
///
/// ```no_run,ignore
/// use netring::afxdp::{XdpSocketBuilder, XdpMode};
///
/// let mut xdp = XdpSocketBuilder::default()
///     .interface("eth0")
///     .queue_id(0)
///     .mode(XdpMode::Tx)  // skip RX prefill so send() can allocate frames
///     .build()
///     .unwrap();
///
/// xdp.send(&[0xff; 64]).unwrap();
/// xdp.flush().unwrap();
/// ```
#[derive(Debug, Clone)]
#[must_use]
pub struct XdpSocketBuilder {
    interface: Option<String>,
    queue_id: u32,
    frame_size: usize,
    frame_count: usize,
    need_wakeup: bool,
    mode: XdpMode,
}

impl Default for XdpSocketBuilder {
    fn default() -> Self {
        Self {
            interface: None,
            queue_id: 0,
            frame_size: 4096,
            frame_count: 4096,
            need_wakeup: true,
            mode: XdpMode::default(),
        }
    }
}

impl XdpSocketBuilder {
    /// Set the network interface name (required).
    pub fn interface(mut self, name: &str) -> Self {
        self.interface = Some(name.to_string());
        self
    }

    /// Set the NIC queue ID to bind to. Default: 0.
    pub fn queue_id(mut self, id: u32) -> Self {
        self.queue_id = id;
        self
    }

    /// UMEM frame size. Default: 4096.
    pub fn frame_size(mut self, size: usize) -> Self {
        self.frame_size = size;
        self
    }

    /// Number of UMEM frames. Default: 4096.
    pub fn frame_count(mut self, count: usize) -> Self {
        self.frame_count = count;
        self
    }

    /// Operating mode (RX/TX/RxTx/Custom prefill split). Default: [`XdpMode::RxTx`].
    ///
    /// For TX-only workloads — most importantly the [`xdp_send`] example pattern —
    /// you **must** set this to [`XdpMode::Tx`], or every `send()` call will
    /// silently fail because all UMEM frames are pre-staged to the fill ring.
    ///
    /// [`xdp_send`]: https://github.com/p13marc/netring/blob/master/examples/xdp_send.rs
    pub fn mode(mut self, mode: XdpMode) -> Self {
        self.mode = mode;
        self
    }

    /// Enable `XDP_USE_NEED_WAKEUP` optimization. Default: true.
    pub fn need_wakeup(mut self, enable: bool) -> Self {
        self.need_wakeup = enable;
        self
    }

    /// Validate the builder configuration.
    ///
    /// Returns the interface name if valid.
    pub fn validate(&self) -> Result<&str, Error> {
        let iface = self
            .interface
            .as_deref()
            .ok_or_else(|| Error::Config("interface is required".into()))?;
        if self.frame_size == 0 {
            return Err(Error::Config("frame_size must be > 0".into()));
        }
        if self.frame_count == 0 {
            return Err(Error::Config("frame_count must be > 0".into()));
        }
        Ok(iface)
    }

    /// Build the XDP socket.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`] if configuration is invalid
    /// - [`Error::PermissionDenied`] if missing `CAP_NET_RAW`
    /// - [`Error::Socket`], [`Error::SockOpt`], [`Error::Mmap`], [`Error::Bind`]
    ///   for the respective syscall failures
    #[cfg(feature = "af-xdp")]
    pub fn build(self) -> Result<XdpSocket, Error> {
        let iface = self.validate()?;
        let ifindex = crate::afpacket::socket::resolve_interface(iface)? as u32;

        // 1. Allocate UMEM (MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE)
        let mut umem = Umem::new(self.frame_size, self.frame_count)?;

        // 2. Create AF_XDP socket
        let fd = socket::create_xdp_socket()?;

        // 3. Register UMEM with kernel
        socket::register_umem(fd.as_fd(), &umem.as_reg())?;

        // 4. Configure ring sizes (each power of 2, independent)
        let ring_size = (self.frame_count as u32).next_power_of_two();
        socket::set_ring_size(
            fd.as_fd(),
            ffi::XDP_UMEM_FILL_RING,
            ring_size,
            "XDP_UMEM_FILL_RING",
        )?;
        socket::set_ring_size(
            fd.as_fd(),
            ffi::XDP_UMEM_COMPLETION_RING,
            ring_size,
            "XDP_UMEM_COMPLETION_RING",
        )?;
        socket::set_ring_size(fd.as_fd(), ffi::XDP_RX_RING, ring_size, "XDP_RX_RING")?;
        socket::set_ring_size(fd.as_fd(), ffi::XDP_TX_RING, ring_size, "XDP_TX_RING")?;

        // 5. Get mmap offsets from kernel
        let offsets = socket::get_mmap_offsets(fd.as_fd())?;

        // 6. mmap all 4 rings
        // NOTE: offsets.fr = fill ring, offsets.cr = completion ring (NOT .fill/.completion)
        let mut fill = unsafe {
            FillRing::mmap(
                fd.as_fd(),
                ring_size,
                &offsets.fr,
                ffi::XDP_UMEM_PGOFF_FILL_RING as libc::off_t,
            )?
        };
        let comp = unsafe {
            CompletionRing::mmap(
                fd.as_fd(),
                ring_size,
                &offsets.cr,
                ffi::XDP_UMEM_PGOFF_COMPLETION_RING as libc::off_t,
            )?
        };
        let rx = unsafe {
            RxRing::mmap(
                fd.as_fd(),
                ring_size,
                &offsets.rx,
                ffi::XDP_PGOFF_RX_RING as libc::off_t,
            )?
        };
        let tx = unsafe {
            TxRing::mmap(
                fd.as_fd(),
                ring_size,
                &offsets.tx,
                ffi::XDP_PGOFF_TX_RING as libc::off_t,
            )?
        };

        // 7. Pre-fill the fill ring with frame addrs for kernel RX. The amount
        //    to prefill depends on the operating mode:
        //      - Rx: every frame goes to the fill ring (TX disabled).
        //      - Tx: nothing prefilled (free list keeps all frames for TX).
        //      - RxTx: half of frames prefilled, half retained for TX.
        //      - Custom: caller-specified count, clamped to [0, min(avail, ring)].
        let cap_avail = umem.available().min(ring_size as usize);
        let prefill = match self.mode {
            XdpMode::Rx => cap_avail,
            XdpMode::Tx => 0,
            XdpMode::RxTx => cap_avail / 2,
            XdpMode::Custom { prefill } => (prefill as usize).min(cap_avail),
        } as u32;

        if prefill > 0 {
            if let Some(idx) = fill.producer_reserve(prefill) {
                let mut written = 0u32;
                for i in 0..prefill {
                    match umem.alloc_frame() {
                        Some(addr) => {
                            unsafe { fill.write_desc(idx + i, addr) };
                            written += 1;
                        }
                        None => break,
                    }
                }
                if written > 0 {
                    fill.producer_submit(written);
                }
            }
        }

        // 8. Bind to interface + queue
        // flags=0: auto-negotiate (kernel tries zero-copy, falls back to copy)
        // XDP_USE_NEED_WAKEUP enables wakeup optimization
        let bind_flags = if self.need_wakeup {
            ffi::XDP_USE_NEED_WAKEUP
        } else {
            0
        };
        socket::bind_xdp(fd.as_fd(), ifindex, self.queue_id, bind_flags)?;

        Ok(XdpSocket {
            fd,
            umem,
            fill,
            rx,
            tx,
            comp,
        })
    }

    /// Build the XDP socket (stub without `af-xdp` feature).
    #[cfg(not(feature = "af-xdp"))]
    pub fn build(self) -> Result<XdpSocket, Error> {
        Err(Error::Config(
            "AF_XDP requires the 'af-xdp' feature flag".into(),
        ))
    }
}

// ── XdpSocket ────────────────────────────────────────────────────────────

/// AF_XDP socket handle.
///
/// Provides non-blocking `recv` / `send` / `flush` operations over a UMEM
/// region and 4 XDP rings (fill, RX, TX, completion).
///
/// Requires the `af-xdp` feature to construct via [`XdpSocketBuilder::build`].
pub struct XdpSocket {
    #[cfg(feature = "af-xdp")]
    fd: OwnedFd,
    #[cfg(feature = "af-xdp")]
    umem: Umem,
    #[cfg(feature = "af-xdp")]
    fill: FillRing,
    #[cfg(feature = "af-xdp")]
    rx: RxRing,
    #[cfg(feature = "af-xdp")]
    tx: TxRing,
    #[cfg(feature = "af-xdp")]
    comp: CompletionRing,
    // Without the feature, keep a private field so the struct is unconstructable.
    #[cfg(not(feature = "af-xdp"))]
    _private: (),
}

impl XdpSocket {
    /// Receive packets (non-blocking).
    ///
    /// Returns owned copies of received packets. The underlying UMEM frames
    /// are recycled automatically to the fill ring.
    ///
    /// Returns an empty `Vec` if no packets are available.
    #[cfg(feature = "af-xdp")]
    pub fn recv(&mut self) -> Result<Vec<OwnedPacket>, Error> {
        // 1. Recycle completed TX frames
        self.recycle_completed();

        // 2. Peek RX ring
        let n = self.rx.consumer_peek(64);
        if n == 0 {
            return Ok(Vec::new());
        }

        let mut packets = Vec::with_capacity(n as usize);
        let base_idx = self.rx.consumer_index();

        for i in 0..n {
            let desc: libc::xdp_desc = unsafe { self.rx.read_desc(base_idx + i) };
            let data = unsafe { self.umem.data(desc.addr, desc.len as usize) };
            packets.push(OwnedPacket {
                data: data.to_vec(),
                timestamp: Timestamp::default(),
                original_len: desc.len as usize,
            });
            // Return frame to free list (will be refilled below)
            self.umem.free_frame(desc.addr);
        }

        // 3. Release consumed RX descriptors
        self.rx.consumer_release(n);

        // 4. Refill fill ring with recycled frames
        self.refill();

        Ok(packets)
    }

    /// Send a raw packet (non-blocking).
    ///
    /// Copies `data` into a UMEM frame and submits a TX descriptor.
    /// Returns `Ok(true)` on success, `Ok(false)` if the TX ring or UMEM is full.
    ///
    /// Call [`flush`](Self::flush) after one or more `send` calls to kick the kernel.
    #[cfg(feature = "af-xdp")]
    pub fn send(&mut self, data: &[u8]) -> Result<bool, Error> {
        if data.len() > self.umem.frame_size() {
            return Err(Error::Config(format!(
                "packet {} bytes exceeds frame size {}",
                data.len(),
                self.umem.frame_size()
            )));
        }

        self.recycle_completed();

        let addr = match self.umem.alloc_frame() {
            Some(a) => a,
            None => return Ok(false),
        };

        // Copy data into UMEM frame
        unsafe {
            let buf = self.umem.data_mut(addr, data.len());
            buf.copy_from_slice(data);
        }

        // Submit TX descriptor
        let idx = match self.tx.producer_reserve(1) {
            Some(i) => i,
            None => {
                self.umem.free_frame(addr);
                return Ok(false);
            }
        };
        unsafe {
            self.tx.write_desc(
                idx,
                libc::xdp_desc {
                    addr,
                    len: data.len() as u32,
                    options: 0,
                },
            );
        }
        self.tx.producer_submit(1);

        Ok(true)
    }

    /// Flush pending TX frames by waking the kernel.
    ///
    /// Uses `sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0)`.
    /// `MSG_DONTWAIT` is **mandatory** — kernel returns `EOPNOTSUPP` without it.
    /// EINTR is retried; transient `EAGAIN`/`ENOBUFS` are reported as success.
    #[cfg(feature = "af-xdp")]
    pub fn flush(&self) -> Result<(), Error> {
        // Always kick for simplicity. Could check self.tx.needs_wakeup()
        // to only kick when kernel signals NEED_WAKEUP.
        crate::syscall::sendto_kick_eintr_safe(self.fd.as_raw_fd(), libc::MSG_DONTWAIT)
            .map_err(Error::Io)
    }

    /// Poll for readability (incoming packets) with a timeout.
    ///
    /// Returns `true` if packets may be available. EINTR is handled internally.
    #[cfg(feature = "af-xdp")]
    pub fn poll(&self, timeout: Duration) -> Result<bool, Error> {
        // SAFETY: BorrowedFd is valid for the call; we only use it within the
        // duration of poll_eintr_safe.
        let fd = self.fd.as_fd();
        let mut pfds = [nix::poll::PollFd::new(fd, nix::poll::PollFlags::POLLIN)];
        let n = crate::syscall::poll_eintr_safe(&mut pfds, timeout).map_err(Error::Io)?;
        Ok(n > 0)
    }

    /// Get XDP socket statistics from the kernel.
    #[cfg(feature = "af-xdp")]
    pub fn statistics(&self) -> Result<ffi::xdp_statistics, Error> {
        socket::get_statistics(self.fd.as_fd())
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Recycle frames from the completion ring back to the UMEM free list.
    #[cfg(feature = "af-xdp")]
    fn recycle_completed(&mut self) {
        let n = self.comp.consumer_peek(64);
        if n == 0 {
            return;
        }
        let base = self.comp.consumer_index();
        let mut addrs = [0u64; 64];
        for i in 0..n {
            addrs[i as usize] = unsafe { self.comp.read_desc(base + i) };
        }
        self.umem.free_frames(&addrs[..n as usize]);
        self.comp.consumer_release(n);
    }

    /// Refill the fill ring with available UMEM frames.
    #[cfg(feature = "af-xdp")]
    fn refill(&mut self) {
        let want = self.umem.available().min(64) as u32;
        if want == 0 {
            return;
        }
        if let Some(idx) = self.fill.producer_reserve(want) {
            let mut filled = 0u32;
            for i in 0..want {
                if let Some(addr) = self.umem.alloc_frame() {
                    unsafe { self.fill.write_desc(idx + i, addr) };
                    filled += 1;
                }
            }
            if filled > 0 {
                self.fill.producer_submit(filled);
            }
        }
    }
}

#[cfg(feature = "af-xdp")]
impl AsFd for XdpSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(feature = "af-xdp")]
impl AsRawFd for XdpSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

// SAFETY: All fields (OwnedFd, Umem, XdpRing) are Send. Access is mediated
// by &mut self on all operations.
#[cfg(feature = "af-xdp")]
unsafe impl Send for XdpSocket {}

impl std::fmt::Debug for XdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("XdpSocket");
        #[cfg(feature = "af-xdp")]
        {
            d.field("frame_size", &self.umem.frame_size());
            d.field("umem_available", &self.umem.available());
        }
        d.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_missing_interface() {
        let err = XdpSocketBuilder::default().build().unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_defaults() {
        let b = XdpSocketBuilder::default();
        // Verify defaults via validate (fields are private)
        assert!(b.validate().is_err()); // no interface
        let b = b.interface("lo");
        assert!(b.validate().is_ok());
    }

    #[test]
    fn builder_validate_ok() {
        let b = XdpSocketBuilder::default().interface("lo");
        assert!(b.validate().is_ok());
    }

    #[test]
    fn builder_validate_zero_frame_size() {
        let b = XdpSocketBuilder::default().interface("lo").frame_size(0);
        assert!(b.validate().is_err());
    }

    #[test]
    fn builder_validate_zero_frame_count() {
        let b = XdpSocketBuilder::default().interface("lo").frame_count(0);
        assert!(b.validate().is_err());
    }

    #[test]
    fn builder_chaining() {
        let b = XdpSocketBuilder::default()
            .interface("eth0")
            .queue_id(3)
            .frame_size(2048)
            .frame_count(1024)
            .need_wakeup(false);
        assert_eq!(b.validate().unwrap(), "eth0");
    }

    #[test]
    fn builder_default_mode_is_rxtx() {
        let b = XdpSocketBuilder::default();
        assert_eq!(b.mode, XdpMode::RxTx);
    }

    #[test]
    fn builder_mode_setter() {
        let b = XdpSocketBuilder::default().mode(XdpMode::Tx);
        assert_eq!(b.mode, XdpMode::Tx);

        let b = XdpSocketBuilder::default().mode(XdpMode::Custom { prefill: 256 });
        assert_eq!(b.mode, XdpMode::Custom { prefill: 256 });
    }

    /// Compute the prefill count the same way `build()` does, in isolation,
    /// so we can unit-test the policy without a live AF_XDP socket.
    fn compute_prefill(mode: XdpMode, available: usize, ring_size: usize) -> u32 {
        let cap_avail = available.min(ring_size);
        let n = match mode {
            XdpMode::Rx => cap_avail,
            XdpMode::Tx => 0,
            XdpMode::RxTx => cap_avail / 2,
            XdpMode::Custom { prefill } => (prefill as usize).min(cap_avail),
        };
        n as u32
    }

    #[test]
    fn prefill_tx_keeps_all_frames_in_free_list() {
        // The bug being fixed: prefill must not consume all frames in TX mode.
        assert_eq!(compute_prefill(XdpMode::Tx, 4096, 4096), 0);
    }

    #[test]
    fn prefill_rx_consumes_all_frames() {
        assert_eq!(compute_prefill(XdpMode::Rx, 4096, 4096), 4096);
    }

    #[test]
    fn prefill_rxtx_splits_in_half() {
        assert_eq!(compute_prefill(XdpMode::RxTx, 4096, 4096), 2048);
    }

    #[test]
    fn prefill_custom_clamped() {
        assert_eq!(
            compute_prefill(XdpMode::Custom { prefill: 100 }, 4096, 4096),
            100
        );
        // Clamps to ring_size when caller asks for too much.
        assert_eq!(
            compute_prefill(XdpMode::Custom { prefill: 8192 }, 4096, 4096),
            4096
        );
        // Clamps to available when caller asks for too much.
        assert_eq!(
            compute_prefill(XdpMode::Custom { prefill: 1000 }, 64, 4096),
            64
        );
    }
}
