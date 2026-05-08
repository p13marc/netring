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

#[cfg(feature = "af-xdp")]
mod batch;
pub(crate) mod ffi;
#[cfg(feature = "af-xdp")]
mod ring;
#[cfg(feature = "af-xdp")]
mod socket;
mod stats;
#[cfg(feature = "af-xdp")]
mod umem;

#[cfg(feature = "af-xdp")]
pub use batch::{XdpBatch, XdpBatchIter, XdpPacket};
pub use stats::XdpStats;

use std::os::fd::{AsFd, AsRawFd};
#[cfg(feature = "af-xdp")]
use std::os::fd::{BorrowedFd, OwnedFd};
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
    /// Raw fd of an already-bound XDP socket whose UMEM we want to share.
    /// `0` means "no sharing". When non-zero, build() skips
    /// `XDP_UMEM_REG` and sets `XDP_SHARED_UMEM` in the bind flags.
    shared_umem_fd: u32,
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
            shared_umem_fd: 0,
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

    /// Bind this socket as a secondary that **shares the UMEM** of an
    /// existing AF_XDP socket.
    ///
    /// Pass an `AsFd` for an already-bound `XdpSocket` that owns the
    /// UMEM you want to reuse. The kernel skips per-socket UMEM
    /// registration and threads packets through *this* socket's RX/TX
    /// rings while addressing the same shared frame pool.
    ///
    /// # Manual partitioning
    ///
    /// netring does **not** synchronize allocation between the primary
    /// and secondary sockets. Each socket's allocator hands out frame
    /// addresses independently — if both pick the same address, the
    /// kernel will overwrite one with the other's data. You're
    /// responsible for partitioning the UMEM range across sockets.
    /// The simplest scheme is: primary uses the first half, secondary
    /// uses the second half; configure each via `frame_count` and
    /// arrange for them to land at disjoint frame indices.
    ///
    /// For the canonical multi-queue capture pattern (one socket per
    /// NIC queue, one process), this is fine: each socket's fill ring
    /// only ever contains its own addresses, and the kernel dispatches
    /// inbound packets to the correct queue's RX ring via the BPF
    /// program's `bpf_redirect_map(&xskmap, queue_id, 0)` call.
    ///
    /// A higher-level `SharedUmem` helper that automates partitioning
    /// is planned for a future release.
    pub fn shared_umem<F: AsFd>(mut self, primary: F) -> Self {
        self.shared_umem_fd = primary.as_fd().as_raw_fd() as u32;
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

        // 3. Register UMEM with kernel.
        //    Skipped when this socket is binding as a XDP_SHARED_UMEM secondary —
        //    the kernel inherits the UMEM from the primary socket fd.
        if self.shared_umem_fd == 0 {
            socket::register_umem(fd.as_fd(), &umem.as_reg())?;
        }

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
            if let Some(tok) = fill.producer_reserve(prefill) {
                let mut written = 0u32;
                for i in 0..prefill {
                    match umem.alloc_frame() {
                        Some(addr) => {
                            fill.write_at(tok, i, addr);
                            written += 1;
                        }
                        None => break,
                    }
                }
                // Even if we wrote fewer than reserved, the producer index
                // was advanced by `n` in reserve — submit the original token.
                // Unwritten descriptors carry stale data, which is fine as
                // long as the kernel reads only `written` of them. In our
                // case alloc_frame can't fail mid-loop because we capped
                // prefill to umem.available() up front.
                debug_assert_eq!(written, tok.n);
                if written > 0 {
                    fill.producer_submit(tok);
                }
            }
        }

        // 8. Bind to interface + queue
        // flags=0: auto-negotiate (kernel tries zero-copy, falls back to copy)
        // XDP_USE_NEED_WAKEUP enables wakeup optimization
        // XDP_SHARED_UMEM tells the kernel to attach this socket to the
        //   UMEM owned by `shared_umem_fd` instead of the one we registered.
        let mut bind_flags: u16 = 0;
        if self.need_wakeup {
            bind_flags |= ffi::XDP_USE_NEED_WAKEUP;
        }
        if self.shared_umem_fd != 0 {
            bind_flags |= ffi::XDP_SHARED_UMEM;
        }
        socket::bind_xdp(
            fd.as_fd(),
            ifindex,
            self.queue_id,
            bind_flags,
            self.shared_umem_fd,
        )?;

        Ok(XdpSocket {
            fd,
            umem,
            fill,
            rx,
            tx,
            comp,
            need_wakeup_enabled: self.need_wakeup,
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
///
/// `XdpSocket` is `Send` but **not** `Sync`. Pass it across threads if you
/// like, but only one thread at a time may call any method on it.
///
/// ```compile_fail
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<netring::XdpSocket>();
/// ```
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
    /// Set when the socket was bound with `XDP_USE_NEED_WAKEUP`. Determines
    /// whether `flush()` honors `tx.needs_wakeup()` or always kicks.
    #[cfg(feature = "af-xdp")]
    need_wakeup_enabled: bool,
    // Without the feature, keep a private field so the struct is unconstructable.
    // `PhantomData<*const ()>` mirrors the with-feature `!Sync` property so
    // the `compile_fail` doctest that asserts `!Sync` works regardless of
    // which features the test run uses.
    #[cfg(not(feature = "af-xdp"))]
    _private: std::marker::PhantomData<*const ()>,
}

impl XdpSocket {
    /// Open an XDP socket on `interface` with default settings.
    ///
    /// Equivalent to `XdpSocketBuilder::default().interface(interface).build()`.
    /// Default mode is [`XdpMode::RxTx`] — for TX-only workloads use
    /// [`XdpSocketBuilder`] with [`XdpMode::Tx`].
    #[cfg(feature = "af-xdp")]
    pub fn open(interface: &str) -> Result<Self, Error> {
        XdpSocketBuilder::default().interface(interface).build()
    }

    /// Start building a configured XDP socket.
    #[cfg(feature = "af-xdp")]
    pub fn builder() -> XdpSocketBuilder {
        XdpSocketBuilder::default()
    }

    /// Take the next batch of packets as a zero-copy view (non-blocking).
    ///
    /// Returns `Some(batch)` borrowing from the UMEM region, or `None` if
    /// no packets are available right now. Pairs with
    /// [`Capture::next_batch`](crate::Capture) on the AF_PACKET side —
    /// same name, same semantics, same `Send`/`Sync` rules.
    ///
    /// The batch holds `&mut self`; only one batch can be live at a time.
    /// Dropping it returns its frames to the free list, releases the RX
    /// descriptors, and refills the fill ring.
    ///
    /// # Soundness — only one batch live at a time
    ///
    /// The batch's `&mut self` borrow is enforced by the compiler:
    ///
    /// ```compile_fail
    /// # fn _ex(mut s: netring::XdpSocket) {
    /// let b1 = s.next_batch();
    /// let b2 = s.next_batch();  // ERROR: two mutable borrows
    /// drop(b1);
    /// drop(b2);
    /// # }
    /// ```
    #[cfg(feature = "af-xdp")]
    pub fn next_batch(&mut self) -> Option<XdpBatch<'_>> {
        self.recycle_completed();
        self.rx
            .consumer_peek(64)
            .map(|tok| XdpBatch::new(self, tok))
    }

    /// Block until a batch is available, or `timeout` elapses.
    ///
    /// Mirrors [`PacketSource::next_batch_blocking`](crate::PacketSource)
    /// for the AF_XDP backend. Internally polls `POLLIN` (EINTR-safe) and
    /// retries [`next_batch`](Self::next_batch).
    #[cfg(feature = "af-xdp")]
    pub fn next_batch_blocking(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<XdpBatch<'_>>, Error> {
        // Fast path: try non-blocking first. If a batch is already there
        // we skip the syscall entirely.
        //
        // We can't actually return early with `Some(batch)` without
        // re-entering the borrow checker — `self.next_batch()` borrows
        // `&mut self` for the lifetime of the returned XdpBatch, and we
        // can't both return that and fall through to poll if it was None.
        // Standard NLL workaround: separate paths.
        if !self.rx_is_empty() {
            return Ok(self.next_batch());
        }

        // No batch ready — poll.
        let mut pfds = [nix::poll::PollFd::new(
            self.fd.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        crate::syscall::poll_eintr_safe(&mut pfds, timeout).map_err(Error::Io)?;

        Ok(self.next_batch())
    }

    /// Internal: probe whether the RX ring has anything we could peek.
    /// Uses the cached producer index (no kernel sync) — false positives
    /// are fine (we'll just loop), false negatives just mean we go through
    /// poll() once unnecessarily on a fresh batch.
    #[cfg(feature = "af-xdp")]
    fn rx_is_empty(&self) -> bool {
        self.rx.cached_count() == 0
    }

    /// Receive packets (non-blocking) as owned copies.
    ///
    /// Returns owned copies of received packets — convenient but allocates
    /// a `Vec<u8>` per packet plus the outer `Vec`. For zero-copy access
    /// use [`next_batch()`](Self::next_batch) instead.
    ///
    /// Returns an empty `Vec` if no packets are available.
    #[cfg(feature = "af-xdp")]
    pub fn recv(&mut self) -> Result<Vec<OwnedPacket>, Error> {
        // 1. Recycle completed TX frames
        self.recycle_completed();

        // 2. Peek RX ring
        let tok = match self.rx.consumer_peek(64) {
            Some(t) => t,
            None => return Ok(Vec::new()),
        };

        let mut packets = Vec::with_capacity(tok.n as usize);

        for i in 0..tok.n {
            let desc: libc::xdp_desc = self.rx.read_at(tok, i);
            match self.umem.data_checked(desc.addr, desc.len as usize) {
                Some(data) => packets.push(OwnedPacket {
                    data: data.to_vec(),
                    timestamp: Timestamp::default(),
                    original_len: desc.len as usize,
                    // AF_XDP doesn't surface AF_PACKET-style metadata; the
                    // RX metadata BPF extension would, but is not yet wired.
                    status: crate::packet::PacketStatus::default(),
                    direction: crate::packet::PacketDirection::Unknown(0),
                    rxhash: 0,
                    vlan_tci: 0,
                    vlan_tpid: 0,
                    ll_protocol: 0,
                    source_ll_addr: [0u8; 8],
                    source_ll_addr_len: 0,
                }),
                None => {
                    // Defense in depth: a kernel that's misbehaving (or a
                    // shared-UMEM peer that wrote a corrupt desc) shouldn't
                    // panic the consumer.
                    tracing::warn!(
                        addr = desc.addr,
                        len = desc.len,
                        "AF_XDP: malformed RX descriptor; skipping"
                    );
                }
            }
            // Return frame to free list (will be refilled below) regardless.
            self.umem.free_frame(desc.addr);
        }

        // 3. Release consumed RX descriptors
        self.rx.consumer_release(tok);

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

        // Copy data into UMEM frame.
        // The frame_size check at the top of send() ensures data.len() fits;
        // expect() here is for an internal invariant that should never fail.
        let buf = self
            .umem
            .data_mut_checked(addr, data.len())
            .expect("send: frame_size pre-check guarantees fit");
        buf.copy_from_slice(data);

        // Submit TX descriptor
        let tok = match self.tx.producer_reserve(1) {
            Some(t) => t,
            None => {
                self.umem.free_frame(addr);
                return Ok(false);
            }
        };
        self.tx.write_at(
            tok,
            0,
            libc::xdp_desc {
                addr,
                len: data.len() as u32,
                options: 0,
            },
        );
        self.tx.producer_submit(tok);

        Ok(true)
    }

    /// Flush pending TX frames by waking the kernel.
    ///
    /// When the socket was bound with `XDP_USE_NEED_WAKEUP` (the default), the
    /// kernel sets a flag in the TX ring whenever it actually needs a kick;
    /// we honor that and skip the syscall otherwise. For sockets bound without
    /// the flag, `needs_wakeup()` always returns false — we still kick.
    ///
    /// Uses `sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0)`.
    /// `MSG_DONTWAIT` is **mandatory** — kernel returns `EOPNOTSUPP` without it.
    /// EINTR is retried; transient `EAGAIN`/`ENOBUFS` are reported as success.
    #[cfg(feature = "af-xdp")]
    pub fn flush(&self) -> Result<(), Error> {
        if self.need_wakeup_enabled && !self.tx.needs_wakeup() {
            return Ok(());
        }
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
    ///
    /// Counters are monotonically non-decreasing for the socket's lifetime
    /// (no destructive-read semantics).
    #[cfg(feature = "af-xdp")]
    pub fn statistics(&self) -> Result<XdpStats, Error> {
        socket::get_statistics(self.fd.as_fd()).map(XdpStats::from)
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Recycle frames from the completion ring back to the UMEM free list.
    #[cfg(feature = "af-xdp")]
    fn recycle_completed(&mut self) {
        let tok = match self.comp.consumer_peek(64) {
            Some(t) => t,
            None => return,
        };
        let mut addrs = [0u64; 64];
        for i in 0..tok.n {
            addrs[i as usize] = self.comp.read_at(tok, i);
        }
        self.umem.free_frames(&addrs[..tok.n as usize]);
        self.comp.consumer_release(tok);
    }

    /// Refill the fill ring with available UMEM frames.
    #[cfg(feature = "af-xdp")]
    fn refill(&mut self) {
        let want = self.umem.available().min(64) as u32;
        if want == 0 {
            return;
        }
        if let Some(tok) = self.fill.producer_reserve(want) {
            let mut filled = 0u32;
            for i in 0..tok.n {
                if let Some(addr) = self.umem.alloc_frame() {
                    self.fill.write_at(tok, i, addr);
                    filled += 1;
                }
            }
            // `want` was bounded by umem.available() so all reservations get
            // filled; the assertion documents the invariant.
            debug_assert_eq!(filled, tok.n);
            if filled > 0 {
                self.fill.producer_submit(tok);
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
