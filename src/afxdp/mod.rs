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

// ── XdpSocketBuilder ─────────────────────────────────────────────────────

/// Builder for AF_XDP sockets.
///
/// # Examples
///
/// ```no_run,ignore
/// use netring::afxdp::XdpSocketBuilder;
///
/// let mut xdp = XdpSocketBuilder::default()
///     .interface("eth0")
///     .queue_id(0)
///     .build()
///     .unwrap();
///
/// // TX-only (no BPF program needed):
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
}

impl Default for XdpSocketBuilder {
    fn default() -> Self {
        Self {
            interface: None,
            queue_id: 0,
            frame_size: 4096,
            frame_count: 4096,
            need_wakeup: true,
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
        socket::set_ring_size(fd.as_fd(), ffi::XDP_UMEM_FILL_RING, ring_size, "XDP_UMEM_FILL_RING")?;
        socket::set_ring_size(fd.as_fd(), ffi::XDP_UMEM_COMPLETION_RING, ring_size, "XDP_UMEM_COMPLETION_RING")?;
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

        // 7. Pre-fill the fill ring with frame addrs for kernel RX
        let prefill = umem.available().min(ring_size as usize) as u32;
        if let Some(idx) = fill.producer_reserve(prefill) {
            for i in 0..prefill {
                if let Some(addr) = umem.alloc_frame() {
                    unsafe { fill.write_desc(idx + i, addr) };
                }
            }
            fill.producer_submit(prefill);
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
    #[cfg(feature = "af-xdp")]
    pub fn flush(&self) -> Result<(), Error> {
        // Always kick for simplicity. Could check self.tx.needs_wakeup()
        // to only kick when kernel signals NEED_WAKEUP.
        let ret = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            )
        };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            // EAGAIN/ENOBUFS are transient — not errors
            if err.raw_os_error() != Some(libc::EAGAIN)
                && err.raw_os_error() != Some(libc::ENOBUFS)
            {
                return Err(Error::Io(err));
            }
        }
        Ok(())
    }

    /// Poll for readability (incoming packets) with a timeout.
    ///
    /// Returns `true` if packets may be available.
    #[cfg(feature = "af-xdp")]
    pub fn poll(&self, timeout: Duration) -> Result<bool, Error> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if n == -1 {
            Err(Error::Io(std::io::Error::last_os_error()))
        } else {
            Ok(n > 0)
        }
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
}
