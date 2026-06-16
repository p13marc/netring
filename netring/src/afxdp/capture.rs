//! High-level multi-queue AF_XDP capture (issue #6).
//!
//! An AF_XDP socket binds to a **single** netdev RX queue. A NIC spreads inbound
//! traffic across queues via RSS, so one socket only ever sees the share hashed
//! to its queue — even in promiscuous mode. [`XdpCapture`] automates the
//! one-socket-per-queue pattern every capture framework (DPDK `queue_count`,
//! Suricata `threads: auto`) exposes: it loads **one** redirect program, opens
//! one socket per queue (each with its own UMEM — the safe default, since
//! sharing a UMEM across per-CPU sockets races on the FILL ring), registers each
//! socket in the program's XSKMAP, attaches the program once, and drains them
//! through a unified round-robin [`next_batch`](XdpCapture::next_batch).

use crate::afxdp::ffi;
use crate::error::Error;

// ── Queue selection ─────────────────────────────────────────────────────────

/// Which NIC RX queues a capture should bind.
///
/// AF_XDP is one socket per queue; this selects how many [`XdpCapture`] opens.
#[derive(Debug, Clone)]
pub enum Queues {
    /// A single queue id. The historical default (queue 0).
    Single(u32),
    /// An explicit half-open range of queue ids, e.g. `0..4`.
    Range(std::ops::Range<u32>),
    /// Every RSS/combined queue on the interface, auto-detected via
    /// `ETHTOOL_GCHANNELS`. Falls back to queue 0 only if detection fails
    /// (virtual interface, `lo`, missing support) — always safe to use.
    Auto,
}

impl Default for Queues {
    fn default() -> Self {
        Queues::Single(0)
    }
}

impl Queues {
    /// One queue.
    pub fn single(q: u32) -> Self {
        Queues::Single(q)
    }

    /// A range of queues (`a..b`).
    pub fn range(r: std::ops::Range<u32>) -> Self {
        Queues::Range(r)
    }

    /// Resolve to a concrete, sorted list of queue ids for `iface`.
    pub fn resolve(&self, iface: &str) -> Result<Vec<u32>, Error> {
        match self {
            Queues::Single(q) => Ok(vec![*q]),
            Queues::Range(r) => {
                if r.start >= r.end {
                    return Err(Error::Config(format!(
                        "empty queue range {}..{}",
                        r.start, r.end
                    )));
                }
                Ok(r.clone().collect())
            }
            Queues::Auto => match queue_count(iface) {
                Ok(n) => Ok((0..n).collect()),
                Err(e) => {
                    tracing::warn!(
                        "Queues::Auto: queue_count({iface}) failed ({e}); \
                         falling back to queue 0 only"
                    );
                    Ok(vec![0])
                }
            },
        }
    }
}

// ── Queue-count discovery ───────────────────────────────────────────────────

/// Number of RSS/combined RX queues on `iface`, via the `ETHTOOL_GCHANNELS`
/// ioctl (issue #6 G3).
///
/// Returns the NIC's `combined_count` (RSS-bearing queues), or `rx_count` on
/// rx/tx-split NICs. Requires no privilege. Errors on interfaces that don't
/// support channel queries (e.g. `lo`, many virtual devices) — callers that want
/// a soft fallback should use [`Queues::Auto`], which degrades to queue 0.
pub fn queue_count(iface: &str) -> Result<u32, Error> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    if iface.len() >= libc::IFNAMSIZ {
        return Err(Error::Config(format!("interface name too long: {iface}")));
    }

    // A datagram socket is the conventional handle for SIOCETHTOOL.
    // SAFETY: standard socket() with valid constants.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if raw < 0 {
        return Err(Error::Socket(std::io::Error::last_os_error()));
    }
    // SAFETY: fd is valid, just returned by socket().
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut channels = ffi::ethtool_channels {
        cmd: ffi::ETHTOOL_GCHANNELS,
        ..Default::default()
    };
    let mut ifr = ffi::ethtool_ifreq {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_data: (&mut channels as *mut ffi::ethtool_channels).cast(),
    };
    for (dst, &b) in ifr.ifr_name.iter_mut().zip(iface.as_bytes()) {
        *dst = b as libc::c_char;
    }

    // SAFETY: `ifr` is a well-formed ifreq whose ifr_data points at `channels`;
    // the kernel writes channel counts into `channels` for ETHTOOL_GCHANNELS.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), ffi::SIOCETHTOOL, &mut ifr as *mut _) };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    let n = if channels.combined_count > 0 {
        channels.combined_count
    } else if channels.rx_count > 0 {
        channels.rx_count
    } else {
        1
    };
    Ok(n)
}

// ── XdpCapture (multi-queue handle) ─────────────────────────────────────────

#[cfg(feature = "xdp-loader")]
pub use mq::{XdpCapture, XdpCaptureBuilder, XdpCaptureGuard};

#[cfg(feature = "xdp-loader")]
mod mq {
    use std::time::Duration;

    use super::{Error, Queues};
    use crate::afxdp::loader::{XdpAttachment, XdpFlags, XdpProgram, default_program};
    use crate::afxdp::{XdpBatch, XdpMode, XdpSocket, XdpSocketBuilder};

    /// The vendored redirect program's XSKMAP capacity (`max_entries`). Queue
    /// ids must be `< XSKMAP_CAP`; far above any real NIC's queue count.
    const XSKMAP_CAP: u32 = 256;

    /// Builder for [`XdpCapture`].
    #[must_use]
    pub struct XdpCaptureBuilder {
        interface: Option<String>,
        queues: Queues,
        frame_size: usize,
        frame_count: usize,
        mode: XdpMode,
        promiscuous: bool,
        hugepages: bool,
        numa_node: Option<u32>,
        attach_flags: XdpFlags,
        program: Option<XdpProgram>,
    }

    impl Default for XdpCaptureBuilder {
        fn default() -> Self {
            Self {
                interface: None,
                queues: Queues::default(),
                frame_size: 4096,
                frame_count: 4096,
                mode: XdpMode::Rx, // capture default (unlike XdpSocketBuilder's RxTx)
                promiscuous: false,
                hugepages: false,
                numa_node: None,
                attach_flags: XdpFlags::SKB_MODE, // safest; works on lo
                program: None,
            }
        }
    }

    impl XdpCaptureBuilder {
        /// Interface to capture (required).
        pub fn interface(mut self, name: &str) -> Self {
            self.interface = Some(name.to_string());
            self
        }

        /// Which RX queues to bind. Default: `Queues::Single(0)`. For full-NIC
        /// capture use [`Queues::Auto`].
        pub fn queues(mut self, queues: Queues) -> Self {
            self.queues = queues;
            self
        }

        /// Per-socket UMEM frame size. Default: 4096.
        pub fn frame_size(mut self, size: usize) -> Self {
            self.frame_size = size;
            self
        }

        /// Per-socket UMEM frame count. Default: 4096.
        pub fn frame_count(mut self, count: usize) -> Self {
            self.frame_count = count;
            self
        }

        /// Operating mode. Default: [`XdpMode::Rx`] (capture).
        pub fn mode(mut self, mode: XdpMode) -> Self {
            self.mode = mode;
            self
        }

        /// Put the interface into promiscuous mode for the capture's lifetime
        /// (issue #4). A **single** interface-global `PACKET_MR_PROMISC` guard
        /// covers all queues (promiscuity is reference-counted), released on
        /// drop. Default: `false`.
        pub fn promiscuous(mut self, enable: bool) -> Self {
            self.promiscuous = enable;
            self
        }

        /// Back each socket's UMEM with hugepages (`MAP_HUGETLB`). Default: false.
        pub fn hugepages(mut self, enable: bool) -> Self {
            self.hugepages = enable;
            self
        }

        /// Bind every socket's UMEM to NUMA `node`. Default: none.
        pub fn numa_node(mut self, node: u32) -> Self {
            self.numa_node = Some(node);
            self
        }

        /// XDP attach mode. Default: `SKB_MODE` (works everywhere incl. `lo`).
        /// Use `DRV_MODE` for native-driver zero-copy on a real NIC.
        pub fn attach_flags(mut self, flags: XdpFlags) -> Self {
            self.attach_flags = flags;
            self
        }

        /// Use a caller-supplied program instead of the built-in redirect-all.
        /// Must contain an `xsks_map` XSKMAP and redirect by `rx_queue_index`.
        pub fn with_program(mut self, prog: XdpProgram) -> Self {
            self.program = Some(prog);
            self
        }

        /// Open the capture: resolve the queue set, load one program, open one
        /// socket per queue (own UMEM each), register them, attach the program,
        /// and (optionally) raise promiscuous mode once.
        pub fn build(mut self) -> Result<XdpCapture, Error> {
            let iface = self
                .interface
                .clone()
                .ok_or_else(|| Error::Config("interface is required".into()))?;
            let ifindex = crate::afpacket::socket::resolve_interface(&iface)? as u32;
            let queue_ids = self.queues.resolve(&iface)?;

            // B1 guard: the vendored XSKMAP holds 256 entries; a queue id past
            // that would silently fail to register. Fail loudly instead.
            if let Some(&max_q) = queue_ids.iter().max()
                && max_q >= XSKMAP_CAP
            {
                return Err(Error::Config(format!(
                    "queue id {max_q} exceeds the built-in XSKMAP capacity ({XSKMAP_CAP}); \
                     narrow the queue range or supply a larger program via with_program()"
                )));
            }

            // One program for the whole interface.
            let mut prog = match self.program.take() {
                Some(p) => p,
                None => default_program(XSKMAP_CAP)?,
            };

            // One bare socket per queue (own UMEM = safe default), each
            // registered at its queue index in the shared XSKMAP.
            let mut sockets = Vec::with_capacity(queue_ids.len());
            for &q in &queue_ids {
                let mut b = XdpSocketBuilder::default()
                    .interface(&iface)
                    .queue_id(q)
                    .mode(self.mode)
                    .frame_size(self.frame_size)
                    .frame_count(self.frame_count)
                    .hugepages(self.hugepages);
                if let Some(node) = self.numa_node {
                    b = b.numa_node(node);
                }
                let sock = b.build()?;
                prog.register(q, &sock)?;
                sockets.push(sock);
            }

            // Attach the program once for the interface (RAII detach on drop).
            let attachment = prog.attach(&iface, self.attach_flags)?;

            // One interface-global promiscuous guard (issue #4), not per socket.
            let promisc = if self.promiscuous {
                Some(crate::afpacket::socket::PromiscGuard::enable(
                    ifindex as i32,
                )?)
            } else {
                None
            };

            Ok(XdpCapture {
                sockets,
                queue_ids,
                cursor: 0,
                _attachment: attachment,
                _promisc: promisc,
            })
        }
    }

    /// A multi-queue AF_XDP capture: one socket per RX queue, one attached
    /// program, drained through a unified round-robin. See the [module
    /// docs](crate::xdp).
    pub struct XdpCapture {
        sockets: Vec<XdpSocket>,
        queue_ids: Vec<u32>,
        cursor: usize,
        // Dropped after the sockets (field order) so the program detaches last.
        _attachment: XdpAttachment,
        _promisc: Option<crate::afpacket::socket::PromiscGuard>,
    }

    impl XdpCapture {
        /// Start building a capture.
        pub fn builder() -> XdpCaptureBuilder {
            XdpCaptureBuilder::default()
        }

        /// Open a capture on `iface` over **all** RSS queues, promiscuous —
        /// the one-line full-NIC recipe. Equivalent to
        /// `builder().interface(iface).queues(Queues::Auto).promiscuous(true).build()`.
        pub fn open(iface: &str) -> Result<Self, Error> {
            Self::builder()
                .interface(iface)
                .queues(Queues::Auto)
                .promiscuous(true)
                .build()
        }

        /// The bound queue ids, in socket order.
        pub fn queue_ids(&self) -> &[u32] {
            &self.queue_ids
        }

        /// Number of per-queue sockets.
        pub fn socket_count(&self) -> usize {
            self.sockets.len()
        }

        /// Whether **every** socket bound in zero-copy mode (issue #6 F2). On
        /// SKB/generic XDP (e.g. `lo`) this is `false`.
        pub fn is_zerocopy(&self) -> bool {
            self.sockets.iter().all(|s| s.is_zerocopy())
        }

        /// Mutable access to the per-queue sockets (for advanced drain loops).
        pub fn sockets_mut(&mut self) -> &mut [XdpSocket] {
            &mut self.sockets
        }

        /// Non-blocking unified RX: round-robins the queues and returns the next
        /// ready queue's borrowed (zero-copy) batch with its queue id, or `None`
        /// if no queue has data right now. Fair — it resumes after the
        /// last-served queue.
        pub fn next_batch(&mut self) -> Option<(u32, XdpBatch<'_>)> {
            let n = self.sockets.len();
            if n == 0 {
                return None;
            }
            // Phase 1: pick the next ready queue using a fresh, kernel-synced
            // probe (the cached `rx_is_empty` can't be used to *decide* to peek
            // — it only refreshes inside `consumer_peek`, which we'd be gating).
            let mut target = None;
            for off in 0..n {
                let i = (self.cursor + off) % n;
                if self.sockets[i].rx_poll_ready() {
                    target = Some(i);
                    break;
                }
            }
            let i = target?;
            // Phase 2: single mutable borrow for the returned batch.
            self.cursor = (i + 1) % n;
            let qid = self.queue_ids[i];
            self.sockets[i].next_batch().map(|b| (qid, b))
        }

        /// Blocking unified RX: like [`next_batch`](Self::next_batch) but polls
        /// every queue's fd for up to `timeout` if none is ready.
        pub fn next_batch_blocking(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<(u32, XdpBatch<'_>)>, Error> {
            if self.sockets.iter_mut().any(|s| s.rx_poll_ready()) {
                return Ok(self.next_batch());
            }
            let mut pfds: Vec<nix::poll::PollFd> = self
                .sockets
                .iter()
                .map(|s| nix::poll::PollFd::new(s.poll_fd(), nix::poll::PollFlags::POLLIN))
                .collect();
            crate::syscall::poll_eintr_safe(&mut pfds, timeout).map_err(Error::Io)?;
            Ok(self.next_batch())
        }

        /// Decompose into the per-queue sockets plus a guard that keeps the
        /// attached program (and promiscuous mode) alive — for the
        /// worker-per-queue model (move each socket to its own core). Hold the
        /// guard (e.g. in an `Arc` shared by the workers) for the capture's
        /// lifetime; dropping it detaches the program.
        pub fn into_parts(self) -> (Vec<XdpSocket>, XdpCaptureGuard) {
            (
                self.sockets,
                XdpCaptureGuard {
                    _attachment: self._attachment,
                    _promisc: self._promisc,
                },
            )
        }
    }

    /// Keeps a multi-queue capture's attached XDP program + promiscuous guard
    /// alive after [`XdpCapture::into_parts`] has handed out the sockets.
    pub struct XdpCaptureGuard {
        _attachment: XdpAttachment,
        _promisc: Option<crate::afpacket::socket::PromiscGuard>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queues_default_is_single_zero() {
        assert!(matches!(Queues::default(), Queues::Single(0)));
    }

    #[test]
    fn queues_resolve_single_and_range() {
        assert_eq!(Queues::Single(2).resolve("lo").unwrap(), vec![2]);
        assert_eq!(Queues::range(0..4).resolve("lo").unwrap(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn queues_resolve_empty_range_errors() {
        assert!(Queues::range(3..3).resolve("lo").is_err());
    }

    #[test]
    fn queues_auto_never_errors_falls_back_to_zero() {
        // `lo` doesn't support ETHTOOL_GCHANNELS, so Auto must degrade to [0]
        // rather than propagate the ioctl error.
        let resolved = Queues::Auto.resolve("lo").unwrap();
        assert!(resolved.contains(&0));
    }

    #[test]
    fn queue_count_does_not_panic() {
        // On `lo` this typically errors (EOPNOTSUPP); on a real NIC it returns
        // >= 1. Either is fine — we only assert it doesn't panic and any Ok is
        // a sane count.
        if let Ok(n) = queue_count("lo") {
            assert!(n >= 1);
        }
    }
}
