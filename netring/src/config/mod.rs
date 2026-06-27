//! Configuration types: fanout, BPF filters, timestamps, ring profiles.

use crate::afpacket::ffi;

pub mod bpf;
pub mod bpf_builder;
pub(crate) mod bpf_compile;
pub(crate) mod bpf_humanize;
pub mod bpf_interp;
pub mod busy_poll;
pub mod ipnet;

pub use bpf::{BpfBuildError, BpfFilter, BpfInsn};
pub use bpf_builder::BpfFilterBuilder;
pub use busy_poll::BusyPollConfig;
pub use ipnet::{IpNet, ParseIpNetError};

/// Fanout distribution mode for multi-socket packet sharing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FanoutMode {
    /// Distribute by flow hash (src/dst IP+port).
    Hash,
    /// Round-robin across sockets.
    LoadBalance,
    /// Route to the CPU that received the NIC interrupt.
    Cpu,
    /// Fill one socket, overflow when backlogged.
    Rollover,
    /// Random distribution.
    Random,
    /// Based on `skb->queue_mapping`.
    QueueMapping,
    /// eBPF program selects the target socket.
    ///
    /// The program receives the packet and returns the socket index
    /// (0-based) within the fanout group. After building the socket with
    /// `.fanout(FanoutMode::Ebpf, group_id)`, attach the program via
    /// [`Capture::attach_fanout_ebpf()`](crate::Capture::attach_fanout_ebpf).
    Ebpf,
}

impl FanoutMode {
    /// Kernel constant for this mode.
    pub(crate) const fn as_raw(self) -> u32 {
        match self {
            Self::Hash => ffi::PACKET_FANOUT_HASH,
            Self::LoadBalance => ffi::PACKET_FANOUT_LB,
            Self::Cpu => ffi::PACKET_FANOUT_CPU,
            Self::Rollover => ffi::PACKET_FANOUT_ROLLOVER,
            Self::Random => ffi::PACKET_FANOUT_RND,
            Self::QueueMapping => ffi::PACKET_FANOUT_QM,
            Self::Ebpf => ffi::PACKET_FANOUT_EBPF,
        }
    }
}

bitflags::bitflags! {
    /// Flags OR'd with the fanout mode.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FanoutFlags: u16 {
        /// Rollover to next socket if selected one's ring is full.
        const ROLLOVER        = 0x1000;
        /// Kernel assigns a unique group ID.
        const UNIQUE_ID       = 0x2000;
        /// Don't deliver outgoing packets.
        const IGNORE_OUTGOING = 0x4000;
        /// Defragment IP before hashing (ensures correct flow distribution).
        const DEFRAG          = 0x8000;
    }
}

/// Kernel timestamp source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimestampSource {
    /// Software timestamp (default).
    #[default]
    Software,
    /// Raw hardware timestamp from NIC.
    RawHardware,
    /// System-adjusted hardware timestamp.
    SysHardware,
}

impl TimestampSource {
    /// The `PACKET_TIMESTAMP` setsockopt value selecting this source.
    ///
    /// `PACKET_TIMESTAMP` takes a bitmask of `SOF_TIMESTAMPING_*` flags;
    /// only the hardware bits are meaningful, and an unset/zero value means
    /// the kernel's default software stamp. The earlier mapping returned the
    /// bare ordinals `1`/`2`, which are `SOF_TIMESTAMPING_TX_HARDWARE` /
    /// `_TX_SOFTWARE` (TX flags) — so requesting a hardware source silently
    /// did nothing and the capture stayed on the software clock (issue #40).
    ///
    /// Note: selecting a hardware source here is necessary but not
    /// sufficient — the NIC must also have hardware timestamping enabled at
    /// the device level (`SIOCSHWTSTAMP` / `ethtool -T`), and the kernel
    /// silently falls back to software per-packet when it can't honor the
    /// request. Read the actual clock back via
    /// [`Packet::timestamp_clock`](crate::Packet::timestamp_clock).
    pub(crate) const fn as_raw(self) -> libc::c_int {
        match self {
            Self::Software => 0,
            Self::RawHardware => crate::afpacket::ffi::SOF_TIMESTAMPING_RAW_HARDWARE as libc::c_int,
            Self::SysHardware => crate::afpacket::ffi::SOF_TIMESTAMPING_SYS_HARDWARE as libc::c_int,
        }
    }
}

// ── Ring Profiles ──────────────────────────────────────────────────────────

/// Pre-configured ring buffer profiles for common workloads.
///
/// Use with [`CaptureBuilder::profile()`](crate::CaptureBuilder::profile)
/// to set block_size, block_count, frame_size, and block_timeout_ms in one call.
/// Individual settings can be overridden after applying a profile.
///
/// # Examples
///
/// ```no_run
/// use netring::{Capture, RingProfile};
///
/// let cap = Capture::builder()
///     .interface("eth0")
///     .profile(RingProfile::LowLatency)
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RingProfile {
    /// Balanced defaults. 4 MiB blocks × 64 (256 MiB), 60ms timeout.
    /// Good for general-purpose capture up to ~500 Kpps.
    Default,

    /// Maximum throughput. 4 MiB blocks × 256 (1 GiB), 60ms timeout.
    /// Pair with [`FanoutMode::Cpu`] for multi-core capture.
    HighThroughput,

    /// Minimal latency. 256 KiB blocks × 64 (16 MiB), 1ms timeout.
    /// Smaller blocks retire faster. Pair with `busy_poll_us()`.
    LowLatency,

    /// Minimal memory. 1 MiB blocks × 16 (16 MiB), 100ms timeout.
    /// For memory-constrained environments.
    LowMemory,

    /// Large frames / jumbo MTU. 4 MiB blocks × 64, frame_size=65536.
    /// For interfaces with MTU > 1500 or GRO/GSO enabled.
    JumboFrames,
}

impl RingProfile {
    /// Returns `(block_size, block_count, frame_size, block_timeout_ms)`.
    #[inline]
    pub(crate) fn params(self) -> (usize, usize, usize, u32) {
        match self {
            Self::Default => (1 << 22, 64, 2048, 60),
            Self::HighThroughput => (1 << 22, 256, 2048, 60),
            Self::LowLatency => (1 << 18, 64, 2048, 1),
            Self::LowMemory => (1 << 20, 16, 2048, 100),
            Self::JumboFrames => (1 << 22, 64, 65536, 60),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fanout_mode_as_raw() {
        assert_eq!(FanoutMode::Hash.as_raw(), 0);
        assert_eq!(FanoutMode::LoadBalance.as_raw(), 1);
        assert_eq!(FanoutMode::Cpu.as_raw(), 2);
        assert_eq!(FanoutMode::Rollover.as_raw(), 3);
        assert_eq!(FanoutMode::Random.as_raw(), 4);
        assert_eq!(FanoutMode::QueueMapping.as_raw(), 5);
    }

    #[test]
    fn fanout_flags_bitwise() {
        let flags = FanoutFlags::ROLLOVER | FanoutFlags::DEFRAG;
        assert_eq!(flags.bits(), 0x9000);
        assert!(flags.contains(FanoutFlags::ROLLOVER));
        assert!(flags.contains(FanoutFlags::DEFRAG));
        assert!(!flags.contains(FanoutFlags::UNIQUE_ID));
    }

    #[test]
    fn timestamp_source_default() {
        assert_eq!(TimestampSource::default(), TimestampSource::Software);
        assert_eq!(TimestampSource::Software.as_raw(), 0);
    }

    #[test]
    fn timestamp_source_hardware_emits_sof_flags_not_bare_ordinals() {
        use crate::afpacket::ffi;
        // Regression for issue #40: these must be the SOF_TIMESTAMPING
        // hardware selectors (64 / 32), NOT the bare ordinals 1 / 2 (which
        // are the unrelated TX_HARDWARE / TX_SOFTWARE flags and left HW
        // requests silently on the software clock).
        assert_eq!(
            TimestampSource::RawHardware.as_raw(),
            ffi::SOF_TIMESTAMPING_RAW_HARDWARE as libc::c_int
        );
        assert_eq!(
            TimestampSource::SysHardware.as_raw(),
            ffi::SOF_TIMESTAMPING_SYS_HARDWARE as libc::c_int
        );
        assert_ne!(TimestampSource::RawHardware.as_raw(), 1);
        assert_ne!(TimestampSource::SysHardware.as_raw(), 2);
    }

    #[test]
    fn ring_profile_params_valid() {
        for profile in [
            RingProfile::Default,
            RingProfile::HighThroughput,
            RingProfile::LowLatency,
            RingProfile::LowMemory,
            RingProfile::JumboFrames,
        ] {
            let (block_size, block_count, frame_size, timeout_ms) = profile.params();
            assert!(block_size.is_power_of_two(), "{profile:?} block_size");
            assert!(block_size.is_multiple_of(4096), "{profile:?} page-aligned");
            assert!(block_count > 0, "{profile:?} block_count");
            assert!(
                frame_size >= 68,
                "{profile:?} frame_size >= TPACKET3_HDRLEN"
            );
            assert!(
                frame_size.is_multiple_of(16),
                "{profile:?} frame_size aligned"
            );
            assert!(
                frame_size <= block_size,
                "{profile:?} frame_size <= block_size"
            );
            let _ = timeout_ms;
        }
    }
}
