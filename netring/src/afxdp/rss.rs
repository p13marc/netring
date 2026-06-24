//! Symmetric RSS / fanout flow coherence (issue #43).
//!
//! NIC receive-side scaling (RSS) hashes each packet's 4-tuple to pick an RX
//! queue. By default that hash is **asymmetric**: `A→B` and `B→A` hash to
//! different queues, so a per-queue sharded capture (`XdpShardedRunner`, a
//! `PACKET_FANOUT` group) silently splits a bidirectional flow across two
//! workers — each sees half the conversation. The flow *key* is canonical
//! everywhere in netring; the *distribution plane* is what's asymmetric, and it
//! can only be fixed at the NIC.
//!
//! [`RssConfig::set_symmetric`] makes the NIC's RX hashing direction-symmetric
//! so both halves land on one queue, preferring the kernel's
//! [`RXH_XFRM_SYM_XOR`](crate::xdp::rss::RssMode::SymXor) transform (kernel
//! ≥ 6.8) and falling back to programming the symmetric Toeplitz key
//! ([`SYMMETRIC_RSS_KEY`]). It **errors** rather than warns when neither is
//! available, so a sharded deployment never *silently* runs with split flows.
//!
//! [`toeplitz`] + [`rss_flow_hash`] reproduce the NIC's Toeplitz hash in
//! software so you can verify coherence offline (with the symmetric key,
//! `rss_flow_hash(a, b) == rss_flow_hash(b, a)`).
//!
//! The ioctl paths require a real NIC with RSS (`lo` has none); they follow the
//! same `SIOCETHTOOL` pattern as [`queue_count`](crate::xdp::queue_count) and
//! are validated on hardware. The Toeplitz reference + key are pure and unit
//! tested.

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::afxdp::ffi;
use crate::error::Error;

/// The canonical **symmetric** Toeplitz RSS key (`6D 5A` repeated). Programming
/// it as the NIC's RSS key makes the Toeplitz hash invariant under swapping the
/// source/destination fields — so `A→B` and `B→A` hash identically. 40 bytes,
/// the common key length; drivers wanting 52 bytes repeat the same pattern.
pub const SYMMETRIC_RSS_KEY: [u8; 40] = [
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
];

/// How [`RssConfig::set_symmetric`] achieved symmetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RssMode {
    /// The driver's `RXH_XFRM_SYM_XOR` input transform (kernel ≥ 6.8). The
    /// indirection table and key are left untouched.
    SymXor,
    /// The symmetric Toeplitz key ([`SYMMETRIC_RSS_KEY`]) was programmed as the
    /// RSS hash key (the fallback when `SYM_XOR` is unsupported).
    SymmetricKey,
}

/// Configure a NIC's RSS hashing for bidirectional-flow coherence.
pub struct RssConfig {
    iface: String,
}

impl RssConfig {
    /// Target `iface` (e.g. `"eth0"`). No syscall yet.
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
        }
    }

    /// Make the NIC hash `A→B` and `B→A` to the **same** RX queue.
    ///
    /// Tries `RXH_XFRM_SYM_XOR` first (clean, leaves the key/table intact), then
    /// programs [`SYMMETRIC_RSS_KEY`]. Returns the [`RssMode`] used, or an error
    /// if the driver supports neither — callers running sharded capture should
    /// treat that error as fatal rather than silently split flows.
    pub fn set_symmetric(&self) -> Result<RssMode, Error> {
        // Preferred: ask the driver to XOR-fold src/dst before hashing. A fixed
        // 24-byte command (no indir table / key in the buffer), leaving both
        // unchanged.
        if self.try_set_sym_xor()? {
            return Ok(RssMode::SymXor);
        }
        // Fallback: program the symmetric Toeplitz key.
        self.set_symmetric_key()?;
        Ok(RssMode::SymmetricKey)
    }

    /// Read the current RSS key size (bytes) via `ETHTOOL_GRSSH`. `0` means the
    /// driver reports no resizable key.
    pub fn key_size(&self) -> Result<u32, Error> {
        let (_, key_size, _) = self.grssh_sizes()?;
        Ok(key_size)
    }

    /// `true` if the active RSS input transform already includes `SYM_XOR`.
    pub fn is_symmetric_xfrm(&self) -> Result<bool, Error> {
        let (_, _, input_xfrm) = self.grssh_sizes()?;
        Ok(input_xfrm & ffi::RXH_XFRM_SYM_XOR != 0)
    }

    /// `GRSSH` size query — returns `(indir_size, key_size, input_xfrm)`.
    fn grssh_sizes(&self) -> Result<(u32, u32, u8), Error> {
        let fd = ethtool_socket()?;
        let mut rxfh = ffi::ethtool_rxfh {
            cmd: ffi::ETHTOOL_GRSSH,
            ..Default::default()
        };
        ethtool_ioctl(
            &fd,
            &self.iface,
            (&mut rxfh as *mut ffi::ethtool_rxfh).cast(),
        )?;
        Ok((rxfh.indir_size, rxfh.key_size, rxfh.input_xfrm))
    }

    /// Attempt the `SYM_XOR` transform. Returns `Ok(false)` (not an error) when
    /// the driver rejects it as unsupported, so the caller can fall back.
    fn try_set_sym_xor(&self) -> Result<bool, Error> {
        let fd = ethtool_socket()?;
        let mut rxfh = ffi::ethtool_rxfh {
            cmd: ffi::ETHTOOL_SRSSH,
            indir_size: ffi::ETH_RXFH_INDIR_NO_CHANGE,
            key_size: 0,
            hfunc: ffi::ETH_RSS_HASH_NO_CHANGE,
            input_xfrm: ffi::RXH_XFRM_SYM_XOR,
            ..Default::default()
        };
        match ethtool_ioctl(
            &fd,
            &self.iface,
            (&mut rxfh as *mut ffi::ethtool_rxfh).cast(),
        ) {
            Ok(()) => Ok(true),
            Err(e) => match io_errno(&e) {
                // Driver / kernel doesn't support the transform → fall back.
                // (ENOTSUP == EOPNOTSUPP on Linux.)
                Some(libc::EOPNOTSUPP) | Some(libc::EINVAL) => Ok(false),
                _ => Err(e),
            },
        }
    }

    /// Program [`SYMMETRIC_RSS_KEY`] as the RSS hash key, leaving the
    /// indirection table unchanged. Builds the variable-length `ethtool_rxfh`
    /// buffer: the 24-byte header followed by `key_size` key bytes (no indir
    /// table in the buffer, since `indir_size = NO_CHANGE`).
    fn set_symmetric_key(&self) -> Result<(), Error> {
        let key_size = self.key_size()? as usize;
        if key_size == 0 {
            return Err(Error::Config(format!(
                "interface {} reports no settable RSS key and no SYM_XOR support",
                self.iface
            )));
        }
        let header = std::mem::size_of::<ffi::ethtool_rxfh>();
        let mut buf = vec![0u8; header + key_size];
        {
            // SAFETY: `buf` is `header + key_size` bytes; the header is a valid
            // `ethtool_rxfh` POD written through an aligned pointer (Vec<u8> is
            // suitably aligned for the u32-leading struct on all targets).
            let hdr = buf.as_mut_ptr().cast::<ffi::ethtool_rxfh>();
            unsafe {
                hdr.write_unaligned(ffi::ethtool_rxfh {
                    cmd: ffi::ETHTOOL_SRSSH,
                    indir_size: ffi::ETH_RXFH_INDIR_NO_CHANGE,
                    key_size: key_size as u32,
                    hfunc: ffi::ETH_RSS_HASH_NO_CHANGE,
                    input_xfrm: ffi::RXH_XFRM_NO_CHANGE,
                    ..Default::default()
                });
            }
        }
        // Fill the key region, repeating the symmetric pattern to `key_size`.
        for (i, slot) in buf[header..].iter_mut().enumerate() {
            *slot = SYMMETRIC_RSS_KEY[i % SYMMETRIC_RSS_KEY.len()];
        }
        let fd = ethtool_socket()?;
        ethtool_ioctl(&fd, &self.iface, buf.as_mut_ptr().cast())
    }
}

/// A datagram socket — the conventional handle for `SIOCETHTOOL`.
fn ethtool_socket() -> Result<OwnedFd, Error> {
    // SAFETY: standard socket() with valid constants.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if raw < 0 {
        return Err(Error::Socket(std::io::Error::last_os_error()));
    }
    // SAFETY: fd is valid, just returned by socket().
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Issue a `SIOCETHTOOL` ioctl pointing `ifr_data` at `cmd` (an ethtool command
/// struct / buffer) for `iface`.
fn ethtool_ioctl(fd: &OwnedFd, iface: &str, cmd: *mut libc::c_void) -> Result<(), Error> {
    if iface.len() >= libc::IFNAMSIZ {
        return Err(Error::Config(format!("interface name too long: {iface}")));
    }
    let mut ifr = ffi::ethtool_ifreq {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_data: cmd,
    };
    for (dst, &b) in ifr.ifr_name.iter_mut().zip(iface.as_bytes()) {
        *dst = b as libc::c_char;
    }
    // SAFETY: `ifr` is a well-formed ifreq whose ifr_data points at a valid
    // ethtool command struct/buffer for the issued sub-command.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), ffi::SIOCETHTOOL, &mut ifr as *mut _) };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Extract the raw errno from an `Error::Io`, if any.
fn io_errno(e: &Error) -> Option<i32> {
    match e {
        Error::Io(io) => io.raw_os_error(),
        _ => None,
    }
}

/// The NIC RSS **Toeplitz** hash of `input` under `key` (MSB-first bit stream),
/// the algorithm every mainstream NIC implements. See [`rss_flow_hash`] for the
/// 4-tuple convenience wrapper.
pub fn toeplitz(key: &[u8], input: &[u8]) -> u32 {
    let mut result = 0u32;
    let mut key_bit = 0usize;
    for &byte in input {
        for i in (0..8).rev() {
            if (byte >> i) & 1 == 1 {
                result ^= key_window(key, key_bit);
            }
            key_bit += 1;
        }
    }
    result
}

/// The 32-bit window of `key` starting at bit `start` (MSB-first), zero-padded
/// past the key end.
fn key_window(key: &[u8], start: usize) -> u32 {
    let mut w = 0u32;
    for i in 0..32 {
        let bit = start + i;
        let byte = bit / 8;
        let off = 7 - (bit % 8);
        let b = key.get(byte).map_or(0, |x| (x >> off) & 1);
        w = (w << 1) | b as u32;
    }
    w
}

/// RSS Toeplitz hash of an IPv4 + TCP/UDP 4-tuple, in the standard field order
/// `src_ip ++ dst_ip ++ src_port ++ dst_port`. With [`SYMMETRIC_RSS_KEY`] (or
/// any `6D5A`-style symmetric key) the result is invariant under swapping
/// `(src) ↔ (dst)` — the property [`RssConfig::set_symmetric`] gives you on the
/// wire.
pub fn rss_flow_hash(
    key: &[u8],
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> u32 {
    let mut input = [0u8; 12];
    input[0..4].copy_from_slice(&src_ip.octets());
    input[4..8].copy_from_slice(&dst_ip.octets());
    input[8..10].copy_from_slice(&src_port.to_be_bytes());
    input[10..12].copy_from_slice(&dst_port.to_be_bytes());
    toeplitz(key, &input)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Microsoft's canonical 40-byte RSS key + its documented test vector.
    const MS_RSS_KEY: [u8; 40] = [
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f,
        0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30,
        0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
    ];

    #[test]
    fn toeplitz_matches_microsoft_test_vector() {
        // The canonical MSDN RSS example: 66.9.149.187:2794 → 161.142.100.80:1766
        // hashes to 0x51ccc178 under the standard key.
        let h = rss_flow_hash(
            &MS_RSS_KEY,
            Ipv4Addr::new(66, 9, 149, 187),
            2794,
            Ipv4Addr::new(161, 142, 100, 80),
            1766,
        );
        assert_eq!(h, 0x51cc_c178, "got {h:#010x}");
    }

    #[test]
    fn symmetric_key_makes_hash_direction_invariant() {
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let b = Ipv4Addr::new(192, 168, 5, 9);
        let fwd = rss_flow_hash(&SYMMETRIC_RSS_KEY, a, 40000, b, 443);
        let rev = rss_flow_hash(&SYMMETRIC_RSS_KEY, b, 443, a, 40000);
        assert_eq!(fwd, rev, "symmetric key must hash both directions equally");
    }

    #[test]
    fn asymmetric_key_splits_directions() {
        // Sanity: the symmetry test is meaningful — the standard MS key does
        // NOT give equal hashes for the two directions.
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let b = Ipv4Addr::new(192, 168, 5, 9);
        let fwd = rss_flow_hash(&MS_RSS_KEY, a, 40000, b, 443);
        let rev = rss_flow_hash(&MS_RSS_KEY, b, 443, a, 40000);
        assert_ne!(fwd, rev, "the default asymmetric key splits the directions");
    }

    #[test]
    fn symmetric_key_is_6d5a_pattern() {
        assert_eq!(SYMMETRIC_RSS_KEY.len(), 40);
        for (i, &b) in SYMMETRIC_RSS_KEY.iter().enumerate() {
            assert_eq!(b, if i % 2 == 0 { 0x6d } else { 0x5a });
        }
    }

    #[test]
    fn ethtool_rxfh_header_is_24_bytes() {
        // Matches the <linux/ethtool.h> layout the kernel expects before the
        // flexible rss_config[] tail.
        assert_eq!(std::mem::size_of::<ffi::ethtool_rxfh>(), 24);
    }
}
