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
    /// The driver's `RXH_XFRM_SYM_XOR` input transform (kernel ≥ 6.8),
    /// confirmed by reading the configuration back. The indirection table,
    /// hash function and key are left untouched.
    SymXor,
    /// The Toeplitz hash function with the symmetric key
    /// ([`SYMMETRIC_RSS_KEY`], repeated to the NIC's key length) — the
    /// fallback when `SYM_XOR` is unsupported; confirmed by reading the
    /// hash function and key back.
    SymmetricKey,
}

/// A NIC's RSS hash configuration (`ETHTOOL_GRSSH`), as read by
/// [`RssConfig::state`]: what [`RssGuard`] restores.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct RssState {
    /// Hash function (`ETH_RSS_HASH_*` bit: 1 = Toeplitz, 2 = XOR,
    /// 4 = CRC32; 0 when the driver does not report it).
    pub hfunc: u8,
    /// Input transform (`RXH_XFRM_*`: bit 0 = `SYM_XOR`, bit 1 =
    /// `SYM_OR_XOR`).
    pub input_xfrm: u8,
    /// The hash key (empty when the driver has none / reports none).
    pub key: Vec<u8>,
    /// Entries in the indirection table (left untouched by netring).
    pub indir_size: u32,
}

impl RssState {
    /// Whether the input transform makes the hash symmetric.
    pub fn is_symmetric_xfrm(&self) -> bool {
        self.input_xfrm & (ffi::RXH_XFRM_SYM_XOR | ffi::RXH_XFRM_SYM_OR_XOR) != 0
    }
}

/// The RSS configuration interface: `SIOCETHTOOL` on a real interface, a
/// fake NIC in the tests.
pub(crate) trait RssDevice {
    /// `ETHTOOL_GRSSH`: sizes, hash function, input transform and — with
    /// `with_key` — the key.
    fn get(&self, with_key: bool) -> Result<RssState, Error>;
    /// `ETHTOOL_SRSSH` with the indirection table unchanged: `hfunc` /
    /// `xfrm` may be the `NO_CHANGE` sentinels; `key` replaces the key.
    fn set(&self, hfunc: u8, xfrm: u8, key: Option<&[u8]>) -> Result<(), Error>;
}

/// [`RssDevice`] over `SIOCETHTOOL`.
struct EthtoolRss {
    iface: String,
}

impl RssDevice for EthtoolRss {
    fn get(&self, with_key: bool) -> Result<RssState, Error> {
        let fd = ethtool_socket()?;
        // Size query: indir_size = key_size = 0 returns the sizes, the hash
        // function and the input transform.
        let mut rxfh = ffi::ethtool_rxfh {
            cmd: ffi::ETHTOOL_GRSSH,
            ..Default::default()
        };
        ethtool_ioctl(
            &fd,
            &self.iface,
            (&mut rxfh as *mut ffi::ethtool_rxfh).cast(),
        )?;
        let mut state = RssState {
            hfunc: rxfh.hfunc,
            input_xfrm: rxfh.input_xfrm,
            key: Vec::new(),
            indir_size: rxfh.indir_size,
        };
        let key_size = rxfh.key_size as usize;
        if with_key && key_size > 0 {
            // Key query: the key lands right after the header (no table
            // requested: indir_size = 0).
            let mut buf = grssh_key_buffer(key_size);
            ethtool_ioctl(&fd, &self.iface, buf.as_mut_ptr().cast())?;
            let header = std::mem::size_of::<ffi::ethtool_rxfh>();
            // SAFETY: the buffer starts with an `ethtool_rxfh` header.
            let hdr = unsafe { buf.as_ptr().cast::<ffi::ethtool_rxfh>().read_unaligned() };
            state.hfunc = hdr.hfunc;
            state.input_xfrm = hdr.input_xfrm;
            state.key = buf[header..header + key_size].to_vec();
        }
        Ok(state)
    }

    fn set(&self, hfunc: u8, xfrm: u8, key: Option<&[u8]>) -> Result<(), Error> {
        let mut buf = srssh_buffer(hfunc, xfrm, key);
        let fd = ethtool_socket()?;
        ethtool_ioctl(&fd, &self.iface, buf.as_mut_ptr().cast())
    }
}

/// The `ETHTOOL_SRSSH` buffer: the 24-byte `ethtool_rxfh` header with the
/// indirection table unchanged, followed by the key. With `indir_size =
/// ETH_RXFH_INDIR_NO_CHANGE` the kernel reads the key right after the header
/// (v6.12 net/ethtool/ioctl.c ethtool_set_rxfh(): `useraddr + rss_cfg_offset
/// + user_indir_len`, `user_indir_len` = 0 without a table).
fn srssh_buffer(hfunc: u8, xfrm: u8, key: Option<&[u8]>) -> Vec<u8> {
    let key = key.unwrap_or(&[]);
    let header = std::mem::size_of::<ffi::ethtool_rxfh>();
    let mut buf = vec![0u8; header + key.len()];
    let hdr = ffi::ethtool_rxfh {
        cmd: ffi::ETHTOOL_SRSSH,
        indir_size: ffi::ETH_RXFH_INDIR_NO_CHANGE,
        key_size: key.len() as u32,
        hfunc,
        input_xfrm: xfrm,
        ..Default::default()
    };
    // SAFETY: `buf` holds at least `header` bytes; the header is POD,
    // written unaligned.
    unsafe {
        buf.as_mut_ptr()
            .cast::<ffi::ethtool_rxfh>()
            .write_unaligned(hdr)
    };
    buf[header..].copy_from_slice(key);
    buf
}

/// The `ETHTOOL_GRSSH` buffer asking for the key only.
fn grssh_key_buffer(key_size: usize) -> Vec<u8> {
    let header = std::mem::size_of::<ffi::ethtool_rxfh>();
    let mut buf = vec![0u8; header + key_size];
    let hdr = ffi::ethtool_rxfh {
        cmd: ffi::ETHTOOL_GRSSH,
        indir_size: 0,
        key_size: key_size as u32,
        ..Default::default()
    };
    // SAFETY: as in `srssh_buffer`.
    unsafe {
        buf.as_mut_ptr()
            .cast::<ffi::ethtool_rxfh>()
            .write_unaligned(hdr)
    };
    buf
}

/// [`SYMMETRIC_RSS_KEY`]'s `6D 5A` pattern, repeated to `len` bytes.
fn symmetric_key(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| SYMMETRIC_RSS_KEY[i % SYMMETRIC_RSS_KEY.len()])
        .collect()
}

/// Whether an SRSSH error means "this request is not supported".
fn unsupported(e: &Error) -> bool {
    matches!(io_errno(e), Some(libc::EOPNOTSUPP) | Some(libc::EINVAL))
}

/// Configure a NIC's RSS hashing for bidirectional-flow coherence.
#[derive(Debug, Clone)]
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

    fn device(&self) -> EthtoolRss {
        EthtoolRss {
            iface: self.iface.clone(),
        }
    }

    /// The NIC's current RSS hash configuration: hash function, input
    /// transform, key and indirection-table size (`ETHTOOL_GRSSH`, twice:
    /// sizes, then the key).
    pub fn state(&self) -> Result<RssState, Error> {
        self.device().get(true)
    }

    /// Make the NIC hash `A→B` and `B→A` to the **same** RX queue, and hand
    /// back a guard that puts the previous configuration back.
    ///
    /// 1. Snapshot the configuration ([`state`](Self::state)).
    /// 2. Try `RXH_XFRM_SYM_XOR`; accept it only if reading the
    ///    configuration back shows a symmetric transform (`SYM_XOR` or
    ///    `SYM_OR_XOR`) — a driver may take the request and not apply it.
    /// 3. Otherwise set the **Toeplitz** hash function with
    ///    [`SYMMETRIC_RSS_KEY`] repeated to the NIC's key length: the key
    ///    makes only Toeplitz symmetric, so a NIC that stays on XOR / CRC32
    ///    (rejects Toeplitz) is an error, not a silent success (#213). The
    ///    result is read back; a hash function or key that did not take is
    ///    an error, after restoring the snapshot.
    ///
    /// Errors (rather than warns) when the NIC cannot be made symmetric, so
    /// a sharded deployment never *silently* runs with split flows. The
    /// returned [`RssGuard`] restores the snapshot when dropped; call
    /// [`RssGuard::persist`] to keep the symmetric configuration instead.
    pub fn set_symmetric(&self) -> Result<RssGuard, Error> {
        set_symmetric_on(Box::new(self.device()), &self.iface)
    }

    /// Read the current RSS key size (bytes) via `ETHTOOL_GRSSH`. `0` means the
    /// driver reports no resizable key.
    pub fn key_size(&self) -> Result<u32, Error> {
        let (_, key_size, _) = self.grssh_sizes()?;
        Ok(key_size)
    }

    /// `true` if the active RSS input transform is symmetric (`SYM_XOR` or
    /// `SYM_OR_XOR`).
    pub fn is_symmetric_xfrm(&self) -> Result<bool, Error> {
        Ok(self.device().get(false)?.is_symmetric_xfrm())
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
}

/// The body of [`RssConfig::set_symmetric`], over any [`RssDevice`].
fn set_symmetric_on(dev: Box<dyn RssDevice + Send + Sync>, iface: &str) -> Result<RssGuard, Error> {
    let previous = dev.get(true)?;
    let guard = |dev, previous, mode| RssGuard {
        iface: iface.to_string(),
        previous,
        mode,
        armed: true,
        dev: Some(dev),
    };

    // 1. The SYM_XOR input transform, confirmed by reading it back.
    match dev.set(ffi::ETH_RSS_HASH_NO_CHANGE, ffi::RXH_XFRM_SYM_XOR, None) {
        Ok(()) => {
            if dev.get(false)?.is_symmetric_xfrm() {
                return Ok(guard(dev, previous, RssMode::SymXor));
            }
            // Accepted but not applied: put the transform back before
            // trying the key.
            tracing::warn!(
                iface,
                "RSS SYM_XOR accepted but not applied; trying the symmetric key"
            );
            dev.set(ffi::ETH_RSS_HASH_NO_CHANGE, previous.input_xfrm, None)?;
        }
        Err(e) if unsupported(&e) => {}
        Err(e) => return Err(e),
    }

    // 2. Toeplitz + the symmetric key.
    if previous.key.is_empty() {
        return Err(Error::Config(format!(
            "interface {iface} reports no settable RSS key and no SYM_XOR support"
        )));
    }
    let key = symmetric_key(previous.key.len());
    match dev.set(ffi::ETH_RSS_HASH_TOP, ffi::RXH_XFRM_NO_CHANGE, Some(&key)) {
        Ok(()) => {}
        // Some drivers refuse any hash-function request; on Toeplitz
        // already, the key alone is enough.
        Err(e) if unsupported(&e) && previous.hfunc == ffi::ETH_RSS_HASH_TOP => {
            dev.set(
                ffi::ETH_RSS_HASH_NO_CHANGE,
                ffi::RXH_XFRM_NO_CHANGE,
                Some(&key),
            )?;
        }
        Err(e) if unsupported(&e) => {
            return Err(Error::Config(format!(
                "interface {iface} is not Toeplitz-capable (RSS hash function {:#x}, \
                 Toeplitz refused: {e}) and has no SYM_XOR: its RSS cannot be made symmetric",
                previous.hfunc
            )));
        }
        Err(e) => return Err(e),
    }
    let now = dev.get(true)?;
    if now.hfunc != ffi::ETH_RSS_HASH_TOP || now.key != key {
        let restored = restore_state(dev.as_ref(), &previous, RssMode::SymmetricKey);
        return Err(Error::Config(format!(
            "interface {iface}: the symmetric RSS key did not take (read back hash \
             function {:#x}, key {}); previous configuration {}",
            now.hfunc,
            if now.key == key {
                "as set"
            } else {
                "different"
            },
            match restored {
                Ok(()) => "restored".to_string(),
                Err(e) => format!("NOT restored: {e}"),
            },
        )));
    }
    Ok(guard(dev, previous, RssMode::SymmetricKey))
}

/// Put `previous` back after `mode` changed it.
fn restore_state(dev: &dyn RssDevice, previous: &RssState, mode: RssMode) -> Result<(), Error> {
    match mode {
        RssMode::SymXor => dev.set(ffi::ETH_RSS_HASH_NO_CHANGE, previous.input_xfrm, None),
        RssMode::SymmetricKey => {
            // The key path set Toeplitz: ask for the previous hash function
            // only when it was another one. A driver already on Toeplitz may
            // refuse every hash-function request (the key-only class
            // `set_symmetric` supports) — restore it with the key alone.
            let hfunc = match previous.hfunc {
                0 | ffi::ETH_RSS_HASH_TOP => ffi::ETH_RSS_HASH_NO_CHANGE,
                h => h,
            };
            let key = (!previous.key.is_empty()).then_some(previous.key.as_slice());
            match dev.set(hfunc, ffi::RXH_XFRM_NO_CHANGE, key) {
                Err(e) if unsupported(&e) && hfunc != ffi::ETH_RSS_HASH_NO_CHANGE => {
                    // The previous hash function can't be asked for: put the
                    // key back at least, and say so.
                    dev.set(ffi::ETH_RSS_HASH_NO_CHANGE, ffi::RXH_XFRM_NO_CHANGE, key)?;
                    Err(e)
                }
                res => res,
            }
        }
    }
}

/// The symmetric RSS configuration [`RssConfig::set_symmetric`] applied,
/// and the configuration it replaced.
///
/// Dropping the guard restores the previous configuration (best-effort; a
/// failure is logged at `warn`). Call [`persist`](Self::persist) to keep the
/// symmetric configuration after the guard goes, or
/// [`restore`](Self::restore) to restore with error reporting.
#[must_use = "dropping the guard restores the previous RSS configuration"]
pub struct RssGuard {
    iface: String,
    previous: RssState,
    mode: RssMode,
    armed: bool,
    dev: Option<Box<dyn RssDevice + Send + Sync>>,
}

impl RssGuard {
    /// How symmetry was achieved.
    pub fn mode(&self) -> RssMode {
        self.mode
    }

    /// The configuration before [`RssConfig::set_symmetric`].
    pub fn previous(&self) -> &RssState {
        &self.previous
    }

    /// Keep the symmetric configuration: the guard no longer restores.
    pub fn persist(mut self) -> RssMode {
        self.armed = false;
        self.mode
    }

    /// Restore the previous configuration now, reporting failure.
    pub fn restore(mut self) -> Result<(), Error> {
        self.armed = false;
        match &self.dev {
            Some(dev) => restore_state(dev.as_ref(), &self.previous, self.mode),
            None => Ok(()),
        }
    }
}

impl std::fmt::Debug for RssGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RssGuard")
            .field("iface", &self.iface)
            .field("mode", &self.mode)
            .field("previous", &self.previous)
            .field("armed", &self.armed)
            .finish()
    }
}

impl Drop for RssGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(dev) = &self.dev
            && let Err(e) = restore_state(dev.as_ref(), &self.previous, self.mode)
        {
            tracing::warn!(iface = %self.iface, error = %e, "could not restore the previous RSS configuration");
        }
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
    let mut ifr = ffi::ethtool_ifreq::new(iface, cmd)?;
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

    // ── set_symmetric against a fake NIC (#213) ───────────────────────

    use std::sync::{Arc, Mutex};

    /// A NIC model: its RSS state plus what its driver supports.
    #[derive(Debug, Clone)]
    struct Nic {
        state: RssState,
        /// `SYM_XOR` accepted (and applied unless `ignore_xfrm`).
        sym_xor: bool,
        ignore_xfrm: bool,
        /// Hash functions the driver accepts on SRSSH.
        hfuncs: u8,
        /// Accept a key but keep only its first half (a lying driver).
        mangle_key: bool,
        sets: usize,
    }

    #[derive(Clone)]
    struct FakeNic(Arc<Mutex<Nic>>);

    impl FakeNic {
        fn new(hfunc: u8, sym_xor: bool, hfuncs: u8) -> Self {
            Self(Arc::new(Mutex::new(Nic {
                state: RssState {
                    hfunc,
                    input_xfrm: 0,
                    key: (0u8..52).collect(),
                    indir_size: 128,
                },
                sym_xor,
                ignore_xfrm: false,
                hfuncs,
                mangle_key: false,
                sets: 0,
            })))
        }

        fn state(&self) -> RssState {
            self.0.lock().unwrap().state.clone()
        }

        fn with(self, f: impl FnOnce(&mut Nic)) -> Self {
            f(&mut self.0.lock().unwrap());
            self
        }
    }

    fn errno(e: i32) -> Error {
        Error::Io(std::io::Error::from_raw_os_error(e))
    }

    impl RssDevice for FakeNic {
        fn get(&self, with_key: bool) -> Result<RssState, Error> {
            let mut s = self.state();
            if !with_key {
                s.key.clear();
            }
            Ok(s)
        }

        fn set(&self, hfunc: u8, xfrm: u8, key: Option<&[u8]>) -> Result<(), Error> {
            let mut nic = self.0.lock().unwrap();
            nic.sets += 1;
            if xfrm != ffi::RXH_XFRM_NO_CHANGE && xfrm & ffi::RXH_XFRM_SYM_XOR != 0 && !nic.sym_xor
            {
                return Err(errno(libc::EOPNOTSUPP));
            }
            if hfunc != ffi::ETH_RSS_HASH_NO_CHANGE && hfunc & nic.hfuncs == 0 {
                return Err(errno(libc::EOPNOTSUPP));
            }
            if let Some(k) = key
                && k.len() != nic.state.key.len()
            {
                return Err(errno(libc::EINVAL));
            }
            if xfrm != ffi::RXH_XFRM_NO_CHANGE && !nic.ignore_xfrm {
                nic.state.input_xfrm = xfrm;
            }
            if hfunc != ffi::ETH_RSS_HASH_NO_CHANGE {
                nic.state.hfunc = hfunc;
            }
            if let Some(k) = key {
                let mut k = k.to_vec();
                if nic.mangle_key {
                    let half = k.len() / 2;
                    k[half..].fill(0);
                }
                nic.state.key = k;
            }
            Ok(())
        }
    }

    fn set_symmetric(nic: &FakeNic) -> Result<RssGuard, Error> {
        set_symmetric_on(Box::new(nic.clone()), "fake0")
    }

    #[test]
    fn sym_xor_is_accepted_when_it_reads_back() {
        let nic = FakeNic::new(ffi::ETH_RSS_HASH_TOP, true, ffi::ETH_RSS_HASH_TOP);
        let before = nic.state();
        let g = set_symmetric(&nic).expect("SYM_XOR");
        assert_eq!(g.mode(), RssMode::SymXor);
        assert_eq!(g.previous(), &before);
        assert_eq!(nic.state().input_xfrm, ffi::RXH_XFRM_SYM_XOR);
        assert_eq!(nic.state().key, before.key, "the key is untouched");
        drop(g);
        assert_eq!(nic.state(), before, "dropping the guard restores");
    }

    /// No SYM_XOR, a NIC on XOR that can do Toeplitz: the key path sets
    /// Toeplitz **and** the key (0.31 left hfunc unchanged, so on XOR /
    /// CRC32 the key made nothing symmetric while returning Ok).
    #[test]
    fn rejected_sym_xor_takes_the_key_path_with_toeplitz() {
        let all = ffi::ETH_RSS_HASH_TOP | ffi::ETH_RSS_HASH_XOR | ffi::ETH_RSS_HASH_CRC32;
        let nic = FakeNic::new(ffi::ETH_RSS_HASH_XOR, false, all);
        let before = nic.state();
        let g = set_symmetric(&nic).expect("Toeplitz + key");
        assert_eq!(g.mode(), RssMode::SymmetricKey);
        let now = nic.state();
        assert_eq!(now.hfunc, ffi::ETH_RSS_HASH_TOP);
        assert_eq!(now.key.len(), 52, "the NIC's own key length");
        assert_eq!(now.key, symmetric_key(52));
        assert!(now.key.chunks(2).all(|c| c == [0x6d, 0x5a]));
        assert_eq!(g.restore().map_err(|e| e.to_string()), Ok(()));
        assert_eq!(nic.state(), before, "hash function and key restored");
    }

    #[test]
    fn sym_xor_accepted_but_not_applied_falls_back_to_the_key() {
        let nic = FakeNic::new(ffi::ETH_RSS_HASH_TOP, true, ffi::ETH_RSS_HASH_TOP)
            .with(|n| n.ignore_xfrm = true);
        let g = set_symmetric(&nic).expect("key fallback");
        assert_eq!(g.mode(), RssMode::SymmetricKey);
        assert_eq!(nic.state().key, symmetric_key(52));
        let _ = g.persist();
    }

    #[test]
    fn a_nic_that_refuses_toeplitz_is_an_error() {
        let nic = FakeNic::new(ffi::ETH_RSS_HASH_CRC32, false, ffi::ETH_RSS_HASH_CRC32);
        let before = nic.state();
        let err = set_symmetric(&nic).expect_err("CRC32-only NIC").to_string();
        assert!(err.contains("not Toeplitz-capable"), "{err}");
        assert_eq!(nic.state(), before, "nothing changed");
    }

    /// A driver already on Toeplitz that refuses any hash-function request:
    /// the key alone makes it symmetric — and the key alone restores it
    /// (review r1: the restore asked for the previous hash function, which
    /// such a driver refuses, and left the symmetric key in place).
    #[test]
    fn toeplitz_nic_refusing_hfunc_requests_takes_the_key_alone() {
        let nic = FakeNic::new(ffi::ETH_RSS_HASH_TOP, false, 0);
        let before = nic.state();
        let g = set_symmetric(&nic).expect("key only");
        assert_eq!(g.mode(), RssMode::SymmetricKey);
        assert_eq!(nic.state().key, symmetric_key(52));
        assert_eq!(nic.state().hfunc, ffi::ETH_RSS_HASH_TOP);
        assert_eq!(g.restore().map_err(|e| e.to_string()), Ok(()));
        assert_eq!(nic.state(), before, "the key is restored");
        // The drop path too.
        drop(set_symmetric(&nic).expect("key only"));
        assert_eq!(nic.state(), before);
    }

    #[test]
    fn a_key_that_does_not_read_back_is_an_error_and_restored() {
        let nic = FakeNic::new(ffi::ETH_RSS_HASH_TOP, false, ffi::ETH_RSS_HASH_TOP)
            .with(|n| n.mangle_key = true);
        let before = nic.state();
        let err = set_symmetric(&nic).expect_err("mangled key").to_string();
        assert!(
            err.contains("did not take") && err.contains("restored"),
            "{err}"
        );
        // The restore itself goes through the same mangling driver, but the
        // hash function and the (first half of the) key are back.
        let now = nic.state();
        assert_eq!(now.hfunc, before.hfunc);
        assert_eq!(now.key[..26], before.key[..26]);
    }

    #[test]
    fn drop_restores_and_persist_keeps() {
        let nic = FakeNic::new(ffi::ETH_RSS_HASH_TOP, true, ffi::ETH_RSS_HASH_TOP);
        let before = nic.state();
        drop(set_symmetric(&nic).unwrap());
        assert_eq!(nic.state(), before);
        let mode = set_symmetric(&nic).unwrap().persist();
        assert_eq!(mode, RssMode::SymXor);
        assert_eq!(nic.state().input_xfrm, ffi::RXH_XFRM_SYM_XOR, "kept");
    }

    #[test]
    fn no_key_and_no_sym_xor_is_an_error() {
        let nic = FakeNic::new(ffi::ETH_RSS_HASH_TOP, false, ffi::ETH_RSS_HASH_TOP)
            .with(|n| n.state.key.clear());
        let err = set_symmetric(&nic).expect_err("nothing to set").to_string();
        assert!(err.contains("no settable RSS key"), "{err}");
    }

    #[test]
    fn rss_state_symmetry_covers_both_transforms() {
        let mut s = RssState::default();
        assert!(!s.is_symmetric_xfrm());
        s.input_xfrm = ffi::RXH_XFRM_SYM_XOR;
        assert!(s.is_symmetric_xfrm());
        s.input_xfrm = ffi::RXH_XFRM_SYM_OR_XOR;
        assert!(s.is_symmetric_xfrm());
    }

    #[test]
    fn rss_constants_match_the_uapi() {
        assert_eq!(ffi::ETH_RSS_HASH_TOP, 1);
        assert_eq!(ffi::ETH_RSS_HASH_XOR, 2);
        assert_eq!(ffi::ETH_RSS_HASH_CRC32, 4);
        assert_eq!(ffi::RXH_XFRM_SYM_XOR, 1);
        assert_eq!(ffi::RXH_XFRM_SYM_OR_XOR, 2);
        assert_eq!(ffi::RXH_XFRM_NO_CHANGE, 0xff);
        assert_eq!(ffi::ETH_RSS_HASH_NO_CHANGE, 0);
        assert_eq!(ffi::ETHTOOL_GRSSH, 0x46);
        assert_eq!(ffi::ETHTOOL_SRSSH, 0x47);
    }

    /// The SRSSH buffer: header (table unchanged), then the key right
    /// after it — where the kernel reads it without a table.
    #[test]
    fn srssh_buffer_layout() {
        let key = symmetric_key(52);
        let buf = srssh_buffer(ffi::ETH_RSS_HASH_TOP, ffi::RXH_XFRM_NO_CHANGE, Some(&key));
        assert_eq!(buf.len(), 24 + 52);
        let u32_at = |o: usize| u32::from_ne_bytes(buf[o..o + 4].try_into().unwrap());
        assert_eq!(u32_at(0), ffi::ETHTOOL_SRSSH, "cmd");
        assert_eq!(u32_at(4), 0, "rss_context");
        assert_eq!(u32_at(8), ffi::ETH_RXFH_INDIR_NO_CHANGE, "indir_size");
        assert_eq!(u32_at(12), 52, "key_size");
        assert_eq!(buf[16], ffi::ETH_RSS_HASH_TOP, "hfunc");
        assert_eq!(buf[17], ffi::RXH_XFRM_NO_CHANGE, "input_xfrm");
        assert_eq!(&buf[18..24], &[0; 6], "reserved fields must be 0");
        assert_eq!(&buf[24..], &key[..]);

        let xor = srssh_buffer(ffi::ETH_RSS_HASH_NO_CHANGE, ffi::RXH_XFRM_SYM_XOR, None);
        assert_eq!(xor.len(), 24);
        assert_eq!(xor[16..18], [0, 1]);

        let get = grssh_key_buffer(40);
        assert_eq!(get.len(), 24 + 40);
        assert_eq!(
            u32::from_ne_bytes(get[0..4].try_into().unwrap()),
            ffi::ETHTOOL_GRSSH
        );
        assert_eq!(
            u32::from_ne_bytes(get[8..12].try_into().unwrap()),
            0,
            "no table"
        );
        assert_eq!(u32::from_ne_bytes(get[12..16].try_into().unwrap()), 40);
    }

    #[test]
    fn ethtool_rxfh_header_is_24_bytes() {
        // Matches the <linux/ethtool.h> layout the kernel expects before the
        // flexible rss_config[] tail.
        assert_eq!(std::mem::size_of::<ffi::ethtool_rxfh>(), 24);
    }
}
