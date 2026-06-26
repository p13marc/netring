//! NIC RX flow steering over the ethtool RX-NFC (ntuple) API (issue #15).
//!
//! Programming the NIC's steering rules pins chosen flows to chosen RX queues —
//! the capability AF_XDP otherwise lacks versus DPDK. A [`FlowRule`] is a typed,
//! validated builder over `struct ethtool_rx_flow_spec`; [`RxSteer`] inserts and
//! removes rules via `SIOCETHTOOL` (the same ioctl plumbing as `queue_count`),
//! and [`SteerGuard`] removes them on drop so a crashed capture doesn't leave
//! stale rules in the NIC.
//!
//! ```no_run
//! use netring::xdp::steer::{FlowRule, RxSteer};
//!
//! let steer = RxSteer::open("eth0")?;
//! // Deliver TCP/443 to RX queue 3, removed when the guard drops.
//! let guard = steer.guarded([FlowRule::tcp().dst_port(443).to_queue(3)])?;
//! // … capture queue 3 with XdpCapture/XdpShardedRunner …
//! # Ok::<(), netring::Error>(())
//! ```
//!
//! **Hardware-gated.** ntuple support, matchable fields, and queue counts vary
//! widely by driver, and inserting a rule needs `CAP_NET_ADMIN`. `lo` and
//! drivers without RX-NFC fail the insert cleanly with `-EOPNOTSUPP` / `-EPERM`.

use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::ffi;
use crate::error::Error;

/// A typed RX flow-steering rule: match a 5-tuple subset, deliver to a queue.
///
/// Build from a protocol constructor ([`tcp`](Self::tcp), [`udp`](Self::udp),
/// [`tcp6`](Self::tcp6), …), narrow with the field setters, then pick a target
/// with [`to_queue`](Self::to_queue) or [`discard`](Self::discard). Unset fields
/// are wildcards. IPv4 constructors reject IPv6 addresses (and vice versa) at
/// insert time.
#[derive(Debug, Clone)]
#[must_use]
pub struct FlowRule {
    flow_type: u32,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    ring_cookie: u64,
    location: u32,
}

impl FlowRule {
    fn new(flow_type: u32) -> Self {
        Self {
            flow_type,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            ring_cookie: 0,
            location: ffi::RX_CLS_LOC_ANY,
        }
    }

    /// Match IPv4 TCP.
    pub fn tcp() -> Self {
        Self::new(ffi::TCP_V4_FLOW)
    }
    /// Match IPv4 UDP.
    pub fn udp() -> Self {
        Self::new(ffi::UDP_V4_FLOW)
    }
    /// Match IPv4 SCTP.
    pub fn sctp() -> Self {
        Self::new(ffi::SCTP_V4_FLOW)
    }
    /// Match IPv6 TCP.
    pub fn tcp6() -> Self {
        Self::new(ffi::TCP_V6_FLOW)
    }
    /// Match IPv6 UDP.
    pub fn udp6() -> Self {
        Self::new(ffi::UDP_V6_FLOW)
    }
    /// Match IPv6 SCTP.
    pub fn sctp6() -> Self {
        Self::new(ffi::SCTP_V6_FLOW)
    }

    /// Match this source address (family must match the constructor).
    pub fn src_ip(mut self, ip: impl Into<IpAddr>) -> Self {
        self.src_ip = Some(ip.into());
        self
    }
    /// Match this destination address (family must match the constructor).
    pub fn dst_ip(mut self, ip: impl Into<IpAddr>) -> Self {
        self.dst_ip = Some(ip.into());
        self
    }
    /// Match this source port.
    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = Some(port);
        self
    }
    /// Match this destination port.
    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    /// Deliver matching packets to RX `queue`.
    pub fn to_queue(mut self, queue: u32) -> Self {
        self.ring_cookie = u64::from(queue);
        self
    }
    /// Drop matching packets in the NIC (`RX_CLS_FLOW_DISC`).
    pub fn discard(mut self) -> Self {
        self.ring_cookie = ffi::RX_CLS_FLOW_DISC;
        self
    }
    /// Request a specific rule slot instead of letting the driver choose.
    pub fn location(mut self, location: u32) -> Self {
        self.location = location;
        self
    }

    /// Pack into an `ethtool_rx_flow_spec`. Field values land in the `h_u`
    /// union at their per-`flow_type` offset; the matching `m_u` mask bytes are
    /// set (`0xff` = match this field), leaving every unset field wildcarded
    /// (`0` = ignore).
    ///
    /// Note: `struct ethtool_rx_flow_spec` (the `ETHTOOL_SRXCLSRL*` ABI used
    /// here) documents `m_u` as "masks for flow field bits to be **matched**" —
    /// a set bit is significant, a clear bit is wildcard. This is the *opposite*
    /// of the older, deprecated `struct ethtool_rx_ntuple_flow_spec`
    /// (`ETHTOOL_SRXNTUPLE`), whose `m_u` documents "bits to be ignored". The
    /// two conventions are easy to conflate; the kernel's
    /// `ethtool_rx_flow_rule_create()` treats a zero mask byte as "skip this
    /// field", confirming set = match for the struct we use.
    fn pack(&self) -> Result<ffi::ethtool_rx_flow_spec, Error> {
        let v6 = matches!(
            self.flow_type,
            ffi::TCP_V6_FLOW | ffi::UDP_V6_FLOW | ffi::SCTP_V6_FLOW
        );
        // (src_ip, dst_ip, src_port, dst_port) offsets in the tcpip4/tcpip6 spec.
        let (dst_off, sport_off, dport_off) = if v6 { (16, 32, 34) } else { (4, 8, 10) };

        let mut h_u = [0u8; 52];
        let mut m_u = [0u8; 52];
        let mut put = |off: usize, bytes: &[u8]| {
            h_u[off..off + bytes.len()].copy_from_slice(bytes);
            m_u[off..off + bytes.len()].fill(0xff);
        };

        if let Some(ip) = self.src_ip {
            put(0, &addr_octets(ip, v6)?);
        }
        if let Some(ip) = self.dst_ip {
            put(dst_off, &addr_octets(ip, v6)?);
        }
        if let Some(p) = self.src_port {
            put(sport_off, &p.to_be_bytes());
        }
        if let Some(p) = self.dst_port {
            put(dport_off, &p.to_be_bytes());
        }

        Ok(ffi::ethtool_rx_flow_spec {
            flow_type: self.flow_type,
            h_u,
            h_ext: [0; 20],
            m_u,
            m_ext: [0; 20],
            ring_cookie: self.ring_cookie,
            location: self.location,
        })
    }
}

/// Return `ip`'s network-order octets, or an error if its family doesn't match
/// the rule's `flow_type`.
fn addr_octets(ip: IpAddr, want_v6: bool) -> Result<Vec<u8>, Error> {
    match (ip, want_v6) {
        (IpAddr::V4(a), false) => Ok(a.octets().to_vec()),
        (IpAddr::V6(a), true) => Ok(a.octets().to_vec()),
        _ => Err(Error::Config(format!(
            "address {ip} family does not match the rule's flow type"
        ))),
    }
}

/// Handle for programming RX flow-steering rules on one interface.
#[derive(Debug)]
pub struct RxSteer {
    iface: String,
    fd: OwnedFd,
}

impl RxSteer {
    /// Open a steering handle for `iface`. The handle is a plain datagram
    /// socket — the conventional `SIOCETHTOOL` carrier — so opening needs no
    /// privileges, but [`insert`](Self::insert) / [`remove`](Self::remove) need
    /// `CAP_NET_ADMIN`.
    pub fn open(iface: &str) -> Result<Self, Error> {
        if iface.len() >= libc::IFNAMSIZ {
            return Err(Error::Config(format!("interface name too long: {iface}")));
        }
        Ok(Self {
            iface: iface.to_string(),
            fd: ethtool_socket()?,
        })
    }

    /// Insert `rule`, returning the rule location the driver assigned (or the
    /// one [`FlowRule::location`] requested). Fails with `-EOPNOTSUPP` on a NIC
    /// without ntuple support and `-EPERM` without `CAP_NET_ADMIN`.
    pub fn insert(&self, rule: &FlowRule) -> Result<u32, Error> {
        let mut nfc = ffi::ethtool_rxnfc {
            cmd: ffi::ETHTOOL_SRXCLSRLINS,
            flow_type: 0,
            data: 0,
            fs: rule.pack()?,
            rule_cnt: 0,
        };
        self.ioctl(&mut nfc)?;
        // The kernel writes the chosen slot back into `fs.location`.
        Ok(nfc.fs.location)
    }

    /// Remove the rule at `location`.
    pub fn remove(&self, location: u32) -> Result<(), Error> {
        let mut nfc = ffi::ethtool_rxnfc {
            cmd: ffi::ETHTOOL_SRXCLSRLDEL,
            flow_type: 0,
            data: 0,
            fs: zeroed_spec(location),
            rule_cnt: 0,
        };
        self.ioctl(&mut nfc)
    }

    /// Number of RX classification rules currently installed.
    pub fn rule_count(&self) -> Result<u32, Error> {
        let mut nfc = ffi::ethtool_rxnfc {
            cmd: ffi::ETHTOOL_GRXCLSRLCNT,
            flow_type: 0,
            data: 0,
            fs: zeroed_spec(0),
            rule_cnt: 0,
        };
        self.ioctl(&mut nfc)?;
        Ok(nfc.rule_cnt)
    }

    /// Insert every rule in `rules` (all-or-nothing) and return a [`SteerGuard`]
    /// that removes them on drop. On any insert failure, already-inserted rules
    /// are rolled back before the error returns.
    pub fn guarded(self, rules: impl IntoIterator<Item = FlowRule>) -> Result<SteerGuard, Error> {
        let mut locations = Vec::new();
        for rule in rules {
            match self.insert(&rule) {
                Ok(loc) => locations.push(loc),
                Err(e) => {
                    for &loc in &locations {
                        let _ = self.remove(loc);
                    }
                    return Err(e);
                }
            }
        }
        Ok(SteerGuard {
            steer: self,
            locations,
        })
    }

    fn ioctl(&self, nfc: &mut ffi::ethtool_rxnfc) -> Result<(), Error> {
        ethtool_ioctl(
            &self.fd,
            &self.iface,
            (nfc as *mut ffi::ethtool_rxnfc).cast(),
        )
    }
}

/// RAII guard that removes its inserted [`FlowRule`]s on drop, mirroring
/// `PromiscGuard`. A hard crash (no unwind) still leaks the rules in the NIC —
/// re-open the interface and remove by location, or `ethtool -N <iface>
/// delete <id>`, to clear them.
#[derive(Debug)]
pub struct SteerGuard {
    steer: RxSteer,
    locations: Vec<u32>,
}

impl SteerGuard {
    /// Locations of the rules this guard owns.
    pub fn locations(&self) -> &[u32] {
        &self.locations
    }
}

impl Drop for SteerGuard {
    fn drop(&mut self) {
        for &loc in &self.locations {
            if let Err(e) = self.steer.remove(loc) {
                tracing::warn!(location = loc, error = %e, "RxSteer: failed to remove rule on drop");
            }
        }
    }
}

/// A zeroed flow spec carrying only `location` — enough for delete / count.
fn zeroed_spec(location: u32) -> ffi::ethtool_rx_flow_spec {
    ffi::ethtool_rx_flow_spec {
        flow_type: 0,
        h_u: [0; 52],
        h_ext: [0; 20],
        m_u: [0; 52],
        m_ext: [0; 20],
        ring_cookie: 0,
        location,
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

/// Issue a `SIOCETHTOOL` ioctl pointing `ifr_data` at `cmd` for `iface`.
fn ethtool_ioctl(fd: &OwnedFd, iface: &str, cmd: *mut libc::c_void) -> Result<(), Error> {
    let mut ifr = ffi::ethtool_ifreq {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_data: cmd,
    };
    for (dst, &b) in ifr.ifr_name.iter_mut().zip(iface.as_bytes()) {
        *dst = b as libc::c_char;
    }
    // SAFETY: `ifr` is a well-formed ifreq whose ifr_data points at a valid
    // ethtool command struct for the issued sub-command.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), ffi::SIOCETHTOOL, &mut ifr as *mut _) };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // h_u union offsets we assert against (IPv4 tcpip4_spec / IPv6 tcpip6_spec).
    fn be16(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }

    #[test]
    fn packs_ipv4_5tuple_with_match_mask() {
        let spec = FlowRule::tcp()
            .src_ip(Ipv4Addr::new(10, 0, 0, 1))
            .dst_ip(Ipv4Addr::new(192, 168, 1, 2))
            .src_port(1234)
            .dst_port(443)
            .to_queue(3)
            .pack()
            .unwrap();

        assert_eq!(spec.flow_type, ffi::TCP_V4_FLOW);
        assert_eq!(&spec.h_u[0..4], &[10, 0, 0, 1]); // ip4src
        assert_eq!(&spec.h_u[4..8], &[192, 168, 1, 2]); // ip4dst
        assert_eq!(&spec.h_u[8..10], &be16(1234)); // psrc
        assert_eq!(&spec.h_u[10..12], &be16(443)); // pdst
        assert_eq!(spec.ring_cookie, 3);
        assert_eq!(spec.location, ffi::RX_CLS_LOC_ANY);

        // Matched bytes have mask 0xff (match this field); everything else is
        // 0 (wildcard / ignore).
        assert_eq!(&spec.m_u[0..12], &[0xffu8; 12]);
        assert!(spec.m_u[12..].iter().all(|&b| b == 0));
    }

    #[test]
    fn unset_fields_are_fully_wildcarded() {
        let spec = FlowRule::udp().dst_port(53).pack().unwrap();
        assert_eq!(spec.flow_type, ffi::UDP_V4_FLOW);
        assert_eq!(&spec.h_u[10..12], &be16(53));
        // Only the dst-port bytes are matched (mask 0xff); the rest is wildcard.
        assert_eq!(&spec.m_u[10..12], &[0xffu8, 0xff]);
        assert!(spec.m_u[0..10].iter().all(|&b| b == 0));
        assert!(spec.m_u[12..].iter().all(|&b| b == 0));
    }

    #[test]
    fn packs_ipv6_at_tcpip6_offsets() {
        let spec = FlowRule::tcp6()
            .dst_ip(Ipv6Addr::LOCALHOST)
            .dst_port(443)
            .pack()
            .unwrap();
        assert_eq!(spec.flow_type, ffi::TCP_V6_FLOW);
        assert_eq!(&spec.h_u[16..32], &Ipv6Addr::LOCALHOST.octets()); // ip6dst
        assert_eq!(&spec.h_u[34..36], &be16(443)); // pdst (tcpip6 offset)
        assert_eq!(&spec.m_u[16..32], &[0xffu8; 16]);
        assert_eq!(&spec.m_u[34..36], &[0xffu8, 0xff]);
    }

    #[test]
    fn discard_sets_disc_cookie() {
        let spec = FlowRule::tcp().dst_port(23).discard().pack().unwrap();
        assert_eq!(spec.ring_cookie, ffi::RX_CLS_FLOW_DISC);
    }

    #[test]
    fn family_mismatch_is_rejected() {
        // IPv6 address on an IPv4 rule (and vice versa) must error, not mis-pack.
        assert!(FlowRule::tcp().dst_ip(Ipv6Addr::LOCALHOST).pack().is_err());
        assert!(FlowRule::tcp6().dst_ip(Ipv4Addr::LOCALHOST).pack().is_err());
    }

    #[test]
    fn lo_insert_degrades_cleanly() {
        // `lo` has no RX-NFC support: the insert must return an error, never
        // panic. Runs unprivileged (EPERM) or with caps (EOPNOTSUPP); skips if
        // the sandbox forbids even opening the carrier socket.
        if let Ok(steer) = RxSteer::open("lo") {
            assert!(
                steer
                    .insert(&FlowRule::tcp().dst_port(443).to_queue(0))
                    .is_err()
            );
        }
    }
}
