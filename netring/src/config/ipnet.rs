//! Minimal IP-network type. Zero external deps — internal use by
//! the typed BPF builder.
//!
//! Intentionally small. Users who need a richer IP-network type
//! (subnet arithmetic, contains, etc.) reach for the
//! [`ipnet`](https://crates.io/crates/ipnet) crate directly. We
//! don't take that dep here to keep netring's tree lean.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// An IP address paired with a network prefix length.
///
/// Construct via [`FromStr`] (`"10.0.0.0/24"`, `"2001:db8::/32"`,
/// or a bare address). Bare addresses default to `/32` for IPv4
/// and `/128` for IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    /// The network address. **The host bits must already be
    /// zeroed** for the prefix to make sense; `FromStr` enforces
    /// this implicitly by masking.
    pub addr: IpAddr,
    /// Prefix length in bits. `0..=32` for IPv4, `0..=128` for IPv6.
    pub prefix: u8,
}

impl IpNet {
    /// Whether this is an IPv4 net.
    pub fn is_ipv4(&self) -> bool {
        matches!(self.addr, IpAddr::V4(_))
    }

    /// Whether this is an IPv6 net.
    pub fn is_ipv6(&self) -> bool {
        matches!(self.addr, IpAddr::V6(_))
    }

    /// Maximum legal prefix for the address family (32 or 128).
    pub fn max_prefix(&self) -> u8 {
        if self.is_ipv4() { 32 } else { 128 }
    }

    /// Returns the network address as a 32-bit big-endian integer
    /// for IPv4, or `None` for IPv6.
    pub(crate) fn as_ipv4_u32(&self) -> Option<u32> {
        match self.addr {
            IpAddr::V4(v4) => Some(u32::from_be_bytes(v4.octets())),
            IpAddr::V6(_) => None,
        }
    }

    /// Returns the IPv4 prefix mask as a 32-bit big-endian integer,
    /// or `None` for IPv6. `0/0` → `0`, `/24` → `0xFFFFFF00`,
    /// `/32` → `0xFFFFFFFF`.
    pub(crate) fn ipv4_mask(&self) -> Option<u32> {
        if !self.is_ipv4() {
            return None;
        }
        Some(prefix_mask_u32(self.prefix))
    }
}

fn prefix_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        // Top `prefix` bits set. Shift logic: 32-prefix zero bits
        // at the bottom.
        u32::MAX << (32 - prefix as u32)
    }
}

/// Errors from [`IpNet::from_str`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseIpNetError {
    /// The address portion didn't parse.
    #[error("invalid IP address: {0}")]
    InvalidAddr(String),

    /// The prefix portion didn't parse as `u8`.
    #[error("invalid prefix length: {0}")]
    InvalidPrefix(String),

    /// Prefix length out of range for the address family
    /// (>32 for IPv4, >128 for IPv6).
    #[error("prefix length {prefix} out of range for {family}")]
    PrefixOutOfRange {
        /// `"IPv4"` or `"IPv6"`.
        family: &'static str,
        /// The supplied prefix length.
        prefix: u8,
    },
}

impl FromStr for IpNet {
    type Err = ParseIpNetError;

    /// Accepts:
    /// - `"10.0.0.0/24"` — IPv4 with explicit prefix
    /// - `"10.0.0.1"` — bare IPv4 (defaults to `/32`)
    /// - `"2001:db8::/32"` — IPv6 with explicit prefix
    /// - `"::1"` — bare IPv6 (defaults to `/128`)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_part
            .parse()
            .map_err(|_| ParseIpNetError::InvalidAddr(addr_part.to_string()))?;
        let prefix = match prefix_part {
            Some(p) => p
                .parse::<u8>()
                .map_err(|_| ParseIpNetError::InvalidPrefix(p.to_string()))?,
            None => match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
        };
        match addr {
            IpAddr::V4(_) if prefix > 32 => {
                return Err(ParseIpNetError::PrefixOutOfRange {
                    family: "IPv4",
                    prefix,
                });
            }
            IpAddr::V6(_) if prefix > 128 => {
                return Err(ParseIpNetError::PrefixOutOfRange {
                    family: "IPv6",
                    prefix,
                });
            }
            _ => {}
        }
        Ok(IpNet { addr, prefix })
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

// `From` shortcuts for common cases.

impl From<Ipv4Addr> for IpNet {
    fn from(addr: Ipv4Addr) -> Self {
        IpNet {
            addr: IpAddr::V4(addr),
            prefix: 32,
        }
    }
}

impl From<Ipv6Addr> for IpNet {
    fn from(addr: Ipv6Addr) -> Self {
        IpNet {
            addr: IpAddr::V6(addr),
            prefix: 128,
        }
    }
}

impl From<IpAddr> for IpNet {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(v) => v.into(),
            IpAddr::V6(v) => v.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_with_prefix() {
        let n: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(n.addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(n.prefix, 24);
        assert!(n.is_ipv4());
    }

    #[test]
    fn parse_bare_ipv4_defaults_to_32() {
        let n: IpNet = "10.0.0.1".parse().unwrap();
        assert_eq!(n.prefix, 32);
    }

    #[test]
    fn parse_ipv6_with_prefix() {
        let n: IpNet = "2001:db8::/32".parse().unwrap();
        assert!(n.is_ipv6());
        assert_eq!(n.prefix, 32);
    }

    #[test]
    fn parse_bare_ipv6_defaults_to_128() {
        let n: IpNet = "::1".parse().unwrap();
        assert_eq!(n.prefix, 128);
    }

    #[test]
    fn rejects_prefix_too_large_v4() {
        let err: ParseIpNetError = "10.0.0.0/33".parse::<IpNet>().unwrap_err();
        assert_eq!(
            err,
            ParseIpNetError::PrefixOutOfRange {
                family: "IPv4",
                prefix: 33,
            }
        );
    }

    #[test]
    fn rejects_prefix_too_large_v6() {
        let err: ParseIpNetError = "::/129".parse::<IpNet>().unwrap_err();
        assert_eq!(
            err,
            ParseIpNetError::PrefixOutOfRange {
                family: "IPv6",
                prefix: 129,
            }
        );
    }

    #[test]
    fn rejects_malformed_addr() {
        assert!(matches!(
            "foo/24".parse::<IpNet>(),
            Err(ParseIpNetError::InvalidAddr(_))
        ));
    }

    #[test]
    fn rejects_malformed_prefix() {
        assert!(matches!(
            "10.0.0.0/abc".parse::<IpNet>(),
            Err(ParseIpNetError::InvalidPrefix(_))
        ));
    }

    #[test]
    fn ipv4_mask_values() {
        assert_eq!(prefix_mask_u32(0), 0x0000_0000);
        assert_eq!(prefix_mask_u32(8), 0xFF00_0000);
        assert_eq!(prefix_mask_u32(24), 0xFFFF_FF00);
        assert_eq!(prefix_mask_u32(32), 0xFFFF_FFFF);
    }

    #[test]
    fn from_ipv4_addr_defaults_to_32() {
        let n: IpNet = Ipv4Addr::new(1, 2, 3, 4).into();
        assert_eq!(n.prefix, 32);
    }

    #[test]
    fn display_round_trip() {
        let n: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(n.to_string(), "10.0.0.0/24");
    }
}
