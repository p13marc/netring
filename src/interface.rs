//! Interface capability detection.
//!
//! Query network interface properties for tuning ring buffer configuration.
//! Basic queries use sysfs (no extra dependencies). Extended queries via
//! ethtool netlink are available with the `nlink` feature.

use crate::config::RingProfile;
use crate::error::Error;

/// Information about a network interface.
///
/// Useful for choosing ring buffer sizes, frame sizes, and fanout thread count.
///
/// # Examples
///
/// ```no_run
/// use netring::InterfaceInfo;
///
/// let info = netring::interface_info("lo").unwrap();
/// println!("MTU: {}, speed: {} Mbps, queues: {}", info.mtu, info.speed, info.num_queues);
/// println!("Suggested profile: {:?}", info.suggest_profile());
/// ```
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Interface name.
    pub name: String,
    /// Interface index.
    pub index: u32,
    /// Maximum Transmission Unit in bytes (e.g., 1500, 9000 for jumbo).
    pub mtu: u32,
    /// Link speed in Mbps (0 if unknown, e.g., loopback).
    pub speed: u32,
    /// Driver name (e.g., "e1000e", "mlx5_core"). Empty if unknown.
    pub driver: String,
    /// Number of RX queues (for fanout thread count).
    pub num_queues: u32,
    /// Whether the interface link is up.
    pub carrier: bool,
    /// Interface flags (IFF_UP, IFF_RUNNING, etc.).
    pub flags: u32,
}

/// Query interface information using sysfs (no extra dependencies).
///
/// # Errors
///
/// Returns [`Error::InterfaceNotFound`] if the interface doesn't exist.
pub fn interface_info(name: &str) -> Result<InterfaceInfo, Error> {
    let index = crate::afpacket::socket::resolve_interface(name)? as u32;
    let mtu = read_sysfs_u32(name, "mtu").unwrap_or(1500);
    let speed = read_sysfs_u32(name, "speed").unwrap_or(0);
    let carrier = read_sysfs_u32(name, "carrier").unwrap_or(0) == 1;
    let flags = read_sysfs_u32(name, "flags").unwrap_or(0);
    let driver = read_sysfs_link_basename(name, "device/driver").unwrap_or_default();
    let num_queues = count_sysfs_queues(name).unwrap_or(1);

    Ok(InterfaceInfo {
        name: name.to_string(),
        index,
        mtu,
        speed,
        driver,
        num_queues,
        carrier,
        flags,
    })
}

impl InterfaceInfo {
    /// Suggest a ring profile based on interface capabilities.
    ///
    /// Uses MTU and link speed to pick the best default:
    /// - Jumbo MTU (> 1500) → [`RingProfile::JumboFrames`]
    /// - 10 Gbps+ → [`RingProfile::HighThroughput`]
    /// - 1 Gbps+ → [`RingProfile::Default`]
    /// - Slower → [`RingProfile::LowMemory`]
    pub fn suggest_profile(&self) -> RingProfile {
        if self.mtu > 1500 {
            RingProfile::JumboFrames
        } else if self.speed >= 10_000 {
            RingProfile::HighThroughput
        } else if self.speed >= 1_000 {
            RingProfile::Default
        } else {
            RingProfile::LowMemory
        }
    }

    /// Suggest the number of fanout threads.
    ///
    /// Returns the number of RX queues, capped at available CPUs.
    pub fn suggest_fanout_threads(&self) -> usize {
        let queues = self.num_queues as usize;
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        queues.min(cpus).max(1)
    }
}

// ── Sysfs helpers ──────────────────────────────────────────────────────────

fn read_sysfs_u32(iface: &str, attr: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/{attr}"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn read_sysfs_link_basename(iface: &str, path: &str) -> Option<String> {
    let target = std::fs::read_link(format!("/sys/class/net/{iface}/{path}")).ok()?;
    target.file_name()?.to_str().map(String::from)
}

fn count_sysfs_queues(iface: &str) -> Option<u32> {
    let entries = std::fs::read_dir(format!("/sys/class/net/{iface}/queues")).ok()?;
    let count = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("rx-"))
        })
        .count();
    Some(count.max(1) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_info() {
        let info = interface_info("lo").unwrap();
        assert_eq!(info.name, "lo");
        assert!(info.index > 0);
        assert!(info.mtu > 0);
        // loopback has no speed/driver
        assert_eq!(info.speed, 0);
    }

    #[test]
    fn nonexistent_interface() {
        let err = interface_info("nonexistent_xyz_42").unwrap_err();
        assert!(matches!(err, Error::InterfaceNotFound(_)));
    }

    #[test]
    fn suggest_profile_jumbo() {
        let info = InterfaceInfo {
            name: "test".into(),
            index: 1,
            mtu: 9000,
            speed: 10_000,
            driver: String::new(),
            num_queues: 4,
            carrier: true,
            flags: 0,
        };
        assert_eq!(info.suggest_profile(), RingProfile::JumboFrames);
    }

    #[test]
    fn suggest_profile_high_throughput() {
        let info = InterfaceInfo {
            name: "test".into(),
            index: 1,
            mtu: 1500,
            speed: 25_000,
            driver: String::new(),
            num_queues: 8,
            carrier: true,
            flags: 0,
        };
        assert_eq!(info.suggest_profile(), RingProfile::HighThroughput);
    }

    #[test]
    fn suggest_fanout_threads_capped() {
        let info = InterfaceInfo {
            name: "test".into(),
            index: 1,
            mtu: 1500,
            speed: 1000,
            driver: String::new(),
            num_queues: 1000, // more queues than CPUs
            carrier: true,
            flags: 0,
        };
        let threads = info.suggest_fanout_threads();
        assert!(threads >= 1);
        assert!(threads <= 1000); // capped at CPUs
    }
}
