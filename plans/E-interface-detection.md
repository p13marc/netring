# Phase E: Interface Capability Detection

## Goal

Help users configure rings correctly by querying interface properties: link speed,
MTU, driver name, hardware timestamp support, number of RX/TX queues.

Two tiers:
- **Basic (no extra deps)**: sysfs-based queries — MTU, speed, carrier, queue count
- **Full (feature `nlink`)**: netlink/ethtool via `nlink` crate — ring sizes, HW offloads, channel counts with max values, link mode details

## 1. InterfaceInfo struct

Location: new `src/interface.rs`

```rust
/// Information about a network interface.
///
/// Useful for choosing ring buffer sizes, frame sizes, and fanout thread count.
/// Basic fields are always populated (via sysfs). Extended fields require
/// the `nlink` feature for ethtool netlink queries.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Interface name (e.g., "eth0").
    pub name: String,
    /// Interface index.
    pub index: u32,
    /// Maximum Transmission Unit in bytes (e.g., 1500, 9000 for jumbo).
    pub mtu: u32,
    /// Link speed in Mbps (0 if unknown, e.g., loopback).
    pub speed: u32,
    /// Driver name (e.g., "e1000e", "mlx5_core", "virtio_net").
    /// Empty string if unknown.
    pub driver: String,
    /// Number of combined RX+TX queues (for fanout thread count).
    /// Falls back to counting sysfs queues/ entries.
    pub num_queues: u32,
    /// Whether the interface link is up.
    pub carrier: bool,
    /// Interface flags (IFF_UP, IFF_RUNNING, IFF_PROMISC, etc.).
    pub flags: u32,
    /// Extended info (only populated with `nlink` feature).
    pub extended: Option<ExtendedInterfaceInfo>,
}

/// Extended interface information from ethtool netlink (feature: `nlink`).
#[derive(Debug, Clone)]
pub struct ExtendedInterfaceInfo {
    /// RX ring buffer size (current).
    pub rx_ring_size: u32,
    /// RX ring buffer size (maximum).
    pub rx_ring_max: u32,
    /// TX ring buffer size (current).
    pub tx_ring_size: u32,
    /// TX ring buffer size (maximum).
    pub tx_ring_max: u32,
    /// Number of RX channels/queues (current).
    pub rx_channels: u32,
    /// Number of TX channels/queues (current).
    pub tx_channels: u32,
    /// Number of combined channels (current).
    pub combined_channels: u32,
    /// Maximum combined channels.
    pub combined_channels_max: u32,
    /// Hardware offloads enabled (TSO, GRO, GSO, etc.).
    pub offloads: Vec<String>,
    /// Duplex mode ("full", "half", "unknown").
    pub duplex: String,
    /// Autonegotiation enabled.
    pub autoneg: bool,
}
```

## 2. Basic implementation (sysfs, no deps)

Location: `src/interface.rs`

```rust
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
        extended: None,
    })
}

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
    // Count rx-* entries (each queue has rx-N and tx-N)
    let count = entries.filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_str().map_or(false, |n| n.starts_with("rx-")))
        .count();
    Some(count.max(1) as u32)
}
```

## 3. Extended implementation (nlink feature)

Location: `src/interface.rs`, gated on `#[cfg(feature = "nlink")]`

```toml
# Cargo.toml
[features]
nlink = ["dep:nlink"]

[dependencies]
nlink = { version = "0.9", optional = true }
```

```rust
#[cfg(feature = "nlink")]
/// Query full interface information including ethtool data via netlink.
///
/// Requires the `nlink` feature. Uses `nlink` crate for ethtool generic
/// netlink queries (ring sizes, channels, offloads, link modes).
///
/// This is an async function — requires a tokio runtime.
pub async fn interface_info_full(name: &str) -> Result<InterfaceInfo, Error> {
    // Start with basic sysfs info
    let mut info = interface_info(name)?;

    // Query ethtool via nlink
    let ethtool = nlink::Connection::<nlink::Ethtool>::new().await
        .map_err(|e| Error::Io(e.into()))?;

    let mut extended = ExtendedInterfaceInfo::default();

    // Link modes (speed, duplex, autoneg)
    if let Ok(modes) = ethtool.get_link_modes(name).await {
        info.speed = modes.speed;
        extended.duplex = format!("{:?}", modes.duplex);
        extended.autoneg = modes.autoneg;
    }

    // Ring buffer sizes
    if let Ok(rings) = ethtool.get_rings(name).await {
        extended.rx_ring_size = rings.rx;
        extended.rx_ring_max = rings.rx_max;
        extended.tx_ring_size = rings.tx;
        extended.tx_ring_max = rings.tx_max;
    }

    // Channel/queue counts
    if let Ok(channels) = ethtool.get_channels(name).await {
        extended.rx_channels = channels.rx;
        extended.tx_channels = channels.tx;
        extended.combined_channels = channels.combined;
        extended.combined_channels_max = channels.combined_max;
        // Override sysfs queue count with accurate netlink data
        info.num_queues = channels.combined.max(channels.rx).max(1);
    }

    // Hardware offloads
    if let Ok(features) = ethtool.get_features(name).await {
        extended.offloads = features.active_names();
    }

    info.extended = Some(extended);
    Ok(info)
}
```

Note: the exact nlink API may differ — adapt to the actual `nlink 0.9` types.

## 4. Auto-tuning helpers

```rust
impl InterfaceInfo {
    /// Suggest a ring profile based on interface capabilities.
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
    /// Returns the number of combined queues (or RX queues),
    /// capped at the number of available CPUs.
    pub fn suggest_fanout_threads(&self) -> usize {
        let queues = self.num_queues as usize;
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        queues.min(cpus).max(1)
    }
}
```

## 5. Builder integration

```rust
impl CaptureBuilder {
    /// Query the configured interface and return its capabilities.
    pub fn interface_info(&self) -> Result<InterfaceInfo, Error> {
        let name = self.interface.as_deref()
            .ok_or_else(|| Error::Config("interface not set".into()))?;
        interface_info(name)
    }
}
```

## Tests

- Unit: `interface_info("lo")` returns mtu=65536, speed=0, carrier depends on system
- Unit: `suggest_profile()` for various MTU/speed combos
- Unit: `suggest_fanout_threads()` capped at CPU count
- Integration (nlink feature): `interface_info_full("lo")` returns extended data

## Exports

- `InterfaceInfo`, `ExtendedInterfaceInfo` to `lib.rs`
- `interface_info()` standalone function
- `interface_info_full()` behind `nlink` feature
- Update `docs/API_OVERVIEW.md`, `docs/TUNING_GUIDE.md`, `README.md`
