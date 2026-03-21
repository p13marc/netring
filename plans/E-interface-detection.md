# Phase E: Interface Capability Detection

## Goal

Help users configure rings correctly by querying interface properties: link speed,
MTU, driver name, hardware timestamp support, number of RX/TX queues.

## 1. InterfaceInfo struct

Location: `src/config.rs` (or new `src/interface.rs`)

```rust
/// Information about a network interface.
///
/// Useful for choosing ring buffer sizes, frame sizes, and fanout thread count.
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
    pub driver: String,
    /// Number of combined RX+TX queues (for fanout thread count).
    pub num_queues: u32,
    /// Whether hardware timestamping is supported.
    pub hw_timestamp: bool,
    /// Interface flags (UP, RUNNING, PROMISC, etc.).
    pub flags: u32,
}
```

## 2. Query implementation

Location: `src/afpacket/socket.rs` or `src/interface.rs`

```rust
/// Query interface information.
///
/// # Errors
///
/// Returns [`Error::InterfaceNotFound`] if the interface doesn't exist.
pub fn interface_info(name: &str) -> Result<InterfaceInfo, Error>;
```

### Data sources

| Field | Source | Syscall |
|-------|--------|---------|
| `index` | `if_nametoindex()` | nix |
| `mtu` | `ioctl(SIOCGIFMTU)` | nix ioctl |
| `speed` | `/sys/class/net/{name}/speed` | read file |
| `driver` | `ethtool -i` ioctl (`ETHTOOL_GDRVINFO`) | ioctl |
| `num_queues` | `/sys/class/net/{name}/queues/` dir count, or ethtool | read dir |
| `hw_timestamp` | `ioctl(SIOCETHTOOL, ETHTOOL_GET_TS_INFO)` | ioctl |
| `flags` | `ioctl(SIOCGIFFLAGS)` | nix ioctl |

The sysfs approach (`/sys/class/net/`) is simpler and doesn't need capabilities:

```rust
fn read_sysfs(iface: &str, attr: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/{attr}")).ok()
        .map(|s| s.trim().to_string())
}

// mtu: read_sysfs(name, "mtu")?.parse()
// speed: read_sysfs(name, "speed")?.parse() (returns -1 if unknown)
// operstate: read_sysfs(name, "operstate") ("up", "down")
// driver: std::fs::read_link(format!("/sys/class/net/{name}/device/driver"))
//         .ok()?.file_name()?.to_str()
// num_queues: std::fs::read_dir(format!("/sys/class/net/{name}/queues"))
//             .ok()?.count() / 2  (rx-N + tx-N pairs)
```

For `hw_timestamp`, use ioctl with `ETHTOOL_GET_TS_INFO` if available, else
fall back to `false`.

## 3. Builder integration

```rust
impl CaptureBuilder {
    /// Query the configured interface and return its capabilities.
    ///
    /// Useful for choosing ring profiles based on interface speed/MTU.
    pub fn interface_info(&self) -> Result<InterfaceInfo, Error>;
}
```

Also a standalone function:
```rust
pub fn interface_info(name: &str) -> Result<InterfaceInfo, Error>;
```

## 4. Auto-tuning helper (optional)

```rust
impl InterfaceInfo {
    /// Suggest a ring profile based on interface capabilities.
    pub fn suggest_profile(&self) -> RingProfile {
        if self.mtu > 1500 {
            RingProfile::JumboFrames
        } else if self.speed >= 10_000 { // 10 Gbps+
            RingProfile::HighThroughput
        } else {
            RingProfile::Default
        }
    }

    /// Suggest the number of fanout threads.
    pub fn suggest_fanout_threads(&self) -> usize {
        (self.num_queues as usize).max(1)
    }
}
```

## Tests

- Unit: parse known sysfs values (mock via tempdir if needed)
- Integration: `interface_info("lo")` returns valid data (mtu=65536, speed=0)
- Unit: suggest_profile for various MTU/speed combos

## Exports

- `InterfaceInfo` to `lib.rs` re-exports
- `interface_info()` standalone function
- Update `docs/API_OVERVIEW.md` and `docs/TUNING_GUIDE.md`
- Update `README.md` with auto-tuning example
