//! Declarative backend selection (issue #106) — the ergonomic capstone over
//! the 0.26 multi-queue work.
//!
//! Instead of hand-picking among `interface` (AF_PACKET), `xdp_interface`,
//! `xdp_interface_loaded`, `xdp_queues`, and `XdpShardedRunner`, a user writes
//! one declarative line:
//!
//! ```ignore
//! Monitor::builder()
//!     .capture("eth0", Backend::Auto)   // probe + pick, logs the chosen plan
//!     .protocol::<Tcp>()
//!     .build()?;
//! ```
//!
//! [`Backend::Auto`] runs a cap-free capability probe and resolves to a
//! concrete backend, **logging the chosen plan** (and surfacing it via
//! [`MonitorBuilder::resolved_capture_plan`](crate::monitor::MonitorBuilder::resolved_capture_plan))
//! so it is never a black box. The realized backends reuse the exact same
//! machinery as the explicit builder methods — `capture()` is sugar that wires
//! `interfaces` / `xdp_interfaces` / `xdp_queues` / `fanout` for you.

use crate::config::FanoutMode;

/// Group id used by [`Backend::Auto`] when it elects an AF_PACKET fanout group.
/// (Single-Monitor Auto never does — fanout only spreads across the *multiple*
/// rings of an [`XdpShardedRunner`](crate::monitor::xdp_shard::XdpShardedRunner)
/// / `ShardedRunner`; Auto on one Monitor stays single-ring and only *advises*
/// sharding. The constant exists for explicit `Backend::AfPacket { fanout }`.)
pub const AUTO_FANOUT_GROUP: u16 = 0xA070;

/// AF_PACKET fanout selection for [`Backend::AfPacket`].
///
/// Only meaningful when the same group id is shared across several rings (one
/// per shard) — i.e. a sharded deployment. A lone Monitor with a fanout group
/// of one sees no spreading, so [`Backend::Auto`] leaves this `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Fanout {
    /// One ring, no `PACKET_FANOUT` group (the single-Monitor default).
    #[default]
    None,
    /// `PACKET_FANOUT_CPU` in the given group — the kernel steers each packet
    /// to the ring whose owner runs on the receiving CPU.
    Cpu(u16),
    /// `PACKET_FANOUT_HASH` in the given group — the kernel steers by flow hash
    /// (both directions of a flow land on the same ring).
    Hash(u16),
}

/// Declarative capture backend for
/// [`MonitorBuilder::capture`](crate::monitor::MonitorBuilder::capture).
///
/// `#[non_exhaustive]` — new backends (e.g. a future XDP elephant-flow shunt)
/// are additive.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Backend {
    /// Probe the host + interface and pick the best available backend,
    /// logging the chosen plan. The probe ladder:
    ///
    /// 1. **Self-loading AF_XDP** (`Queues::Auto`, single-reactor) when the
    ///    `xdp-loader` feature is compiled in — the explicit opt-in capability
    ///    signal. Multi-core hosts get a logged hint to reach for
    ///    [`XdpShardedRunner`](crate::monitor::xdp_shard::XdpShardedRunner) for
    ///    line rate.
    /// 2. else **AF_PACKET** (TPACKET_v3), the always-available base.
    Auto,
    /// AF_PACKET (TPACKET_v3), optionally in a fanout group.
    AfPacket {
        /// Fanout group selection (see [`Fanout`]).
        fanout: Fanout,
    },
    /// Self-loading AF_XDP across the given queues (the Monitor attaches the
    /// built-in redirect program in `SKB_MODE`). Requires `af-xdp` +
    /// `xdp-loader`.
    #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
    AfXdp {
        /// RX queues to bind (`Queues::Auto` = every queue, one socket each).
        queues: crate::xdp::Queues,
    },
    /// **Offline** replay from a pcap / pcapng file instead of a live NIC — the
    /// same declarative facade for the existing
    /// [`pcap_source`](crate::monitor::MonitorBuilder::pcap_source) flow. A
    /// Monitor configured with a `Pcap` backend is driven with
    /// [`Monitor::replay`](crate::monitor::Monitor::replay) (not `run_for` —
    /// there is no live ring to poll). Requires `pcap` + `tokio`.
    #[cfg(all(feature = "pcap", feature = "tokio"))]
    Pcap {
        /// Path to the `.pcap` / `.pcapng` file (format auto-detected).
        path: std::path::PathBuf,
        /// Replay pacing: `Some(f)` scales packet-timestamp inter-arrival by
        /// `1/f` (`> 1.0` = faster than real time); `None` = as fast as
        /// possible (the [`AsyncPcapConfig`](crate::pcap_source::AsyncPcapConfig)
        /// default).
        speed_factor: Option<f32>,
    },
}

impl Backend {
    /// AF_PACKET with no fanout group — the simplest live backend.
    pub fn af_packet() -> Self {
        Self::AfPacket {
            fanout: Fanout::None,
        }
    }

    /// AF_PACKET in an explicit fanout group (for sharded deployments).
    pub fn af_packet_fanout(fanout: Fanout) -> Self {
        Self::AfPacket { fanout }
    }

    /// Self-loading AF_XDP across **every** RX queue (`Queues::Auto`).
    #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
    pub fn af_xdp() -> Self {
        Self::AfXdp {
            queues: crate::xdp::Queues::Auto,
        }
    }

    /// Offline replay from a pcap / pcapng file, as fast as possible. Drive the
    /// built Monitor with [`Monitor::replay`](crate::monitor::Monitor::replay).
    #[cfg(all(feature = "pcap", feature = "tokio"))]
    pub fn pcap(path: impl Into<std::path::PathBuf>) -> Self {
        Self::Pcap {
            path: path.into(),
            speed_factor: None,
        }
    }

    /// Offline replay paced by packet timestamps scaled by `speed_factor`
    /// (`> 1.0` = faster than real time).
    #[cfg(all(feature = "pcap", feature = "tokio"))]
    pub fn pcap_at_speed(path: impl Into<std::path::PathBuf>, speed_factor: f32) -> Self {
        Self::Pcap {
            path: path.into(),
            speed_factor: Some(speed_factor),
        }
    }
}

/// Host / interface capabilities consulted by [`Backend::Auto`]. A trait so the
/// resolution ladder is unit-testable against a mocked host (no NIC / root).
//
// `xdp_loader_compiled` / `queue_count` are consulted only on the AF_XDP rung
// of the ladder, which is itself `cfg`-gated; the `allow(dead_code)` keeps the
// trait whole across feature combos (the methods are live on AF_XDP builds and
// always exercised by the unit tests).
#[allow(dead_code)]
pub(crate) trait CapabilityProbe {
    /// Whether the self-loading AF_XDP path (`af-xdp` + `xdp-loader`) is
    /// compiled in — the capability signal `Auto` keys on.
    fn xdp_loader_compiled(&self) -> bool;
    /// RX queue count for `iface` (`ETHTOOL_GCHANNELS`), if probeable. Cap-free.
    /// `None` when the interface can't be queried (used only for the logged
    /// plan, not the decision).
    fn queue_count(&self, iface: &str) -> Option<usize>;
    /// Available CPU parallelism (`available_parallelism`). Feeds the
    /// sharding *advice* in the logged plan, not the decision.
    fn parallelism(&self) -> usize;
}

/// The real, host-backed [`CapabilityProbe`].
pub(crate) struct SystemProbe;

impl CapabilityProbe for SystemProbe {
    fn xdp_loader_compiled(&self) -> bool {
        cfg!(all(feature = "af-xdp", feature = "xdp-loader"))
    }

    fn queue_count(&self, _iface: &str) -> Option<usize> {
        #[cfg(feature = "af-xdp")]
        {
            crate::xdp::queue_count(_iface).ok().map(|n| n as usize)
        }
        #[cfg(not(feature = "af-xdp"))]
        {
            None
        }
    }

    fn parallelism(&self) -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }
}

/// A resolved, concrete backend plan plus a human-readable description (logged
/// at `capture()` time and surfaced via
/// [`MonitorBuilder::resolved_capture_plan`](crate::monitor::MonitorBuilder::resolved_capture_plan)).
pub(crate) struct ResolvedBackend {
    /// The concrete backend — never [`Backend::Auto`].
    pub backend: Backend,
    /// One-line operator-facing explanation of what was chosen and why.
    pub description: String,
}

/// Resolve a (possibly [`Auto`](Backend::Auto)) backend against `probe` for
/// `iface`, returning the concrete plan + its description.
pub(crate) fn resolve(
    iface: &str,
    backend: &Backend,
    probe: &dyn CapabilityProbe,
) -> ResolvedBackend {
    match backend {
        Backend::Auto => resolve_auto(iface, probe),
        concrete => ResolvedBackend {
            backend: concrete.clone(),
            description: describe(concrete),
        },
    }
}

/// The [`Backend::Auto`] ladder. AF_XDP-loaded when the feature is compiled,
/// else AF_PACKET. Parallelism only colours the *advice* in the description
/// (a single Monitor doesn't spread a fanout group across cores).
fn resolve_auto(iface: &str, probe: &dyn CapabilityProbe) -> ResolvedBackend {
    let cores = probe.parallelism();

    #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
    if probe.xdp_loader_compiled() {
        let queues = crate::xdp::Queues::Auto;
        let q = probe.queue_count(iface);
        let qdesc = match q {
            Some(n) => format!("{n} RX queue(s)"),
            None => "all RX queues".to_string(),
        };
        let advice = if cores > 1 {
            format!("; single-reactor — for line rate across {cores} cores use XdpShardedRunner")
        } else {
            String::new()
        };
        return ResolvedBackend {
            backend: Backend::AfXdp { queues },
            description: format!("AF_XDP self-loaded (SKB_MODE, {qdesc}{advice})"),
        };
    }

    let _ = iface;
    let advice = if cores > 1 {
        format!(" — for multi-core scaling use ShardedRunner (PACKET_FANOUT across {cores} cores)")
    } else {
        String::new()
    };
    ResolvedBackend {
        backend: Backend::AfPacket {
            fanout: Fanout::None,
        },
        description: format!("AF_PACKET (TPACKET_v3, single ring{advice})"),
    }
}

/// One-line description of an already-concrete backend.
fn describe(backend: &Backend) -> String {
    match backend {
        Backend::Auto => "Auto (unresolved)".to_string(),
        Backend::AfPacket { fanout } => match fanout {
            Fanout::None => "AF_PACKET (TPACKET_v3, single ring)".to_string(),
            Fanout::Cpu(g) => format!("AF_PACKET (PACKET_FANOUT_CPU, group {g:#06x})"),
            Fanout::Hash(g) => format!("AF_PACKET (PACKET_FANOUT_HASH, group {g:#06x})"),
        },
        #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
        Backend::AfXdp { queues } => format!("AF_XDP self-loaded (SKB_MODE, queues={queues:?})"),
        #[cfg(all(feature = "pcap", feature = "tokio"))]
        Backend::Pcap { path, speed_factor } => match speed_factor {
            Some(f) => format!("offline pcap replay: {} ({f}x)", path.display()),
            None => format!("offline pcap replay: {} (max speed)", path.display()),
        },
    }
}

/// Map a [`Fanout`] to the `(FanoutMode, group_id)` the AF_PACKET builder field
/// expects. `None` → `None` (no fanout group).
pub(crate) fn fanout_to_spec(fanout: Fanout) -> Option<(FanoutMode, u16)> {
    match fanout {
        Fanout::None => None,
        Fanout::Cpu(g) => Some((FanoutMode::Cpu, g)),
        Fanout::Hash(g) => Some((FanoutMode::Hash, g)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProbe {
        loader: bool,
        queues: Option<usize>,
        cores: usize,
    }
    impl CapabilityProbe for MockProbe {
        fn xdp_loader_compiled(&self) -> bool {
            self.loader
        }
        fn queue_count(&self, _: &str) -> Option<usize> {
            self.queues
        }
        fn parallelism(&self) -> usize {
            self.cores
        }
    }

    #[test]
    fn auto_without_xdp_loader_picks_af_packet() {
        // Even with many cores + queues, no xdp-loader compiled ⇒ AF_PACKET.
        let probe = MockProbe {
            loader: false,
            queues: Some(8),
            cores: 16,
        };
        let r = resolve("eth0", &Backend::Auto, &probe);
        assert!(matches!(
            r.backend,
            Backend::AfPacket {
                fanout: Fanout::None
            }
        ));
        assert!(r.description.contains("AF_PACKET"));
        // Multi-core advice surfaces in the plan.
        assert!(r.description.contains("ShardedRunner"), "{}", r.description);
    }

    #[test]
    fn explicit_backend_passes_through_with_description() {
        let probe = MockProbe {
            loader: false,
            queues: None,
            cores: 1,
        };
        let r = resolve(
            "eth0",
            &Backend::af_packet_fanout(Fanout::Cpu(0x1234)),
            &probe,
        );
        assert!(matches!(
            r.backend,
            Backend::AfPacket {
                fanout: Fanout::Cpu(0x1234)
            }
        ));
        assert!(r.description.contains("PACKET_FANOUT_CPU"));
    }

    #[test]
    fn fanout_spec_mapping() {
        assert_eq!(fanout_to_spec(Fanout::None), None);
        assert_eq!(fanout_to_spec(Fanout::Cpu(7)), Some((FanoutMode::Cpu, 7)));
        assert_eq!(fanout_to_spec(Fanout::Hash(9)), Some((FanoutMode::Hash, 9)));
    }

    #[cfg(all(feature = "pcap", feature = "tokio"))]
    #[test]
    fn pcap_backend_resolves_to_offline_description() {
        let probe = MockProbe {
            loader: false,
            queues: None,
            cores: 1,
        };
        // Auto never picks Pcap — it must be explicit; here it passes through.
        let r = resolve(
            "trace",
            &Backend::pcap_at_speed("/tmp/cap.pcapng", 4.0),
            &probe,
        );
        assert!(matches!(r.backend, Backend::Pcap { .. }));
        assert!(
            r.description.contains("offline pcap replay"),
            "{}",
            r.description
        );
        assert!(r.description.contains("4x"), "{}", r.description);
        // Max-speed variant.
        let r2 = resolve("trace", &Backend::pcap("/tmp/cap.pcapng"), &probe);
        assert!(r2.description.contains("max speed"), "{}", r2.description);
    }

    #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
    #[test]
    fn auto_with_xdp_loader_picks_af_xdp() {
        let probe = MockProbe {
            loader: true,
            queues: Some(4),
            cores: 8,
        };
        let r = resolve("eth0", &Backend::Auto, &probe);
        assert!(matches!(r.backend, Backend::AfXdp { .. }));
        assert!(r.description.contains("AF_XDP"));
        assert!(r.description.contains("4 RX queue"), "{}", r.description);
        assert!(
            r.description.contains("XdpShardedRunner"),
            "{}",
            r.description
        );
    }
}
