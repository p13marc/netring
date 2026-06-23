//! Glob-importable re-exports of the canonical netring API.
//!
//! ```no_run
//! use netring::prelude::*;
//! ```
//!
//! Brings in the names a typical monitor + detector needs.
//! Power users reach past this module to
//! [`crate::protocol`], [`crate::ctx`], [`crate::layer`], etc.
//! directly.

// ─── Core builder + run modes ────────────────────────────────────
pub use crate::monitor::{Handler, Monitor, MonitorBuilder};

// ─── Async + middleware (Phase D) ────────────────────────────────
pub use crate::monitor::AsyncHandler;

// ─── Threat-intel IOC matching (issue #48) ───────────────────────
pub use crate::monitor::ioc::IocSet;

// ─── Sigma rule evaluation (issue #46) ───────────────────────────
#[cfg(feature = "sigma")]
pub use crate::monitor::sigma::SigmaRuleSet;

// ─── Protocol markers (built-in) ─────────────────────────────────
#[cfg(all(feature = "http", feature = "ja4plus"))]
pub use crate::monitor::HttpFingerprint;
#[cfg(feature = "tls")]
pub use crate::monitor::TlsFingerprint;
#[cfg(feature = "dhcp")]
pub use crate::protocol::builtin::Dhcp;
#[cfg(feature = "dns")]
pub use crate::protocol::builtin::Dns;
#[cfg(feature = "http")]
pub use crate::protocol::builtin::Http;
pub use crate::protocol::builtin::Icmp;
#[cfg(feature = "kerberos")]
pub use crate::protocol::builtin::Kerberos;
#[cfg(feature = "ldap")]
pub use crate::protocol::builtin::Ldap;
#[cfg(feature = "netbios-ns")]
pub use crate::protocol::builtin::Nbns;
#[cfg(feature = "ntp")]
pub use crate::protocol::builtin::Ntp;
#[cfg(feature = "quic")]
pub use crate::protocol::builtin::Quic;
#[cfg(feature = "radius")]
pub use crate::protocol::builtin::Radius;
#[cfg(feature = "rdp")]
pub use crate::protocol::builtin::Rdp;
#[cfg(feature = "smb")]
pub use crate::protocol::builtin::Smb;
#[cfg(feature = "snmp")]
pub use crate::protocol::builtin::Snmp;
#[cfg(feature = "ssdp")]
pub use crate::protocol::builtin::Ssdp;
#[cfg(feature = "ssh")]
pub use crate::protocol::builtin::Ssh;
#[cfg(feature = "tftp")]
pub use crate::protocol::builtin::Tftp;
pub use crate::protocol::builtin::{Tcp, Udp};
#[cfg(feature = "tls")]
pub use crate::protocol::builtin::{Tls, TlsHandshake};

// ─── Protocol trait + roles + dispatch types ─────────────────────
pub use crate::protocol::{
    Dispatch, FlowKey, FlowProtocol, MessageProtocol, Protocol, ProtocolInitError, SignatureMatch,
};

// ─── Event types ─────────────────────────────────────────────────
// 0.22: FlowPacket is flat (carries `proto`); FlowTick/ParserClosed are
// parameterised lifecycle events; TcpRst/IcmpError are synthesised.
pub use crate::protocol::event_typed::{
    AnyFlowAnomaly, FlowEnded, FlowEstablished, FlowPacket, FlowStarted, FlowTick, ParserClosed,
    TcpRst, Tick,
};
#[cfg(feature = "icmp")]
pub use crate::protocol::event_typed::{IcmpError, IcmpErrorKind, IcmpFamily};

// ─── Per-event Ctx ───────────────────────────────────────────────
pub use crate::ctx::{Ctx, SourceIdx};

// ─── Anomaly emission ────────────────────────────────────────────
pub use crate::anomaly::OwnedAnomaly;
pub use crate::anomaly::Severity;
#[cfg(feature = "eve-sink")]
pub use crate::anomaly::eve_sink::EveSink;
#[cfg(feature = "metrics")]
pub use crate::anomaly::metrics_sink::MetricsSink;
#[cfg(feature = "ocsf-sink")]
pub use crate::anomaly::ocsf_sink::OcsfSink;
#[cfg(feature = "serde")]
pub use crate::anomaly::shipped_sinks::StdoutJsonSink;
pub use crate::anomaly::shipped_sinks::{ChannelSink, StdoutSink, TracingSink};
pub use crate::anomaly::sink::{AnomalySink, AnomalySinkExt, AnomalyWriter, NoopSink};
/// 0.21 B.1 — structured-anomaly + key accessor traits +
/// `DetectorScore` trait routing detector outputs through
/// `OwnedAnomaly`. Re-exported from flowscope.
pub use crate::anomaly::{AnomalyFields, DetectorScore, Key, KeyFields};

// ─── Middleware (Phase D) ────────────────────────────────────────
pub use crate::layer::{
    DedupeAnomalies, Layer, LayerFactory, LayerSpec, MinSeverity, RateLimitAnomalies, Sample, Tee,
};

// ─── Sliding-window correlate primitives ─────────────────────────
pub use crate::correlate::{
    BurstDetector, Ewma, KeyIndexed, RollingRate, TimeBucketedCounter, TimeBucketedSet, TopK,
};

// `MacAddr` is the L2 address type used by ARP / NDP / LLDP / CDP and the asset
// inventory; export it once whenever any MAC-bearing feature is on.
#[cfg(any(
    feature = "arp",
    feature = "ndp",
    feature = "lldp",
    feature = "cdp",
    feature = "asset"
))]
pub use flowscope::MacAddr;

// ─── ARP (issue #12, feature `arp`) ──────────────────────────────
#[cfg(feature = "arp")]
pub use crate::monitor::arp::{ArpAnomaly, ArpAnomalyKind};
#[cfg(feature = "arp")]
pub use flowscope::{ArpMessage, ArpOp};

// ─── NDP (issue #24, feature `ndp`) ──────────────────────────────
#[cfg(feature = "ndp")]
pub use crate::monitor::ndp::{NdpAnomaly, NdpAnomalyKind};
#[cfg(feature = "ndp")]
pub use flowscope::{NdpKind, NdpMessage};

// ─── LLDP / CDP L2 discovery (issue #28, features `lldp` / `cdp`) ─
#[cfg(feature = "cdp")]
pub use flowscope::{CdpAddress, CdpCapabilities, CdpMessage};
#[cfg(feature = "lldp")]
pub use flowscope::{ChassisId, LldpMessage, PortId};

// ─── QUIC (issue #14, feature `quic`) ────────────────────────────
#[cfg(feature = "quic")]
pub use flowscope::{QuicInitial, QuicVersion};

// ─── p0f passive TCP/OS fingerprint (issue #31, feature `p0f`) ────
#[cfg(feature = "p0f")]
pub use flowscope::{TcpDirection, TcpFingerprint};

// ─── Asset inventory (issue #28, feature `asset`) ────────────────
#[cfg(feature = "asset")]
pub use flowscope::{Asset, AssetCapabilities, AssetFingerprints, AssetSourceSet, Inventory};

// ─── Bandwidth + reports + well-known labels (0.22) ──────────────
pub use crate::monitor::{BandwidthReport, BandwidthSnapshot};
#[cfg(feature = "serde")]
pub use crate::report::JsonReportSink;
pub use crate::report::{Report, ReportSink, ReportSnapshot, StdoutReportSink};
pub use crate::well_known::LabelTable;
#[cfg(feature = "icmp")]
pub use flowscope::icmp::{DestUnreachableKind, MtuSignalKind};

// ─── Common external types ───────────────────────────────────────
pub use flowscope::{EndReason, FlowSide, L4Proto, Timestamp};
// Issue #34: reassembler-hardening config enums for `MonitorBuilder`.
pub use flowscope::{MemcapPolicy, TcpOverlapPolicy};
pub use std::time::Duration;

// ─── The detector! macro ────────────────────────────────────────
// `detector!` is `#[macro_export]` so it's reachable as
// `crate::detector!` — but the `pub use` re-export of a macro
// works at the crate root, not via the prelude `pub use` chain.
// Users get the macro via `use netring::detector;` (always-on
// when feature gates allow). The prelude doesn't need to
// re-export it explicitly — including it in `use netring::prelude::*;`
// implicitly imports the crate-root macro under standard
// 2024-edition macro hygiene rules.
