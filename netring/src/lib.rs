#![doc = include_str!("../README.md")]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

// netring is built on AF_PACKET (TPACKET_v3) and AF_XDP, which are Linux-only
// kernel interfaces. Fail fast with a clear message rather than deep inside
// `libc` / `nix` / `aya` on other targets.
#[cfg(not(target_os = "linux"))]
compile_error!(
    "netring requires Linux — it is built on AF_PACKET (TPACKET_v3) and AF_XDP, \
     which are Linux-only kernel interfaces. For cross-platform packet capture, \
     use the `pcap` crate instead."
);

pub mod afpacket;
pub mod afxdp;
#[cfg(all(feature = "flow", feature = "tokio"))]
pub mod anomaly;
pub mod async_adapters;
pub mod bridge;
pub mod config;
/// 0.21 G: netring's `TimeBucketedCounter` is now re-exported from
/// flowscope (the `new_unbounded` ctor lands the 2-arg shape). Three
/// extra primitives (`BurstDetector`, `Ewma`, `TopK`, `TimeBucketedSet`,
/// `SequencePattern`, `KeylessSequencePattern`, `FlowStateMap`) join
/// the module for free. `KeyIndexed` stays netring-side until flowscope
/// adds a `drain_expired`-style iterator method (see module docstring).
#[cfg(feature = "flow")]
pub mod correlate;
#[cfg(all(feature = "flow", feature = "tokio"))]
pub mod ctx;
pub mod dedup;
#[cfg(all(feature = "flow", feature = "tokio"))]
#[macro_use]
pub mod detector_macro;
pub mod error;
/// 0.24 Phase D: flow export — `FlowRecord` / `FlowExporter` /
/// `MonitorBuilder::export_flows`. The fourth output shape beside
/// anomalies, reports, and broadcast streams: one record per *completed
/// flow* (NetFlow/IPFIX-style).
#[cfg(all(feature = "flow", feature = "tokio"))]
pub mod export;
pub mod interface;
#[cfg(all(feature = "flow", feature = "tokio"))]
pub mod layer;
#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(all(feature = "flow", feature = "tokio"))]
pub mod monitor;
pub mod packet;
#[cfg(feature = "pcap")]
pub mod pcap;
#[cfg(all(feature = "pcap", feature = "tokio", feature = "flow"))]
pub mod pcap_flow;
#[cfg(all(feature = "pcap", feature = "tokio"))]
pub mod pcap_source;
#[cfg(all(feature = "pcap", feature = "tokio"))]
pub mod pcap_tap;
#[cfg(all(feature = "flow", feature = "tokio"))]
pub mod prelude;
#[cfg(all(feature = "flow", feature = "tokio"))]
pub mod protocol;
/// 0.22 §3: periodic structured reports (`Report` / `ReportSink` /
/// `ReportSnapshot`) — the third output stream beside anomalies and
/// broadcast event streams.
#[cfg(all(feature = "flow", feature = "tokio"))]
pub mod report;
pub mod stats;
pub mod traits;

/// 0.22 §2.2: well-known port → app/protocol label table, re-exported
/// from flowscope for a stable `netring::well_known::LabelTable` path.
/// Pass a custom table to
/// [`MonitorBuilder::label_table`](crate::monitor::MonitorBuilder::label_table).
#[cfg(feature = "parse")]
pub mod well_known {
    pub use flowscope::well_known::LabelTable;
}

pub(crate) mod sockopt;
pub(crate) mod syscall;

// ── Primary public surface ─────────────────────────────────────────────────
//
// Promote the most common types to the crate root so users can write
// `use netring::Capture;` rather than `use netring::afpacket::rx::Capture;`.

pub use afpacket::rx::{Capture, CaptureBuilder, Packets};
pub use afpacket::tx::{Injector, InjectorBuilder, TxSlot};
pub use bridge::{
    Bridge, BridgeAction, BridgeBuilder, BridgeDirection, BridgeHandles, BridgeStats,
};
pub use config::{
    BpfBuildError, BpfFilter, BpfFilterBuilder, BpfInsn, BusyPollConfig, FanoutFlags, FanoutMode,
    IpNet, ParseIpNetError, RingProfile, TimestampSource,
};
pub use dedup::Dedup;
pub use error::Error;
pub use interface::{InterfaceInfo, interface_info};
pub use packet::{
    BatchIter, OwnedPacket, Packet, PacketBatch, PacketDirection, PacketStatus, Timestamp,
    TimestampClock,
};
// Always re-exported — needed for `Packet::view()`.
pub use flowscope::PacketView;
pub use stats::{CaptureStats, DropBreakdown};
pub use traits::{PacketSetFilter, PacketSink, PacketSource};

// AF_XDP
#[cfg(feature = "af-xdp")]
pub use afxdp::{XdpBatch, XdpBatchIter, XdpPacket};
pub use afxdp::{XdpMode, XdpSocket, XdpSocketBuilder, XdpStats};

/// AF_XDP capture surface: queue discovery + multi-queue capture (issue #6) and,
/// with the `xdp-loader` feature, the built-in XDP program loader.
#[cfg(feature = "af-xdp")]
pub mod xdp {
    #[cfg(feature = "xdp-loader")]
    pub use crate::afxdp::loader::{
        LoaderError, XdpAttachment, XdpFlags, XdpProgram, default_program, filter_program,
    };
    pub use crate::afxdp::{Queues, interface_numa_node, queue_count};
    #[cfg(feature = "xdp-loader")]
    pub use crate::afxdp::{XdpCapture, XdpCaptureBuilder, XdpCaptureGuard};

    /// Symmetric RSS / fanout flow coherence (issue #43) — make both directions
    /// of a bidirectional flow hash to the same RX queue.
    pub mod rss {
        pub use crate::afxdp::rss::{
            RssConfig, RssMode, SYMMETRIC_RSS_KEY, rss_flow_hash, toeplitz,
        };
    }

    /// NIC RX flow steering (issue #15) — pin chosen flows to chosen RX queues
    /// via ethtool ntuple rules.
    pub mod steer {
        pub use crate::afxdp::steer::{FlowRule, RxSteer, SteerGuard};
    }
}

// Async / channel adapters
#[cfg(feature = "channel")]
pub use async_adapters::channel::ChannelCapture;
#[cfg(feature = "tokio")]
pub use async_adapters::dedup_stream::DedupStream;
#[cfg(feature = "tokio")]
pub use async_adapters::tokio_adapter::{AsyncCapture, PacketStream, ReadableGuard};
#[cfg(feature = "tokio")]
pub use async_adapters::tokio_injector::{AsyncInjector, TxPacer};
#[cfg(all(feature = "tokio", feature = "af-xdp"))]
pub use async_adapters::tokio_xdp::{AsyncXdpSocket, XdpReadableGuard, XdpStream};
#[cfg(all(feature = "tokio", feature = "af-xdp", feature = "xdp-loader"))]
pub use async_adapters::tokio_xdp_capture::AsyncXdpCapture;
#[cfg(feature = "tokio")]
pub use traits::AsyncPacketSource;

// ── Flow tracking re-exports ─────────────────────────────────────────────
//
// When `parse` is enabled (which pulls etherparse), surface the
// flowscope extractor types as `netring::flow::*`. Users who want
// the full flow API need the `flow` feature; the extractor surface
// alone is available under `parse`.

/// Source-agnostic flow & session tracking types from
/// [`flowscope`](https://crates.io/crates/flowscope).
///
/// Re-exports under `parse` because the built-in extractors require
/// `etherparse`. Users can also depend on `flowscope` directly.
#[cfg(feature = "parse")]
pub mod flow {
    pub use flowscope::extract;
    pub use flowscope::{
        Extracted, FlowExtractor, L4Proto, Orientation, PacketView, TcpFlags, TcpInfo,
    };

    #[cfg(feature = "flow")]
    pub use flowscope::tracker::IdleTimeoutFn;
    #[cfg(feature = "flow")]
    pub use flowscope::{
        AnomalyKind, BufferedReassembler, BufferedReassemblerFactory, EndReason, FlowDriver,
        FlowEntry, FlowEvent, FlowEvents, FlowSide, FlowState, FlowStats, FlowTracker,
        FlowTrackerConfig, FlowTrackerStats, HistoryString, OverflowPolicy, ParserKind,
        Reassembler, ReassemblerFactory,
    };

    // netring 0.20-adoption: flowscope retired its public `SessionEvent`
    // (flowscope #100) and deleted `Flow{Session,Datagram}Driver`
    // (#99). netring now owns its session-stream event type.
    #[cfg(all(feature = "tokio", feature = "flow"))]
    pub use crate::async_adapters::session_event::SessionEvent;

    /// Async reassembly types for tokio integration.
    /// Available under `flow + tokio`.
    #[cfg(all(feature = "tokio", feature = "flow"))]
    pub use crate::async_adapters::async_reassembler::{
        AsyncReassembler, AsyncReassemblerFactory, ChannelFactory, ChannelReassembler,
        channel_factory,
    };
}

#[cfg(all(feature = "tokio", feature = "flow"))]
pub use async_adapters::conversation::{Conversation, ConversationChunk, ConversationStream};
#[cfg(all(feature = "tokio", feature = "flow"))]
pub use async_adapters::flow_broadcast::{BroadcastRecvError, FlowBroadcast, FlowSubscriber};
#[cfg(all(feature = "tokio", feature = "flow"))]
pub use async_adapters::flow_stream::{AsyncReassemblerSlot, FlowStream, NoReassembler};
#[cfg(all(feature = "tokio", feature = "flow"))]
pub use async_adapters::multi_capture::AsyncMultiCapture;
#[cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "af-xdp",
    feature = "xdp-loader"
))]
pub use async_adapters::multi_capture::AsyncXdpMultiCapture;
#[cfg(all(feature = "tokio", feature = "flow"))]
pub use async_adapters::multi_config::MultiStreamConfig;
#[cfg(all(feature = "tokio", feature = "flow"))]
pub use async_adapters::multi_streams::{
    MergedFlowStream, MultiDatagramStream, MultiFlowStream, MultiSessionStream, TaggedEvent,
};
#[cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "af-xdp",
    feature = "xdp-loader"
))]
pub use async_adapters::multi_streams::{
    XdpMultiDatagramStream, XdpMultiFlowStream, XdpMultiSessionStream,
};
#[cfg(feature = "tokio")]
pub use async_adapters::stream_capture::{StreamCapture, StreamSetFilter};
#[cfg(all(feature = "pcap", feature = "tokio", feature = "flow"))]
pub use pcap_flow::{PcapDatagramStream, PcapFlowStream, PcapSessionStream};
#[cfg(all(feature = "pcap", feature = "tokio"))]
pub use pcap_source::{AsyncPcapConfig, AsyncPcapSource, PcapFormat};
#[cfg(all(feature = "pcap", feature = "tokio"))]
pub use pcap_tap::{PcapTap, TapErrorPolicy};
// 0.20 plugin layer re-exports. Consumed by the `Monitor::builder()`
// API. The 0.19 `ProtocolMonitor` / `ProtocolEvent` surface was removed
// in 0.22.
#[cfg(all(feature = "flow", feature = "tokio"))]
pub use protocol::{
    Dispatch, FlowKey, FlowProtocol, MessageProtocol, Protocol, ProtocolInitError, SignatureMatch,
};

#[cfg(all(feature = "flow", feature = "tokio"))]
pub use anomaly::{Anomaly, AnomalyContext, Severity};
