#![doc = include_str!("../README.md")]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod afpacket;
pub mod afxdp;
pub mod async_adapters;
pub mod bridge;
pub mod config;
pub mod dedup;
pub mod error;
pub mod interface;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod packet;
#[cfg(feature = "pcap")]
pub mod pcap;
#[cfg(all(feature = "pcap", feature = "tokio"))]
pub mod pcap_tap;
pub mod stats;
pub mod traits;

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
    BpfFilter, BpfFilterBuilder, BpfInsn, BuildError, FanoutFlags, FanoutMode, IpNet,
    ParseIpNetError, RingProfile, TimestampSource,
};
pub use dedup::Dedup;
pub use error::Error;
pub use interface::{InterfaceInfo, interface_info};
pub use packet::{
    BatchIter, OwnedPacket, Packet, PacketBatch, PacketDirection, PacketStatus, Timestamp,
};
// Always re-exported — needed for `Packet::view()`.
pub use flowscope::PacketView;
pub use stats::CaptureStats;
pub use traits::{PacketSink, PacketSource};

// AF_XDP
#[cfg(feature = "af-xdp")]
pub use afxdp::{XdpBatch, XdpBatchIter, XdpPacket};
pub use afxdp::{XdpMode, XdpSocket, XdpSocketBuilder, XdpStats};

/// XDP program loader (built-in redirect-all program). Requires the
/// `xdp-loader` Cargo feature.
#[cfg(feature = "xdp-loader")]
pub mod xdp {
    pub use crate::afxdp::loader::{
        LoaderError, XdpAttachment, XdpFlags, XdpProgram, default_program,
    };
}

// Async / channel adapters
#[cfg(feature = "channel")]
pub use async_adapters::channel::ChannelCapture;
#[cfg(feature = "tokio")]
pub use async_adapters::dedup_stream::DedupStream;
#[cfg(feature = "tokio")]
pub use async_adapters::tokio_adapter::{AsyncCapture, PacketStream, ReadableGuard};
#[cfg(feature = "tokio")]
pub use async_adapters::tokio_injector::AsyncInjector;
#[cfg(all(feature = "tokio", feature = "af-xdp"))]
pub use async_adapters::tokio_xdp::{AsyncXdpSocket, XdpReadableGuard, XdpStream};
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
        FlowEntry, FlowEvent, FlowEvents, FlowSessionDriver, FlowSide, FlowState, FlowStats,
        FlowTracker, FlowTrackerConfig, FlowTrackerStats, HistoryString, OverflowPolicy,
        Reassembler, ReassemblerFactory,
    };

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
#[cfg(feature = "tokio")]
pub use async_adapters::stream_capture::StreamCapture;
#[cfg(all(feature = "pcap", feature = "tokio"))]
pub use pcap_tap::{PcapTap, TapErrorPolicy};
