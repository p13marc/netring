#![doc = include_str!("../../README.md")]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod afpacket;
pub mod afxdp;
pub mod async_adapters;
pub mod bridge;
pub mod config;
pub mod error;
pub mod interface;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod packet;
#[cfg(feature = "pcap")]
pub mod pcap;
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
pub use config::{BpfFilter, BpfInsn, FanoutFlags, FanoutMode, RingProfile, TimestampSource};
pub use error::Error;
pub use interface::{InterfaceInfo, interface_info};
pub use packet::{
    BatchIter, OwnedPacket, Packet, PacketBatch, PacketDirection, PacketStatus, Timestamp,
};
// Always re-exported — needed for `Packet::view()`.
pub use netring_flow::PacketView;
pub use stats::CaptureStats;
pub use traits::{PacketSink, PacketSource};

// AF_XDP
#[cfg(feature = "af-xdp")]
pub use afxdp::{XdpBatch, XdpBatchIter, XdpPacket};
pub use afxdp::{XdpMode, XdpSocket, XdpSocketBuilder, XdpStats};

// Async / channel adapters
#[cfg(feature = "channel")]
pub use async_adapters::channel::ChannelCapture;
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
// netring-flow extractor types as `netring::flow::*`. Users who want
// the full flow API still need to enable the upcoming `flow` feature
// (plan 02), but the extractor surface is available now.

/// Source-agnostic flow & session tracking types from `netring-flow`.
///
/// Re-exports under `parse` because the built-in extractors require
/// `etherparse`. Users can also depend on `netring-flow` directly.
#[cfg(feature = "parse")]
pub mod flow {
    pub use netring_flow::extract;
    pub use netring_flow::{
        Extracted, FlowExtractor, L4Proto, Orientation, PacketView, TcpFlags, TcpInfo,
    };

    #[cfg(feature = "flow")]
    pub use netring_flow::{
        BufferedReassembler, BufferedReassemblerFactory, EndReason, FlowDriver, FlowEntry,
        FlowEvent, FlowEvents, FlowSide, FlowState, FlowStats, FlowTracker, FlowTrackerConfig,
        FlowTrackerStats, HistoryString, Reassembler, ReassemblerFactory,
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
pub use async_adapters::flow_stream::{AsyncReassemblerSlot, FlowStream, NoReassembler};
