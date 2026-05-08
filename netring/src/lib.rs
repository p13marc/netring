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
