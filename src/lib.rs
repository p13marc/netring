#![doc = include_str!("../README.md")]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod bridge;
pub mod capture;
pub mod config;
pub mod error;
pub mod inject;
pub mod interface;
pub mod packet;
pub mod stats;
pub mod traits;

pub mod afpacket;
pub mod afxdp;
pub mod async_adapters;
pub(crate) mod sockopt;
pub(crate) mod syscall;

// Re-exports
pub use capture::{Capture, CaptureBuilder};
pub use config::{BpfFilter, BpfInsn, FanoutFlags, FanoutMode, RingProfile, TimestampSource};
pub use error::Error;
pub use inject::{Injector, InjectorBuilder};
pub use interface::{InterfaceInfo, interface_info};
pub use packet::{OwnedPacket, Packet, PacketBatch, PacketDirection, PacketStatus, Timestamp};
pub use stats::CaptureStats;
pub use traits::{PacketSink, PacketSource};

pub use afpacket::rx::{AfPacketRx, AfPacketRxBuilder};
pub use afpacket::tx::{AfPacketTx, AfPacketTxBuilder, TxSlot};

pub use afxdp::{XdpMode, XdpSocket, XdpSocketBuilder, XdpStats};
pub use bridge::{Bridge, BridgeAction, BridgeBuilder, BridgeDirection, BridgeStats};

#[cfg(feature = "channel")]
pub use async_adapters::channel::ChannelCapture;
#[cfg(feature = "tokio")]
pub use async_adapters::tokio_adapter::AsyncCapture;
#[cfg(feature = "tokio")]
pub use traits::AsyncPacketSource;
