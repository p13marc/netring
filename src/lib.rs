#![doc = include_str!("../README.md")]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod capture;
pub mod config;
pub mod error;
pub mod inject;
pub mod interface;
pub mod packet;
pub mod stats;
pub mod traits;

pub mod afpacket;
pub mod async_adapters;

// Convenience re-exports for channel feature
#[cfg(feature = "channel")]
pub mod channel {
    //! Convenience re-export of [`ChannelCapture`].
    pub use crate::async_adapters::channel::ChannelCapture;
}

// Re-exports
pub use capture::{Capture, CaptureBuilder};
pub use config::{BpfFilter, BpfInsn, FanoutFlags, FanoutMode, RingProfile, TimestampSource};
pub use error::Error;
pub use inject::{Injector, InjectorBuilder};
pub use interface::{interface_info, InterfaceInfo};
pub use packet::{OwnedPacket, Packet, PacketBatch, PacketDirection, PacketStatus, Timestamp};
pub use stats::CaptureStats;
pub use traits::{PacketSink, PacketSource};

pub use afpacket::rx::{AfPacketRx, AfPacketRxBuilder};
pub use afpacket::tx::{AfPacketTx, AfPacketTxBuilder, TxSlot};
