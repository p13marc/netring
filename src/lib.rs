//! High-performance zero-copy packet I/O for Linux.
//!
//! `netring` provides packet capture and injection via AF_PACKET with TPACKET_V3
//! (block-based mmap ring buffers). It offers both a high-level ergonomic API
//! and a low-level batch API for maximum throughput.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod capture;
pub mod config;
pub mod error;
pub mod inject;
pub mod packet;
pub mod stats;
pub mod traits;

pub mod afpacket;
pub mod async_adapters;

// Convenience re-exports for channel feature
#[cfg(feature = "channel")]
pub mod channel {
    //! Convenience re-export of [`ChannelCapture`](crate::async_adapters::channel::ChannelCapture).
    pub use crate::async_adapters::channel::ChannelCapture;
}

// Re-exports
pub use capture::{Capture, CaptureBuilder};
pub use config::{BpfFilter, BpfInsn, FanoutFlags, FanoutMode, TimestampSource};
pub use error::Error;
pub use inject::{Injector, InjectorBuilder};
pub use packet::{OwnedPacket, Packet, PacketBatch, PacketStatus, Timestamp};
pub use stats::CaptureStats;
pub use traits::{PacketSink, PacketSource};

pub use afpacket::rx::{AfPacketRx, AfPacketRxBuilder};
pub use afpacket::tx::{AfPacketTx, AfPacketTxBuilder, TxSlot};
