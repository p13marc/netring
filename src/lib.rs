//! High-performance zero-copy packet I/O for Linux.
//!
//! `netring` provides packet capture and injection via AF_PACKET with TPACKET_V3
//! (block-based mmap ring buffers). It offers both a high-level ergonomic API
//! and a low-level batch API for maximum throughput.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod inject;
pub mod packet;
pub mod stats;
pub mod traits;

pub mod afpacket;

// Re-exports
pub use config::{BpfFilter, BpfInsn, FanoutFlags, FanoutMode, TimestampSource};
pub use error::Error;
pub use inject::{Injector, InjectorBuilder};
pub use packet::{OwnedPacket, Packet, PacketBatch, PacketStatus, Timestamp};
pub use stats::CaptureStats;
pub use traits::{PacketSink, PacketSource};

pub use afpacket::rx::{AfPacketRx, AfPacketRxBuilder};
pub use afpacket::tx::{AfPacketTx, AfPacketTxBuilder, TxSlot};
