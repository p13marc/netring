//! netring-flow — pluggable flow & session tracking.
//!
//! Cross-platform, runtime-free library used by `netring` (Linux
//! AF_PACKET / AF_XDP) and any other packet source (pcap, tun-tap,
//! replay, embedded). No tokio, no futures, no async runtime
//! dependency.
//!
//! # Layers
//!
//! 1. [`FlowExtractor`] — user (or built-in) trait that turns a frame
//!    into a flow descriptor.
//! 2. `FlowTracker<E, S>` (plan 02) — accounts for flows, runs the
//!    TCP state machine, emits lifecycle events.
//! 3. `Reassembler` (plan 03) — sync hook for TCP byte streams;
//!    plug `protolens` / `blatta` / your own buffer in.
//!
//! Plan 01 ships layers 1's types and a set of built-in extractors;
//! the tracker and reassembler arrive in subsequent plans. See
//! `plans/INDEX.md` in the repository.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod timestamp;
mod view;

pub mod extractor;

#[cfg(feature = "extractors")]
pub mod extract;

pub use timestamp::Timestamp;
pub use view::PacketView;

pub use extractor::{Extracted, FlowExtractor, L4Proto, Orientation, TcpFlags, TcpInfo};
