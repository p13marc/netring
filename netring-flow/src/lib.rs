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
//! 2. [`FlowTracker`] — accounts for flows, runs the TCP state
//!    machine, emits lifecycle events.
//! 3. `Reassembler` (plan 03) — sync hook for TCP byte streams;
//!    plug `protolens` / `blatta` / your own buffer in.
//!
//! Plan 02 ships layers 1+2; the reassembler arrives in plan 03.
//! See `plans/INDEX.md` in the repository.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod timestamp;
mod view;

pub mod extractor;

#[cfg(feature = "extractors")]
pub mod extract;

#[cfg(feature = "tracker")]
pub mod event;
#[cfg(feature = "tracker")]
pub mod history;
#[cfg(feature = "tracker")]
mod tcp_state;
#[cfg(feature = "tracker")]
pub mod tracker;

pub use timestamp::Timestamp;
pub use view::PacketView;

pub use extractor::{Extracted, FlowExtractor, L4Proto, Orientation, TcpFlags, TcpInfo};

#[cfg(feature = "tracker")]
pub use event::{EndReason, FlowEvent, FlowSide, FlowState, FlowStats};
#[cfg(feature = "tracker")]
pub use history::HistoryString;
#[cfg(feature = "tracker")]
pub use tracker::{FlowEntry, FlowEvents, FlowTracker, FlowTrackerConfig, FlowTrackerStats};
