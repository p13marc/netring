//! `netring-flow-pcap` — pcap source adapter for `netring-flow`.
//!
//! Removes ~10 lines of boilerplate from every program that wants
//! to do flow tracking on a pcap file. Wraps `pcap-file`, exposes
//! the result as iterators of [`PacketView`]s or [`FlowEvent`]s.
//!
//! # Quick start
//!
//! ```no_run
//! use netring_flow_pcap::PcapFlowSource;
//! use netring_flow::extract::FiveTuple;
//! use netring_flow::FlowEvent;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! for evt in PcapFlowSource::open("trace.pcap")?.with_extractor(FiveTuple::bidirectional()) {
//!     if let FlowEvent::Started { key, .. } = evt? {
//!         println!("{} <-> {}", key.a, key.b);
//!     }
//! }
//! # Ok(()) }
//! ```
//!
//! # See also
//!
//! - [`netring-flow`](https://crates.io/crates/netring-flow) for the
//!   core flow types.
//! - [`netring`](https://crates.io/crates/netring) for live AF_PACKET
//!   capture on Linux (pair with `netring-flow` directly).

#![cfg_attr(docsrs, feature(doc_cfg))]

mod source;

pub use source::{Error, EventIter, OwnedPacketView, PcapFlowSource, ViewIter};
