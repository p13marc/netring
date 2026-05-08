//! netring-flow — pluggable flow & session tracking.
//!
//! Cross-platform, runtime-free library used by `netring` (Linux
//! AF_PACKET / AF_XDP) and any other packet source (pcap, tun-tap,
//! replay, embedded). No tokio, no futures, no async runtime
//! dependency.
//!
//! Plan 00 ships only `Timestamp`; subsequent plans add the
//! `FlowExtractor` trait, built-in extractors, the tracker, and the
//! reassembler hook. See `plans/INDEX.md` in the repository for the
//! roadmap.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod timestamp;

pub use timestamp::Timestamp;
