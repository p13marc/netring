//! Async and channel adapters for packet capture.

#[cfg(feature = "tokio")]
pub mod tokio_adapter;

#[cfg(feature = "tokio")]
pub mod tokio_injector;

#[cfg(all(feature = "tokio", feature = "af-xdp"))]
pub mod tokio_xdp;

#[cfg(all(feature = "tokio", feature = "flow"))]
pub mod async_reassembler;
#[cfg(all(feature = "tokio", feature = "flow"))]
pub mod conversation;
#[cfg(all(feature = "tokio", feature = "flow"))]
pub mod datagram_stream;
#[cfg(feature = "tokio")]
pub mod dedup_stream;
#[cfg(all(feature = "tokio", feature = "flow"))]
pub mod flow_broadcast;
#[cfg(all(feature = "tokio", feature = "flow"))]
pub mod flow_stream;
#[cfg(all(feature = "tokio", feature = "flow"))]
pub mod multi_capture;
#[cfg(all(feature = "tokio", feature = "flow"))]
pub mod multi_streams;
#[cfg(all(feature = "tokio", feature = "flow"))]
pub mod session_stream;

#[cfg(feature = "tokio")]
pub mod stream_capture;

#[cfg(feature = "channel")]
pub mod channel;
