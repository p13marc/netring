//! Async and channel adapters for packet capture.

#[cfg(feature = "tokio")]
pub mod tokio_adapter;

#[cfg(feature = "tokio")]
pub mod tokio_injector;

#[cfg(feature = "channel")]
pub mod channel;
