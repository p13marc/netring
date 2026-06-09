//! The 0.20 declarative monitor — `Monitor::builder().on::<E>(handler).build()`.
//!
//! Phase B lands this module in pieces:
//! - B.2 (this commit): [`Handler`] trait + blanket impls
//! - B.3: `Dispatcher` + `HandlerRegistry` + `TypedProtocolSlot`
//! - B.4: `Monitor` + `MonitorBuilder` + run loop + tick stub
//!
//! Until B.4 lands, this module exposes only the type machinery
//! that downstream commits build on; there's no
//! `Monitor::builder()` constructor yet.

pub mod handler;

pub use handler::{Handler, PayloadCtx, PayloadOnly};
