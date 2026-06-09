//! The 0.20 declarative monitor — `Monitor::builder().on::<E>(handler).build()`.
//!
//! Phase B lands this module in pieces:
//! - B.2: [`Handler`] trait + blanket impls (`PayloadOnly` / `PayloadCtx`)
//! - B.3 (this commit): [`Dispatcher`] + [`HandlerRegistry`] +
//!   [`TypedProtocolSlot`]
//! - B.4: `Monitor` + `MonitorBuilder` + run loop + tick stub
//!
//! Until B.4 lands, this module exposes only the type machinery
//! that downstream commits build on; there's no
//! `Monitor::builder()` constructor yet.

pub mod dispatcher;
pub mod handler;
pub mod registry;

pub use dispatcher::{Dispatcher, MAX_EVENT_TYPES};
pub use handler::{Handler, PayloadCtx, PayloadOnly};
pub use registry::{HandlerRegistry, ProtocolSlot, TypedProtocolSlot};
