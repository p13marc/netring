//! TCP lifecycle marker.

use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, FlowProtocol, Protocol, ProtocolInitError};

/// TCP lifecycle marker. Registering this protocol enables
/// `FlowStarted<Tcp>`, `FlowEstablished<Tcp>`, `FlowEnded<Tcp>`
/// typed events — no parser slot is registered on flowscope's
/// side because the central flow tracker already emits TCP
/// lifecycle events.
#[derive(Debug, Clone, Copy)]
pub struct Tcp;

impl Protocol for Tcp {
    type Message = ();
    const NAME: &'static str = "tcp";

    fn dispatch() -> Dispatch {
        Dispatch::AllTcp
    }

    fn register(
        _builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        Err(ProtocolInitError::new(
            "Tcp marker is lifecycle-only — no parser; \
             handled by the central flow tracker",
        ))
    }
}

// 0.22 R1: TCP is flow-tracked (lifecycle + FlowPacket), not a
// message protocol — `on::<Tcp>` is a type error, use
// `on::<FlowStarted<Tcp>>` etc.
impl FlowProtocol for Tcp {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_is_all_tcp() {
        assert!(matches!(<Tcp as Protocol>::dispatch(), Dispatch::AllTcp));
    }

    #[test]
    fn register_returns_err_for_lifecycle_only_marker() {
        let mut b = flowscope::driver::Driver::builder(FiveTuple::bidirectional());
        assert!(<Tcp as Protocol>::register(&mut b).is_err());
    }

    #[test]
    fn name_is_stable_slug() {
        assert_eq!(<Tcp as Protocol>::NAME, "tcp");
    }
}
