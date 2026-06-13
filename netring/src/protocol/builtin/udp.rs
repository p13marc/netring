//! UDP lifecycle marker.

use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, FlowProtocol, Protocol, ProtocolInitError};

/// UDP lifecycle marker. Registering this protocol enables
/// `FlowStarted<Udp>`, `FlowEnded<Udp>` typed events — no parser
/// slot is registered on flowscope's side because the central
/// flow tracker already emits UDP lifecycle events.
#[derive(Debug, Clone, Copy)]
pub struct Udp;

impl Protocol for Udp {
    type Message = ();
    const NAME: &'static str = "udp";

    fn dispatch() -> Dispatch {
        Dispatch::AllUdp
    }

    fn register(
        _builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        Err(ProtocolInitError(
            "Udp marker is lifecycle-only — no parser; \
             handled by the central flow tracker"
                .into(),
        ))
    }
}

// 0.22 R1: UDP is flow-tracked, not a message protocol.
impl FlowProtocol for Udp {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_is_all_udp() {
        assert!(matches!(<Udp as Protocol>::dispatch(), Dispatch::AllUdp));
    }

    #[test]
    fn register_returns_err_for_lifecycle_only_marker() {
        let mut b = flowscope::driver::Driver::builder(FiveTuple::bidirectional());
        assert!(<Udp as Protocol>::register(&mut b).is_err());
    }
}
