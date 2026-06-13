//! ICMP message parser marker.

#[cfg(feature = "icmp")]
use flowscope::driver::{DriverBuilder, SlotHandle};
#[cfg(feature = "icmp")]
use flowscope::extract::{FiveTuple, FiveTupleKey};

#[cfg(feature = "icmp")]
use crate::protocol::{Dispatch, FlowProtocol, MessageProtocol, Protocol, ProtocolInitError};

/// ICMPv4 + ICMPv6 message parser. Surfaces `IcmpMessage` events
/// including `inner: Option<IcmpInner>` on error variants — the
/// cross-protocol correlation primitive that ties an ICMP error
/// back to the originating TCP/UDP flow.
#[derive(Debug, Clone, Copy)]
pub struct Icmp;

#[cfg(feature = "icmp")]
impl Protocol for Icmp {
    type Message = flowscope::icmp::IcmpMessage;
    const NAME: &'static str = flowscope::parser_kinds::ICMP;

    fn dispatch() -> Dispatch {
        Dispatch::Icmp
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        Ok(builder.datagram_broadcast(flowscope::icmp::IcmpParser::new()))
    }

    /// 0.22 §2.5: ICMP installs an `IcmpSlot` (raw `IcmpMessage`
    /// forwarding **plus** `IcmpError` synthesis) instead of the
    /// generic `TypedProtocolSlot`.
    fn make_slot(
        handle: SlotHandle<Self::Message, FiveTupleKey>,
    ) -> Box<dyn crate::monitor::ProtocolSlot> {
        Box::new(crate::monitor::registry::IcmpSlot::new(handle))
    }
}

// 0.22 R1: ICMP is *both* flow-tracked (the tracker follows ICMP
// echo + error 5-tuples → `FlowStarted<Icmp>` / `FlowPacket`) and a
// message protocol (`on::<Icmp>` fires `IcmpMessage`).
#[cfg(feature = "icmp")]
impl FlowProtocol for Icmp {}
#[cfg(feature = "icmp")]
impl MessageProtocol for Icmp {}

#[cfg(all(test, feature = "icmp"))]
mod tests {
    use super::*;

    #[test]
    fn dispatch_is_icmp() {
        assert!(matches!(<Icmp as Protocol>::dispatch(), Dispatch::Icmp));
    }

    #[test]
    fn name_matches_flowscope_parser_kind() {
        assert_eq!(<Icmp as Protocol>::NAME, flowscope::parser_kinds::ICMP);
    }

    #[test]
    fn register_returns_handle() {
        let mut b = flowscope::driver::Driver::builder(FiveTuple::bidirectional());
        let h = <Icmp as Protocol>::register(&mut b);
        assert!(h.is_ok());
    }
}
