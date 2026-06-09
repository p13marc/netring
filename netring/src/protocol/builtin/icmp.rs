//! ICMP message parser marker.

#[cfg(feature = "icmp")]
use flowscope::driver::{DriverBuilder, SlotHandle};
#[cfg(feature = "icmp")]
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, Protocol, ProtocolInitError};

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
}

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
