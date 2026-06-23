use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// DNP3 (TCP/20000) passive metadata visibility (issue #30).
///
/// `on::<Dnp3>(|m: &DnpMessage, ctx|)` fires once per parsed link-layer frame.
/// `Dnp3` is a [`MessageProtocol`]; its flow lifecycle is the underlying TCP
/// flow.
///
/// Each [`flowscope::dnp3::DnpMessage`] exposes the source/destination link
/// addresses and the application function code — OT/ICS (electric / water SCADA)
/// visibility for unauthorized control operations and rogue DNP3 outstations.
#[derive(Debug, Clone, Copy)]
pub struct Dnp3;

impl MessageProtocol for Dnp3 {}

impl Protocol for Dnp3 {
    type Message = flowscope::dnp3::DnpMessage;
    // Matches flowscope's `dnp3::PARSER_KIND` ("dnp3").
    const NAME: &'static str = "dnp3";

    fn dispatch() -> Dispatch {
        Dispatch::Tcp(vec![flowscope::dnp3::DNP3_PORT])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Tcp(p) => p,
            _ => unreachable!("Dnp3::dispatch is Dispatch::Tcp by construction"),
        };
        Ok(builder.session_on_ports(flowscope::dnp3::DnpParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_tcp_20000() {
        match Dnp3::dispatch() {
            Dispatch::Tcp(ports) => assert_eq!(ports, vec![20000]),
            other => panic!("expected Dispatch::Tcp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(Dnp3::NAME, flowscope::dnp3::PARSER_KIND);
    }
}
