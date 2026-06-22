use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// SSDP / UPnP discovery (UDP/1900) passive metadata visibility — surfaces
/// IoT and consumer devices that announce themselves on the LAN (issue #28).
///
/// `on::<Ssdp>(|m: &SsdpMessage, ctx|)` fires once per parsed message.
/// `Ssdp` is a [`MessageProtocol`]; its flow lifecycle is the underlying UDP
/// flow.
///
/// Each [`flowscope::ssdp::SsdpMessage`] carries the `server` firmware banner,
/// the `location` description URL, the `usn` unique service name, and the
/// `st` / `nt` service-type vocabulary (`upnp:rootdevice`, `urn:schemas-…`).
#[derive(Debug, Clone, Copy)]
pub struct Ssdp;

impl MessageProtocol for Ssdp {}

impl Protocol for Ssdp {
    type Message = flowscope::ssdp::SsdpMessage;
    // Matches flowscope's `ssdp::PARSER_KIND` ("ssdp").
    const NAME: &'static str = "ssdp";

    fn dispatch() -> Dispatch {
        Dispatch::Udp(vec![flowscope::ssdp::SSDP_MULTICAST_PORT])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Udp(p) => p,
            _ => unreachable!("Ssdp::dispatch is Dispatch::Udp by construction"),
        };
        Ok(builder.datagram_on_ports(flowscope::ssdp::SsdpParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_udp_1900() {
        match Ssdp::dispatch() {
            Dispatch::Udp(ports) => assert_eq!(ports, vec![1900]),
            other => panic!("expected Dispatch::Udp, got {other:?}"),
        }
    }

    #[test]
    fn name_is_ssdp() {
        assert_eq!(Ssdp::NAME, "ssdp");
    }
}
