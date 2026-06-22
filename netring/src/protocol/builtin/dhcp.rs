use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// DHCP / BOOTP (UDP/67–68) passive metadata visibility — the richest
/// single asset-discovery signal on a LAN (issue #28).
///
/// `on::<Dhcp>(|m: &DhcpMessage, ctx|)` fires once per parsed message.
/// `Dhcp` is a [`MessageProtocol`]; its flow lifecycle is the underlying UDP
/// flow.
///
/// Each [`flowscope::dhcp::DhcpMessage`] ties a `client_mac` to its
/// `hostname` (option 12), `requested_ip` / `yiaddr`, `vendor_class`
/// (option 60), and `param_request_list` (option 55) — the inputs to a
/// Fingerbank-style OS/device fingerprint via
/// [`DhcpMessage::fingerprint`](flowscope::dhcp::DhcpMessage::fingerprint).
#[derive(Debug, Clone, Copy)]
pub struct Dhcp;

impl MessageProtocol for Dhcp {}

impl Protocol for Dhcp {
    type Message = flowscope::dhcp::DhcpMessage;
    // Matches flowscope's `dhcp::PARSER_KIND` ("dhcp").
    const NAME: &'static str = "dhcp";

    fn dispatch() -> Dispatch {
        // 67 = BOOTP server, 68 = BOOTP client.
        Dispatch::Udp(vec![67, 68])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Udp(p) => p,
            _ => unreachable!("Dhcp::dispatch is Dispatch::Udp by construction"),
        };
        Ok(builder.datagram_on_ports(flowscope::dhcp::DhcpParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_udp_bootp_ports() {
        match Dhcp::dispatch() {
            Dispatch::Udp(ports) => assert_eq!(ports, vec![67, 68]),
            other => panic!("expected Dispatch::Udp, got {other:?}"),
        }
    }

    #[test]
    fn name_is_dhcp() {
        assert_eq!(Dhcp::NAME, "dhcp");
    }
}
