use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// NetBIOS Name Service / NBT-NS (UDP/137) passive metadata visibility — a
/// legacy Windows asset-discovery (and spoofing) channel (issue #28).
///
/// `on::<Nbns>(|m: &NbnsMessage, ctx|)` fires once per parsed message.
/// `Nbns` is a [`MessageProtocol`]; its flow lifecycle is the underlying UDP
/// flow.
///
/// Each [`flowscope::netbios_ns::NbnsMessage`] surfaces the `queried_name`
/// (and `name_suffix` host-type byte), the `opcode` (Query / Registration /
/// Release), and `answer_addresses` — the inputs an asset inventory uses to
/// learn hostnames, and that a defender watches for NBT-NS poisoning.
#[derive(Debug, Clone, Copy)]
pub struct Nbns;

impl MessageProtocol for Nbns {}

impl Protocol for Nbns {
    type Message = flowscope::netbios_ns::NbnsMessage;
    // Matches flowscope's `netbios_ns::PARSER_KIND` ("netbios-ns").
    const NAME: &'static str = "netbios-ns";

    fn dispatch() -> Dispatch {
        Dispatch::Udp(vec![flowscope::netbios_ns::NBNS_PORT])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Udp(p) => p,
            _ => unreachable!("Nbns::dispatch is Dispatch::Udp by construction"),
        };
        Ok(builder.datagram_on_ports(flowscope::netbios_ns::NbnsParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_udp_137() {
        match Nbns::dispatch() {
            Dispatch::Udp(ports) => assert_eq!(ports, vec![137]),
            other => panic!("expected Dispatch::Udp, got {other:?}"),
        }
    }

    #[test]
    fn name_is_netbios_ns() {
        assert_eq!(Nbns::NAME, "netbios-ns");
    }
}
