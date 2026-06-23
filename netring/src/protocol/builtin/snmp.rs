use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// SNMP (UDP/161 query + 162 trap) passive metadata visibility (issue #30).
///
/// `on::<Snmp>(|m: &SnmpMessage, ctx|)` fires once per parsed datagram. `Snmp`
/// is a [`MessageProtocol`]; its flow lifecycle is the underlying UDP flow.
///
/// Each [`flowscope::snmp::SnmpMessage`] exposes the version (v1/v2c/v3), PDU
/// type (Get/Set/Trap/…), and — for v1/v2c — the **community string** sent in
/// cleartext, a classic credential-exposure and lateral-movement signal.
#[derive(Debug, Clone, Copy)]
pub struct Snmp;

impl MessageProtocol for Snmp {}

impl Protocol for Snmp {
    type Message = flowscope::snmp::SnmpMessage;
    // Matches flowscope's `snmp::PARSER_KIND` ("snmp").
    const NAME: &'static str = "snmp";

    fn dispatch() -> Dispatch {
        Dispatch::Udp(vec![
            flowscope::snmp::SNMP_PORT,
            flowscope::snmp::SNMP_TRAP_PORT,
        ])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Udp(p) => p,
            _ => unreachable!("Snmp::dispatch is Dispatch::Udp by construction"),
        };
        Ok(builder.datagram_on_ports(flowscope::snmp::SnmpParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_udp_161_162() {
        match Snmp::dispatch() {
            Dispatch::Udp(ports) => assert_eq!(ports, vec![161, 162]),
            other => panic!("expected Dispatch::Udp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(Snmp::NAME, flowscope::snmp::PARSER_KIND);
    }
}
