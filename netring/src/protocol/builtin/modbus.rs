use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// Modbus/TCP (TCP/502) passive metadata visibility (issue #30).
///
/// `on::<Modbus>(|m: &ModbusMessage, ctx|)` fires once per parsed PDU.
/// `Modbus` is a [`MessageProtocol`]; its flow lifecycle is the underlying TCP
/// flow.
///
/// Each [`flowscope::modbus::ModbusMessage`] exposes the unit id, function code
/// (read/write coils/registers, …), and address range — OT/ICS visibility for
/// spotting unauthorized writes to a PLC and rogue Modbus masters.
#[derive(Debug, Clone, Copy)]
pub struct Modbus;

impl MessageProtocol for Modbus {}

impl Protocol for Modbus {
    type Message = flowscope::modbus::ModbusMessage;
    // Matches flowscope's `modbus::PARSER_KIND` ("modbus").
    const NAME: &'static str = "modbus";

    fn dispatch() -> Dispatch {
        Dispatch::Tcp(vec![flowscope::modbus::MODBUS_PORT])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Tcp(p) => p,
            _ => unreachable!("Modbus::dispatch is Dispatch::Tcp by construction"),
        };
        Ok(builder.session_on_ports(flowscope::modbus::ModbusParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_tcp_502() {
        match Modbus::dispatch() {
            Dispatch::Tcp(ports) => assert_eq!(ports, vec![502]),
            other => panic!("expected Dispatch::Tcp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(Modbus::NAME, flowscope::modbus::PARSER_KIND);
    }
}
