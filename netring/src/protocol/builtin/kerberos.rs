use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// Kerberos (TCP/88) passive metadata visibility — AS-REQ / TGS-REQ /
/// AP-REQ and KRB-ERROR responses (issue #29).
///
/// `on::<Kerberos>(|m: &KerberosMessage, ctx|)` fires once per parsed
/// message. `Kerberos` is a [`MessageProtocol`]; its flow lifecycle is the
/// underlying TCP flow.
///
/// Each [`flowscope::kerberos::KerberosMessage`] surfaces the AD attack
/// signals: `kerberoast_suspect` (TGS-REQ negotiating RC4-HMAC, T1558.003),
/// the offered `etypes` (downgrade to DES/RC4), `cname` / `sname` / `realm`,
/// and `error_code` (pre-auth-failed / principal-unknown — password-spray and
/// enumeration tells).
///
/// This surfaces the **TCP** parser ([`flowscope::kerberos::KerberosTcpParser`]),
/// the path modern Windows uses for any ticket large enough to exceed the UDP
/// datagram limit. UDP/88 (small AS-REQ) is a follow-up.
#[derive(Debug, Clone, Copy)]
pub struct Kerberos;

impl MessageProtocol for Kerberos {}

impl Protocol for Kerberos {
    type Message = flowscope::kerberos::KerberosMessage;
    // Matches flowscope's `kerberos::parser_kind()` ("kerberos").
    const NAME: &'static str = "kerberos";

    fn dispatch() -> Dispatch {
        Dispatch::Tcp(vec![flowscope::kerberos::KERBEROS_PORT])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Tcp(p) => p,
            _ => unreachable!("Kerberos::dispatch is Dispatch::Tcp by construction"),
        };
        Ok(builder.session_on_ports(flowscope::kerberos::KerberosTcpParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_tcp_88() {
        match Kerberos::dispatch() {
            Dispatch::Tcp(ports) => assert_eq!(ports, vec![88]),
            other => panic!("expected Dispatch::Tcp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(Kerberos::NAME, flowscope::kerberos::parser_kind());
    }
}
