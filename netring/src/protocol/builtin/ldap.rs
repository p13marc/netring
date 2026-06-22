use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError};

/// LDAP (TCP/389) passive metadata visibility — the directory-enumeration
/// channel behind BloodHound / GetUserSPNs (issue #29).
///
/// `on::<Ldap>(|m: &LdapMessage, ctx|)` fires once per parsed message.
/// `Ldap` is a [`MessageProtocol`]; its flow lifecycle is the underlying TCP
/// flow.
///
/// Each [`flowscope::ldap::LdapMessage`] carries the recon signals: the
/// `operation` (Bind / Search / …), `bind_auth_kind` (cleartext Simple bind
/// vs SASL/GSSAPI), `search_base` / `search_attributes`, the
/// `search_attributes_spn_query` flag (a `servicePrincipalName` request — the
/// GetUserSPNs / BloodHound prerequisite to Kerberoasting), and `result_code`
/// (invalid-credentials, insufficient-access).
///
/// Plaintext LDAP only; LDAPS (TCP/636) rides inside TLS and is visible via
/// [`Tls`](crate::protocol::builtin::Tls).
#[derive(Debug, Clone, Copy)]
pub struct Ldap;

impl MessageProtocol for Ldap {}

impl Protocol for Ldap {
    type Message = flowscope::ldap::LdapMessage;
    // Matches flowscope's `ldap::parser_kind()` ("ldap").
    const NAME: &'static str = "ldap";

    fn dispatch() -> Dispatch {
        Dispatch::Tcp(vec![flowscope::ldap::LDAP_PORT])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Tcp(p) => p,
            _ => unreachable!("Ldap::dispatch is Dispatch::Tcp by construction"),
        };
        Ok(builder.session_on_ports(flowscope::ldap::LdapParser::new(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_targets_tcp_389() {
        match Ldap::dispatch() {
            Dispatch::Tcp(ports) => assert_eq!(ports, vec![389]),
            other => panic!("expected Dispatch::Tcp, got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_kind() {
        assert_eq!(Ldap::NAME, flowscope::ldap::parser_kind());
    }
}
