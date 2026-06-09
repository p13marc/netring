//! TLS message-granularity parser marker.

use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, Protocol, ProtocolInitError};

/// TLS handshake observation at message granularity
/// (ClientHello / ServerHello / Alert). For one synthesised
/// event per completed handshake, use
/// [`super::TlsHandshake`](crate::protocol::builtin::TlsHandshake)
/// instead.
///
/// Default ports: 443, 8443.
#[derive(Debug, Clone, Copy)]
pub struct Tls;

impl Protocol for Tls {
    type Message = flowscope::tls::TlsMessage;
    const NAME: &'static str = flowscope::parser_kinds::TLS;

    fn dispatch() -> Dispatch {
        Dispatch::Tcp(vec![443, 8443])
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Tcp(p) => p,
            _ => unreachable!("Tls::dispatch is Dispatch::Tcp by construction"),
        };
        Ok(builder.session_on_ports(flowscope::tls::TlsParser::default(), ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_is_tcp_443_8443() {
        match <Tls as Protocol>::dispatch() {
            Dispatch::Tcp(ports) => assert_eq!(ports, vec![443, 8443]),
            other => panic!("expected Dispatch::Tcp([443,8443]), got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_parser_kind() {
        assert_eq!(<Tls as Protocol>::NAME, flowscope::parser_kinds::TLS);
    }

    #[test]
    fn register_returns_handle() {
        let mut b = flowscope::driver::Driver::builder(FiveTuple::bidirectional());
        let h = <Tls as Protocol>::register(&mut b);
        assert!(h.is_ok());
    }
}
