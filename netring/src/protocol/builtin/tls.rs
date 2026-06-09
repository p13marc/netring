//! TLS message-granularity parser marker.

use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

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

    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError> {
        Ok(ParserKind::Session(Box::new(
            flowscope::tls::TlsParser::default(),
        )))
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
}
