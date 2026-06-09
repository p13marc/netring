//! TLS handshake aggregator marker — one synthesised event per
//! completed handshake.

use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

/// TLS handshake aggregator. Emits one
/// [`flowscope::tls::TlsHandshake`] per completed handshake,
/// carrying SNI / ALPN / optional JA3 / JA4 / version / cipher /
/// `resumption_attempted` / `HandshakeOutcome`.
///
/// Pairs with [`super::Tls`] — they run independent parser slots.
/// Most consumers want one or the other.
///
/// Default ports: 443, 8443.
#[derive(Debug, Clone, Copy)]
pub struct TlsHandshake;

impl Protocol for TlsHandshake {
    type Message = flowscope::tls::TlsHandshake;
    const NAME: &'static str = flowscope::parser_kinds::TLS_HANDSHAKE;

    fn dispatch() -> Dispatch {
        Dispatch::Tcp(vec![443, 8443])
    }

    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError> {
        Ok(ParserKind::Session(Box::new(
            flowscope::tls::TlsHandshakeParser::default(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_matches_flowscope_parser_kind() {
        assert_eq!(
            <TlsHandshake as Protocol>::NAME,
            flowscope::parser_kinds::TLS_HANDSHAKE
        );
    }

    #[test]
    fn parser_constructs_successfully() {
        assert!(matches!(
            <TlsHandshake as Protocol>::parser().unwrap(),
            ParserKind::Session(_)
        ));
    }
}
