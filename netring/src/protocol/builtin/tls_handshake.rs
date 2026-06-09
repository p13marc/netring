//! TLS handshake aggregator marker — one synthesised event per
//! completed handshake.

use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, Protocol, ProtocolInitError};

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

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Tcp(p) => p,
            _ => unreachable!("TlsHandshake::dispatch is Dispatch::Tcp by construction"),
        };
        Ok(builder.session_on_ports(flowscope::tls::TlsHandshakeParser::default(), ports))
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
    fn register_returns_handle() {
        let mut b = flowscope::driver::Driver::builder(FiveTuple::bidirectional());
        let h = <TlsHandshake as Protocol>::register(&mut b);
        assert!(h.is_ok());
    }
}
