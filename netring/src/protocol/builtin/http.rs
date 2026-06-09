//! HTTP/1.x protocol marker.

use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

/// HTTP/1.x — RFC 7230 request/response over TCP.
///
/// Default ports: 80, 8080. Override by writing your own
/// `Protocol` impl in a downstream crate with the port set you
/// want — netring's plugin layer is open-ended.
#[derive(Debug, Clone, Copy)]
pub struct Http;

impl Protocol for Http {
    type Message = flowscope::http::HttpMessage;
    const NAME: &'static str = flowscope::parser_kinds::HTTP;

    fn dispatch() -> Dispatch {
        Dispatch::Tcp(vec![80, 8080])
    }

    fn parser() -> Result<ParserKind<Self::Message>, ProtocolInitError> {
        Ok(ParserKind::Session(Box::new(
            flowscope::http::HttpParser::default(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_is_tcp_80_8080() {
        match <Http as Protocol>::dispatch() {
            Dispatch::Tcp(ports) => assert_eq!(ports, vec![80, 8080]),
            other => panic!("expected Dispatch::Tcp([80,8080]), got {other:?}"),
        }
    }

    #[test]
    fn name_matches_flowscope_parser_kind() {
        assert_eq!(<Http as Protocol>::NAME, flowscope::parser_kinds::HTTP);
    }

    #[test]
    fn parser_constructs_successfully() {
        let p = <Http as Protocol>::parser();
        assert!(p.is_ok());
        assert!(matches!(p.unwrap(), ParserKind::Session(_)));
    }
}
