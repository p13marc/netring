//! HTTP/1.x protocol marker.

use flowscope::driver::{BroadcastSlotHandle, DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, Protocol, ProtocolInitError};

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

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Tcp(p) => p,
            _ => unreachable!("Http::dispatch is Dispatch::Tcp by construction"),
        };
        Ok(builder.session_on_ports(flowscope::http::HttpParser::default(), ports))
    }

    fn register_broadcast(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<BroadcastSlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        let ports = match Self::dispatch() {
            Dispatch::Tcp(p) => p,
            _ => unreachable!("Http::dispatch is Dispatch::Tcp by construction"),
        };
        Ok(builder.session_on_ports_broadcast_each(flowscope::http::HttpParser::default(), ports))
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
    fn register_returns_handle() {
        let mut b = flowscope::driver::Driver::builder(FiveTuple::bidirectional());
        let h = <Http as Protocol>::register(&mut b);
        assert!(h.is_ok());
    }
}
