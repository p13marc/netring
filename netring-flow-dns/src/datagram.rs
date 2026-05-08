//! [`DnsUdpParser`] — `DatagramParser` impl that surfaces DNS
//! query/response messages.
//!
//! Pair with `netring::FlowStream::datagram_stream(...)` for an
//! async iterator API. For the callback-style "tap on top of an
//! existing extractor" integration, see [`crate::DnsUdpObserver`].

use netring_flow::{DatagramParser, FlowSide};

use crate::parser::{DnsParseResult, parse_message};
use crate::types::{DnsQuery, DnsResponse};

/// Unified message type emitted by [`DnsUdpParser`].
#[derive(Debug, Clone)]
pub enum DnsMessage {
    Query(DnsQuery),
    Response(DnsResponse),
}

/// Per-flow parser. Stateless w.r.t. across-packet correlation —
/// each datagram is parsed independently. For query/response RTT
/// matching, see [`crate::Correlator`] (used by [`crate::DnsUdpObserver`]).
#[derive(Debug, Default, Clone)]
pub struct DnsUdpParser;

impl DatagramParser for DnsUdpParser {
    type Message = DnsMessage;

    fn parse(&mut self, payload: &[u8], _side: FlowSide) -> Vec<DnsMessage> {
        match parse_message(payload) {
            Ok(DnsParseResult::Query(q)) => vec![DnsMessage::Query(q)],
            Ok(DnsParseResult::Response(r)) => vec![DnsMessage::Response(r)],
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_a_query(tx_id: u16, qname: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&tx_id.to_be_bytes());
        v.extend_from_slice(&0x0100u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        for label in qname.split('.') {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v
    }

    #[test]
    fn parses_query() {
        let mut p = DnsUdpParser;
        let bytes = build_a_query(0xabcd, "example.com");
        let msgs = p.parse(&bytes, FlowSide::Initiator);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            DnsMessage::Query(q) => assert_eq!(q.transaction_id, 0xabcd),
            _ => panic!("expected Query"),
        }
    }

    #[test]
    fn malformed_returns_empty() {
        let mut p = DnsUdpParser;
        let msgs = p.parse(b"\x00", FlowSide::Initiator);
        assert!(msgs.is_empty());
    }
}
