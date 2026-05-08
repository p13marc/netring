//! Parser tests using hand-crafted DNS messages.

use netring_flow_dns::{DnsParseResult, DnsRcode, parse_message};

/// Wire-format DNS A query for `example.com`, transaction ID 0x1234.
fn build_a_query(tx_id: u16, qname: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&tx_id.to_be_bytes());
    v.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query, RD
    v.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    v.extend_from_slice(&0u16.to_be_bytes()); // ancount
    v.extend_from_slice(&0u16.to_be_bytes()); // nscount
    v.extend_from_slice(&0u16.to_be_bytes()); // arcount
    encode_qname(&mut v, qname);
    v.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    v.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    v
}

fn build_a_response(tx_id: u16, qname: &str, addr: [u8; 4]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&tx_id.to_be_bytes());
    v.extend_from_slice(&0x8180u16.to_be_bytes()); // response, RA
    v.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    v.extend_from_slice(&1u16.to_be_bytes()); // ancount
    v.extend_from_slice(&0u16.to_be_bytes()); // nscount
    v.extend_from_slice(&0u16.to_be_bytes()); // arcount
    encode_qname(&mut v, qname);
    v.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    v.extend_from_slice(&1u16.to_be_bytes()); // qclass IN

    encode_qname(&mut v, qname);
    v.extend_from_slice(&1u16.to_be_bytes()); // type A
    v.extend_from_slice(&1u16.to_be_bytes()); // class IN
    v.extend_from_slice(&60u32.to_be_bytes()); // TTL
    v.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    v.extend_from_slice(&addr);
    v
}

fn build_nxdomain(tx_id: u16, qname: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&tx_id.to_be_bytes());
    v.extend_from_slice(&0x8183u16.to_be_bytes()); // response, NXDOMAIN (rcode=3)
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    encode_qname(&mut v, qname);
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v
}

fn encode_qname(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}

#[test]
fn parses_a_query() {
    let bytes = build_a_query(0x1234, "example.com");
    match parse_message(&bytes).unwrap() {
        DnsParseResult::Query(q) => {
            assert_eq!(q.transaction_id, 0x1234);
            assert_eq!(q.questions.len(), 1);
            assert_eq!(q.questions[0].name, "example.com");
            assert!(q.flags.is_recursion_desired());
            assert!(!q.flags.is_response());
        }
        _ => panic!("expected Query"),
    }
}

#[test]
fn parses_a_response_with_address() {
    use netring_flow_dns::DnsRdata;
    let bytes = build_a_response(0x5678, "rust-lang.org", [192, 0, 2, 1]);
    match parse_message(&bytes).unwrap() {
        DnsParseResult::Response(r) => {
            assert_eq!(r.transaction_id, 0x5678);
            assert_eq!(r.rcode, DnsRcode::NoError);
            assert!(r.flags.is_response());
            assert_eq!(r.answers.len(), 1);
            match &r.answers[0].data {
                DnsRdata::A(addr) => {
                    assert_eq!(addr.octets(), [192, 0, 2, 1]);
                }
                other => panic!("expected A, got {other:?}"),
            }
        }
        _ => panic!("expected Response"),
    }
}

#[test]
fn parses_nxdomain() {
    let bytes = build_nxdomain(0x9abc, "does-not-exist.invalid");
    match parse_message(&bytes).unwrap() {
        DnsParseResult::Response(r) => {
            assert_eq!(r.rcode, DnsRcode::NXDomain);
            assert_eq!(r.answers.len(), 0);
        }
        _ => panic!("expected Response"),
    }
}

#[test]
fn malformed_returns_error() {
    assert!(parse_message(b"").is_err());
    assert!(parse_message(b"\x00\x00").is_err()); // too short
}

#[test]
fn correlator_matches_query_response() {
    use netring_flow::Timestamp;
    use netring_flow_dns::Correlator;
    let mut c = Correlator::<u32>::new();

    // Record query at t=0
    let q_bytes = build_a_query(42, "example.com");
    let q = match netring_flow_dns::parse_message_at(&q_bytes, Timestamp::new(0, 0)).unwrap() {
        DnsParseResult::Query(q) => q,
        _ => unreachable!(),
    };
    c.record_query(7u32, q);
    assert_eq!(c.pending_len(), 1);

    // Match response at t=1.5s
    let matched = c.match_response(&7u32, 42, Timestamp::new(1, 500_000_000));
    assert!(matched.is_some());
    let (_q, elapsed) = matched.unwrap();
    assert_eq!(elapsed.as_secs(), 1);
    assert_eq!(elapsed.subsec_millis(), 500);
    assert_eq!(c.pending_len(), 0);
}

#[test]
fn correlator_orphan_response() {
    use netring_flow::Timestamp;
    use netring_flow_dns::Correlator;
    let mut c = Correlator::<u32>::new();
    let matched = c.match_response(&7u32, 999, Timestamp::new(0, 0));
    assert!(matched.is_none());
}

#[test]
fn correlator_sweep_flags_unanswered() {
    use netring_flow::Timestamp;
    use netring_flow_dns::Correlator;
    let mut c = Correlator::<u32>::new();
    let q_bytes = build_a_query(99, "slow.example");
    let q = match netring_flow_dns::parse_message_at(&q_bytes, Timestamp::new(0, 0)).unwrap() {
        DnsParseResult::Query(q) => q,
        _ => unreachable!(),
    };
    c.record_query(7u32, q);
    // 31 seconds later — past the default 30 s timeout.
    let expired = c.sweep(Timestamp::new(31, 0));
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].transaction_id, 99);
}
