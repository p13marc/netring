//! DNS message parsing on top of `simple-dns`.

use std::net::{Ipv4Addr, Ipv6Addr};

use simple_dns::Packet;
use simple_dns::ResourceRecord;
use simple_dns::rdata::RData;

use crate::types::{DnsFlags, DnsQuery, DnsQuestion, DnsRcode, DnsRdata, DnsRecord, DnsResponse};
use netring_flow::Timestamp;

/// Outcome of [`parse_message`].
#[derive(Debug, Clone)]
pub enum DnsParseResult {
    Query(DnsQuery),
    Response(DnsResponse),
}

/// Parse one DNS UDP payload into a [`DnsQuery`] or [`DnsResponse`].
///
/// `timestamp` is attached to the resulting event. `elapsed` is
/// always `None` here — that field is filled by [`crate::Correlator`]
/// when the response is matched against a previously-seen query.
pub fn parse_message(payload: &[u8]) -> Result<DnsParseResult, crate::Error> {
    parse_message_at(payload, Timestamp::default())
}

/// Same as [`parse_message`] but lets you set the event timestamp.
pub fn parse_message_at(
    payload: &[u8],
    timestamp: Timestamp,
) -> Result<DnsParseResult, crate::Error> {
    if payload.len() < 12 {
        return Err(crate::Error::Parse("payload < 12 bytes".into()));
    }

    // Header word (16 bits at offset 2) — we read flags + rcode
    // straight from the wire to avoid juggling simple-dns's
    // RCODE/OPCODE conversion plumbing.
    let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags_raw = u16::from_be_bytes([payload[2], payload[3]]);
    let flags = DnsFlags(flags_raw);
    let rcode_raw = (flags_raw & 0x000F) as u8;

    let pkt = Packet::parse(payload).map_err(|e| crate::Error::Parse(format!("{e:?}")))?;

    let questions = pkt
        .questions
        .iter()
        .map(|q| DnsQuestion {
            name: q.qname.to_string(),
            qtype: u16::from(q.qtype),
            qclass: u16::from(q.qclass),
        })
        .collect();

    if flags.is_response() {
        let answers = pkt.answers.iter().map(rr_to_record).collect();
        let authorities = pkt.name_servers.iter().map(rr_to_record).collect();
        let additionals = pkt.additional_records.iter().map(rr_to_record).collect();
        let rcode = DnsRcode::from_raw(rcode_raw);
        Ok(DnsParseResult::Response(DnsResponse {
            transaction_id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
            rcode,
            timestamp,
            elapsed: None,
        }))
    } else {
        Ok(DnsParseResult::Query(DnsQuery {
            transaction_id,
            flags,
            questions,
            timestamp,
        }))
    }
}

fn class_to_u16(c: simple_dns::CLASS) -> u16 {
    use simple_dns::CLASS;
    match c {
        CLASS::IN => 1,
        CLASS::CS => 2,
        CLASS::CH => 3,
        CLASS::HS => 4,
        CLASS::NONE => 254,
    }
}

fn rr_to_record(rr: &ResourceRecord<'_>) -> DnsRecord {
    let name = rr.name.to_string();
    let rclass = class_to_u16(rr.class);
    let ttl = rr.ttl;
    let (rtype, data) = rdata_to_ours(&rr.rdata);
    DnsRecord {
        name,
        rtype,
        rclass,
        ttl,
        data,
    }
}

/// Map the simple-dns RData enum to our owned DnsRdata.
fn rdata_to_ours(r: &RData<'_>) -> (u16, DnsRdata) {
    match r {
        RData::A(a) => (1, DnsRdata::A(Ipv4Addr::from(a.address))),
        RData::AAAA(a) => (28, DnsRdata::AAAA(Ipv6Addr::from(a.address))),
        RData::CNAME(c) => (5, DnsRdata::CNAME(c.0.to_string())),
        RData::NS(n) => (2, DnsRdata::NS(n.0.to_string())),
        RData::PTR(p) => (12, DnsRdata::PTR(p.0.to_string())),
        RData::MX(m) => (
            15,
            DnsRdata::MX {
                priority: m.preference,
                exchange: m.exchange.to_string(),
            },
        ),
        RData::TXT(_t) => {
            // simple-dns's TXT API returns key/value pairs; for
            // passive observation we surface the raw byte chunks.
            // Without a stable accessor, we render an empty list
            // here and tag the type code so users who need raw
            // strings can drop down to the wire bytes themselves.
            (16, DnsRdata::TXT(Vec::new()))
        }
        // Variants we don't decode get tagged with their type code
        // and an empty data buffer. Users who need the rdata can
        // re-parse the original UDP payload via simple-dns.
        other => {
            let rtype = match other {
                RData::SOA(_) => 6,
                RData::WKS(_) => 11,
                RData::HINFO(_) => 13,
                RData::MINFO(_) => 14,
                RData::SRV(_) => 33,
                RData::OPT(_) => 41,
                RData::DS(_) => 43,
                RData::RRSIG(_) => 46,
                RData::NSEC(_) => 47,
                RData::DNSKEY(_) => 48,
                RData::CAA(_) => 257,
                RData::SVCB(_) => 64,
                RData::HTTPS(_) => 65,
                RData::NULL(t, _) => *t,
                RData::Empty(_t) => 0,
                _ => 0,
            };
            (
                rtype,
                DnsRdata::Other {
                    rtype,
                    data: Vec::new(),
                },
            )
        }
    }
}
