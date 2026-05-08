use netring_flow::Timestamp;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Parsed DNS query observed on the wire.
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub transaction_id: u16,
    pub flags: DnsFlags,
    pub questions: Vec<DnsQuestion>,
    pub timestamp: Timestamp,
}

/// Parsed DNS response.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub transaction_id: u16,
    pub flags: DnsFlags,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
    pub rcode: DnsRcode,
    pub timestamp: Timestamp,
    /// Time elapsed since the matching query (if seen). `None` for
    /// orphan responses (no matching query in the correlator), or
    /// when running without a correlator.
    pub elapsed: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// One DNS resource record.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub data: DnsRdata,
}

/// Decoded record data for the common types we can render simply.
/// Everything else lands in [`DnsRdata::Other`].
#[derive(Debug, Clone)]
pub enum DnsRdata {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    NS(String),
    PTR(String),
    MX {
        priority: u16,
        exchange: String,
    },
    TXT(Vec<Vec<u8>>),
    /// Unparsed: raw bytes, with the original record type code.
    /// Useful for record types we don't decode (SOA, SRV, OPT,
    /// SVCB, HTTPS, DNSKEY, RRSIG, …).
    Other {
        rtype: u16,
        data: Vec<u8>,
    },
}

/// DNS response code (RFC 1035 §4.1.1, RFC 6895 for extended codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImpl,
    Refused,
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
    Other(u8),
}

impl DnsRcode {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NXDomain,
            4 => Self::NotImpl,
            5 => Self::Refused,
            6 => Self::YXDomain,
            7 => Self::YXRRSet,
            8 => Self::NXRRSet,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            other => Self::Other(other),
        }
    }
}

/// Flag/header bits from the DNS message header word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsFlags(pub u16);

impl DnsFlags {
    pub fn is_response(&self) -> bool {
        self.0 & 0x8000 != 0
    }
    pub fn is_authoritative(&self) -> bool {
        self.0 & 0x0400 != 0
    }
    pub fn is_truncated(&self) -> bool {
        self.0 & 0x0200 != 0
    }
    pub fn is_recursion_desired(&self) -> bool {
        self.0 & 0x0100 != 0
    }
    pub fn is_recursion_available(&self) -> bool {
        self.0 & 0x0080 != 0
    }
    /// 4-bit opcode field (RFC 1035 §4.1.1).
    pub fn opcode(&self) -> u8 {
        ((self.0 >> 11) & 0x0F) as u8
    }
    /// 4-bit RCODE field.
    pub fn rcode_raw(&self) -> u8 {
        (self.0 & 0x000F) as u8
    }
}

/// User implements this to receive parsed DNS events.
pub trait DnsHandler: Send + Sync + 'static {
    fn on_query(&self, _q: &DnsQuery) {}
    fn on_response(&self, _r: &DnsResponse) {}
    /// Called by [`crate::Correlator::sweep`] for queries that
    /// timed out without a matching response.
    fn on_unanswered(&self, _q: &DnsQuery) {}
}

/// Tunables for the DNS observer.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// How long to wait for a response before flagging as unanswered.
    /// Default: 30 s.
    pub query_timeout: Duration,
    /// Cap on pending queries in the correlator. Beyond this, oldest
    /// pending entries are dropped. Default: 10 000.
    pub max_pending: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            query_timeout: Duration::from_secs(30),
            max_pending: 10_000,
        }
    }
}
