//! [`IpfixExporter`] — a minimal IPFIX / NetFlow v10 ([RFC 7011]) flow
//! exporter (feature `ipfix`).
//!
//! The binary wire encoding is **delegated to flowscope's
//! [`ipfix::wire`](flowscope::ipfix::wire)** ([issue #33]) — flowscope owns
//! the IANA Information-Element registry, the canonical flow templates, and
//! the RFC 7011 Message assembly; netring owns the **I/O / transport rails**.
//! Each completed [`FlowRecord`] is mapped to flowscope's IE-keyed
//! [`FlowRecord`](flowscope::ipfix::FlowRecord), encoded by a
//! [`MessageBuilder`], and written to
//! a `W: Write + Send` — a UDP/TCP socket to a flow collector (nfdump, pmacct,
//! Elastiflow, …) or a file. The first message carries the **template sets**
//! (one for IPv4 flows, one for IPv6); every message carries a **data set**
//! with the flow's fields. Re-send templates periodically over lossy
//! transports with [`IpfixExporter::resend_templates_every`].
//!
//! ## Fields (canonical `FLOWSCOPE_TEMPLATE_FLOW_IPV4`/`_IPV6` templates)
//!
//! `protocolIdentifier` (4), `source`/`destinationTransportPort` (7/11),
//! `source`/`destinationIPv4Address` (8/12) or `…IPv6Address` (27/28),
//! `octetDeltaCount` (1) + `packetDeltaCount` (2) on the **initiator**
//! direction, `octetTotalCount` (85) + `packetTotalCount` (86) for both
//! directions summed, `flowStartMilliseconds` (152),
//! `flowEndMilliseconds` (153), `tcpControlBits` (6), `flowEndReason` (136).
//!
//! ## Semantics & limits
//!
//! - The delta counts (IE 1/2) carry the **initiator** direction; the total
//!   counts (IE 85/86) carry initiator + responder. A collector that wants
//!   per-direction (biflow, RFC 5103) responder counts needs a reverse-IE
//!   template — out of scope for the default templates.
//! - The delta counts are **since the flow's previous record**: a flow
//!   exported on the active timeout
//!   ([`MonitorBuilder::export_active_timeout`](crate::monitor::MonitorBuilder::export_active_timeout))
//!   reports only what is new in each interim and final record, so a
//!   collector summing deltas gets the flow's total; IE 85/86 stay running
//!   totals. The exporter keeps the last exported counters of each ongoing
//!   flow until its final record (an hour without a record drops them).
//! - `tcpControlBits` (IE 6) is emitted as `0`: flowscope's `FlowStats` does
//!   not accumulate per-flow TCP control flags, so there is no source to fill
//!   it (a flowscope dependency, not a netring gap). The IE stays in the
//!   template so the wire shape is the canonical one.
//! - The 5-state IE 136 `flowEndReason` collapses netring's 8-variant
//!   [`EndReason`]; the canonical record also keeps
//!   the un-collapsed reason in flowscope's `original_end_reason` shadow field
//!   (issue #33). Reach the canonical record via [`FlowRecord::to_ipfix_record`].
//! - Source/destination map to the record's `a`/`b` endpoints. With the
//!   default bidirectional extractor those are canonically ordered, not
//!   connection direction — use a directional extractor if "source =
//!   initiator" matters to your collector.
//! - One Data Record per Message; the IPFIX `sequenceNumber` is the
//!   cumulative count of Data Records sent (RFC 7011 §3.1), advanced by the
//!   data-record count after each write.
//! - `exportTime` is the flow's end time (deterministic; the flow just
//!   ended), not wall-clock at write.
//!
//! [RFC 7011]: https://www.rfc-editor.org/rfc/rfc7011
//! [issue #33]: https://github.com/p13marc/netring/issues/33

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};

use flowscope::event::EndReason;
use flowscope::ipfix::wire::{
    FLOWSCOPE_TEMPLATE_FLOW_IPV4, FLOWSCOPE_TEMPLATE_FLOW_IPV6, MessageBuilder,
    TEMPLATE_ID_FLOW_IPV4, TEMPLATE_ID_FLOW_IPV6, TemplateRegistry,
};
use flowscope::ipfix::{FlowEndReason, FlowRecord as IeFlowRecord};

use crate::export::{FlowExporter, FlowRecord};

/// IE 136 `flowEndReason` for a netring [`FlowRecord::reason`]. `None` (an
/// ongoing active-timeout snapshot) maps to `ActiveTimeout`; otherwise the
/// canonical [`FlowEndReason::from`] mapping owned by flowscope is used.
fn flow_end_reason(reason: Option<EndReason>) -> FlowEndReason {
    match reason {
        None => FlowEndReason::ActiveTimeout,
        Some(r) => FlowEndReason::from(r),
    }
}

/// L4 protocol number for the IP `protocolIdentifier` field — flowscope's
/// own mapping, which covers SCTP (132) and `Other(n)` (`n`) too.
fn protocol_number(proto: flowscope::L4Proto) -> u8 {
    proto.as_u8()
}

/// Milliseconds since the Unix epoch for a flowscope `Timestamp`.
fn ts_millis(ts: flowscope::Timestamp) -> u64 {
    (ts.to_unix_f64() * 1000.0) as u64
}

/// Map a netring [`FlowRecord`] onto flowscope's IANA-IE-keyed record.
///
/// `#[non_exhaustive]` forbids the struct-literal *expression* across crates,
/// but not field assignment on a `default()` value — so we build from
/// `default()` and set the fields the default templates reference. netring's
/// per-direction counters populate both the delta (IE 1/2) and total
/// (IE 85/86) IEs honestly.
fn to_ie_record(record: &FlowRecord) -> IeFlowRecord {
    let mut rec = IeFlowRecord::default();
    rec.protocol_identifier = protocol_number(record.proto);
    match record.a.ip() {
        IpAddr::V4(v4) => rec.source_ipv4_address = Some(v4),
        IpAddr::V6(v6) => rec.source_ipv6_address = Some(v6),
    }
    match record.b.ip() {
        IpAddr::V4(v4) => rec.destination_ipv4_address = Some(v4),
        IpAddr::V6(v6) => rec.destination_ipv6_address = Some(v6),
    }
    rec.source_transport_port = record.a.port();
    rec.destination_transport_port = record.b.port();
    rec.octet_delta_count_initiator = record.bytes_initiator;
    rec.octet_delta_count_responder = record.bytes_responder;
    rec.packet_delta_count_initiator = record.packets_initiator;
    rec.packet_delta_count_responder = record.packets_responder;
    rec.octet_total_count = record.total_bytes();
    rec.packet_total_count = record.total_packets();
    rec.flow_start_milliseconds = ts_millis(record.start);
    rec.flow_end_milliseconds = ts_millis(record.end);
    rec.flow_end_reason = Some(flow_end_reason(record.reason));
    // Preserve netring's full end-reason fidelity (issue #33): IE 136
    // `flowEndReason` above collapses to 5 RFC states, so the canonical record
    // also keeps the un-collapsed 8-variant `EndReason` in flowscope's
    // `original_end_reason` shadow field — flowscope added it precisely so this
    // distinction (Fin vs Rst vs ParseError vs Evicted vs …) survives for
    // consumers reading the IE record directly. `None` (an ongoing
    // active-timeout snapshot) stays `None` here, mirroring `flow_end_reason`'s
    // `ActiveTimeout`.
    rec.original_end_reason = record.reason;
    // Carry the Community ID onto the canonical IE record for faithfulness
    // (issue #33). It does **not** ride the wire under the default
    // `FLOWSCOPE_TEMPLATE_FLOW_IPV4`/`_IPV6` templates — Community ID is not an
    // IANA IE — so this is a no-op for the emitted bytes today; it keeps the
    // mapping honest for any future template that adds an enterprise IE for it.
    rec.community_id = record.community_id.clone();
    rec
}

impl FlowRecord {
    /// View this record as flowscope's canonical, **IANA-IE-keyed**
    /// [`ipfix::FlowRecord`](flowscope::ipfix::FlowRecord) — the single
    /// flow-record shape every flowscope emitter (IPFIX wire, CSV, Zeek
    /// `conn.log`, NDJSON) renders from (issue #33).
    ///
    /// netring keeps its own ergonomic [`FlowRecord`] as the stable public type
    /// (so the core API isn't bound to flowscope's IE registry), and this is the
    /// opt-in bridge for code that wants the canonical record — e.g. to drive a
    /// flowscope IE-writer other than netring's [`IpfixExporter`]. The mapping is
    /// the same one `IpfixExporter` uses on the wire: per-direction delta counts
    /// (IE 1/2) + both-direction totals (IE 85/86), `flowEndReason` (IE 136)
    /// **plus** the un-collapsed `original_end_reason` shadow, and the Community
    /// ID. `tcpControlBits` is left unset — flowscope's `FlowStats` does not
    /// accumulate per-flow TCP flags, so there is no source for it (a flowscope
    /// dependency, not a netring gap).
    pub fn to_ipfix_record(&self) -> IeFlowRecord {
        to_ie_record(self)
    }
}

/// The flow a record belongs to.
fn flow_id(record: &FlowRecord) -> FlowId {
    (record.proto, record.a, record.b, record.start)
}

/// The flowscope template ID for a record, chosen by IP family.
fn template_id(record: &FlowRecord) -> u16 {
    match record.a.ip() {
        IpAddr::V4(_) => TEMPLATE_ID_FLOW_IPV4,
        IpAddr::V6(_) => TEMPLATE_ID_FLOW_IPV6,
    }
}

/// One flow across its records: the tuple and its start (a later flow on
/// the same tuple starts afresh).
type FlowId = (
    flowscope::L4Proto,
    SocketAddr,
    SocketAddr,
    flowscope::Timestamp,
);

/// The counters an ongoing flow's last exported (active-timeout) record
/// carried — the baseline of its next delta counts.
#[derive(Debug, Clone, Copy)]
struct Exported {
    bytes_initiator: u64,
    bytes_responder: u64,
    packets_initiator: u64,
    packets_responder: u64,
    /// The record's `end`, to forget flows that never get a final record.
    at: flowscope::Timestamp,
}

/// A baseline not refreshed for this long (record time) is dropped — its
/// flow is long gone without a final record. A floor: the threshold also
/// grows to 3× the longest interval seen between two records of a flow,
/// so a long active timeout keeps its baselines. (Final records remove
/// theirs, so this only catches flows that never got one.)
const BASELINE_STALE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Baselines kept before the first stale-entry sweep.
const BASELINE_PRUNE_MIN: usize = 1024;

/// An IPFIX flow exporter. See the [module docs](self).
pub struct IpfixExporter<W: Write + Send> {
    writer: W,
    /// Holds the registered IPv4 + IPv6 flow templates; lent to each
    /// per-message [`MessageBuilder`].
    registry: TemplateRegistry,
    /// Cumulative Data Records emitted — the IPFIX sequence number.
    records_sent: u32,
    /// Re-send the template sets once this many records have gone by
    /// since the last template (0 = only in the very first message).
    resend_every: u32,
    /// Records since templates were last included.
    since_template: u32,
    /// Whether templates have been sent at least once.
    template_sent: bool,
    /// Ongoing flows → the counters their last record carried. Removed
    /// with the final record; stale ones are swept.
    exported: HashMap<FlowId, Exported>,
    /// Map size that triggers the next stale-baseline sweep.
    prune_at: usize,
    /// Longest interval seen between two records of one flow (record
    /// time) — the sweep keeps baselines at least 3× this old.
    longest_interval: std::time::Duration,
}

impl<W: Write + Send> IpfixExporter<W> {
    /// Wrap `writer` with the given observation domain ID (identifies the
    /// exporting process to the collector).
    pub fn new(writer: W, observation_domain_id: u32) -> Self {
        let mut registry = TemplateRegistry::new(observation_domain_id);
        registry.register(FLOWSCOPE_TEMPLATE_FLOW_IPV4.clone());
        registry.register(FLOWSCOPE_TEMPLATE_FLOW_IPV6.clone());
        Self {
            writer,
            registry,
            records_sent: 0,
            resend_every: 0,
            since_template: 0,
            template_sent: false,
            exported: HashMap::new(),
            prune_at: BASELINE_PRUNE_MIN,
            longest_interval: std::time::Duration::ZERO,
        }
    }

    /// Re-send the template sets every `n` flow records (recommended over
    /// lossy UDP transport so a collector that missed the first templates
    /// can recover). `0` (the default) sends templates only once.
    pub fn resend_templates_every(mut self, n: u32) -> Self {
        self.resend_every = n;
        self
    }

    /// Consume and recover the inner writer (tests read back the bytes).
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Whether the next message should carry the template sets.
    fn want_templates(&self) -> bool {
        !self.template_sent || (self.resend_every != 0 && self.since_template >= self.resend_every)
    }

    /// The IE record for `record`, its delta counts (IE 1/2) relative to
    /// the flow's previous record: IANA's `octetDeltaCount` /
    /// `packetDeltaCount` count "since the previous report for this Flow".
    /// Active-timeout records carry cumulative counters, so without this a
    /// collector summing deltas would count a long flow once per interim
    /// record. The totals (IE 85/86) stay cumulative.
    fn delta_record(&self, record: &FlowRecord) -> IeFlowRecord {
        let mut rec = to_ie_record(record);
        if let Some(prev) = self.exported.get(&flow_id(record)) {
            rec.octet_delta_count_initiator =
                record.bytes_initiator.saturating_sub(prev.bytes_initiator);
            rec.octet_delta_count_responder =
                record.bytes_responder.saturating_sub(prev.bytes_responder);
            rec.packet_delta_count_initiator = record
                .packets_initiator
                .saturating_sub(prev.packets_initiator);
            rec.packet_delta_count_responder = record
                .packets_responder
                .saturating_sub(prev.packets_responder);
        }
        rec
    }

    /// Track `record` (just sent) as the baseline of its flow's next
    /// record: kept for an ongoing flow, dropped with the final record.
    fn remember(&mut self, record: &FlowRecord) {
        let id = flow_id(record);
        if !record.is_ongoing() {
            self.exported.remove(&id);
            return;
        }
        if let Some(prev) = self.exported.get(&id) {
            let interval = record.end.saturating_sub(prev.at);
            self.longest_interval = self.longest_interval.max(interval);
        }
        if self.exported.len() >= self.prune_at {
            let now = record.end;
            let stale = BASELINE_STALE.max(self.longest_interval.saturating_mul(3));
            self.exported
                .retain(|_, e| now.saturating_sub(e.at) <= stale);
            self.prune_at = (self.exported.len() * 2).max(BASELINE_PRUNE_MIN);
        }
        self.exported.insert(
            id,
            Exported {
                bytes_initiator: record.bytes_initiator,
                bytes_responder: record.bytes_responder,
                packets_initiator: record.packets_initiator,
                packets_responder: record.packets_responder,
                at: record.end,
            },
        );
    }

    /// Encode one flow record into a complete RFC 7011 message, delegating
    /// the wire format to flowscope. `None` on an encode error (logged; the
    /// fixed templates make this unreachable in practice).
    fn encode_message(&self, record: &FlowRecord, include_templates: bool) -> Option<Vec<u8>> {
        let export_time = (ts_millis(record.end) / 1000) as u32;
        let mut msg = MessageBuilder::new(&self.registry, self.records_sent, export_time);
        if include_templates
            && let Err(e) = msg.add_template_set(&[TEMPLATE_ID_FLOW_IPV4, TEMPLATE_ID_FLOW_IPV6])
        {
            eprintln!("IpfixExporter: template set encode failed: {e}");
            return None;
        }
        let ie_record = self.delta_record(record);
        if let Err(e) = msg.add_data_record(&ie_record, template_id(record)) {
            eprintln!("IpfixExporter: data record encode failed: {e}");
            return None;
        }
        match msg.finalize() {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                eprintln!("IpfixExporter: message finalize failed: {e}");
                None
            }
        }
    }
}

impl<W: Write + Send> FlowExporter for IpfixExporter<W> {
    fn export(&mut self, record: &FlowRecord) {
        let include_templates = self.want_templates();

        let Some(bytes) = self.encode_message(record, include_templates) else {
            return;
        };

        // Swallow write errors like the other shipped sinks (broken stdout /
        // socket is operator-recoverable, not a panic).
        if self.writer.write_all(&bytes).is_ok() {
            // One Data Record per message → sequenceNumber advances by 1
            // (RFC 7011 §3.1: by Data-Record count, not message count).
            self.records_sent = self.records_sent.wrapping_add(1);
            if include_templates {
                self.template_sent = true;
                self.since_template = 0;
            } else {
                self.since_template = self.since_template.wrapping_add(1);
            }
            // Only a record the collector got moves the delta baseline.
            self.remember(record);
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::FlowKey;
    use flowscope::event::FlowStats;
    use flowscope::ipfix::wire::{IPFIX_VERSION, MESSAGE_HEADER_LEN, SET_ID_TEMPLATE};
    use flowscope::{L4Proto, Timestamp};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn v4_record() -> FlowRecord {
        let key = FlowKey::new(
            L4Proto::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
        );
        let mut s = FlowStats::default();
        s.packets_initiator = 5;
        s.packets_responder = 5;
        s.bytes_initiator = 400;
        s.bytes_responder = 600;
        s.started = Timestamp::from_unix_f64(1000.0);
        s.last_seen = Timestamp::from_unix_f64(1002.0);
        FlowRecord::from_ended(&key, &s, EndReason::Fin)
    }

    /// Read the big-endian `u16` at `off` in an IPFIX message.
    fn be16(bytes: &[u8], off: usize) -> u16 {
        u16::from_be_bytes([bytes[off], bytes[off + 1]])
    }
    fn be32(bytes: &[u8], off: usize) -> u32 {
        u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
    }

    #[test]
    fn end_reason_and_protocol_maps() {
        // Ongoing snapshot (reason = None) → active timeout.
        assert_eq!(flow_end_reason(None), FlowEndReason::ActiveTimeout);
        // FIN → end-of-flow-detected (the canonical flowscope mapping).
        assert_eq!(
            flow_end_reason(Some(EndReason::Fin)),
            FlowEndReason::EndOfFlowDetected
        );
        assert_eq!(protocol_number(L4Proto::Tcp), 6);
        assert_eq!(protocol_number(L4Proto::Udp), 17);
    }

    /// `protocolIdentifier` is the IP protocol number for every L4
    /// protocol, not 0 for the ones without a named arm.
    #[test]
    fn protocol_identifier_covers_sctp_and_other() {
        assert_eq!(protocol_number(L4Proto::Sctp), 132);
        assert_eq!(protocol_number(L4Proto::Other(47)), 47);
        assert_eq!(protocol_number(L4Proto::IcmpV6), 58);
    }

    #[test]
    fn ie_record_carries_directional_and_total_counts() {
        let rec = to_ie_record(&v4_record());
        assert_eq!(rec.protocol_identifier, 6);
        assert_eq!(rec.source_ipv4_address, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(
            rec.destination_ipv4_address,
            Some(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(rec.source_transport_port, 1234);
        assert_eq!(rec.destination_transport_port, 80);
        // Per-direction deltas (IE 1/2) populated from netring's counters …
        assert_eq!(rec.octet_delta_count_initiator, 400);
        assert_eq!(rec.octet_delta_count_responder, 600);
        assert_eq!(rec.packet_delta_count_initiator, 5);
        assert_eq!(rec.packet_delta_count_responder, 5);
        // … and the totals (IE 85/86) are both directions summed.
        assert_eq!(rec.octet_total_count, 1000);
        assert_eq!(rec.packet_total_count, 10);
        assert_eq!(rec.flow_end_reason, Some(FlowEndReason::EndOfFlowDetected));
        // Issue #33: the Community ID carries onto the canonical IE record
        // (faithfulness — even though the default templates don't encode it).
        assert!(
            rec.community_id
                .as_deref()
                .is_some_and(|c| c.starts_with("1:"))
        );
        // Issue #33: the full 8-variant EndReason survives in the shadow field.
        assert_eq!(rec.original_end_reason, Some(EndReason::Fin));
    }

    #[test]
    fn original_end_reason_preserves_fidelity_ie136_collapses() {
        // `ParseError` and `Evicted` both collapse to one IE-136 state, but the
        // canonical record keeps them distinct in `original_end_reason` — the
        // whole point of the shadow field (issue #33).
        let key = FlowKey::new(
            L4Proto::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2),
        );
        let stats = FlowStats::default();
        let parse_err =
            FlowRecord::from_ended(&key, &stats, EndReason::ParseError).to_ipfix_record();
        let evicted = FlowRecord::from_ended(&key, &stats, EndReason::Evicted).to_ipfix_record();
        assert_eq!(parse_err.original_end_reason, Some(EndReason::ParseError));
        assert_eq!(evicted.original_end_reason, Some(EndReason::Evicted));
        assert_ne!(
            parse_err.original_end_reason, evicted.original_end_reason,
            "the shadow field must keep reasons IE 136 would collapse"
        );
        // An ongoing active-timeout snapshot (reason = None) stays None.
        assert_eq!(
            FlowRecord::from_active(&key, &stats)
                .to_ipfix_record()
                .original_end_reason,
            None
        );
    }

    #[test]
    fn to_ipfix_record_matches_internal_mapping() {
        // The public bridge is exactly the on-wire mapping.
        let r = v4_record();
        assert_eq!(r.to_ipfix_record(), to_ie_record(&r));
    }

    #[test]
    fn first_message_has_header_template_and_data() {
        let mut exporter = IpfixExporter::new(Vec::<u8>::new(), 42);
        exporter.export(&v4_record());
        let bytes = exporter.into_inner();
        // Header: version 10, length == total, observationDomainID 42.
        assert_eq!(be16(&bytes, 0), IPFIX_VERSION);
        assert_eq!(be16(&bytes, 2) as usize, bytes.len());
        assert_eq!(be32(&bytes, 8), 0); // first sequence number
        assert_eq!(be32(&bytes, 12), 42);
        // Body starts with the template set (set id 2).
        assert_eq!(be16(&bytes, MESSAGE_HEADER_LEN), SET_ID_TEMPLATE);
    }

    #[test]
    fn second_message_omits_templates_and_bumps_sequence() {
        let mut exporter = IpfixExporter::new(Vec::<u8>::new(), 7);
        exporter.export(&v4_record());
        exporter.export(&v4_record());
        let bytes = exporter.into_inner();
        // The first message's length field tells us where the second starts.
        let first_msg_len = be16(&bytes, 2) as usize;
        let second = &bytes[first_msg_len..];
        assert_eq!(be16(second, 0), IPFIX_VERSION);
        assert_eq!(be32(second, 8), 1); // sequence advanced by one Data Record
        // The second message's first set is a Data Set (template id 256),
        // not the template set (set id 2).
        assert_eq!(be16(second, MESSAGE_HEADER_LEN), TEMPLATE_ID_FLOW_IPV4);
    }

    #[test]
    fn resend_templates_every_reincludes_templates() {
        // `resend_every(1)` re-sends templates one record *after* the last
        // template: message 0 carries templates, message 1 (the 1 record
        // since) does not, message 2 re-includes them.
        let mut exporter = IpfixExporter::new(Vec::<u8>::new(), 1).resend_templates_every(1);
        for _ in 0..3 {
            exporter.export(&v4_record());
        }
        let bytes = exporter.into_inner();
        // Walk the messages by their length fields, recording whether each
        // opens with a template set (id 2) or a data set (id 256).
        let mut off = 0;
        let mut opens = Vec::new();
        while off < bytes.len() {
            let len = be16(&bytes, off + 2) as usize;
            opens.push(be16(&bytes, off + MESSAGE_HEADER_LEN));
            off += len;
        }
        assert_eq!(
            opens,
            vec![SET_ID_TEMPLATE, TEMPLATE_ID_FLOW_IPV4, SET_ID_TEMPLATE]
        );
    }

    /// Split concatenated IPFIX messages by their length fields.
    fn messages(bytes: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut off = 0;
        while off < bytes.len() {
            let len = be16(bytes, off + 2) as usize;
            out.push(&bytes[off..off + len]);
            off += len;
        }
        out
    }

    /// `(octetDeltaCount, packetDeltaCount, octetTotalCount)` of the
    /// message's (IPv4) data record.
    fn counts(msg: &[u8]) -> (u64, u64, u64) {
        let be64 = |off: usize| u64::from_be_bytes(msg[off..off + 8].try_into().unwrap());
        let mut set = MESSAGE_HEADER_LEN;
        while be16(msg, set) == SET_ID_TEMPLATE {
            set += be16(msg, set + 2) as usize;
        }
        // proto(1) sport(2) src(4) dport(2) dst(4), then IE 1 / 2 / 85.
        let rec = set + 4;
        (be64(rec + 13), be64(rec + 21), be64(rec + 29))
    }

    /// IE 1/2 are delta counts: an active-timeout record and the final
    /// one each carry what is new since the flow's previous record, so
    /// a collector summing them gets the flow's total; IE 85 keeps the
    /// running total. A later flow on the same tuple starts afresh.
    #[test]
    fn interim_records_carry_deltas_since_the_previous_record() {
        let key = FlowKey::new(
            L4Proto::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
        );
        let mut s = FlowStats::default();
        s.started = Timestamp::from_unix_f64(1000.0);
        s.last_seen = Timestamp::from_unix_f64(1060.0);
        s.bytes_initiator = 100;
        s.packets_initiator = 2;
        let mut exporter = IpfixExporter::new(Vec::<u8>::new(), 1);
        exporter.export(&FlowRecord::from_active(&key, &s));
        s.bytes_initiator = 150;
        s.packets_initiator = 3;
        s.last_seen = Timestamp::from_unix_f64(1090.0);
        exporter.export(&FlowRecord::from_ended(&key, &s, EndReason::Fin));
        let mut next = FlowStats::default();
        next.started = Timestamp::from_unix_f64(2000.0);
        next.last_seen = next.started;
        next.bytes_initiator = 40;
        next.packets_initiator = 1;
        exporter.export(&FlowRecord::from_ended(&key, &next, EndReason::Fin));

        let bytes = exporter.into_inner();
        let msgs = messages(&bytes);
        assert_eq!(counts(msgs[0]), (100, 2, 100));
        assert_eq!(counts(msgs[1]), (50, 1, 150));
        assert_eq!(counts(msgs[2]), (40, 1, 40));
    }

    /// A long active timeout (interim records 2 h apart) with many
    /// concurrent flows must keep every flow's baseline: a pruned one
    /// would make the next interim delta the flow's cumulative count.
    #[test]
    fn a_long_active_timeout_keeps_its_baselines() {
        let key = |port| {
            FlowKey::new(
                L4Proto::Udp,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 53),
            )
        };
        let mut exporter = IpfixExporter::new(std::io::sink(), 1);
        let mut records = vec![0u64; 4500];
        let mut export = |exporter: &mut IpfixExporter<std::io::Sink>, port: u16, round: u32| {
            records[usize::from(port)] += 1;
            let mut s = FlowStats::default();
            s.started = Timestamp::from_unix_f64(1000.0);
            s.last_seen = Timestamp::from_unix_f64(1000.0 + 7200.0 * f64::from(round));
            s.bytes_initiator = 100 * records[usize::from(port)];
            let rec = FlowRecord::from_active(&key(port), &s);
            let delta = exporter.delta_record(&rec).octet_delta_count_initiator;
            exporter.export(&rec);
            delta
        };
        // Each round (2 h of record time apart) new flows arrive first —
        // growing the map past its sweep threshold — then the earlier
        // flows send their next interim record.
        for round in 0..3u32 {
            let new = (round as u16 * 1500)..((round as u16 + 1) * 1500);
            for port in new.clone() {
                export(&mut exporter, port, round);
            }
            for port in 0..new.start {
                let delta = export(&mut exporter, port, round);
                assert_eq!(delta, 100, "round {round} port {port}: baseline lost");
            }
        }
    }

    /// The per-flow baselines go with the final record, and those of
    /// flows that never get one are dropped once stale.
    #[test]
    fn delta_baselines_are_bounded() {
        let key = |port| {
            FlowKey::new(
                L4Proto::Udp,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 53),
            )
        };
        let mut s = FlowStats::default();
        s.started = Timestamp::from_unix_f64(1000.0);
        s.last_seen = s.started;
        let mut exporter = IpfixExporter::new(std::io::sink(), 1);
        exporter.export(&FlowRecord::from_active(&key(1), &s));
        exporter.export(&FlowRecord::from_ended(&key(1), &s, EndReason::IdleTimeout));
        assert!(exporter.exported.is_empty());

        for port in 0..2000 {
            exporter.export(&FlowRecord::from_active(&key(port), &s));
        }
        assert!(exporter.exported.len() <= 2000);
        // Two days later the old interim baselines are pruned.
        s.started = Timestamp::from_unix_f64(1000.0 + 2.0 * 86_400.0);
        s.last_seen = s.started;
        for port in 0..2000 {
            exporter.export(&FlowRecord::from_active(&key(port), &s));
        }
        assert!(
            exporter.exported.len() <= 2000,
            "{}",
            exporter.exported.len()
        );
    }

    #[test]
    fn v6_record_uses_the_v6_template() {
        let key = FlowKey::new(
            L4Proto::Udp,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53),
        );
        let s = FlowStats::default();
        let rec = FlowRecord::from_ended(&key, &s, EndReason::IdleTimeout);
        assert_eq!(template_id(&rec), TEMPLATE_ID_FLOW_IPV6);
        let mut exporter = IpfixExporter::new(Vec::<u8>::new(), 9);
        exporter.export(&rec);
        let bytes = exporter.into_inner();
        // First message carries the template set; the data set that follows
        // references the IPv6 template (257). Find it after the template set.
        assert_eq!(be16(&bytes, MESSAGE_HEADER_LEN), SET_ID_TEMPLATE);
        let tmpl_set_len = be16(&bytes, MESSAGE_HEADER_LEN + 2) as usize;
        let data_set_off = MESSAGE_HEADER_LEN + tmpl_set_len;
        assert_eq!(be16(&bytes, data_set_off), TEMPLATE_ID_FLOW_IPV6);
    }
}
