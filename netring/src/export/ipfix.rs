//! [`IpfixExporter`] — a minimal IPFIX / NetFlow v10 ([RFC 7011]) flow
//! exporter, hand-rolled with **no dependencies** (feature `ipfix`).
//!
//! Each completed [`FlowRecord`] is encoded as one IPFIX message
//! (16-byte header + sets) written to a `W: Write + Send` — a UDP/TCP
//! socket to a flow collector (nfdump, pmacct, Elastiflow, …) or a file.
//! The first message carries the **template sets** (one for IPv4 flows,
//! one for IPv6); every message carries a **data set** with the flow's
//! fields. Re-send templates periodically over lossy transports with
//! [`IpfixExporter::resend_templates_every`].
//!
//! ## Fields (core IANA Information Elements)
//!
//! `protocolIdentifier` (4), `source`/`destinationIPv4Address` (8/12) or
//! `…IPv6Address` (27/28), `source`/`destinationTransportPort` (7/11),
//! `packetDeltaCount` (2), `octetDeltaCount` (1),
//! `flowStartMilliseconds` (152), `flowEndMilliseconds` (153),
//! `flowEndReason` (136).
//!
//! ## Semantics & limits
//!
//! - `octetDeltaCount` / `packetDeltaCount` carry the flow **total**
//!   (initiator + responder). Per-direction (biflow, RFC 5103) export is
//!   not encoded here.
//! - Source/destination map to the record's `a`/`b` endpoints. With the
//!   default bidirectional extractor those are canonically ordered, not
//!   connection direction — use a directional extractor if "source =
//!   initiator" matters to your collector.
//! - `exportTime` is the flow's end time (deterministic; the flow just
//!   ended), not wall-clock at write.
//!
//! [RFC 7011]: https://www.rfc-editor.org/rfc/rfc7011

use std::io::Write;
use std::net::{IpAddr, SocketAddr};

use flowscope::event::EndReason;

use crate::export::{FlowExporter, FlowRecord};

const IPFIX_VERSION: u16 = 10;
const SET_ID_TEMPLATE: u16 = 2;
const TEMPLATE_ID_V4: u16 = 256;
const TEMPLATE_ID_V6: u16 = 257;

// IANA Information Element IDs.
const IE_OCTET_DELTA_COUNT: u16 = 1;
const IE_PACKET_DELTA_COUNT: u16 = 2;
const IE_PROTOCOL_IDENTIFIER: u16 = 4;
const IE_SOURCE_TRANSPORT_PORT: u16 = 7;
const IE_SOURCE_IPV4: u16 = 8;
const IE_DESTINATION_TRANSPORT_PORT: u16 = 11;
const IE_DESTINATION_IPV4: u16 = 12;
const IE_FLOW_END_REASON: u16 = 136;
const IE_FLOW_START_MS: u16 = 152;
const IE_FLOW_END_MS: u16 = 153;
const IE_SOURCE_IPV6: u16 = 27;
const IE_DESTINATION_IPV6: u16 = 28;

/// `(IE id, field length)` specifiers for the IPv4 flow template, in
/// data-record order.
const V4_FIELDS: &[(u16, u16)] = &[
    (IE_PROTOCOL_IDENTIFIER, 1),
    (IE_SOURCE_IPV4, 4),
    (IE_DESTINATION_IPV4, 4),
    (IE_SOURCE_TRANSPORT_PORT, 2),
    (IE_DESTINATION_TRANSPORT_PORT, 2),
    (IE_PACKET_DELTA_COUNT, 8),
    (IE_OCTET_DELTA_COUNT, 8),
    (IE_FLOW_START_MS, 8),
    (IE_FLOW_END_MS, 8),
    (IE_FLOW_END_REASON, 1),
];

/// Same as [`V4_FIELDS`] but with 16-byte IPv6 address fields.
const V6_FIELDS: &[(u16, u16)] = &[
    (IE_PROTOCOL_IDENTIFIER, 1),
    (IE_SOURCE_IPV6, 16),
    (IE_DESTINATION_IPV6, 16),
    (IE_SOURCE_TRANSPORT_PORT, 2),
    (IE_DESTINATION_TRANSPORT_PORT, 2),
    (IE_PACKET_DELTA_COUNT, 8),
    (IE_OCTET_DELTA_COUNT, 8),
    (IE_FLOW_START_MS, 8),
    (IE_FLOW_END_MS, 8),
    (IE_FLOW_END_REASON, 1),
];

/// IE 136 `flowEndReason` value for a netring [`EndReason`].
fn flow_end_reason(reason: EndReason) -> u8 {
    match reason {
        EndReason::IdleTimeout => 0x01, // idle timeout
        EndReason::Fin | EndReason::Rst | EndReason::ParserDone => 0x03, // end of flow detected
        EndReason::BufferOverflow => 0x05, // lack of resources
        // Evicted / ParseError / ForceClose / future non_exhaustive → forced end.
        _ => 0x04,
    }
}

/// L4 protocol number for the IP `protocolIdentifier` field.
fn protocol_number(proto: flowscope::L4Proto) -> u8 {
    use flowscope::L4Proto::*;
    match proto {
        Tcp => 6,
        Udp => 17,
        Icmp => 1,
        IcmpV6 => 58,
        // Unknown / future variants: 0 (HOPOPT / reserved) is the least
        // wrong choice for "no specific protocol".
        _ => 0,
    }
}

/// An IPFIX flow exporter. See the [module docs](self).
pub struct IpfixExporter<W: Write + Send> {
    writer: W,
    observation_domain_id: u32,
    /// Cumulative data records emitted — the IPFIX sequence number.
    records_sent: u32,
    /// Re-send the template sets once this many records have gone by
    /// since the last template (0 = only in the very first message).
    resend_every: u32,
    /// Records since templates were last included.
    since_template: u32,
    /// Whether templates have been sent at least once.
    template_sent: bool,
    /// Reused message buffer.
    scratch: Vec<u8>,
}

impl<W: Write + Send> IpfixExporter<W> {
    /// Wrap `writer` with the given observation domain ID (identifies the
    /// exporting process to the collector).
    pub fn new(writer: W, observation_domain_id: u32) -> Self {
        Self {
            writer,
            observation_domain_id,
            records_sent: 0,
            resend_every: 0,
            since_template: 0,
            template_sent: false,
            scratch: Vec::with_capacity(128),
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
}

/// Push a big-endian `u16`.
fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Push a big-endian `u64`.
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Append a template set (both the v4 and v6 templates) to `out`.
fn encode_template_set(out: &mut Vec<u8>) {
    let start = out.len();
    put_u16(out, SET_ID_TEMPLATE);
    put_u16(out, 0); // length placeholder
    encode_template_record(out, TEMPLATE_ID_V4, V4_FIELDS);
    encode_template_record(out, TEMPLATE_ID_V6, V6_FIELDS);
    let len = (out.len() - start) as u16;
    out[start + 2..start + 4].copy_from_slice(&len.to_be_bytes());
}

/// Append one template record (header + field specifiers) to `out`.
fn encode_template_record(out: &mut Vec<u8>, template_id: u16, fields: &[(u16, u16)]) {
    put_u16(out, template_id);
    put_u16(out, fields.len() as u16);
    for &(ie, len) in fields {
        put_u16(out, ie); // enterprise bit clear → IANA IE
        put_u16(out, len);
    }
}

/// Append `record` as a single data set to `out`.
fn encode_data_set(out: &mut Vec<u8>, record: &FlowRecord) {
    let template_id = match record.a.ip() {
        IpAddr::V4(_) => TEMPLATE_ID_V4,
        IpAddr::V6(_) => TEMPLATE_ID_V6,
    };
    let start = out.len();
    put_u16(out, template_id);
    put_u16(out, 0); // length placeholder
    encode_data_record(out, record);
    let len = (out.len() - start) as u16;
    out[start + 2..start + 4].copy_from_slice(&len.to_be_bytes());
}

/// Append the field values for `record`, in template order.
fn encode_data_record(out: &mut Vec<u8>, record: &FlowRecord) {
    out.push(protocol_number(record.proto));
    put_addr(out, record.a);
    put_addr(out, record.b);
    put_u16(out, record.a.port());
    put_u16(out, record.b.port());
    put_u64(out, record.total_packets());
    put_u64(out, record.total_bytes());
    put_u64(out, ts_millis(record.start));
    put_u64(out, ts_millis(record.end));
    out.push(flow_end_reason(record.reason));
}

/// Append a socket address's IP (4 or 16 bytes). The address family must
/// match the chosen template — both endpoints of a flow share a family.
fn put_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
    }
}

/// Milliseconds since the Unix epoch for a flowscope `Timestamp`.
fn ts_millis(ts: flowscope::Timestamp) -> u64 {
    (ts.to_unix_f64() * 1000.0) as u64
}

impl<W: Write + Send> FlowExporter for IpfixExporter<W> {
    fn export(&mut self, record: &FlowRecord) {
        let include_templates = self.want_templates();

        // Build the message body (sets) first so we know its length.
        self.scratch.clear();
        if include_templates {
            encode_template_set(&mut self.scratch);
        }
        encode_data_set(&mut self.scratch, record);

        // Message header (16 bytes): version, length, exportTime,
        // sequenceNumber, observationDomainID.
        let total_len = (16 + self.scratch.len()) as u16;
        let mut header = [0u8; 16];
        header[0..2].copy_from_slice(&IPFIX_VERSION.to_be_bytes());
        header[2..4].copy_from_slice(&total_len.to_be_bytes());
        let export_time = (ts_millis(record.end) / 1000) as u32;
        header[4..8].copy_from_slice(&export_time.to_be_bytes());
        header[8..12].copy_from_slice(&self.records_sent.to_be_bytes());
        header[12..16].copy_from_slice(&self.observation_domain_id.to_be_bytes());

        // Swallow write errors like the other shipped sinks.
        if self
            .writer
            .write_all(&header)
            .and_then(|_| self.writer.write_all(&self.scratch))
            .is_ok()
        {
            self.records_sent = self.records_sent.wrapping_add(1);
            if include_templates {
                self.template_sent = true;
                self.since_template = 0;
            } else {
                self.since_template = self.since_template.wrapping_add(1);
            }
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
    use flowscope::{L4Proto, Timestamp};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4_record() -> FlowRecord {
        let key = FlowKey {
            proto: L4Proto::Tcp,
            a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234),
            b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
        };
        let mut s = FlowStats::default();
        s.packets_initiator = 5;
        s.packets_responder = 5;
        s.bytes_initiator = 400;
        s.bytes_responder = 600;
        s.started = Timestamp::from_unix_f64(1000.0);
        s.last_seen = Timestamp::from_unix_f64(1002.0);
        FlowRecord::from_ended(&key, &s, EndReason::Fin)
    }

    #[test]
    fn end_reason_and_protocol_maps() {
        assert_eq!(flow_end_reason(EndReason::Fin), 3);
        assert_eq!(flow_end_reason(EndReason::IdleTimeout), 1);
        assert_eq!(flow_end_reason(EndReason::BufferOverflow), 5);
        assert_eq!(flow_end_reason(EndReason::Evicted), 4);
        assert_eq!(protocol_number(L4Proto::Tcp), 6);
        assert_eq!(protocol_number(L4Proto::Udp), 17);
    }

    #[test]
    fn v4_data_record_is_46_bytes_with_expected_fields() {
        let mut out = Vec::new();
        encode_data_record(&mut out, &v4_record());
        // 1 + 4 + 4 + 2 + 2 + 8 + 8 + 8 + 8 + 1 = 46.
        assert_eq!(out.len(), 46, "record = {out:?}");
        assert_eq!(out[0], 6); // protocol = TCP
        assert_eq!(&out[1..5], &[10, 0, 0, 1]); // source IPv4
        assert_eq!(&out[5..9], &[10, 0, 0, 2]); // dest IPv4
        assert_eq!(&out[9..11], &1234u16.to_be_bytes()); // source port
        assert_eq!(&out[11..13], &80u16.to_be_bytes()); // dest port
        assert_eq!(&out[13..21], &10u64.to_be_bytes()); // total packets
        assert_eq!(&out[21..29], &1000u64.to_be_bytes()); // total bytes
        assert_eq!(out[45], 3); // flowEndReason = end of flow
    }

    #[test]
    fn template_set_declares_both_templates() {
        let mut out = Vec::new();
        encode_template_set(&mut out);
        assert_eq!(&out[0..2], &SET_ID_TEMPLATE.to_be_bytes());
        // Set length is self-consistent with the buffer.
        let set_len = u16::from_be_bytes([out[2], out[3]]) as usize;
        assert_eq!(set_len, out.len());
        // First template record header: id 256, 10 fields.
        assert_eq!(&out[4..6], &TEMPLATE_ID_V4.to_be_bytes());
        assert_eq!(&out[6..8], &(V4_FIELDS.len() as u16).to_be_bytes());
    }

    #[test]
    fn first_message_has_header_template_and_data() {
        let mut exporter = IpfixExporter::new(Vec::<u8>::new(), 42);
        exporter.export(&v4_record());
        let bytes = exporter.into_inner();
        // Header: version 10, length == total, observationDomainID 42.
        assert_eq!(&bytes[0..2], &IPFIX_VERSION.to_be_bytes());
        let msg_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(msg_len, bytes.len());
        assert_eq!(&bytes[8..12], &0u32.to_be_bytes()); // first sequence number
        assert_eq!(&bytes[12..16], &42u32.to_be_bytes());
        // Body starts with the template set (set id 2).
        assert_eq!(&bytes[16..18], &SET_ID_TEMPLATE.to_be_bytes());
    }

    #[test]
    fn second_message_omits_templates_and_bumps_sequence() {
        let mut exporter = IpfixExporter::new(Vec::<u8>::new(), 7);
        exporter.export(&v4_record());
        let first_len = exporter.scratch.len();
        exporter.export(&v4_record());
        let bytes = exporter.into_inner();
        // The second message is shorter (no template set) and its body
        // starts with a data set (set id 256), not the template set.
        // Find the second message: it starts at the end of the first.
        let first_msg_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let second = &bytes[first_msg_len..];
        assert_eq!(&second[0..2], &IPFIX_VERSION.to_be_bytes());
        assert_eq!(&second[8..12], &1u32.to_be_bytes()); // sequence advanced
        assert_eq!(&second[16..18], &TEMPLATE_ID_V4.to_be_bytes()); // data set, no template
        assert!(first_len > 0);
    }

    #[test]
    fn v6_record_uses_the_v6_template() {
        let key = FlowKey {
            proto: L4Proto::Udp,
            a: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353),
            b: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53),
        };
        let s = FlowStats::default();
        let rec = FlowRecord::from_ended(&key, &s, EndReason::IdleTimeout);
        let mut out = Vec::new();
        encode_data_set(&mut out, &rec);
        assert_eq!(&out[0..2], &TEMPLATE_ID_V6.to_be_bytes());
    }
}
