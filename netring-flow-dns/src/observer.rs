//! [`DnsUdpObserver`] — a `FlowExtractor` wrapper that fires DNS
//! events for UDP/53 traffic while delegating flow extraction to
//! an inner extractor.
//!
//! This is the unconventional "extractor as tap" pattern. It's
//! convenient for one-line integration, but it bakes DNS handling
//! into the per-packet extractor call. For more decoupled
//! integrations, parse the UDP payload directly via
//! [`crate::parse_message`] inside your own packet loop.

use std::hash::Hash;
use std::sync::{Arc, Mutex};

use netring_flow::{Extracted, FlowExtractor, PacketView, Timestamp};

use crate::correlator::Correlator;
use crate::parser::{DnsParseResult, parse_message_at};
use crate::types::{DnsConfig, DnsHandler};

/// Wraps an inner [`FlowExtractor`]; for every packet whose UDP
/// src or dst port matches `udp_port`, parses the DNS payload and
/// fires events via the user's [`DnsHandler`].
pub struct DnsUdpObserver<E, H>
where
    E: FlowExtractor,
    H: DnsHandler,
{
    pub inner: E,
    pub handler: Arc<H>,
    pub udp_port: u16,
    correlator: Arc<Mutex<Correlator<E::Key>>>,
}

impl<E, H> DnsUdpObserver<E, H>
where
    E: FlowExtractor,
    H: DnsHandler,
    E::Key: Eq + Hash + Clone,
{
    /// Default config + UDP port 53.
    pub fn new(inner: E, handler: H) -> Self {
        Self::with_config(inner, handler, DnsConfig::default(), 53)
    }

    /// Explicit config + custom UDP port.
    pub fn with_config(inner: E, handler: H, config: DnsConfig, udp_port: u16) -> Self {
        Self {
            inner,
            handler: Arc::new(handler),
            udp_port,
            correlator: Arc::new(Mutex::new(Correlator::with_config(config))),
        }
    }

    /// Run a sweep on the correlator. Calls `on_unanswered` for
    /// every query that's been pending longer than `query_timeout`.
    /// Sync — call periodically from your packet loop.
    pub fn sweep_unanswered(&self, now: Timestamp) {
        let expired = self.correlator.lock().unwrap().sweep(now);
        for q in expired {
            self.handler.on_unanswered(&q);
        }
    }
}

impl<E, H> FlowExtractor for DnsUdpObserver<E, H>
where
    E: FlowExtractor,
    H: DnsHandler,
    E::Key: Eq + Hash + Clone,
{
    type Key = E::Key;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        // Run the inner extractor first so the FlowTracker still
        // sees the flow.
        let inner_result = self.inner.extract(view);

        // Now look for UDP/53 (or configured port).
        if let Some(udp) = peek_udp(view.frame)
            && (udp.dst_port == self.udp_port || udp.src_port == self.udp_port)
            && let Ok(parsed) = parse_message_at(udp.payload, view.timestamp)
        {
            // Use the inner result's key (if present) as correlator scope.
            let scope = inner_result.as_ref().map(|e| e.key.clone());

            match parsed {
                DnsParseResult::Query(q) => {
                    if let Some(s) = scope {
                        self.correlator.lock().unwrap().record_query(s, q.clone());
                    }
                    self.handler.on_query(&q);
                }
                DnsParseResult::Response(mut resp) => {
                    if let Some(s) = scope {
                        if let Some((_, elapsed)) = self.correlator.lock().unwrap().match_response(
                            &s,
                            resp.transaction_id,
                            view.timestamp,
                        ) {
                            resp.elapsed = Some(elapsed);
                        }
                    }
                    self.handler.on_response(&resp);
                }
            }
        }

        inner_result
    }
}

// ── tiny UDP peek (no etherparse dependency) ────────────────────────

struct UdpInfo<'a> {
    src_port: u16,
    dst_port: u16,
    payload: &'a [u8],
}

/// Walk the L2/L3 headers of `frame` to find a UDP header, return
/// its src/dst ports + payload. Returns None on any parse failure.
///
/// Supported: Ethernet → (optional VLAN) → IPv4 or IPv6 → UDP.
/// IPv6 extension headers and IP fragmentation are not supported
/// (returns None).
fn peek_udp(frame: &[u8]) -> Option<UdpInfo<'_>> {
    let mut offset = 14usize; // Ethernet header
    if frame.len() < offset {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    // Skip up to 2 VLAN tags.
    for _ in 0..2 {
        if ethertype != 0x8100 && ethertype != 0x88a8 {
            break;
        }
        if frame.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    let (proto, l4_offset) = match ethertype {
        0x0800 => {
            // IPv4
            if frame.len() < offset + 20 {
                return None;
            }
            let ihl = (frame[offset] & 0x0f) as usize * 4;
            if ihl < 20 || frame.len() < offset + ihl {
                return None;
            }
            let proto = frame[offset + 9];
            // Check fragment offset: the lower 13 bits of bytes 6-7.
            let frag = u16::from_be_bytes([frame[offset + 6], frame[offset + 7]]);
            let frag_off = frag & 0x1FFF;
            let mf = (frag & 0x2000) != 0;
            if frag_off != 0 || mf {
                // Fragmented; we don't reassemble.
                return None;
            }
            (proto, offset + ihl)
        }
        0x86dd => {
            // IPv6 — we don't walk extension headers; just check the
            // next-header byte at offset 6 from the start of the IPv6
            // header. UDP = 17.
            if frame.len() < offset + 40 {
                return None;
            }
            (frame[offset + 6], offset + 40)
        }
        _ => return None,
    };

    if proto != 17 {
        return None;
    }

    if frame.len() < l4_offset + 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([frame[l4_offset], frame[l4_offset + 1]]);
    let dst_port = u16::from_be_bytes([frame[l4_offset + 2], frame[l4_offset + 3]]);
    let udp_len = u16::from_be_bytes([frame[l4_offset + 4], frame[l4_offset + 5]]) as usize;
    if udp_len < 8 || frame.len() < l4_offset + udp_len {
        return None;
    }
    let payload = &frame[l4_offset + 8..l4_offset + udp_len];
    Some(UdpInfo {
        src_port,
        dst_port,
        payload,
    })
}
