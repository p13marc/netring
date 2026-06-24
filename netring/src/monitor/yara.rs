//! YARA-X payload scanning over reassembled flows (issue #45).
//!
//! Compiles a set of [YARA](https://virustotal.github.io/yara-x/) rules and
//! scans each flow's accumulated L4 payload at **flow end**, delivering a
//! [`YaraMatch`] per hit to an
//! [`on_yara_match`](crate::monitor::MonitorBuilder::on_yara_match) handler.
//!
//! Scanning at flow end (not per packet) is what lets a signature span segment
//! boundaries. Payload is buffered **per direction** in arrival order — a
//! pragmatic v1 that catches the common case (contiguous content within one
//! direction) without a full TCP reassembler; out-of-order / retransmitted
//! segments are concatenated as they arrive. The buffers are bounded by
//! [`max_scan_bytes`](crate::monitor::MonitorBuilder::max_scan_bytes) per
//! direction and the live-flow set by
//! [`max_tracked_yara_flows`](crate::monitor::MonitorBuilder::max_tracked_yara_flows).
//!
//! Reuses the run loop's internal per-flow byte-accumulator seam (the same
//! per-packet-feed / flush-at-flow-end path as nPrint). The
//! `Send` accumulator can't hold a `yara_x::Scanner` (it's `!Send`), so it holds
//! a shareable `Arc<Rules>` and builds a `Scanner` inside `flush` — scanning
//! happens once per flow, so the per-flow scanner build is amortized.

use std::sync::Arc;

use flowscope::PacketView;

use crate::error::Error;
use crate::protocol::FlowKey;

/// A compiled set of YARA rules, ready to scan with.
#[derive(Clone)]
pub struct YaraRules(Arc<yara_x::Rules>);

impl YaraRules {
    /// Compile YARA rule source (one or more rules in a single string).
    pub fn compile(source: &str) -> Result<Self, Error> {
        let rules =
            yara_x::compile(source).map_err(|e| Error::Config(format!("YARA compile: {e}")))?;
        Ok(Self(Arc::new(rules)))
    }
}

/// One YARA rule hit on a flow's payload.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct YaraMatch {
    /// The matched rule's identifier.
    pub rule: String,
    /// The rule's namespace (`"default"` unless set).
    pub namespace: String,
    /// Which direction's payload matched.
    pub direction: ScanDirection,
}

/// Which half of a flow a [`YaraMatch`] fired on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScanDirection {
    /// Initiator → responder payload.
    Initiator,
    /// Responder → initiator payload.
    Responder,
}

/// A flow-end YARA-match callback.
pub(crate) type YaraHandler = Box<dyn FnMut(&FlowKey, &YaraMatch) + Send>;

/// Per-flow payload buffers (per direction, arrival order, bounded).
#[derive(Default)]
struct FlowBufs {
    init: Vec<u8>,
    resp: Vec<u8>,
}

/// Buffers each flow's L4 payload and scans it with YARA at flow end.
pub(crate) struct YaraAccumulator {
    rules: Arc<yara_x::Rules>,
    extractor: flowscope::extract::FiveTuple,
    flows: rustc_hash::FxHashMap<FlowKey, FlowBufs>,
    handlers: Vec<YaraHandler>,
    max_flows: usize,
    max_bytes: usize,
}

impl YaraAccumulator {
    pub(crate) fn new(
        rules: YaraRules,
        handlers: Vec<YaraHandler>,
        max_flows: usize,
        max_bytes: usize,
    ) -> Self {
        Self {
            rules: rules.0,
            // Bidirectional: key flows the same way the tracker keys FlowEnded.
            extractor: flowscope::extract::FiveTuple::bidirectional(),
            flows: rustc_hash::FxHashMap::default(),
            handlers,
            max_flows,
            max_bytes,
        }
    }

    /// Append `payload` to `buf`, capped at `max_bytes` (drop the overflow —
    /// signatures past the window aren't scanned, like Suricata's stream depth).
    fn append_capped(buf: &mut Vec<u8>, payload: &[u8], max_bytes: usize) {
        if buf.len() >= max_bytes {
            return;
        }
        let room = max_bytes - buf.len();
        let take = payload.len().min(room);
        buf.extend_from_slice(&payload[..take]);
    }

    /// Scan one direction's buffer and fire handlers for each matching rule.
    fn scan_dir(
        rules: &yara_x::Rules,
        handlers: &mut [YaraHandler],
        key: &FlowKey,
        buf: &[u8],
        direction: ScanDirection,
    ) {
        if buf.is_empty() {
            return;
        }
        let mut scanner = yara_x::Scanner::new(rules);
        let Ok(results) = scanner.scan(buf) else {
            return;
        };
        for rule in results.matching_rules() {
            let m = YaraMatch {
                rule: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                direction,
            };
            for handler in handlers.iter_mut() {
                handler(key, &m);
            }
        }
    }
}

impl crate::monitor::nprint::FlowByteAccumulator for YaraAccumulator {
    fn feed(&mut self, view: &PacketView<'_>) {
        use flowscope::FlowExtractor;
        let Some(extracted) = self.extractor.extract(*view) else {
            return;
        };
        let Some(payload) = l4_payload(view.frame) else {
            return;
        };
        if payload.is_empty() {
            return;
        }
        let max_bytes = self.max_bytes;
        let bufs = match self.flows.get_mut(&extracted.key) {
            Some(b) => b,
            None => {
                if self.flows.len() >= self.max_flows {
                    return;
                }
                self.flows.entry(extracted.key).or_default()
            }
        };
        // `Forward` orientation = wire src→dst is the canonical (a→b) initiator.
        match extracted.orientation {
            flowscope::Orientation::Forward => {
                Self::append_capped(&mut bufs.init, payload, max_bytes)
            }
            flowscope::Orientation::Reverse => {
                Self::append_capped(&mut bufs.resp, payload, max_bytes)
            }
        }
    }

    fn flush(&mut self, key: &FlowKey) {
        if let Some(bufs) = self.flows.remove(key) {
            Self::scan_dir(
                &self.rules,
                &mut self.handlers,
                key,
                &bufs.init,
                ScanDirection::Initiator,
            );
            Self::scan_dir(
                &self.rules,
                &mut self.handlers,
                key,
                &bufs.resp,
                ScanDirection::Responder,
            );
        }
    }
}

/// The L4 (TCP/UDP) payload of an Ethernet frame, or `None` if it isn't a
/// parseable TCP/UDP packet.
fn l4_payload(frame: &[u8]) -> Option<&[u8]> {
    use etherparse::{SlicedPacket, TransportSlice};
    let sliced = SlicedPacket::from_ethernet(frame).ok()?;
    match sliced.transport? {
        TransportSlice::Tcp(t) => Some(t.payload()),
        TransportSlice::Udp(u) => Some(u.payload()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_rejects_bad_rules() {
        assert!(YaraRules::compile("rule { this is not yara }").is_err());
    }

    #[test]
    fn compile_accepts_a_simple_rule() {
        let r =
            YaraRules::compile(r#"rule eicar { strings: $a = "EICAR-STANDARD" condition: $a }"#);
        assert!(r.is_ok(), "{:?}", r.err());
    }

    #[test]
    fn append_capped_bounds_the_buffer() {
        let mut buf = Vec::new();
        YaraAccumulator::append_capped(&mut buf, &[1, 2, 3, 4, 5], 3);
        assert_eq!(buf, vec![1, 2, 3]);
        YaraAccumulator::append_capped(&mut buf, &[6, 7], 3);
        assert_eq!(buf, vec![1, 2, 3], "no growth past the cap");
    }
}
