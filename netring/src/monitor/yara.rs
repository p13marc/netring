//! YARA-X payload scanning over reassembled flows (issue #45).
//!
//! Compiles a set of [YARA](https://virustotal.github.io/yara-x/) rules and
//! scans each flow's accumulated L4 payload at **flow end**, delivering a
//! [`YaraMatch`] per hit to an
//! [`on_yara_match`](crate::monitor::MonitorBuilder::on_yara_match) handler.
//!
//! Scanning at flow end (not per packet) is what lets a signature span segment
//! boundaries. Payload is buffered **per side** (initiator / responder, as the
//! flow tracker sees them) in arrival order — a pragmatic v1 that catches the
//! common case (contiguous content within one direction) without a full TCP
//! reassembler; out-of-order / retransmitted segments are concatenated as they
//! arrive. With [`reassemble_ip_fragments`](crate::monitor::MonitorBuilder::reassemble_ip_fragments)
//! armed, a fragmented datagram is buffered whole. The buffers are bounded by
//! [`max_scan_bytes`](crate::monitor::MonitorBuilder::max_scan_bytes) per
//! direction, all together by
//! [`yara_memory_budget`](crate::monitor::MonitorBuilder::yara_memory_budget),
//! and the live-flow set by
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

    /// The shared inner `Arc<yara_x::Rules>` — used to seed / hot-swap the
    /// scanner's live rule cell (issue #53).
    pub(crate) fn into_inner(self) -> Arc<yara_x::Rules> {
        self.0
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

/// Per-flow payload buffers, one per [`FlowSide`](flowscope::FlowSide), in
/// arrival order, bounded.
#[derive(Default)]
struct FlowBufs {
    init: Vec<u8>,
    resp: Vec<u8>,
}

impl FlowBufs {
    /// Bytes allocated for this flow (what the memory budget counts).
    fn held(&self) -> usize {
        self.init.capacity() + self.resp.capacity()
    }
}

/// Smallest buffer a flow's direction starts with.
const MIN_BUFFER: usize = 256;

/// Buffers each flow's L4 payload and scans it with YARA at flow end.
///
/// Fed what the flow tracker made of each packet (#214): its flow key and
/// side — so the initiator's buffer holds the client's bytes whatever the
/// address order (#215) — and the payload location in the frame it tracked:
/// a reassembled IP datagram, never a raw fragment.
///
/// Memory: each direction is capped at `max_bytes` (the scan window), the
/// live-flow set at `max_flows`, and all buffers together at `budget` bytes
/// of allocated capacity — grown geometrically, never past the window or
/// the budget. Payload the budget refuses is counted in `skipped_bytes`.
///
/// The rule set is held behind an [`ArcSwap`](arc_swap::ArcSwap) so it can be
/// hot-reloaded (issue #53) via [`ReloadHandle::set_yara`](crate::monitor::ReloadHandle::set_yara):
/// `flush` loads the current rules once per flow end (no per-packet cost).
pub(crate) struct YaraAccumulator {
    rules: Arc<arc_swap::ArcSwap<yara_x::Rules>>,
    flows: rustc_hash::FxHashMap<FlowKey, FlowBufs>,
    handlers: Vec<YaraHandler>,
    max_flows: usize,
    max_bytes: usize,
    budget: usize,
    /// Capacity allocated across every live flow's buffers.
    held: usize,
    skipped_flows: u64,
    skipped_bytes: u64,
}

impl YaraAccumulator {
    pub(crate) fn new(
        rules: Arc<arc_swap::ArcSwap<yara_x::Rules>>,
        handlers: Vec<YaraHandler>,
        max_flows: usize,
        max_bytes: usize,
        budget: usize,
    ) -> Self {
        Self {
            rules,
            flows: rustc_hash::FxHashMap::default(),
            handlers,
            max_flows,
            max_bytes,
            budget,
            held: 0,
            skipped_flows: 0,
            skipped_bytes: 0,
        }
    }

    /// Buffer `payload` sent by `side` of flow `key` (`is_new`: its first
    /// packet).
    fn append(&mut self, key: FlowKey, side: flowscope::FlowSide, is_new: bool, payload: &[u8]) {
        let bufs = match self.flows.get_mut(&key) {
            Some(b) => b,
            None => {
                if self.flows.len() >= self.max_flows {
                    if is_new {
                        self.skipped_flows = self.skipped_flows.saturating_add(1);
                    }
                    return;
                }
                self.flows.entry(key).or_default()
            }
        };
        let buf = match side {
            flowscope::FlowSide::Initiator => &mut bufs.init,
            flowscope::FlowSide::Responder => &mut bufs.resp,
        };
        let budget_left = self.budget.saturating_sub(self.held);
        let (grown, refused) = append_capped(buf, payload, self.max_bytes, budget_left);
        self.held += grown;
        self.skipped_bytes = self.skipped_bytes.saturating_add(refused as u64);
    }

    /// Scan a flow's buffers — one scanner for both — and fire the handlers
    /// for each matching rule.
    fn scan(rules: &yara_x::Rules, handlers: &mut [YaraHandler], key: &FlowKey, bufs: &FlowBufs) {
        if bufs.init.is_empty() && bufs.resp.is_empty() {
            return;
        }
        let mut scanner = yara_x::Scanner::new(rules);
        for (buf, direction) in [
            (&bufs.init, ScanDirection::Initiator),
            (&bufs.resp, ScanDirection::Responder),
        ] {
            if buf.is_empty() {
                continue;
            }
            let Ok(results) = scanner.scan(buf) else {
                continue;
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
}

/// Append `payload` to `buf`, up to `max_bytes` in all (the scan window:
/// what doesn't fit is not scanned, like Suricata's stream depth), growing
/// the capacity by at most `budget_left`. Returns the capacity added and the
/// bytes the budget refused.
///
/// Growth is geometric but capped — at the window and at the budget — and
/// exact (`reserve_exact`), so a buffer never holds more capacity than it
/// was allowed.
fn append_capped(
    buf: &mut Vec<u8>,
    payload: &[u8],
    max_bytes: usize,
    budget_left: usize,
) -> (usize, usize) {
    let fits = payload.len().min(max_bytes.saturating_sub(buf.len()));
    let mut take = fits;
    let cap = buf.capacity();
    let need = buf.len() + take;
    if need > cap {
        let target = cap
            .saturating_mul(2)
            .max(need)
            .max(MIN_BUFFER)
            .min(max_bytes)
            .min(cap.saturating_add(budget_left));
        take = take.min(target.saturating_sub(buf.len()));
        if target > cap {
            buf.reserve_exact(target - buf.len());
        }
    }
    buf.extend_from_slice(&payload[..take]);
    (buf.capacity() - cap, fits - take)
}

impl crate::monitor::nprint::FlowByteAccumulator for YaraAccumulator {
    fn feed(&mut self, pkt: &flowscope::PacketInfo<FlowKey>, view: &PacketView<'_>) {
        if !matches!(
            pkt.l4,
            Some(flowscope::L4Proto::Tcp) | Some(flowscope::L4Proto::Udp)
        ) {
            return;
        }
        let Some(meta) = pkt.l4_meta else {
            return;
        };
        let payload = meta.payload(view.frame);
        if !payload.is_empty() {
            self.append(pkt.key, pkt.side, pkt.is_new, payload);
        }
    }

    fn flush(&mut self, key: &FlowKey) {
        if let Some(bufs) = self.flows.remove(key) {
            self.held -= bufs.held();
            // Load the live rule set once per flow end (issue #53 hot-reload):
            // an in-flight reload takes effect on the next flushed flow.
            let rules = self.rules.load_full();
            Self::scan(&rules, &mut self.handlers, key, &bufs);
        }
    }

    fn retain(&mut self, alive: &dyn Fn(&FlowKey) -> bool) {
        let held = &mut self.held;
        self.flows.retain(|key, bufs| {
            let keep = alive(key);
            if !keep {
                *held -= bufs.held();
            }
            keep
        });
    }

    fn stats(&self) -> crate::monitor::nprint::AccumulatorStats {
        crate::monitor::nprint::AccumulatorStats {
            live_flows: self.flows.len(),
            skipped_flows: self.skipped_flows,
            buffered_bytes: self.held,
            skipped_bytes: self.skipped_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::nprint::FlowByteAccumulator;

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
        assert_eq!(
            append_capped(&mut buf, &[1, 2, 3, 4, 5], 3, usize::MAX).1,
            0
        );
        assert_eq!(buf, vec![1, 2, 3]);
        append_capped(&mut buf, &[6, 7], 3, usize::MAX);
        assert_eq!(buf, vec![1, 2, 3], "no growth past the window");
        assert_eq!(buf.capacity(), 3, "capacity capped at the window too");
    }

    #[test]
    fn append_capped_grows_geometrically_within_the_budget() {
        let mut buf = Vec::new();
        let (grown, refused) = append_capped(&mut buf, &[0; 100], 1 << 20, 300);
        assert_eq!((grown, refused), (MIN_BUFFER, 0));
        // Doubling to 512 would pass the budget left (300 − 256 = 44).
        let (grown, refused) = append_capped(&mut buf, &[0; 200], 1 << 20, 44);
        assert_eq!(buf.capacity(), MIN_BUFFER + 44);
        assert_eq!(grown, 44);
        assert_eq!(buf.len(), MIN_BUFFER + 44);
        assert_eq!(refused, 100 + 200 - (MIN_BUFFER + 44));
    }

    fn accumulator(max_flows: usize, max_bytes: usize, budget: usize) -> YaraAccumulator {
        let rules = YaraRules::compile(r#"rule x { strings: $a = "x" condition: $a }"#).unwrap();
        YaraAccumulator::new(
            Arc::new(arc_swap::ArcSwap::new(rules.into_inner())),
            Vec::new(),
            max_flows,
            max_bytes,
            budget,
        )
    }

    fn key(port: u16) -> FlowKey {
        FlowKey::new(
            flowscope::L4Proto::Udp,
            std::net::SocketAddr::from(([10, 0, 0, 1], port)),
            std::net::SocketAddr::from(([10, 0, 0, 2], 53)),
        )
    }

    /// #214: all buffers together stay within the global budget; what it
    /// refuses is counted, and freeing a flow makes room again.
    #[test]
    fn global_budget_bounds_buffers() {
        use flowscope::FlowSide::Initiator;
        let mut acc = accumulator(1_000, 1 << 20, 4_096);
        for port in 0..100 {
            acc.append(key(port), Initiator, true, &[0xab; 300]);
        }
        let stats = acc.stats();
        assert!(stats.buffered_bytes <= 4_096, "{stats:?}");
        assert!(stats.skipped_bytes > 0, "{stats:?}");
        assert_eq!(
            stats.skipped_bytes + acc.flows.values().map(|b| b.init.len() as u64).sum::<u64>(),
            100 * 300,
            "every byte either buffered or counted"
        );
        acc.flush(&key(0));
        assert!(acc.stats().buffered_bytes < stats.buffered_bytes);
    }

    /// The live-flow cap: a new flow past it is skipped and counted once.
    #[test]
    fn flow_cap_skips_and_counts_new_flows() {
        use flowscope::FlowSide::Initiator;
        let mut acc = accumulator(1, 1 << 20, 1 << 20);
        acc.append(key(1), Initiator, true, b"a");
        acc.append(key(2), Initiator, true, b"b");
        acc.append(key(2), Initiator, false, b"c");
        let stats = acc.stats();
        assert_eq!((stats.live_flows, stats.skipped_flows), (1, 1));
    }

    /// #214: flows the tracker no longer has (they ended without a
    /// `FlowEnded`) are dropped, and their memory released.
    #[test]
    fn retain_drops_dead_flows() {
        use flowscope::FlowSide::{Initiator, Responder};
        let mut acc = accumulator(10, 1 << 20, 1 << 20);
        acc.append(key(1), Initiator, true, &[1; 10]);
        acc.append(key(2), Responder, true, &[2; 10]);
        let before = acc.stats().buffered_bytes;
        acc.retain(&|k| *k == key(1));
        let after = acc.stats();
        assert_eq!(after.live_flows, 1);
        assert!(after.buffered_bytes < before);
        assert!(acc.flows.contains_key(&key(1)));
    }
}
