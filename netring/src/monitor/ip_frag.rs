//! IP-fragment reassembly (issue #134) — defeat fragmentation-based evasion.
//!
//! When armed (off by default), each IPv4 fragment seen by the capture is fed to
//! flowscope's [`IpFragmentReassembler`] *before* the flow tracker parses it.
//! Non-fragments pass straight through (zero-copy, wire metadata intact); a
//! fragment is buffered and withheld from the tracker until its datagram
//! completes, at which point a **reassembled frame** (the original L2 + IP
//! header with `MF`/offset cleared and checksum recomputed, plus the reassembled
//! payload) is synthesized and handed to the tracker in its place. So a payload
//! split across fragments — the classic IDS/NSM evasion — reaches the L7 parsers
//! whole.
//!
//! This only rewrites the **tracker input**. Per-frame taps, packet
//! subscriptions, p0f, and byte accumulators still see the raw wire fragments
//! (forensic truth). Overlapping fragments (RFC 5722 / the teardrop family) are
//! *poisoned and dropped* by flowscope's reassembler, so an evasion payload
//! hidden behind an overlap never reassembles; the overlap count is surfaced for
//! visibility.

use std::time::Duration;

use flowscope::PacketView;
use flowscope::ip_fragment::{FragmentConfig, IpFragmentReassembler};

/// Tuning for [`reassemble_ip_fragments_with`](crate::monitor::MonitorBuilder::reassemble_ip_fragments_with).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IpFragConfig {
    /// Max datagrams reassembling concurrently (oldest evicted on overflow).
    pub max_datagrams: usize,
    /// Max buffered bytes for a single datagram before it's dropped.
    pub max_datagram_bytes: usize,
    /// Reassembly timeout — a datagram missing fragments longer than this is
    /// dropped.
    pub timeout: Duration,
    /// Log a `tracing` warning on each overlapping-fragment drop (a
    /// fragmentation-evasion IOC). Default `true`.
    pub warn_on_overlap: bool,
}

impl Default for IpFragConfig {
    fn default() -> Self {
        // Mirror flowscope's FragmentConfig defaults (RFC-791-ish bounds).
        let d = FragmentConfig::default();
        Self {
            max_datagrams: d.max_datagrams,
            max_datagram_bytes: d.max_datagram_bytes,
            timeout: d.timeout,
            warn_on_overlap: true,
        }
    }
}

impl IpFragConfig {
    fn to_flowscope(&self) -> FragmentConfig {
        let mut c = FragmentConfig::default();
        c.max_datagrams = self.max_datagrams;
        c.max_datagram_bytes = self.max_datagram_bytes;
        c.timeout = self.timeout;
        c
    }
}

/// What to do with a frame after the fragment check (issue #134).
pub(crate) enum FragAction {
    /// Not a fragment (or not IPv4) — feed the original view to the tracker.
    PassThrough,
    /// A fragment whose datagram is still incomplete — withhold from the tracker.
    Buffered,
    /// A fragment completed a datagram — feed this synthesized frame instead.
    Reassembled(Vec<u8>),
}

/// The run-loop-owned reassembly state (issue #134).
pub(crate) struct IpFragReassembly {
    reasm: IpFragmentReassembler,
    warn_on_overlap: bool,
    /// `overlaps()` value already reported, to log only the new ones.
    overlaps_seen: u64,
}

impl IpFragReassembly {
    pub(crate) fn new(cfg: &IpFragConfig) -> Self {
        Self {
            reasm: IpFragmentReassembler::with_config(cfg.to_flowscope()),
            warn_on_overlap: cfg.warn_on_overlap,
            overlaps_seen: 0,
        }
    }

    /// Classify one frame: pass non-fragments through, buffer incomplete
    /// fragments, and synthesize a reassembled frame when a datagram completes.
    pub(crate) fn intercept(&mut self, view: &PacketView<'_>) -> FragAction {
        let Ok(layers) = view.layers() else {
            return FragAction::PassThrough;
        };
        let Some(ip) = layers.ipv4() else {
            return FragAction::PassThrough;
        };
        // A non-fragment has MF clear and offset 0 — leave it zero-copy.
        if !ip.mf() && ip.fragment_offset() == 0 {
            return FragAction::PassThrough;
        }

        let action = match self.reasm.push_ipv4(ip, view.timestamp) {
            None => FragAction::Buffered,
            Some(payload) => {
                let frame = view.frame;
                let header = ip.header();
                // Both slices are into `frame`, so the address delta is the L2
                // (+ any VLAN) header length. Copying `frame[..l2_len]` verbatim
                // preserves the Ethernet/VLAN headers.
                let l2_len = (header.as_ptr().addr()).wrapping_sub(frame.as_ptr().addr());
                let ihl = header.len();
                let total = ihl + payload.len();
                // IPv4 total-length is 16-bit; a datagram that wouldn't fit is
                // dropped rather than truncated.
                if total > 0xFFFF || l2_len + ihl > frame.len() {
                    FragAction::Buffered
                } else {
                    let mut out = Vec::with_capacity(l2_len + total);
                    out.extend_from_slice(&frame[..l2_len + ihl]);
                    patch_ipv4_header(&mut out[l2_len..l2_len + ihl], total as u16);
                    out.extend_from_slice(&payload);
                    FragAction::Reassembled(out)
                }
            }
        };
        self.report_overlaps();
        action
    }

    /// Drop datagrams whose first fragment aged past the timeout.
    pub(crate) fn evict(&mut self, now: flowscope::Timestamp) {
        self.reasm.evict_expired(now);
        self.report_overlaps();
    }

    /// `tracing`-warn on newly-poisoned overlapping datagrams (evasion IOC).
    fn report_overlaps(&mut self) {
        if !self.warn_on_overlap {
            return;
        }
        let now = self.reasm.overlaps();
        if now > self.overlaps_seen {
            tracing::warn!(
                overlaps = now - self.overlaps_seen,
                total = now,
                "ip_frag: overlapping IPv4 fragments dropped (RFC 5722 — fragmentation-evasion signal)"
            );
            self.overlaps_seen = now;
        }
    }
}

/// Rewrite a copied IPv4 header in place for a reassembled datagram: set the
/// total length, clear the flags (DF/MF) + fragment offset, and recompute the
/// header checksum. `total` is the full IP datagram length (header + payload).
fn patch_ipv4_header(hdr: &mut [u8], total: u16) {
    hdr[2..4].copy_from_slice(&total.to_be_bytes());
    // Bytes 6..8 hold the 3 flag bits + 13-bit fragment offset; zero them.
    hdr[6] = 0;
    hdr[7] = 0;
    // Zero the checksum field before recomputing over the header.
    hdr[10] = 0;
    hdr[11] = 0;
    let ck = ipv4_header_checksum(hdr);
    hdr[10..12].copy_from_slice(&ck.to_be_bytes());
}

/// Standard RFC 791 IPv4 header checksum: 16-bit one's-complement sum of the
/// header (with the checksum field already zeroed), then complemented.
fn ipv4_header_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < hdr.len() {
        sum += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
        i += 2;
    }
    if i < hdr.len() {
        sum += (hdr[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_a_known_header() {
        // RFC-791-style header (Wikipedia IPv4 example), checksum field zeroed.
        // 4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7
        let mut hdr = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let ck = ipv4_header_checksum(&hdr);
        assert_eq!(ck, 0xb861, "known-vector checksum");
        // Writing it back and re-summing a valid header yields 0.
        hdr[10..12].copy_from_slice(&ck.to_be_bytes());
        assert_eq!(ipv4_header_checksum(&hdr), 0, "header now verifies");
    }
}
