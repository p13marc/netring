//! Software cBPF interpreter for [`BpfFilter::matches`].
//!
//! Implements the opcode subset emitted by the typed builder
//! (and a small handful beyond it for forward-compatibility).
//! Out-of-bounds loads, instruction-counter overruns, and
//! opcodes outside the supported subset all return `false`
//! (fail-closed) — same shape as the kernel verifier rejecting
//! unknown opcodes at attach time.

use super::bpf::{BpfAncillary, BpfFilter, vlan_tpid};
use super::bpf_compile::{
    BPF_ALU_AND_K, BPF_JMP_JA, BPF_JMP_JEQ_K, BPF_JMP_JGT_K, BPF_JMP_JSET_K, BPF_LD_B_ABS,
    BPF_LD_H_ABS, BPF_LD_H_IND, BPF_LD_W_ABS, BPF_LDX_B_MSH, BPF_MISC_TXA, BPF_RET_A, BPF_RET_K,
    BPF_RET_X, SKF_AD_OFF, SKF_AD_VLAN_TAG, SKF_AD_VLAN_TAG_PRESENT, SKF_AD_VLAN_TPID,
};

impl BpfFilter {
    /// Run this filter against `frame` in software, with **no** ancillary
    /// data: every VLAN tag is taken to be in the frame — tcpdump's
    /// semantics on a pcap file. Returns true iff the program would return
    /// a non-zero verdict (accept). Same as
    /// [`matches_with(frame, &BpfAncillary::NONE)`](Self::matches_with).
    ///
    /// On a live capture the kernel strips the outer VLAN tag before the
    /// socket filter runs; use [`matches_with`](Self::matches_with) with
    /// [`Packet::bpf_ancillary`](crate::Packet) to get the verdict the
    /// kernel gave a captured packet.
    ///
    /// Out-of-bounds loads, instruction-counter overruns, and
    /// opcodes outside the supported subset return `false`
    /// (fail-closed). The kernel verifier behaves the same way
    /// at `setsockopt(SO_ATTACH_FILTER)`: an unknown opcode
    /// rejects the program before it ever runs.
    ///
    /// Supported opcodes (exactly what
    /// [`BpfFilterBuilder`](crate::config::BpfFilterBuilder) and
    /// [`with_snap_len`](Self::with_snap_len) emit, plus a few
    /// forward-compatible additions):
    ///
    /// - `BPF_LD | BPF_W | BPF_ABS` (0x20) — load 32-bit at offset k
    /// - `BPF_LD | BPF_H | BPF_ABS` (0x28) — load 16-bit at offset k
    /// - `BPF_LD | BPF_B | BPF_ABS` (0x30) — load 8-bit at offset k
    /// - the same loads with `k = SKF_AD_OFF + SKF_AD_VLAN_TAG` (44),
    ///   `SKF_AD_VLAN_TAG_PRESENT` (48) or `SKF_AD_VLAN_TPID` (60) read the
    ///   ancillary VLAN data; any other `k ≥ SKF_AD_OFF` fails closed
    /// - `BPF_LD | BPF_H | BPF_IND` (0x48) — load 16-bit at X+k
    /// - `BPF_LDX | BPF_B | BPF_MSH` (0xb1) — X = 4 * (mem\[k\] & 0xf)
    /// - `BPF_ALU | BPF_AND | BPF_K` (0x54) — A &= k
    /// - `BPF_MISC | BPF_TXA` (0x87) — A = X
    /// - `BPF_JMP | BPF_JEQ | BPF_K` (0x15) — pc += jt if A==k else pc += jf
    /// - `BPF_JMP | BPF_JGT | BPF_K` (0x25) — pc += jt if A>k else pc += jf
    /// - `BPF_JMP | BPF_JSET | BPF_K` (0x45) — pc += jt if A&k!=0 else pc += jf
    /// - `BPF_JMP | BPF_JA` (0x05) — pc += k (32-bit relative)
    /// - `BPF_RET | BPF_K` (0x06) — return k (0 = drop, non-zero = accept)
    /// - `BPF_RET | BPF_A` (0x16), `BPF_RET | BPF_X` (0x0e) — return A / X
    ///
    /// Hand-rolled programs from [`BpfFilter::new`] that use
    /// opcodes outside this set will match nothing under
    /// `matches`; the kernel remains the source of truth.
    pub fn matches(&self, frame: &[u8]) -> bool {
        self.matches_with(frame, &BpfAncillary::NONE)
    }

    /// Run this filter the way the kernel ran it on a captured packet:
    /// `frame` plus the ancillary data `anc` (see [`BpfAncillary`]).
    ///
    /// `SKF_AD_VLAN_TAG` / `_PRESENT` / `_TPID` loads read `anc.vlan`
    /// (as the kernel's `convert_bpf_extensions` does: the TCI or 0, 1 or
    /// 0, the TPID or 0). With [`BpfAncillary::reinserted`], packet loads
    /// see `frame` without its bytes 12..16 — the frame the kernel's filter
    /// ran on before the tag was put back. So for a packet `p` from a
    /// [`Capture`](crate::Capture),
    /// `filter.matches_with(p.data(), &p.bpf_ancillary())` is the verdict
    /// the socket filter gave it.
    pub fn matches_with(&self, frame: &[u8], anc: &BpfAncillary) -> bool {
        self.verdict_with(frame, anc) != 0
    }

    /// The program's return value for `frame` with no ancillary data: what
    /// the kernel uses as the number of bytes to capture (`0` drops).
    /// Fail-closed paths return `0`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn verdict(&self, frame: &[u8]) -> u32 {
        self.verdict_with(frame, &BpfAncillary::NONE)
    }

    /// [`verdict`](Self::verdict) with ancillary data.
    pub(crate) fn verdict_with(&self, frame: &[u8], anc: &BpfAncillary) -> u32 {
        let insns = self.instructions();
        if insns.is_empty() {
            return 0;
        }
        let mem = Frame::new(frame, anc);
        // cBPF programs are bounded by BPF_MAXINSNS (4096); we
        // cap iteration at 2× that to be safe against malformed
        // hand-rolled programs that loop. (Forward-only jumps
        // make true loops impossible in well-formed programs,
        // but defensive programming.)
        let max_steps = (BpfFilter::MAX_INSNS * 2).max(insns.len() * 2);
        let mut pc: usize = 0;
        let mut a: u32 = 0;
        let mut x: u32 = 0;
        let mut steps: usize = 0;

        // Conditional jump: `jt` when `taken`, else `jf`.
        let branch = |pc: usize, taken: bool, jt: u8, jf: u8| -> Option<usize> {
            let off = usize::from(if taken { jt } else { jf });
            pc.checked_add(off + 1)
        };

        while steps < max_steps {
            steps += 1;
            let Some(insn) = insns.get(pc) else {
                return 0; // ran off the end without RET
            };
            match insn.code {
                BPF_LD_W_ABS | BPF_LD_H_ABS | BPF_LD_B_ABS if insn.k >= SKF_AD_OFF => {
                    // Ancillary data (the kernel converts these whatever the
                    // load size). Unknown extensions fail closed.
                    a = match insn.k - SKF_AD_OFF {
                        SKF_AD_VLAN_TAG => anc.vlan.map_or(0, |t| u32::from(t.tci)),
                        SKF_AD_VLAN_TAG_PRESENT => u32::from(anc.vlan.is_some()),
                        SKF_AD_VLAN_TPID => anc.vlan.map_or(0, |t| u32::from(vlan_tpid(t.proto))),
                        _ => return 0,
                    };
                }
                BPF_LD_W_ABS => match mem.word(insn.k as usize) {
                    Some(v) => a = v,
                    None => return 0,
                },
                BPF_LD_H_ABS => match mem.half(insn.k as usize) {
                    Some(v) => a = u32::from(v),
                    None => return 0,
                },
                BPF_LD_B_ABS => match mem.byte(insn.k as usize) {
                    Some(v) => a = u32::from(v),
                    None => return 0,
                },
                BPF_LD_H_IND => {
                    let off = (x as usize).checked_add(insn.k as usize);
                    match off.and_then(|o| mem.half(o)) {
                        Some(v) => a = u32::from(v),
                        None => return 0,
                    }
                }
                BPF_LDX_B_MSH => match mem.byte(insn.k as usize) {
                    Some(b) => x = 4 * u32::from(b & 0x0F),
                    None => return 0,
                },
                BPF_ALU_AND_K => {
                    a &= insn.k;
                }
                BPF_MISC_TXA => {
                    a = x;
                }
                BPF_JMP_JEQ_K | BPF_JMP_JGT_K | BPF_JMP_JSET_K => {
                    let taken = match insn.code {
                        BPF_JMP_JEQ_K => a == insn.k,
                        BPF_JMP_JGT_K => a > insn.k,
                        _ => (a & insn.k) != 0,
                    };
                    pc = match branch(pc, taken, insn.jt, insn.jf) {
                        Some(p) => p,
                        None => return 0,
                    };
                    continue;
                }
                BPF_JMP_JA => {
                    // Unconditional 32-bit relative offset (k).
                    pc = match pc.checked_add(insn.k as usize + 1) {
                        Some(p) => p,
                        None => return 0,
                    };
                    continue;
                }
                BPF_RET_K => return insn.k,
                BPF_RET_A => return a,
                BPF_RET_X => return x,
                _ => return 0, // unknown opcode → fail-closed
            }
            pc += 1;
        }
        0
    }
}

/// The packet bytes the filter reads: `frame` as is, or — when a stripped
/// VLAN tag was re-inserted at bytes 12..16 — the frame without those four
/// bytes (logical offset `o` reads `o` below 12, `o + 4` from 12 on).
struct Frame<'a> {
    data: &'a [u8],
    /// Skip bytes 12..16 (the re-inserted tag).
    skip_tag: bool,
}

impl<'a> Frame<'a> {
    fn new(data: &'a [u8], anc: &BpfAncillary) -> Self {
        Self {
            data,
            skip_tag: anc.vlan_in_frame && anc.vlan.is_some() && data.len() >= 16,
        }
    }

    #[inline]
    fn byte(&self, o: usize) -> Option<u8> {
        if !self.skip_tag {
            return self.data.get(o).copied();
        }
        let phys = if o < 12 { o } else { o.checked_add(4)? };
        self.data.get(phys).copied()
    }

    #[inline]
    fn half(&self, o: usize) -> Option<u16> {
        if !self.skip_tag {
            let b = self.data.get(o..o.checked_add(2)?)?;
            return Some(u16::from_be_bytes([b[0], b[1]]));
        }
        Some(u16::from_be_bytes([
            self.byte(o)?,
            self.byte(o.checked_add(1)?)?,
        ]))
    }

    #[inline]
    fn word(&self, o: usize) -> Option<u32> {
        if !self.skip_tag {
            let b = self.data.get(o..o.checked_add(4)?)?;
            return Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        }
        Some(u32::from_be_bytes([
            self.byte(o)?,
            self.byte(o.checked_add(1)?)?,
            self.byte(o.checked_add(2)?)?,
            self.byte(o.checked_add(3)?)?,
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BpfFilter as Filter;
    use crate::config::BpfInsn;

    /// Build a synthetic Ethernet+IPv4+TCP frame with the given
    /// src/dst addr/port and SYN flag. 54 bytes total. Used for
    /// interpreter unit tests; pcap fixture coverage lives in
    /// `tests/bpf_builder_match.rs` once that lands.
    fn synth_eth_ipv4_tcp(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut f = Vec::with_capacity(54);
        // Ethernet: dst=0..0, src=0..0, ethtype=0x0800
        f.extend_from_slice(&[0u8; 12]);
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        // IPv4 header (20 bytes, IHL=5):
        f.push(0x45); // version=4, IHL=5
        f.push(0); // DSCP/ECN
        f.extend_from_slice(&20u16.to_be_bytes()); // total len = IP+TCP
        f.extend_from_slice(&0u16.to_be_bytes()); // ID
        f.extend_from_slice(&0u16.to_be_bytes()); // flags+frag = 0 (no fragment)
        f.push(64); // TTL
        f.push(6); // proto = TCP
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum (skip)
        f.extend_from_slice(&src_ip);
        f.extend_from_slice(&dst_ip);
        // TCP header (20 bytes, no options):
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes()); // seq
        f.extend_from_slice(&0u32.to_be_bytes()); // ack
        f.push(0x50); // data offset = 5
        f.push(0x02); // flags = SYN
        f.extend_from_slice(&8192u16.to_be_bytes()); // window
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum
        f.extend_from_slice(&0u16.to_be_bytes()); // urgent ptr
        f
    }

    #[test]
    fn ret_nonzero_accepts() {
        let f = Filter::new(vec![BpfInsn {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: u32::MAX,
        }])
        .unwrap();
        assert!(f.matches(&[0u8; 64]));
    }

    #[test]
    fn ret_zero_drops() {
        let f = Filter::new(vec![BpfInsn {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: 0,
        }])
        .unwrap();
        assert!(!f.matches(&[0u8; 64]));
    }

    #[test]
    fn empty_filter_drops() {
        let f = Filter::new(vec![]).unwrap();
        assert!(!f.matches(&[0u8; 64]));
    }

    #[test]
    fn unknown_opcode_fails_closed() {
        let f = Filter::new(vec![BpfInsn {
            code: 0xFF,
            jt: 0,
            jf: 0,
            k: 0,
        }])
        .unwrap();
        assert!(!f.matches(&[0u8; 64]));
    }

    #[test]
    fn ipv4_filter_matches_ipv4_packet() {
        let f = Filter::builder().ipv4().build().unwrap();
        let pkt = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        assert!(f.matches(&pkt));
    }

    #[test]
    fn ipv4_filter_rejects_arp() {
        let f = Filter::builder().ipv4().build().unwrap();
        let mut arp = vec![0u8; 42];
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP ethtype
        assert!(!f.matches(&arp));
    }

    #[test]
    fn tcp_filter_matches_tcp_packet() {
        let f = Filter::builder().tcp().build().unwrap();
        let pkt = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        assert!(f.matches(&pkt));
    }

    #[test]
    fn tcp_filter_rejects_udp_packet() {
        let f = Filter::builder().tcp().build().unwrap();
        let mut pkt = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        pkt[23] = 17; // change IP proto to UDP
        assert!(!f.matches(&pkt));
    }

    #[test]
    fn dst_port_80_matches() {
        let f = Filter::builder().tcp().dst_port(80).build().unwrap();
        let pkt = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 12345, 80);
        assert!(f.matches(&pkt));
    }

    #[test]
    fn dst_port_80_rejects_443() {
        let f = Filter::builder().tcp().dst_port(80).build().unwrap();
        let pkt = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 12345, 443);
        assert!(!f.matches(&pkt));
    }

    #[test]
    fn host_matches_either_direction() {
        let target: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let f = Filter::builder().host(target).build().unwrap();
        let pkt_src = synth_eth_ipv4_tcp([10, 0, 0, 5], [2, 2, 2, 2], 1234, 80);
        let pkt_dst = synth_eth_ipv4_tcp([2, 2, 2, 2], [10, 0, 0, 5], 1234, 80);
        let pkt_neither = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        assert!(f.matches(&pkt_src));
        assert!(f.matches(&pkt_dst));
        assert!(!f.matches(&pkt_neither));
    }

    #[test]
    fn src_net_matches_subnet() {
        let net: crate::config::IpNet = "10.0.0.0/24".parse().unwrap();
        let f = Filter::builder().src_net(net).build().unwrap();
        let inside = synth_eth_ipv4_tcp([10, 0, 0, 99], [2, 2, 2, 2], 1234, 80);
        let outside = synth_eth_ipv4_tcp([10, 0, 1, 99], [2, 2, 2, 2], 1234, 80);
        assert!(f.matches(&inside));
        assert!(!f.matches(&outside));
    }

    #[test]
    fn dst_port_rejects_ipv4_fragment() {
        // dst_port 80 with a fragment offset != 0 → reject (the
        // jset #0x1fff guard).
        let f = Filter::builder().tcp().dst_port(80).build().unwrap();
        let mut pkt = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        // Set the fragment-offset low bits at IPv4 frag offset 6 (Eth 14 + 6 = 20).
        pkt[20] = 0x00;
        pkt[21] = 0x10; // frag_off = 16 (non-zero)
        assert!(!f.matches(&pkt));
    }

    fn synth_eth_ipv4_udp(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut f = synth_eth_ipv4_tcp(src_ip, dst_ip, src_port, dst_port);
        f[23] = 17; // IP proto = UDP
        // UDP header: src(2), dst(2), len(2), cksum(2). Reuse first
        // 8 bytes of TCP space.
        f
    }

    /// Wrap a synthetic IPv4/TCP frame in an 802.1Q VLAN tag.
    /// Inserts 4 bytes [0x8100, TCI] between src MAC and ethtype.
    fn synth_vlan_eth_ipv4_tcp(
        vlan_id: u16,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let inner = synth_eth_ipv4_tcp(src_ip, dst_ip, src_port, dst_port);
        let mut f = Vec::with_capacity(inner.len() + 4);
        // dst MAC + src MAC (12 bytes from inner).
        f.extend_from_slice(&inner[0..12]);
        // VLAN tag: 0x8100 + TCI. TCI = priority(3) + DEI(1) +
        // VLAN ID(12). For tests we set priority/DEI to 0.
        f.extend_from_slice(&0x8100u16.to_be_bytes());
        f.extend_from_slice(&(vlan_id & 0x0FFF).to_be_bytes());
        // Inner ethertype + IP header + TCP header (rest of inner).
        f.extend_from_slice(&inner[12..]);
        f
    }

    #[test]
    fn or_tcp80_or_udp53_accepts_both() {
        let f = Filter::builder()
            .tcp()
            .port(80)
            .or(|b| b.udp().port(53))
            .build()
            .unwrap();
        let tcp_80 = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        let udp_53 = synth_eth_ipv4_udp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 53);
        let tcp_443 = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 443);
        let udp_99 = synth_eth_ipv4_udp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 99);
        assert!(f.matches(&tcp_80), "TCP 80 should match");
        assert!(f.matches(&udp_53), "UDP 53 should match");
        assert!(!f.matches(&tcp_443), "TCP 443 should not match");
        assert!(!f.matches(&udp_99), "UDP 99 should not match");
    }

    #[test]
    fn negate_inverts_match() {
        // "not arp" — accepts everything except ARP.
        let f = Filter::builder().arp().negate().build().unwrap();
        let mut arp = vec![0u8; 42];
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        let ip_pkt = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        assert!(!f.matches(&arp));
        assert!(f.matches(&ip_pkt));
    }

    #[test]
    fn vlan_and_tcp_port_matches_vlan_tagged() {
        let f = Filter::builder().vlan().tcp().dst_port(80).build().unwrap();
        let vlan_tcp = synth_vlan_eth_ipv4_tcp(100, [1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        let plain_tcp = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        assert!(f.matches(&vlan_tcp), "VLAN-tagged TCP/80 should match");
        assert!(
            !f.matches(&plain_tcp),
            "untagged TCP/80 should NOT match a vlan-required filter"
        );
    }

    #[test]
    fn vlan_id_match() {
        let f = Filter::builder().vlan().vlan_id(100).build().unwrap();
        let vlan_100 = synth_vlan_eth_ipv4_tcp(100, [1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        let vlan_200 = synth_vlan_eth_ipv4_tcp(200, [1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        assert!(f.matches(&vlan_100));
        assert!(!f.matches(&vlan_200));
    }

    /// Build a synthetic Ethernet+IPv6+TCP frame. 74 bytes total.
    fn synth_eth_ipv6_tcp(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut f = Vec::with_capacity(74);
        f.extend_from_slice(&[0u8; 12]); // dst+src MAC
        f.extend_from_slice(&0x86ddu16.to_be_bytes()); // ethtype = IPv6
        // IPv6 header (40 bytes):
        f.push(0x60); // version 6, traffic class top
        f.push(0); // traffic class bottom + flow label top
        f.extend_from_slice(&[0u8; 2]); // flow label rest
        f.extend_from_slice(&20u16.to_be_bytes()); // payload length (TCP hdr only)
        f.push(6); // next header = TCP
        f.push(64); // hop limit
        f.extend_from_slice(&src_ip);
        f.extend_from_slice(&dst_ip);
        // TCP header:
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes());
        f.push(0x50);
        f.push(0x02);
        f.extend_from_slice(&8192u16.to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes());
        f
    }

    #[test]
    fn ipv6_filter_matches_ipv6_packet() {
        let f = Filter::builder().ipv6().build().unwrap();
        let pkt = synth_eth_ipv6_tcp(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            1234,
            80,
        );
        assert!(f.matches(&pkt));
    }

    #[test]
    fn ipv6_tcp_dst_port_match() {
        let f = Filter::builder().ipv6().tcp().dst_port(80).build().unwrap();
        let pkt_yes = synth_eth_ipv6_tcp(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            1234,
            80,
        );
        let pkt_no = synth_eth_ipv6_tcp(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            1234,
            443,
        );
        assert!(f.matches(&pkt_yes));
        assert!(!f.matches(&pkt_no));
    }

    #[test]
    fn ipv6_src_host_match() {
        let target: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        let f = Filter::builder().ipv6().src_host(target).build().unwrap();
        let pkt_yes = synth_eth_ipv6_tcp(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            1234,
            80,
        );
        let pkt_no = synth_eth_ipv6_tcp(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            1234,
            80,
        );
        assert!(f.matches(&pkt_yes));
        assert!(!f.matches(&pkt_no));
    }

    #[test]
    fn ipv6_any_host_matches_either_direction() {
        let target: std::net::IpAddr = "2001:db8::5".parse().unwrap();
        let f = Filter::builder().ipv6().host(target).build().unwrap();
        let addr_a = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        let addr_b = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99];
        let pkt_src = synth_eth_ipv6_tcp(addr_a, addr_b, 1234, 80);
        let pkt_dst = synth_eth_ipv6_tcp(addr_b, addr_a, 1234, 80);
        let pkt_neither = synth_eth_ipv6_tcp(addr_b, addr_b, 1234, 80);
        assert!(f.matches(&pkt_src));
        assert!(f.matches(&pkt_dst));
        assert!(!f.matches(&pkt_neither));
    }

    #[test]
    fn double_negate_is_identity() {
        let plain = Filter::builder().tcp().build().unwrap();
        let double = Filter::builder().tcp().negate().negate().build().unwrap();
        let pkt_yes = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        let mut pkt_no = pkt_yes.clone();
        pkt_no[23] = 17; // UDP
        assert_eq!(plain.matches(&pkt_yes), double.matches(&pkt_yes));
        assert_eq!(plain.matches(&pkt_no), double.matches(&pkt_no));
    }

    #[test]
    fn out_of_bounds_load_drops() {
        // ldh [100] on a 64-byte frame → out of bounds.
        let f = Filter::new(vec![
            BpfInsn {
                code: BPF_LD_H_ABS,
                jt: 0,
                jf: 0,
                k: 100,
            },
            BpfInsn {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: u32::MAX,
            },
        ])
        .unwrap();
        assert!(!f.matches(&[0u8; 64]));
    }

    // ── Ancillary data / stripped VLAN tags (#208) ─────────────────────

    use crate::config::{BpfAncillary, VlanProto, VlanTag};

    fn ins(code: u16, k: u32) -> BpfInsn {
        BpfInsn {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// `ld [SKF_AD_OFF + ext]; ret a` — returns the ancillary word.
    fn load_ext(ext: u32) -> Filter {
        Filter::new(vec![ins(BPF_LD_W_ABS, SKF_AD_OFF + ext), ins(BPF_RET_A, 0)]).unwrap()
    }

    /// `frame` with a tag (`tpid`, `tci`) inserted at bytes 12..16.
    fn reinsert(frame: &[u8], tpid: u16, tci: u16) -> Vec<u8> {
        let mut f = frame[..12].to_vec();
        f.extend_from_slice(&tpid.to_be_bytes());
        f.extend_from_slice(&tci.to_be_bytes());
        f.extend_from_slice(&frame[12..]);
        f
    }

    #[test]
    fn ancillary_vlan_loads_read_the_stripped_tag() {
        let frame = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        let tag = VlanTag::new(0x2064, VlanProto::Dot1Ad);
        let anc = BpfAncillary::stripped(tag);
        assert_eq!(load_ext(SKF_AD_VLAN_TAG).verdict_with(&frame, &anc), 0x2064);
        assert_eq!(
            load_ext(SKF_AD_VLAN_TAG_PRESENT).verdict_with(&frame, &anc),
            1
        );
        assert_eq!(
            load_ext(SKF_AD_VLAN_TPID).verdict_with(&frame, &anc),
            0x88a8
        );
        // Any load size reads the extension, as the kernel converts it.
        let half = Filter::new(vec![
            ins(BPF_LD_H_ABS, SKF_AD_OFF + SKF_AD_VLAN_TAG),
            ins(BPF_RET_A, 0),
        ])
        .unwrap();
        assert_eq!(half.verdict_with(&frame, &anc), 0x2064);
        let other = BpfAncillary::stripped(VlanTag::new(5, VlanProto::Other(0x9100)));
        assert_eq!(
            load_ext(SKF_AD_VLAN_TPID).verdict_with(&frame, &other),
            0x9100
        );
    }

    #[test]
    fn ancillary_vlan_loads_without_a_tag_are_zero() {
        let frame = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        for ext in [SKF_AD_VLAN_TAG, SKF_AD_VLAN_TAG_PRESENT, SKF_AD_VLAN_TPID] {
            assert_eq!(load_ext(ext).verdict_with(&frame, &BpfAncillary::NONE), 0);
            assert_eq!(load_ext(ext).verdict(&frame), 0);
        }
    }

    #[test]
    fn unknown_ancillary_offset_fails_closed() {
        // SKF_AD_PROTOCOL (0) and anything else netring does not model:
        // `false`, never a guess.
        let frame = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        let tag = BpfAncillary::stripped(VlanTag::new(100, VlanProto::Dot1Q));
        for ext in [0u32, 4, 8, 40, 52, 56, 0xfff] {
            let f =
                Filter::new(vec![ins(BPF_LD_W_ABS, SKF_AD_OFF + ext), ins(BPF_RET_K, 1)]).unwrap();
            assert!(!f.matches_with(&frame, &tag), "SKF_AD_OFF + {ext}");
            assert!(!f.matches(&frame), "SKF_AD_OFF + {ext}");
        }
    }

    #[test]
    fn reinserted_tag_is_skipped_by_packet_loads() {
        let untagged = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80);
        let tagged = reinsert(&untagged, 0x8100, 100);
        let anc = BpfAncillary::reinserted(VlanTag::new(100, VlanProto::Dot1Q));
        // ldh [12] sees the inner EtherType, not the TPID.
        let ethertype = Filter::new(vec![ins(BPF_LD_H_ABS, 12), ins(BPF_RET_A, 0)]).unwrap();
        assert_eq!(ethertype.verdict_with(&tagged, &anc), 0x0800);
        assert_eq!(ethertype.verdict(&tagged), 0x8100);
        // A word straddling the hole and the IHL-relative port loads agree.
        let tcp80 = Filter::builder().tcp().dst_port(80).build().unwrap();
        assert!(tcp80.matches_with(&tagged, &anc));
        assert!(!tcp80.matches(&tagged), "offline: the tag is in the frame");
        let word = Filter::new(vec![ins(BPF_LD_W_ABS, 10), ins(BPF_RET_A, 0)]).unwrap();
        assert_eq!(word.verdict_with(&tagged, &anc), word.verdict(&untagged));
        // The logical frame is 4 bytes shorter.
        let last = Filter::new(vec![
            ins(BPF_LD_B_ABS, (untagged.len() - 1) as u32),
            ins(BPF_RET_K, 1),
        ])
        .unwrap();
        assert!(last.matches_with(&tagged, &anc));
        let past = Filter::new(vec![
            ins(BPF_LD_B_ABS, untagged.len() as u32),
            ins(BPF_RET_K, 1),
        ])
        .unwrap();
        assert!(!past.matches_with(&tagged, &anc));
        assert!(past.matches(&tagged));
    }

    /// The kernel's verdict on a frame whose outer tag it stripped is the
    /// same whether we hand the interpreter the stripped frame or the
    /// re-inserted one.
    #[test]
    fn stripped_and_reinserted_agree() {
        let filters = [
            Filter::builder()
                .vlan()
                .vlan_id(100)
                .tcp()
                .dst_port(80)
                .build()
                .unwrap(),
            Filter::builder().vlan().vlan_id(200).build().unwrap(),
            Filter::builder().vlan().build().unwrap(),
            Filter::builder().vlan().negate().build().unwrap(),
            Filter::builder().tcp().dst_port(80).build().unwrap(),
            Filter::builder()
                .tcp()
                .dst_port(80)
                .or(|b| b.vlan().udp())
                .build()
                .unwrap(),
            Filter::builder().eth_type(0x8100).build().unwrap(),
        ];
        let inner = [
            synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80),
            synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 443),
            synth_eth_ipv4_udp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 53),
            synth_vlan_eth_ipv4_tcp(200, [1, 1, 1, 1], [2, 2, 2, 2], 1234, 80), // QinQ inner
        ];
        let tags = [
            VlanTag::new(100, VlanProto::Dot1Q),
            VlanTag::new(0x2000 | 200, VlanProto::Dot1Q),
            VlanTag::new(100, VlanProto::Dot1Ad),
        ];
        for f in &filters {
            for frame in &inner {
                for tag in tags {
                    let tpid = vlan_tpid(tag.proto);
                    let stripped = f.matches_with(frame, &BpfAncillary::stripped(tag));
                    let reinserted = f.matches_with(
                        &reinsert(frame, tpid, tag.tci),
                        &BpfAncillary::reinserted(tag),
                    );
                    assert_eq!(
                        stripped,
                        reinserted,
                        "{} on {frame:02x?} with {tag:?}",
                        f.to_human()
                    );
                }
            }
        }
    }
}
