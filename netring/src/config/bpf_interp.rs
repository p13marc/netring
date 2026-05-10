//! Software cBPF interpreter for [`BpfFilter::matches`].
//!
//! Implements the opcode subset emitted by the typed builder
//! (and a small handful beyond it for forward-compatibility).
//! Out-of-bounds loads, instruction-counter overruns, and
//! opcodes outside the supported subset all return `false`
//! (fail-closed) — same shape as the kernel verifier rejecting
//! unknown opcodes at attach time.

use super::bpf::BpfFilter;
use super::bpf_compile::{
    BPF_ALU_AND_K, BPF_JMP_JA, BPF_JMP_JEQ_K, BPF_JMP_JSET_K, BPF_LD_B_ABS, BPF_LD_H_ABS,
    BPF_LD_H_IND, BPF_LD_W_ABS, BPF_LDX_B_MSH, BPF_RET_K,
};

impl BpfFilter {
    /// Run this filter against `frame` in software. Returns true
    /// iff the program would `ret #non-zero`.
    ///
    /// Out-of-bounds loads, instruction-counter overruns, and
    /// opcodes outside the supported subset return `false`
    /// (fail-closed). The kernel verifier behaves the same way
    /// at `setsockopt(SO_ATTACH_FILTER)`: an unknown opcode
    /// rejects the program before it ever runs.
    ///
    /// Supported opcodes (exactly what
    /// [`BpfFilterBuilder`](crate::config::BpfFilterBuilder)
    /// emits, plus a few forward-compatible additions):
    ///
    /// - `BPF_LD | BPF_W | BPF_ABS` (0x20) — load 32-bit at offset k
    /// - `BPF_LD | BPF_H | BPF_ABS` (0x28) — load 16-bit at offset k
    /// - `BPF_LD | BPF_B | BPF_ABS` (0x30) — load 8-bit at offset k
    /// - `BPF_LD | BPF_H | BPF_IND` (0x48) — load 16-bit at X+k
    /// - `BPF_LDX | BPF_B | BPF_MSH` (0xb1) — X = 4 * (mem[k] & 0xf)
    /// - `BPF_ALU | BPF_AND | BPF_K` (0x54) — A &= k
    /// - `BPF_JMP | BPF_JEQ | BPF_K` (0x15) — pc += jt if A==k else pc += jf
    /// - `BPF_JMP | BPF_JSET | BPF_K` (0x45) — pc += jt if A&k!=0 else pc += jf
    /// - `BPF_JMP | BPF_JA` (0x05) — pc += k (32-bit relative)
    /// - `BPF_RET | BPF_K` (0x06) — return k (0 = drop, non-zero = accept)
    ///
    /// Hand-rolled programs from [`BpfFilter::new`] that use
    /// opcodes outside this set will match nothing under
    /// `matches`; the kernel remains the source of truth.
    pub fn matches(&self, frame: &[u8]) -> bool {
        let insns = self.instructions();
        if insns.is_empty() {
            return false;
        }
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

        while steps < max_steps {
            steps += 1;
            let Some(insn) = insns.get(pc) else {
                return false; // ran off the end without RET
            };
            match insn.code {
                BPF_LD_W_ABS => match load_word(frame, insn.k as usize) {
                    Some(v) => a = v,
                    None => return false,
                },
                BPF_LD_H_ABS => match load_half(frame, insn.k as usize) {
                    Some(v) => a = u32::from(v),
                    None => return false,
                },
                BPF_LD_B_ABS => match load_byte(frame, insn.k as usize) {
                    Some(v) => a = u32::from(v),
                    None => return false,
                },
                BPF_LD_H_IND => {
                    let off = (x as usize).checked_add(insn.k as usize);
                    match off.and_then(|o| load_half(frame, o)) {
                        Some(v) => a = u32::from(v),
                        None => return false,
                    }
                }
                BPF_LDX_B_MSH => match load_byte(frame, insn.k as usize) {
                    Some(b) => x = 4 * u32::from(b & 0x0F),
                    None => return false,
                },
                BPF_ALU_AND_K => {
                    a &= insn.k;
                }
                BPF_JMP_JEQ_K => {
                    let off = if a == insn.k {
                        usize::from(insn.jt)
                    } else {
                        usize::from(insn.jf)
                    };
                    pc = match pc.checked_add(off + 1) {
                        Some(p) => p,
                        None => return false,
                    };
                    continue;
                }
                BPF_JMP_JSET_K => {
                    let off = if (a & insn.k) != 0 {
                        usize::from(insn.jt)
                    } else {
                        usize::from(insn.jf)
                    };
                    pc = match pc.checked_add(off + 1) {
                        Some(p) => p,
                        None => return false,
                    };
                    continue;
                }
                BPF_JMP_JA => {
                    // Unconditional 32-bit relative offset (k).
                    pc = match pc.checked_add(insn.k as usize + 1) {
                        Some(p) => p,
                        None => return false,
                    };
                    continue;
                }
                BPF_RET_K => {
                    return insn.k != 0;
                }
                _ => return false, // unknown opcode → fail-closed
            }
            pc += 1;
        }
        false
    }
}

#[inline]
fn load_word(frame: &[u8], offset: usize) -> Option<u32> {
    let bytes = frame.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

#[inline]
fn load_half(frame: &[u8], offset: usize) -> Option<u16> {
    let bytes = frame.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

#[inline]
fn load_byte(frame: &[u8], offset: usize) -> Option<u8> {
    frame.get(offset).copied()
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
            k: 0xFFFF,
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
                k: 0xFFFF,
            },
        ])
        .unwrap();
        assert!(!f.matches(&[0u8; 64]));
    }
}
