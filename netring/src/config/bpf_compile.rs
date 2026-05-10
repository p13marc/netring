//! Symbolic-label IR + linker pass for the typed BPF builder.
//!
//! Pipeline: see plan-18 §"Compiler pipeline".
//!
//! 1. `normalize(...)` reorders + dedups + auto-inserts the
//!    implicit `EthType(0x0800)` for IPv4 ip_proto/host/port.
//! 2. `compile_and_chain(...)` emits per-fragment [`SymInsn`]
//!    streams with [`Label`] targets.
//! 3. `link(...)` concatenates AND chain + OR branches and adds
//!    accept/drop tails. (OR + NOT come in phase B part 2.)
//! 4. `resolve(...)` walks the symbolic stream and rewrites each
//!    jump's `jt`/`jf` to numeric u8 relative offsets.

use std::net::IpAddr;

use super::bpf::{BpfFilter, BpfInsn, BuildError};
use super::bpf_builder::{BpfFilterBuilder, MatchFrag};
use super::ipnet::IpNet;

// ── Opcode constants (subset emitted by the builder) ──────────

// `LD | H | ABS` — load 16-bit half-word from absolute offset k.
pub(crate) const BPF_LD_H_ABS: u16 = 0x28;
// `LD | B | ABS` — load 8-bit byte from absolute offset k.
pub(crate) const BPF_LD_B_ABS: u16 = 0x30;
// `LD | W | ABS` — load 32-bit word from absolute offset k.
pub(crate) const BPF_LD_W_ABS: u16 = 0x20;
// `LD | H | IND` — load 16-bit half-word from offset (X + k).
pub(crate) const BPF_LD_H_IND: u16 = 0x48;
// `LDX | B | MSH` — X = 4 * (mem[k] & 0xf). The IPv4 IHL helper.
pub(crate) const BPF_LDX_B_MSH: u16 = 0xb1;
// `ALU | AND | K` — A &= k.
pub(crate) const BPF_ALU_AND_K: u16 = 0x54;
// `JMP | JEQ | K` — pc += jt if A == k else pc += jf.
pub(crate) const BPF_JMP_JEQ_K: u16 = 0x15;
// `JMP | JSET | K` — pc += jt if (A & k) != 0 else pc += jf.
pub(crate) const BPF_JMP_JSET_K: u16 = 0x45;
// `JMP | JA` — pc += k (unconditional, 32-bit offset). Reserved
// for OR composition (phase B part 2) where a successful branch
// jumps over remaining branches to the accept tail.
#[allow(dead_code)]
pub(crate) const BPF_JMP_JA: u16 = 0x05;
// `RET | K` — return constant `k` (0 = drop, non-zero = accept).
pub(crate) const BPF_RET_K: u16 = 0x06;

/// Accept verdict. `0xFFFF` matches libpcap's default snap length.
pub(crate) const ACCEPT_RETVAL: u32 = 0xFFFF;
/// Drop verdict. The kernel discards the packet.
#[allow(dead_code)]
pub(crate) const DROP_RETVAL: u32 = 0;

// ── Symbolic IR ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // `Accept` is wired up in phase B part 2 (OR composition).
pub(crate) enum Label {
    /// Fall through to the next instruction. For non-jump
    /// instructions both jt/jf carry this.
    Fallthrough,
    /// Global accept tail. Used by OR composition (phase B p2)
    /// where each branch's success is independent.
    Accept,
    /// Global drop tail.
    Drop,
    /// Skip the next `n` instructions and continue. Used by
    /// fragment-local jumps (e.g. the `host` early-accept on
    /// src match) so we don't need a per-fragment label table.
    SkipNextN(u8),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SymInsn {
    pub code: u16,
    pub jt: Label,
    pub jf: Label,
    pub k: u32,
}

impl SymInsn {
    /// Non-jump instruction (load, ALU, ldx). Jump fields are
    /// `Fallthrough`; the resolver writes them as `0`.
    fn straight(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: Label::Fallthrough,
            jf: Label::Fallthrough,
            k,
        }
    }

    /// Conditional jump: take `jt` if true, `jf` if false.
    fn jump(code: u16, jt: Label, jf: Label, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

/// Layer-3 family for IP-aware fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum L3Family {
    Ipv4,
    Ipv6,
}

/// Compiler context, carries the offset shift introduced by the
/// VLAN marker plus the inferred L3 family for IP/L4 fragments.
#[derive(Debug, Clone, Copy)]
struct CompileCtx {
    vlan_offset: u8,
    l3: L3Family,
}

// ── Public entry point ────────────────────────────────────────

/// Compile a [`BpfFilterBuilder`] into a [`BpfFilter`].
pub(crate) fn compile(builder: BpfFilterBuilder) -> Result<BpfFilter, BuildError> {
    let BpfFilterBuilder {
        fragments,
        or_branches,
        negated,
    } = builder;

    // Phase B part 2 will handle OR/NOT. For now reject anything
    // beyond a plain AND chain so we surface obvious user errors
    // early instead of silently dropping branches.
    if !or_branches.is_empty() {
        // OR composition is not yet wired up. Treat as TODO and
        // return the equivalent of "impossible filter" so tests
        // notice if anyone reaches this path before phase B p2.
        return Err(BuildError::EmptyOr);
    }
    if negated {
        // Same — phase B p2.
        return Err(BuildError::ConflictingProtocols {
            a: "negate (TODO phase B p2)",
            b: "_",
        });
    }

    let normalized = normalize(fragments)?;
    let ctx = infer_ctx(&normalized);

    // Empty builder → accept-all program (no fragments to check).
    if normalized.is_empty() {
        return BpfFilter::new(vec![BpfInsn {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: ACCEPT_RETVAL,
        }]);
    }

    let mut sym: Vec<SymInsn> = Vec::with_capacity(normalized.len() * 6);
    for frag in &normalized {
        compile_fragment(frag, &ctx, &mut sym)?;
    }

    // Append accept + drop tails. The resolver maps Accept/Drop
    // labels to these positions.
    let accept_pc = sym.len();
    sym.push(SymInsn::straight(BPF_RET_K, ACCEPT_RETVAL));
    let drop_pc = sym.len();
    sym.push(SymInsn::straight(BPF_RET_K, super::bpf_compile::DROP_RETVAL));

    let resolved = resolve(&sym, accept_pc, drop_pc)?;
    BpfFilter::new(resolved)
}

// ── Normaliser ────────────────────────────────────────────────

/// Sort/dedupe fragments so user chain order doesn't matter for
/// AND. Detect and reject conflicting protocol selections. Auto-
/// insert `EthType(0x0800)` for IPv4 fragments that need it.
fn normalize(fragments: Vec<MatchFrag>) -> Result<Vec<MatchFrag>, BuildError> {
    // First pass: collect canonical EthType / IpProto choices and
    // detect conflicts.
    let mut chosen_eth: Option<u16> = None;
    let mut chosen_proto: Option<u8> = None;
    for f in &fragments {
        match f {
            MatchFrag::EthType(t) => match chosen_eth {
                Some(prev) if prev != *t => {
                    return Err(BuildError::ConflictingProtocols {
                        a: ethtype_label(prev),
                        b: ethtype_label(*t),
                    });
                }
                _ => chosen_eth = Some(*t),
            },
            MatchFrag::IpProto(p) => match chosen_proto {
                Some(prev) if prev != *p => {
                    return Err(BuildError::ConflictingProtocols {
                        a: ipproto_label(prev),
                        b: ipproto_label(*p),
                    });
                }
                _ => chosen_proto = Some(*p),
            },
            _ => {}
        }
    }

    // Second pass: emit normalized fragments.
    //
    // Order: EthType → IpProto → IP host/net → L4 port. Within
    // each bucket we preserve user order so multi-host or multi-
    // port ANDs (uncommon) compile predictably.
    //
    // Auto-insertion: if any IP-aware fragment is present without
    // an explicit EthType, we default to IPv4. Phase C will allow
    // ipv6 inference; for phase B we default IPv4 because the IP
    // proto / host / port templates below are IPv4-only.

    let needs_ip = chosen_eth.is_none()
        && fragments.iter().any(|f| {
            matches!(
                f,
                MatchFrag::IpProto(_)
                    | MatchFrag::SrcHost(_)
                    | MatchFrag::DstHost(_)
                    | MatchFrag::AnyHost(_)
                    | MatchFrag::SrcNet(_)
                    | MatchFrag::DstNet(_)
                    | MatchFrag::AnyNet(_)
                    | MatchFrag::SrcPort(_)
                    | MatchFrag::DstPort(_)
                    | MatchFrag::AnyPort(_)
            )
        });
    let needs_ip_proto = chosen_proto.is_none()
        && fragments.iter().any(|f| {
            matches!(
                f,
                MatchFrag::SrcPort(_) | MatchFrag::DstPort(_) | MatchFrag::AnyPort(_)
            )
        });

    let mut out: Vec<MatchFrag> = Vec::with_capacity(fragments.len() + 2);

    // EthType bucket (only one canonical value, if any).
    if let Some(t) = chosen_eth {
        out.push(MatchFrag::EthType(t));
    } else if needs_ip {
        out.push(MatchFrag::EthType(0x0800));
    }

    // IpProto bucket.
    if let Some(p) = chosen_proto {
        out.push(MatchFrag::IpProto(p));
    } else if needs_ip_proto {
        // Port fragments require an IP proto for the ports to
        // mean anything. Without one, we'd emit a frag that
        // checks ports against any L4. The kernel still
        // accepts the program, but the user almost certainly
        // wanted .tcp() or .udp() — surface as an error.
        return Err(BuildError::ConflictingProtocols {
            a: "port",
            b: "<no IP protocol — call .tcp() or .udp()>",
        });
    }

    // IP host / net bucket.
    for f in &fragments {
        if matches!(
            f,
            MatchFrag::SrcHost(_)
                | MatchFrag::DstHost(_)
                | MatchFrag::AnyHost(_)
                | MatchFrag::SrcNet(_)
                | MatchFrag::DstNet(_)
                | MatchFrag::AnyNet(_)
        ) {
            push_dedup(&mut out, f.clone());
        }
    }

    // L4 port bucket.
    for f in &fragments {
        if matches!(
            f,
            MatchFrag::SrcPort(_) | MatchFrag::DstPort(_) | MatchFrag::AnyPort(_)
        ) {
            push_dedup(&mut out, f.clone());
        }
    }

    Ok(out)
}

fn push_dedup(buf: &mut Vec<MatchFrag>, f: MatchFrag) {
    if !buf.iter().any(|existing| existing == &f) {
        buf.push(f);
    }
}

fn ethtype_label(t: u16) -> &'static str {
    match t {
        0x0800 => "ipv4",
        0x86dd => "ipv6",
        0x0806 => "arp",
        0x8100 => "vlan",
        _ => "eth_type",
    }
}

fn ipproto_label(p: u8) -> &'static str {
    match p {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        47 => "gre",
        58 => "icmpv6",
        _ => "ip_proto",
    }
}

fn infer_ctx(fragments: &[MatchFrag]) -> CompileCtx {
    let l3 = if fragments
        .iter()
        .any(|f| matches!(f, MatchFrag::EthType(0x86dd)))
    {
        L3Family::Ipv6
    } else {
        L3Family::Ipv4
    };
    CompileCtx { vlan_offset: 0, l3 }
}

// ── Per-fragment templates ────────────────────────────────────

fn compile_fragment(
    frag: &MatchFrag,
    ctx: &CompileCtx,
    out: &mut Vec<SymInsn>,
) -> Result<(), BuildError> {
    match frag {
        MatchFrag::EthType(t) => emit_eth_type(*t, ctx, out),
        MatchFrag::IpProto(p) => emit_ip_proto(*p, ctx, out),
        MatchFrag::SrcHost(IpAddr::V4(a)) => emit_ipv4_host(SrcDst::Src, u32::from_be_bytes(a.octets()), ctx, out),
        MatchFrag::DstHost(IpAddr::V4(a)) => emit_ipv4_host(SrcDst::Dst, u32::from_be_bytes(a.octets()), ctx, out),
        MatchFrag::AnyHost(IpAddr::V4(a)) => emit_ipv4_host(SrcDst::Any, u32::from_be_bytes(a.octets()), ctx, out),
        MatchFrag::SrcNet(net) | MatchFrag::DstNet(net) | MatchFrag::AnyNet(net) => {
            let sd = match frag {
                MatchFrag::SrcNet(_) => SrcDst::Src,
                MatchFrag::DstNet(_) => SrcDst::Dst,
                _ => SrcDst::Any,
            };
            emit_ipv4_net(sd, net, ctx, out)
        }
        MatchFrag::SrcPort(p) => emit_ipv4_port(SrcDst::Src, *p, ctx, out),
        MatchFrag::DstPort(p) => emit_ipv4_port(SrcDst::Dst, *p, ctx, out),
        MatchFrag::AnyPort(p) => emit_ipv4_port(SrcDst::Any, *p, ctx, out),
        // Phase C territory — surface with a clear error.
        MatchFrag::SrcHost(IpAddr::V6(_))
        | MatchFrag::DstHost(IpAddr::V6(_))
        | MatchFrag::AnyHost(IpAddr::V6(_))
        | MatchFrag::Vlan
        | MatchFrag::VlanId(_) => Err(BuildError::Ipv6ExtHeader),
    }
}

#[derive(Debug, Clone, Copy)]
enum SrcDst {
    Src,
    Dst,
    Any,
}

fn emit_eth_type(t: u16, ctx: &CompileCtx, out: &mut Vec<SymInsn>) -> Result<(), BuildError> {
    // Outer ethertype is always at offset 12, regardless of vlan_offset
    // (the vlan_offset shift applies to subsequent loads, not to
    // the ethtype check that *consumed* the VLAN tag).
    let _ = ctx;
    out.push(SymInsn::straight(BPF_LD_H_ABS, 12));
    out.push(SymInsn::jump(
        BPF_JMP_JEQ_K,
        Label::Fallthrough,
        Label::Drop,
        u32::from(t),
    ));
    Ok(())
}

fn emit_ip_proto(p: u8, ctx: &CompileCtx, out: &mut Vec<SymInsn>) -> Result<(), BuildError> {
    let off = match ctx.l3 {
        L3Family::Ipv4 => 23u32 + u32::from(ctx.vlan_offset), // Eth(14) + IPv4 proto(9)
        L3Family::Ipv6 => 20u32 + u32::from(ctx.vlan_offset), // Eth(14) + IPv6 next-hdr(6)
    };
    out.push(SymInsn::straight(BPF_LD_B_ABS, off));
    out.push(SymInsn::jump(
        BPF_JMP_JEQ_K,
        Label::Fallthrough,
        Label::Drop,
        u32::from(p),
    ));
    Ok(())
}

fn emit_ipv4_host(
    sd: SrcDst,
    addr: u32,
    ctx: &CompileCtx,
    out: &mut Vec<SymInsn>,
) -> Result<(), BuildError> {
    let src_off = 26u32 + u32::from(ctx.vlan_offset); // Eth(14) + IPv4 src(12)
    let dst_off = 30u32 + u32::from(ctx.vlan_offset); // Eth(14) + IPv4 dst(16)
    match sd {
        SrcDst::Src => {
            out.push(SymInsn::straight(BPF_LD_W_ABS, src_off));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::Fallthrough,
                Label::Drop,
                addr,
            ));
        }
        SrcDst::Dst => {
            out.push(SymInsn::straight(BPF_LD_W_ABS, dst_off));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::Fallthrough,
                Label::Drop,
                addr,
            ));
        }
        SrcDst::Any => {
            // src match → fallthrough; otherwise check dst; if
            // neither → Drop. Use the resolver's relative-offset
            // semantics: the JEQ on src has jt=Fallthrough (skip
            // the dst check on a src match) but jf must reach the
            // dst load, which is exactly the next instruction —
            // so jf=Fallthrough also works. The trick is that
            // "jt=Fallthrough" needs to skip the next two
            // instructions (the dst check), not just one. We
            // handle that by introducing a per-fragment local
            // skip target: jump-on-src-match goes to a synthetic
            // post-fragment "matched" point. Without per-fragment
            // labels yet, the simplest correct shape is: src
            // match → unconditional JA over the dst check.
            //
            // Sequence:
            //   ld W abs [src]
            //   jeq #addr, jt=skip_dst, jf=fall
            //   ld W abs [dst]
            //   jeq #addr, jt=fall, jf=Drop
            //   skip_dst:    (nothing — fall through to next fragment)
            //
            // Encoded: the JEQ on src has jt skipping the next
            // two instructions (the dst load + dst JEQ). cBPF
            // jt/jf are 8-bit relative, and the resolver will
            // compute "skip 2".
            out.push(SymInsn::straight(BPF_LD_W_ABS, src_off));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::SkipNextN(2),
                Label::Fallthrough,
                addr,
            ));
            out.push(SymInsn::straight(BPF_LD_W_ABS, dst_off));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::Fallthrough,
                Label::Drop,
                addr,
            ));
        }
    }
    Ok(())
}

fn emit_ipv4_net(
    sd: SrcDst,
    net: &IpNet,
    ctx: &CompileCtx,
    out: &mut Vec<SymInsn>,
) -> Result<(), BuildError> {
    if !net.is_ipv4() {
        return Err(BuildError::Ipv6ExtHeader);
    }
    if net.prefix > 32 {
        return Err(BuildError::InvalidPrefix(net.prefix));
    }
    let mask = net.ipv4_mask().expect("ipv4 net has mask");
    let target = net.as_ipv4_u32().expect("ipv4 net has u32 addr") & mask;

    let src_off = 26u32 + u32::from(ctx.vlan_offset);
    let dst_off = 30u32 + u32::from(ctx.vlan_offset);
    match sd {
        SrcDst::Src => {
            out.push(SymInsn::straight(BPF_LD_W_ABS, src_off));
            out.push(SymInsn::straight(BPF_ALU_AND_K, mask));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::Fallthrough,
                Label::Drop,
                target,
            ));
        }
        SrcDst::Dst => {
            out.push(SymInsn::straight(BPF_LD_W_ABS, dst_off));
            out.push(SymInsn::straight(BPF_ALU_AND_K, mask));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::Fallthrough,
                Label::Drop,
                target,
            ));
        }
        SrcDst::Any => {
            // ld src; and mask; jeq → matched (skip 4); else
            // ld dst; and mask; jeq → matched (fall); else Drop.
            out.push(SymInsn::straight(BPF_LD_W_ABS, src_off));
            out.push(SymInsn::straight(BPF_ALU_AND_K, mask));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::SkipNextN(3),
                Label::Fallthrough,
                target,
            ));
            out.push(SymInsn::straight(BPF_LD_W_ABS, dst_off));
            out.push(SymInsn::straight(BPF_ALU_AND_K, mask));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::Fallthrough,
                Label::Drop,
                target,
            ));
        }
    }
    Ok(())
}

fn emit_ipv4_port(
    sd: SrcDst,
    port: u16,
    ctx: &CompileCtx,
    out: &mut Vec<SymInsn>,
) -> Result<(), BuildError> {
    let frag_off = 20u32 + u32::from(ctx.vlan_offset);  // flags+frag at IP+6 = 14+6
    let ihl_off = 14u32 + u32::from(ctx.vlan_offset);   // start of IPv4 header
    let l4_base = 14u32 + u32::from(ctx.vlan_offset);   // bytes preceding L4 (before adding X = IHL)

    // Common preamble: reject IPv4 fragments (ports valid only
    // in the first fragment), then load IHL into X.
    out.push(SymInsn::straight(BPF_LD_H_ABS, frag_off));
    out.push(SymInsn::jump(
        BPF_JMP_JSET_K,
        Label::Drop,
        Label::Fallthrough,
        0x1FFF,
    ));
    out.push(SymInsn::straight(BPF_LDX_B_MSH, ihl_off));

    // Now load src/dst port (relative to L4 base + IHL).
    match sd {
        SrcDst::Src => {
            out.push(SymInsn::straight(BPF_LD_H_IND, l4_base /* + 0 */));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::Fallthrough,
                Label::Drop,
                u32::from(port),
            ));
        }
        SrcDst::Dst => {
            out.push(SymInsn::straight(BPF_LD_H_IND, l4_base + 2));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::Fallthrough,
                Label::Drop,
                u32::from(port),
            ));
        }
        SrcDst::Any => {
            // Load src port; if matches → SkipNext(2); else load
            // dst port and compare; else Drop.
            out.push(SymInsn::straight(BPF_LD_H_IND, l4_base));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::SkipNextN(2),
                Label::Fallthrough,
                u32::from(port),
            ));
            out.push(SymInsn::straight(BPF_LD_H_IND, l4_base + 2));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::Fallthrough,
                Label::Drop,
                u32::from(port),
            ));
        }
    }
    Ok(())
}

// ── Resolver ──────────────────────────────────────────────────

/// Resolve a symbolic instruction stream into [`BpfInsn`]s.
///
/// `accept_pc` and `drop_pc` are the indices of the accept and
/// drop tail instructions in `sym`. Each `Label` in jt/jf is
/// rewritten to a u8 relative offset (target - current_pc - 1).
fn resolve(
    sym: &[SymInsn],
    accept_pc: usize,
    drop_pc: usize,
) -> Result<Vec<BpfInsn>, BuildError> {
    let mut out = Vec::with_capacity(sym.len());
    for (pc, insn) in sym.iter().enumerate() {
        let jt = resolve_label(insn.jt, pc, accept_pc, drop_pc)?;
        let jf = resolve_label(insn.jf, pc, accept_pc, drop_pc)?;
        out.push(BpfInsn {
            code: insn.code,
            jt,
            jf,
            k: insn.k,
        });
    }
    Ok(out)
}

fn resolve_label(
    label: Label,
    pc: usize,
    accept_pc: usize,
    drop_pc: usize,
) -> Result<u8, BuildError> {
    let target = match label {
        Label::Fallthrough => return Ok(0),
        Label::Accept => accept_pc,
        Label::Drop => drop_pc,
        Label::SkipNextN(n) => pc.saturating_add(n as usize + 1),
    };
    let dist = target.checked_sub(pc + 1).ok_or(BuildError::JumpTooFar)?;
    u8::try_from(dist).map_err(|_| BuildError::JumpTooFar)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_builder_compiles_to_accept_only() {
        let b = BpfFilterBuilder::new();
        let f = compile(b).unwrap();
        assert_eq!(f.len(), 1);
        let insn = f.instructions()[0];
        assert_eq!(insn.code, BPF_RET_K);
        assert_eq!(insn.k, ACCEPT_RETVAL);
    }

    #[test]
    fn ipv4_compiles() {
        let b = BpfFilterBuilder::new().ipv4();
        let f = compile(b).unwrap();
        // Expected: ldh [12]; jeq 0x800, jt=fall, jf=Drop; ret accept; ret drop
        assert_eq!(f.len(), 4);
        assert_eq!(f.instructions()[0].code, BPF_LD_H_ABS);
        assert_eq!(f.instructions()[0].k, 12);
        assert_eq!(f.instructions()[1].code, BPF_JMP_JEQ_K);
        assert_eq!(f.instructions()[1].k, 0x0800);
        assert_eq!(f.instructions()[2].code, BPF_RET_K);
        assert_eq!(f.instructions()[2].k, ACCEPT_RETVAL);
        assert_eq!(f.instructions()[3].code, BPF_RET_K);
        assert_eq!(f.instructions()[3].k, DROP_RETVAL);
    }

    #[test]
    fn tcp_auto_inserts_ipv4_check() {
        let b = BpfFilterBuilder::new().tcp();
        let f = compile(b).unwrap();
        // Expected: ldh [12]; jeq 0x800; ldb [23]; jeq 6; ret accept; ret drop
        assert_eq!(f.len(), 6);
        assert_eq!(f.instructions()[0].k, 12);
        assert_eq!(f.instructions()[1].k, 0x0800);
        assert_eq!(f.instructions()[2].code, BPF_LD_B_ABS);
        assert_eq!(f.instructions()[2].k, 23);
        assert_eq!(f.instructions()[3].k, 6);
    }

    #[test]
    fn conflicting_protocols_rejected() {
        let b = BpfFilterBuilder::new().tcp().udp();
        let err = compile(b).unwrap_err();
        assert!(matches!(err, BuildError::ConflictingProtocols { .. }));
    }

    #[test]
    fn duplicate_tcp_dedups() {
        let b = BpfFilterBuilder::new().tcp().tcp();
        let f = compile(b).unwrap();
        // Same length as a single .tcp() — no extra emission.
        assert_eq!(f.len(), 6);
    }

    #[test]
    fn port_without_proto_errors() {
        let b = BpfFilterBuilder::new().port(80);
        let err = compile(b).unwrap_err();
        assert!(matches!(err, BuildError::ConflictingProtocols { .. }));
    }

    #[test]
    fn jump_offsets_resolve() {
        // ipv4 → 4 instructions: jt/jf of the JEQ should resolve.
        let b = BpfFilterBuilder::new().ipv4();
        let f = compile(b).unwrap();
        let jeq = f.instructions()[1];
        assert_eq!(jeq.code, BPF_JMP_JEQ_K);
        // jt is Fallthrough → 0; jf is Drop at pc=3 (0-indexed),
        // current pc=1, so jf = 3 - 1 - 1 = 1.
        assert_eq!(jeq.jt, 0);
        assert_eq!(jeq.jf, 1);
    }
}
