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
pub(crate) enum Label {
    /// Fall through to the next instruction. For non-jump
    /// instructions both jt/jf carry this.
    Fallthrough,
    /// Global accept tail.
    Accept,
    /// Global drop tail.
    Drop,
    /// Skip the next `n` instructions and continue. Used by
    /// fragment-local jumps (e.g. the `host` early-accept on
    /// src match) so we don't need a per-fragment label table.
    SkipNextN(u8),
    /// Start of branch `id`. Used by OR composition: when a
    /// fragment in branch N fails, it jumps to branch N+1's start
    /// (or to `Drop` if N is the last branch). The linker
    /// records each branch's pc and the resolver looks it up.
    Branch(u32),
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

    // Special case: empty builder with no branches → accept-all.
    if fragments.is_empty() && or_branches.is_empty() {
        return BpfFilter::new(vec![BpfInsn {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: if negated { DROP_RETVAL } else { ACCEPT_RETVAL },
        }]);
    }

    // Compile each block (top-level AND chain + each OR branch)
    // independently. Within each block, fragments use
    // `Label::Drop` to mean "fail this block"; the linker
    // rewrites this to either the next branch's start or the
    // global Drop tail (last branch).
    let mut blocks: Vec<Vec<SymInsn>> = Vec::with_capacity(1 + or_branches.len());
    blocks.push(compile_block(&fragments)?);
    for branch in &or_branches {
        if branch.fragments.is_empty() {
            return Err(BuildError::EmptyOr);
        }
        // Nested OR/NOT inside an OR branch is rejected for now —
        // keeps the linker simple. Users can flatten by hand.
        if !branch.or_branches.is_empty() || branch.negated {
            return Err(BuildError::ConflictingProtocols {
                a: "or() branch with its own or()/negate()",
                b: "<flatten the chain>",
            });
        }
        blocks.push(compile_block(&branch.fragments)?);
    }

    // Stitch blocks: each block's body, followed by `JA Accept`
    // on success, then the next block. Each block's
    // `Label::Drop` targets are rewritten to `Label::Branch(i+1)`
    // (next block's start) for all but the last block; the last
    // keeps `Label::Drop` (real global drop tail).
    let mut sym: Vec<SymInsn> = Vec::new();
    let mut branch_starts: Vec<usize> = Vec::with_capacity(blocks.len());
    let n_blocks = blocks.len();
    for (i, block) in blocks.into_iter().enumerate() {
        branch_starts.push(sym.len());
        // Rewrite block-local Drop labels.
        // - Non-last block: failure jumps to next branch's start.
        // - Last block: failure falls through to global Drop tail.
        let drop_target = if i + 1 < n_blocks {
            Label::Branch((i + 1) as u32)
        } else {
            Label::Drop
        };
        let mut block = block;
        for insn in block.iter_mut() {
            if insn.jt == Label::Drop {
                insn.jt = drop_target;
            }
            if insn.jf == Label::Drop {
                insn.jf = drop_target;
            }
        }
        sym.extend(block);
        // Success-path link.
        // - Non-last block: must skip past every following branch
        //   to the global Accept tail. Emit `JA Accept`.
        // - Last block: fall through directly to the Accept tail
        //   (which is the next instruction). No JA needed; saves
        //   one instruction and matches tcpdump's emission for
        //   plain AND filters.
        if i + 1 < n_blocks {
            sym.push(SymInsn::jump(
                BPF_JMP_JA,
                Label::Accept,
                Label::Fallthrough,
                0,
            ));
        }
    }

    // Append accept + drop tails. Under NOT, swap their `k`
    // values so that any path landing on the "accept tail"
    // position emits the drop verdict, and vice versa. This
    // works for both label-driven jumps AND natural fall-
    // through to program end (the accept tail is at pc N-2).
    let accept_pc = sym.len();
    sym.push(SymInsn::straight(
        BPF_RET_K,
        if negated { DROP_RETVAL } else { ACCEPT_RETVAL },
    ));
    let drop_pc = sym.len();
    sym.push(SymInsn::straight(
        BPF_RET_K,
        if negated { ACCEPT_RETVAL } else { DROP_RETVAL },
    ));

    let resolved = resolve(&sym, accept_pc, drop_pc, &branch_starts)?;
    BpfFilter::new(resolved)
}

/// Compile a single block (an AND chain of fragments) into a
/// symbolic instruction stream. Drop labels inside the stream
/// mean "fail this block"; the linker rewrites them.
fn compile_block(fragments: &[MatchFrag]) -> Result<Vec<SymInsn>, BuildError> {
    let normalized = normalize(fragments.to_vec())?;
    let mut ctx = infer_ctx(&normalized);
    let mut sym = Vec::with_capacity(normalized.len() * 6);
    for frag in &normalized {
        compile_fragment(frag, &mut ctx, &mut sym)?;
    }
    Ok(sym)
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

    // VLAN bucket — must come first so the +4 offset shift is in
    // effect when subsequent EthType/IpProto/host/port fragments
    // emit their loads.
    let has_vlan = fragments
        .iter()
        .filter(|f| matches!(f, MatchFrag::Vlan))
        .count();
    if has_vlan > 1 {
        return Err(BuildError::ConflictingProtocols {
            a: "vlan",
            b: "vlan (Q-in-Q not supported)",
        });
    }
    if has_vlan == 1 {
        out.push(MatchFrag::Vlan);
    }
    // VlanId fragments come immediately after the VLAN marker so
    // the TCI load is at the right offset (14, fixed; doesn't
    // depend on vlan_offset, but conceptually "after vlan").
    for f in &fragments {
        if matches!(f, MatchFrag::VlanId(_)) {
            push_dedup(&mut out, f.clone());
        }
    }

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
    ctx: &mut CompileCtx,
    out: &mut Vec<SymInsn>,
) -> Result<(), BuildError> {
    match frag {
        MatchFrag::EthType(t) => emit_eth_type(*t, ctx, out),
        MatchFrag::Vlan => {
            // Two effects: (1) ethertype check at offset 12
            // against 0x8100, and (2) shift subsequent loads
            // by +4 bytes for the rest of this block.
            if ctx.vlan_offset != 0 {
                // Q-in-Q (.vlan().vlan()) is intentionally out
                // of scope; surface the conflict early.
                return Err(BuildError::ConflictingProtocols {
                    a: "vlan",
                    b: "vlan (Q-in-Q not supported)",
                });
            }
            // Outer 802.1Q ethertype.
            out.push(SymInsn::straight(BPF_LD_H_ABS, 12));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::Fallthrough,
                Label::Drop,
                0x8100,
            ));
            ctx.vlan_offset = 4;
            Ok(())
        }
        MatchFrag::VlanId(id) => emit_vlan_id(*id, ctx, out),
        MatchFrag::IpProto(p) => emit_ip_proto(*p, ctx, out),
        MatchFrag::SrcHost(IpAddr::V4(a)) => {
            emit_ipv4_host(SrcDst::Src, u32::from_be_bytes(a.octets()), ctx, out)
        }
        MatchFrag::DstHost(IpAddr::V4(a)) => {
            emit_ipv4_host(SrcDst::Dst, u32::from_be_bytes(a.octets()), ctx, out)
        }
        MatchFrag::AnyHost(IpAddr::V4(a)) => {
            emit_ipv4_host(SrcDst::Any, u32::from_be_bytes(a.octets()), ctx, out)
        }
        MatchFrag::SrcHost(IpAddr::V6(a)) => emit_ipv6_host(SrcDst::Src, a.octets(), ctx, out),
        MatchFrag::DstHost(IpAddr::V6(a)) => emit_ipv6_host(SrcDst::Dst, a.octets(), ctx, out),
        MatchFrag::AnyHost(IpAddr::V6(a)) => emit_ipv6_host(SrcDst::Any, a.octets(), ctx, out),
        MatchFrag::SrcNet(net) | MatchFrag::DstNet(net) | MatchFrag::AnyNet(net) => {
            let sd = match frag {
                MatchFrag::SrcNet(_) => SrcDst::Src,
                MatchFrag::DstNet(_) => SrcDst::Dst,
                _ => SrcDst::Any,
            };
            if net.is_ipv6() {
                // Phase C.2 covers full-address IPv6 hosts but
                // not IPv6 prefix matching (16-byte mask requires
                // 4 separate u32 ALU ANDs — bigger template).
                // Surface as a clear error until plan 19 lands it.
                return Err(BuildError::Ipv6ExtHeader);
            }
            emit_ipv4_net(sd, net, ctx, out)
        }
        MatchFrag::SrcPort(p) => emit_l4_port(SrcDst::Src, *p, ctx, out),
        MatchFrag::DstPort(p) => emit_l4_port(SrcDst::Dst, *p, ctx, out),
        MatchFrag::AnyPort(p) => emit_l4_port(SrcDst::Any, *p, ctx, out),
    }
}

fn emit_vlan_id(id: u16, ctx: &CompileCtx, out: &mut Vec<SymInsn>) -> Result<(), BuildError> {
    if ctx.vlan_offset == 0 {
        return Err(BuildError::ConflictingProtocols {
            a: "vlan_id",
            b: "<requires .vlan() earlier in the chain>",
        });
    }
    // VLAN TCI is at offset 14 (the start of the 802.1Q tag).
    // VLAN ID is the low 12 bits of the TCI.
    out.push(SymInsn::straight(BPF_LD_H_ABS, 14));
    out.push(SymInsn::straight(BPF_ALU_AND_K, 0x0FFF));
    out.push(SymInsn::jump(
        BPF_JMP_JEQ_K,
        Label::Fallthrough,
        Label::Drop,
        u32::from(id),
    ));
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum SrcDst {
    Src,
    Dst,
    Any,
}

fn emit_eth_type(t: u16, ctx: &CompileCtx, out: &mut Vec<SymInsn>) -> Result<(), BuildError> {
    // Without a preceding `.vlan()`, the ethertype field is at
    // offset 12. With `.vlan()` already in the chain, the inner
    // ethertype (the one we want to match against IPv4/IPv6/etc.)
    // sits at offset 16 — i.e. after the 4-byte 802.1Q tag.
    let off = 12u32 + u32::from(ctx.vlan_offset);
    out.push(SymInsn::straight(BPF_LD_H_ABS, off));
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

fn emit_l4_port(
    sd: SrcDst,
    port: u16,
    ctx: &CompileCtx,
    out: &mut Vec<SymInsn>,
) -> Result<(), BuildError> {
    match ctx.l3 {
        L3Family::Ipv4 => emit_ipv4_port(sd, port, ctx, out),
        L3Family::Ipv6 => emit_ipv6_port(sd, port, ctx, out),
    }
}

fn emit_ipv4_port(
    sd: SrcDst,
    port: u16,
    ctx: &CompileCtx,
    out: &mut Vec<SymInsn>,
) -> Result<(), BuildError> {
    let frag_off = 20u32 + u32::from(ctx.vlan_offset); // flags+frag at IP+6 = 14+6
    let ihl_off = 14u32 + u32::from(ctx.vlan_offset); // start of IPv4 header
    let l4_base = 14u32 + u32::from(ctx.vlan_offset); // bytes preceding L4 (before adding X = IHL)

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

fn emit_ipv6_port(
    sd: SrcDst,
    port: u16,
    ctx: &CompileCtx,
    out: &mut Vec<SymInsn>,
) -> Result<(), BuildError> {
    // IPv6 has a fixed 40-byte header; no IHL trick. Ports are
    // at fixed absolute offsets:
    //   src_port at 14 + 40 + 0 = 54  (+ vlan_offset)
    //   dst_port at 14 + 40 + 2 = 56  (+ vlan_offset)
    // The IpProto fragment already verified next-header == 6 or 17;
    // packets with extension headers between the IPv6 header and
    // L4 fail that check (next-header would be Hop-by-Hop=0, etc.)
    // and are rejected — fail-closed for the extension-header case.
    let src_off = 54u32 + u32::from(ctx.vlan_offset);
    let dst_off = 56u32 + u32::from(ctx.vlan_offset);
    match sd {
        SrcDst::Src => {
            out.push(SymInsn::straight(BPF_LD_H_ABS, src_off));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::Fallthrough,
                Label::Drop,
                u32::from(port),
            ));
        }
        SrcDst::Dst => {
            out.push(SymInsn::straight(BPF_LD_H_ABS, dst_off));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::Fallthrough,
                Label::Drop,
                u32::from(port),
            ));
        }
        SrcDst::Any => {
            out.push(SymInsn::straight(BPF_LD_H_ABS, src_off));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::SkipNextN(2),
                Label::Fallthrough,
                u32::from(port),
            ));
            out.push(SymInsn::straight(BPF_LD_H_ABS, dst_off));
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

/// IPv6 host match. 16 address bytes split into 4 × 32-bit
/// loads and 4 × JEQs. All four words must match for `accept`.
fn emit_ipv6_host(
    sd: SrcDst,
    addr_octets: [u8; 16],
    ctx: &CompileCtx,
    out: &mut Vec<SymInsn>,
) -> Result<(), BuildError> {
    // IPv6 src at offset 14+8 = 22, dst at 14+24 = 38 (+ vlan_offset).
    let src_off = 22u32 + u32::from(ctx.vlan_offset);
    let dst_off = 38u32 + u32::from(ctx.vlan_offset);

    let words: [u32; 4] = [
        u32::from_be_bytes([
            addr_octets[0],
            addr_octets[1],
            addr_octets[2],
            addr_octets[3],
        ]),
        u32::from_be_bytes([
            addr_octets[4],
            addr_octets[5],
            addr_octets[6],
            addr_octets[7],
        ]),
        u32::from_be_bytes([
            addr_octets[8],
            addr_octets[9],
            addr_octets[10],
            addr_octets[11],
        ]),
        u32::from_be_bytes([
            addr_octets[12],
            addr_octets[13],
            addr_octets[14],
            addr_octets[15],
        ]),
    ];

    fn emit_one_dir(out: &mut Vec<SymInsn>, base: u32, words: &[u32; 4]) {
        // ld word at base+0; jeq w0; ld at base+4; jeq w1; ...
        // The first three JEQs pass through on match (Fallthrough)
        // and jump to Drop on mismatch. The last JEQ also jumps
        // to Drop on mismatch; on match, falls through to the
        // next fragment.
        for (i, &w) in words.iter().enumerate() {
            out.push(SymInsn::straight(BPF_LD_W_ABS, base + (i as u32) * 4));
            out.push(SymInsn::jump(
                BPF_JMP_JEQ_K,
                Label::Fallthrough,
                Label::Drop,
                w,
            ));
        }
    }

    match sd {
        SrcDst::Src => emit_one_dir(out, src_off, &words),
        SrcDst::Dst => emit_one_dir(out, dst_off, &words),
        SrcDst::Any => {
            // Try src first; if all four words match, skip past
            // the dst block (8 instructions). On any mismatch
            // we'd want to "skip remaining src checks AND fall
            // into dst block". That requires a per-word "early
            // out" jump, which inflates the bytecode.
            //
            // Compromise: use a sub-block where each src JEQ on
            // mismatch jumps to the start of the dst block.
            // We emit src loads + JEQs with `jf = SkipNextN(remaining
            // src instructions)` so a mismatch in word i lands
            // at the dst block start.
            //
            // This is the only place where per-fragment label
            // arithmetic gets fiddly. Wrap in a helper.
            //
            // src block:    8 instructions (4 LD + 4 JEQ)
            // dst block:    8 instructions
            //
            // Word 0 mismatch needs to skip remaining 7 instructions
            // of src block + 0 = 7 (so we land at first dst load).
            // Word 1 mismatch: skip 5. Word 2: skip 3. Word 3: skip 1.

            for i in 0..4u8 {
                let remaining_src = (3 - i) * 2 + 1; // remaining LD+JEQ pairs after this JEQ + last 1 to land at dst start
                let _ = remaining_src; // computed below
            }

            // src block, with mismatch jumps to dst block start.
            //
            // Layout (8 instructions for src + 8 for dst = 16):
            //   pc+0: LD  src[0..4]
            //   pc+1: JEQ word0  match→pc+2 (Fall);   miss→SkipNextN(6) → pc+8 (dst start)
            //   pc+2: LD  src[4..8]
            //   pc+3: JEQ word1  match→pc+4;          miss→SkipNextN(4) → pc+8
            //   pc+4: LD  src[8..12]
            //   pc+5: JEQ word2  match→pc+6;          miss→SkipNextN(2) → pc+8
            //   pc+6: LD  src[12..16]
            //   pc+7: JEQ word3  match→SkipNextN(8) → pc+16 (past dst block, falls through to next fragment);
            //                    miss→SkipNextN(0) → pc+8 (dst start)
            //
            //   pc+8..pc+15: dst block emitted by emit_one_dir
            //                with jf → Drop on each JEQ.
            //
            // SkipNextN(n) means "land at pc + 1 + n", i.e. skip
            // n instructions after the current jump.
            for (i, &word) in words.iter().enumerate() {
                out.push(SymInsn::straight(BPF_LD_W_ABS, src_off + (i as u32) * 4));
                let jf_skip = (3 - i as u8) * 2; // remaining src instructions after this JEQ
                let jt_skip = if i == 3 {
                    // Last src JEQ: on match, skip the entire
                    // dst block (8 instructions) so we fall
                    // through to the next fragment.
                    Label::SkipNextN(8)
                } else {
                    Label::Fallthrough
                };
                out.push(SymInsn::jump(
                    BPF_JMP_JEQ_K,
                    jt_skip,
                    Label::SkipNextN(jf_skip),
                    word,
                ));
            }
            // dst block: same shape, mismatch → Drop.
            emit_one_dir(out, dst_off, &words);
        }
    }
    Ok(())
}

// ── Resolver ──────────────────────────────────────────────────

/// Resolve a symbolic instruction stream into [`BpfInsn`]s.
///
/// - `accept_pc` / `drop_pc`: positions of the accept / drop
///   tail instructions.
/// - `branch_starts[i]`: position of branch `i`'s first
///   instruction. Block 0 is the AND chain; blocks 1..N are OR
///   branches.
///
/// For ordinary opcodes (LD/JEQ/JSET/etc.), each `Label` in
/// jt/jf is rewritten to a u8 relative offset
/// (`target - current_pc - 1`).
///
/// For `BPF_JMP_JA`, jt's label is the unconditional target
/// and the resolver writes the relative offset into the
/// instruction's `k` field. (The instruction's hardware jt/jf
/// fields are zeroed; the kernel ignores them for JA.)
fn resolve(
    sym: &[SymInsn],
    accept_pc: usize,
    drop_pc: usize,
    branch_starts: &[usize],
) -> Result<Vec<BpfInsn>, BuildError> {
    let mut out = Vec::with_capacity(sym.len());
    for (pc, insn) in sym.iter().enumerate() {
        if insn.code == BPF_JMP_JA {
            // Unconditional jump. Target encoded in jt label;
            // emit as k (32-bit relative).
            let target = label_target(insn.jt, pc, accept_pc, drop_pc, branch_starts)?;
            let rel = target.checked_sub(pc + 1).ok_or(BuildError::JumpTooFar)?;
            out.push(BpfInsn {
                code: insn.code,
                jt: 0,
                jf: 0,
                k: rel as u32,
            });
        } else {
            let jt = resolve_label(insn.jt, pc, accept_pc, drop_pc, branch_starts)?;
            let jf = resolve_label(insn.jf, pc, accept_pc, drop_pc, branch_starts)?;
            out.push(BpfInsn {
                code: insn.code,
                jt,
                jf,
                k: insn.k,
            });
        }
    }
    Ok(out)
}

fn resolve_label(
    label: Label,
    pc: usize,
    accept_pc: usize,
    drop_pc: usize,
    branch_starts: &[usize],
) -> Result<u8, BuildError> {
    let target = label_target(label, pc, accept_pc, drop_pc, branch_starts)?;
    let dist = target.checked_sub(pc + 1).ok_or(BuildError::JumpTooFar)?;
    u8::try_from(dist).map_err(|_| BuildError::JumpTooFar)
}

fn label_target(
    label: Label,
    pc: usize,
    accept_pc: usize,
    drop_pc: usize,
    branch_starts: &[usize],
) -> Result<usize, BuildError> {
    match label {
        Label::Fallthrough => Ok(pc + 1),
        Label::Accept => Ok(accept_pc),
        Label::Drop => Ok(drop_pc),
        Label::SkipNextN(n) => Ok(pc.saturating_add(n as usize + 1)),
        Label::Branch(id) => branch_starts
            .get(id as usize)
            .copied()
            .ok_or(BuildError::JumpTooFar),
    }
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

    #[test]
    fn or_two_branches_compiles() {
        // tcp port 80 OR udp port 53. Should produce two blocks
        // separated by a JA Accept, then accept + drop tails.
        let b = BpfFilterBuilder::new()
            .tcp()
            .port(80)
            .or(|b| b.udp().port(53));
        let f = compile(b).unwrap();
        // Should compile without error and emit a non-empty
        // program of plausible length.
        assert!(f.len() > 10);
        // First instruction must still be ldh [12].
        assert_eq!(f.instructions()[0].code, BPF_LD_H_ABS);
        assert_eq!(f.instructions()[0].k, 12);
    }

    #[test]
    fn negate_produces_same_length_program() {
        let b = BpfFilterBuilder::new().tcp();
        let plain = compile(b.clone()).unwrap();
        let negated = compile(b.negate()).unwrap();
        // Negate is implemented by swapping accept/drop jump
        // targets, not by changing the tail bytes — same
        // instruction count.
        assert_eq!(plain.len(), negated.len());
        // The interpreter test (`negate_inverts_match`) verifies
        // semantics; here we only assert structural equivalence.
    }

    #[test]
    fn empty_or_branch_rejected() {
        let b = BpfFilterBuilder::new().tcp().or(|b| b);
        let err = compile(b).unwrap_err();
        assert!(matches!(err, BuildError::EmptyOr));
    }

    #[test]
    fn nested_or_in_branch_rejected() {
        let b = BpfFilterBuilder::new()
            .tcp()
            .or(|b| b.udp().or(|b| b.icmp()));
        let err = compile(b).unwrap_err();
        assert!(matches!(err, BuildError::ConflictingProtocols { .. }));
    }
}
