//! Kernel-filter compilation (0.25 Phase A3a) — lower a packet-tier filter's
//! [kernel over-approximation](super::predicate::Predicate::kernel_approx) to a
//! classic-BPF [`BpfFilter`], and union the filters of all packet subs into one
//! kernel prefilter.
//!
//! The compiler is **conservative with a safe fallback**: anything it can't
//! express returns `None`, meaning "no kernel filter" (pass everything to
//! userspace). Since userspace still runs the authoritative
//! [`Predicate::eval`](super::predicate::Predicate::eval), a `None` only costs
//! efficiency, never correctness. The cases it *does* compile — conjunctions of
//! positive L2–L4 atoms, OR-unioned across subs — cover the common packet
//! filters (`tcp().dst_port(443)`, `udp().port(53).or(tcp().port(80))`).
//!
//! Negations are not lowered (per-atom cBPF negation isn't expressible through
//! the builder); a filter whose kernel approximation contains a `Not` falls
//! back to `None`.

use flowscope::L4Proto;

use super::packet::PacketSubscription;
use super::predicate::{Atom, Predicate};
use crate::config::bpf::BpfFilter;
use crate::config::bpf_builder::BpfFilterBuilder;

/// Compile the **union** kernel prefilter for a set of packet subscriptions:
/// the OR of each sub's [`kernel_approx`](Predicate::kernel_approx). Returns
/// `None` when no useful filter can be pushed (no subs, any sub matches
/// everything in-kernel, or an unsupported shape) — the caller then leaves the
/// capture unfiltered and relies on userspace evaluation.
pub(crate) fn union_filter(subs: &[PacketSubscription]) -> Option<BpfFilter> {
    let mut union: Option<Predicate> = None;
    for sub in subs {
        let k = sub.predicate.kernel_approx();
        union = Some(match union {
            None => k,
            Some(acc) => acc.or(k),
        });
    }
    // No subs, or the union relaxed to Always (some sub wants everything) →
    // don't push a filter.
    match union {
        Some(Predicate::Always) | None => None,
        Some(p) => predicate_to_bpf(&p),
    }
}

/// Lower a **kernel-only** predicate (already `kernel_approx`'d) to a
/// [`BpfFilter`]. `None` if the shape can't be expressed (contains a `Not`,
/// is `Always`, or the bytecode build fails) — a safe "pass all" fallback.
pub(crate) fn predicate_to_bpf(pred: &Predicate) -> Option<BpfFilter> {
    let dnf = to_dnf(pred)?;
    if dnf.is_empty() {
        return None;
    }
    let mut clauses = dnf.into_iter();
    // First conjunction is the base builder; the rest become OR branches.
    let first = clauses.next()?;
    let mut builder = apply_conjunction(BpfFilterBuilder::new(), &first)?;
    for clause in clauses {
        // `or(|b| ...)` needs a closure returning the branch builder; capture
        // the clause by reference and apply it. A clause that can't be applied
        // aborts the whole compile (fall back to no filter).
        let mut ok = true;
        builder = builder.or(|b| match apply_conjunction(b, &clause) {
            Some(b) => b,
            None => {
                ok = false;
                BpfFilterBuilder::new()
            }
        });
        if !ok {
            return None;
        }
    }
    builder.build().ok()
}

/// Convert a kernel-only predicate to disjunctive normal form: a list of
/// conjunctions, each a list of positive [`Atom`]s. `None` if a `Not` is
/// present (not lowerable). `Always` yields an empty conjunction list's
/// special handling at the call site — here it returns `Some(vec![vec![]])`
/// (one always-true clause), which the caller treats as "no filter".
fn to_dnf(pred: &Predicate) -> Option<Vec<Vec<Atom>>> {
    match pred {
        // An always-true clause: one conjunction with no constraints.
        Predicate::Always => Some(vec![vec![]]),
        Predicate::Atom(a) => Some(vec![vec![a.clone()]]),
        Predicate::And(l, r) => {
            let dl = to_dnf(l)?;
            let dr = to_dnf(r)?;
            // Cross product: (a ∨ b) ∧ (c ∨ d) = ac ∨ ad ∨ bc ∨ bd.
            let mut out = Vec::with_capacity(dl.len() * dr.len());
            for cl in &dl {
                for cr in &dr {
                    let mut conj = cl.clone();
                    conj.extend(cr.clone());
                    out.push(conj);
                }
            }
            Some(out)
        }
        Predicate::Or(l, r) => {
            let mut dl = to_dnf(l)?;
            dl.extend(to_dnf(r)?);
            Some(dl)
        }
        // Per-atom negation isn't expressible through the builder — bail.
        Predicate::Not(_) => None,
    }
}

/// Apply a conjunction of positive atoms onto a builder (AND chain). `None` if
/// any atom can't be mapped or the conjunction is empty (an always-true clause,
/// which the union compiler rejects upstream — an empty clause here means the
/// whole filter would match everything).
fn apply_conjunction(mut b: BpfFilterBuilder, atoms: &[Atom]) -> Option<BpfFilterBuilder> {
    if atoms.is_empty() {
        // An unconstrained clause ⇒ matches everything ⇒ no useful filter.
        return None;
    }
    for atom in atoms {
        b = apply_atom(b, atom)?;
    }
    Some(b)
}

/// Map one kernel-pushable atom onto a builder call. `None` for atoms that
/// aren't kernel-pushable (shouldn't appear post-`kernel_approx`, but stay safe).
fn apply_atom(b: BpfFilterBuilder, atom: &Atom) -> Option<BpfFilterBuilder> {
    Some(match atom {
        Atom::Proto(p) => match p {
            L4Proto::Tcp => b.tcp(),
            L4Proto::Udp => b.udp(),
            L4Proto::Icmp => b.icmp(),
            L4Proto::IcmpV6 => b.ipv6().ip_proto(58),
            L4Proto::Sctp => b.ip_proto(132),
            L4Proto::Other(n) => b.ip_proto(*n),
        },
        Atom::SrcPort(port) => b.src_port(*port),
        Atom::DstPort(port) => b.dst_port(*port),
        Atom::AnyPort(port) => b.port(*port),
        Atom::SrcHost(ip) => b.src_host(*ip),
        Atom::DstHost(ip) => b.dst_host(*ip),
        Atom::AnyHost(ip) => b.host(*ip),
        Atom::SrcNet(net) => b.src_net(*net),
        Atom::DstNet(net) => b.dst_net(*net),
        Atom::AnyNet(net) => b.net(*net),
        Atom::VlanId(id) => b.vlan().vlan_id(*id),
        // Userspace atoms can't reach here after kernel_approx; refuse safely.
        Atom::SniGlob(_)
        | Atom::HttpHostGlob(_)
        | Atom::DnsQnameGlob(_)
        | Atom::BytesOver(_)
        | Atom::PacketsOver(_) => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::super::builder::packet;
    use super::*;

    /// Build a minimal Ethernet/IPv4 frame for the given L4 proto + dst port.
    fn frame(proto: u8, dst_port: u16) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // dst mac
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // src mac
        f.extend_from_slice(&[0x08, 0x00]); // ipv4
        f.push(0x45);
        f.push(0);
        f.extend_from_slice(&(28u16 + 4).to_be_bytes()); // total len-ish
        f.extend_from_slice(&[0, 0, 0, 0]);
        f.push(64);
        f.push(proto);
        f.extend_from_slice(&[0, 0]); // checksum
        f.extend_from_slice(&[10, 0, 0, 1]); // src
        f.extend_from_slice(&[10, 0, 0, 2]); // dst
        f.extend_from_slice(&54321u16.to_be_bytes()); // src port
        f.extend_from_slice(&dst_port.to_be_bytes()); // dst port
        f.extend_from_slice(&[0, 0, 0, 0]); // l4 rest
        f
    }

    #[test]
    fn compiles_conjunction_and_matches_only_target() {
        // udp AND dst_port 53.
        let pred = packet().udp().dst_port(53).into_predicate();
        let bpf = predicate_to_bpf(&pred.kernel_approx()).expect("compiles");
        assert!(bpf.matches(&frame(17, 53)), "udp/53 should pass");
        assert!(!bpf.matches(&frame(17, 80)), "udp/80 should not pass");
        assert!(!bpf.matches(&frame(6, 53)), "tcp/53 should not pass");
    }

    #[test]
    fn compiles_or_union_of_two_subs() {
        // sub A: udp/53 ; sub B: tcp/80 → union matches either.
        let subs = vec![
            packet().udp().dst_port(53).to(|_v, _c| Ok(())),
            packet().tcp().dst_port(80).to(|_v, _c| Ok(())),
        ];
        let bpf = union_filter(&subs).expect("union compiles");
        assert!(bpf.matches(&frame(17, 53)), "udp/53 in union");
        assert!(bpf.matches(&frame(6, 80)), "tcp/80 in union");
        assert!(!bpf.matches(&frame(6, 53)), "tcp/53 not in union");
        assert!(!bpf.matches(&frame(17, 80)), "udp/80 not in union");
    }

    #[test]
    fn unfiltered_sub_yields_no_kernel_filter() {
        // A sub with only a userspace atom (sni) → kernel_approx is Always →
        // union must be None (pass everything to userspace).
        // (Use a session-less proxy: a packet sub with an empty filter.)
        let subs = vec![packet().to(|_v, _c| Ok(()))];
        assert!(union_filter(&subs).is_none());
    }

    #[test]
    fn mixed_union_with_one_unfiltered_sub_is_none() {
        // One narrow sub + one match-everything sub ⇒ union is everything.
        let subs = vec![
            packet().tcp().dst_port(443).to(|_v, _c| Ok(())),
            packet().to(|_v, _c| Ok(())),
        ];
        assert!(union_filter(&subs).is_none());
    }

    #[test]
    fn negation_falls_back_to_none() {
        // not(tcp) is kernel-pushable as a predicate but not lowerable here.
        let pred = packet().tcp().into_predicate().negate();
        assert!(predicate_to_bpf(&pred.kernel_approx()).is_none());
    }

    #[test]
    fn empty_subs_is_none() {
        assert!(union_filter(&[]).is_none());
    }
}
