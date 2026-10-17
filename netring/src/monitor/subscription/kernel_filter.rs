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
//!
//! Address families: userspace matches IPv4 and IPv6 alike, while the cBPF
//! builder defaults an IP-aware chain to IPv4. So every conjunction that
//! doesn't pin a family (by an EtherType or a host / net address) is lowered
//! once per family, the IPv6 copy widened past what its fixed-offset templates
//! can't see (extension headers) — see [`split_families`].

use flowscope::L4Proto;

use super::predicate::{Atom, Predicate};
use crate::config::bpf::BpfFilter;
use crate::config::bpf_builder::BpfFilterBuilder;
use crate::config::bpf_compile::VLAN_TPIDS;
use crate::protocol::{Dispatch, TrafficClass};

/// Map a consumer's [`TrafficClass`] to its [`Predicate`] traffic interest
/// (0.25 S1). [`TrafficClass::Any`] → [`Predicate::Always`] (capture-all);
/// a `Dispatch` → its proto (+ port) predicate.
pub(crate) fn class_interest(class: &TrafficClass) -> Predicate {
    match class {
        TrafficClass::Any => Predicate::Always,
        TrafficClass::Dispatch(d) => dispatch_interest(d),
    }
}

/// Map a protocol's [`Dispatch`] to its traffic-interest predicate.
pub(crate) fn dispatch_interest(d: &Dispatch) -> Predicate {
    match d {
        Dispatch::Tcp(ports) => proto_ports(L4Proto::Tcp, ports),
        Dispatch::Udp(ports) => proto_ports(L4Proto::Udp, ports),
        // ICMP interest spans v4 + v6 (the dispatch matches both).
        Dispatch::Icmp => Predicate::Atom(Atom::Proto(L4Proto::Icmp))
            .or(Predicate::Atom(Atom::Proto(L4Proto::IcmpV6))),
        Dispatch::AllTcp => Predicate::Atom(Atom::Proto(L4Proto::Tcp)),
        Dispatch::AllUdp => Predicate::Atom(Atom::Proto(L4Proto::Udp)),
        // Port-agnostic signature dispatch can't be narrowed → capture-all.
        Dispatch::Signature(_) => Predicate::Always,
    }
}

/// `proto AND (port==p1 OR port==p2 …)`, or just `proto` if no ports. Ports use
/// `AnyPort` (either endpoint) so both directions of the flow are captured.
fn proto_ports(proto: L4Proto, ports: &[u16]) -> Predicate {
    let base = Predicate::Atom(Atom::Proto(proto));
    let mut port_pred: Option<Predicate> = None;
    for &p in ports {
        let atom = Predicate::Atom(Atom::AnyPort(p));
        port_pred = Some(match port_pred {
            None => atom,
            Some(acc) => acc.or(atom),
        });
    }
    match port_pred {
        Some(pp) => base.and(pp),
        None => base,
    }
}

/// Cost cap (Zeek `max_filter_compile_time` analog): if the union's DNF has
/// more than this many OR-clauses, **widen to no filter** (capture all) rather
/// than push a huge/slow cBPF program. Fail-open — degrade toward over-capture,
/// never toward dropping a wanted frame. The cap applies both to the union's
/// DNF and to the per-family clauses it lowers to (see [`split_families`]).
const MAX_KERNEL_CLAUSES: usize = 64;

/// IPv6 extension headers userspace walks past to reach the transport header
/// (etherparse's `Ipv6ExtensionsSlice`, under flowscope's extractors:
/// Hop-by-Hop, Routing, Fragment, Authentication, Destination Options). The
/// cBPF builder's IPv6 templates read the next-header byte and the ports at
/// **fixed** offsets, so an IPv6 frame whose first next-header is one of these
/// has its transport header where the kernel can't look — it must pass.
const IPV6_EXT_HEADERS: [u8; 5] = [0, 43, 44, 51, 60];

const ETH_IPV4: u16 = 0x0800;
const ETH_IPV6: u16 = 0x86dd;

/// VLAN TPIDs userspace parses through (etherparse: 802.1Q, 802.1ad, the
/// legacy QinQ 0x9100; flowscope's ARP parser: 802.1Q) — the compiler's
/// [`VLAN_TPIDS`]. Linux strips only the *outer* 802.1Q / 802.1ad tag before
/// packet taps (the cBPF `vlan` fragments read it from the metadata), so a
/// QinQ inner tag — or a 0x9100 one, or a tag a non-offloading NIC got
/// in-band on transmit — is still in the frame when the socket filter runs,
/// where every template reads at untagged offsets. Frames with one of these
/// at the EtherType slot pass.
const IN_FRAME_VLAN_TPIDS: [u16; 3] = VLAN_TPIDS;

/// How [`split_families`] lowers the IPv6 copy of a conjunction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V6Lowering {
    /// The conjunction on `ip6` (exact for frames without extension headers),
    /// plus one `ip6 && next-header == E` escape clause per
    /// [`IPV6_EXT_HEADERS`] entry carrying only the conjunction's address /
    /// VLAN atoms (those sit at fixed offsets, so stay exact).
    Precise,
    /// `ip6` plus the address / VLAN atoms only: every IPv6 frame of those
    /// hosts passes. The fallback when `Precise` exceeds the clause budget.
    Coarse,
}

/// How [`compile_union`] lowers the union.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KernelOpts {
    /// Let non-first IPv4 fragments pass the port terms
    /// ([`BpfFilterBuilder::pass_ip_fragments`]) — set when the Monitor's
    /// IP-fragment reassembler is armed: it needs every fragment of the
    /// datagrams it reassembles, and only the first carries the ports
    /// (#217).
    pub(crate) pass_ip_fragments: bool,
}

/// Compile the conservative kernel prefilter for an arbitrary set of consumer
/// **traffic-interest** predicates (0.25 S2): the OR-union of each interest's
/// [`kernel_approx`](Predicate::kernel_approx). Returns `None` — meaning
/// "capture everything, filter in userspace" — when there are no interests, any
/// interest wants everything (`Always`), or the union can't be expressed within
/// budget. The union is a superset of every interest, so **no consumer is ever
/// starved**, and `None` is always safe (fail-open).
pub(crate) fn compile_union(
    interests: impl IntoIterator<Item = Predicate>,
    opts: KernelOpts,
) -> Option<BpfFilter> {
    let mut union: Option<Predicate> = None;
    for p in interests {
        let k = p.kernel_approx();
        union = Some(match union {
            None => k,
            Some(acc) => acc.or(k),
        });
    }
    match union {
        Some(Predicate::Always) | None => None,
        Some(p) => predicate_to_bpf(&p, opts),
    }
}

/// Lower a **kernel-only** predicate (already `kernel_approx`'d) to a
/// [`BpfFilter`]. `None` if the shape can't be expressed (contains a `Not`,
/// is `Always`, exceeds [`MAX_KERNEL_CLAUSES`], or the bytecode build fails) —
/// a safe "pass all" fallback.
pub(crate) fn predicate_to_bpf(pred: &Predicate, opts: KernelOpts) -> Option<BpfFilter> {
    let dnf = to_dnf(pred, MAX_KERNEL_CLAUSES)?;
    if dnf.is_empty() {
        return None;
    }
    // Name every IP-dependent conjunction's address family explicitly — the
    // builder would default it to IPv4 and shed all IPv6. The precise IPv6
    // lowering first; the coarse one if that's over budget; else no filter.
    // Then let frames with an in-frame VLAN tag through (see
    // `IN_FRAME_VLAN_TPIDS`).
    let dnf = [V6Lowering::Precise, V6Lowering::Coarse]
        .into_iter()
        .map(|v6| {
            let mut lowered = split_families(&dnf, v6);
            if !lowered.is_empty() {
                for tpid in IN_FRAME_VLAN_TPIDS {
                    push_unique(&mut lowered, vec![Atom::EtherType(tpid)]);
                }
            }
            lowered
        })
        .find(|lowered| lowered.len() <= MAX_KERNEL_CLAUSES)?;
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
    if opts.pass_ip_fragments {
        builder = builder.pass_ip_fragments();
    }
    builder.build().ok()
}

/// Convert a kernel-only predicate to disjunctive normal form: a list of
/// conjunctions, each a list of positive [`Atom`]s. `None` if a `Not` is
/// present (not lowerable) or the DNF would have more than `max_clauses`
/// conjunctions. `Always` yields an empty conjunction list's
/// special handling at the call site — here it returns `Some(vec![vec![]])`
/// (one always-true clause), which the caller treats as "no filter".
///
/// The budget is checked **before** each cross product / concatenation is
/// built. A DNF only grows on the way up — every sub-DNF is non-empty, so
/// `|l ∧ r| ≥ max(|l|, |r|)` and `|l ∨ r| > max(|l|, |r|)` — so the first
/// over-budget node already decides the outcome. Checking only the finished
/// DNF let an innocuous `.expr()` string of ~60 leaves
/// (`(port 1 or port 2) and …`) expand to 2^30 conjunctions and exhaust
/// memory first.
fn to_dnf(pred: &Predicate, max_clauses: usize) -> Option<Vec<Vec<Atom>>> {
    match pred {
        // An always-true clause: one conjunction with no constraints.
        Predicate::Always => Some(vec![vec![]]),
        Predicate::Atom(a) => Some(vec![vec![a.clone()]]),
        Predicate::And(l, r) => {
            let dl = to_dnf(l, max_clauses)?;
            let dr = to_dnf(r, max_clauses)?;
            let n = dl.len().checked_mul(dr.len())?;
            if n > max_clauses {
                return None;
            }
            // Cross product: (a ∨ b) ∧ (c ∨ d) = ac ∨ ad ∨ bc ∨ bd.
            let mut out = Vec::with_capacity(n);
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
            let mut dl = to_dnf(l, max_clauses)?;
            let dr = to_dnf(r, max_clauses)?;
            if dl.len().checked_add(dr.len())? > max_clauses {
                return None;
            }
            dl.extend(dr);
            Some(dl)
        }
        // Per-atom negation isn't expressible through the builder — bail.
        Predicate::Not(_) => None,
    }
}

/// The address family an atom pins its conjunction to, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
    /// A non-IP EtherType (ARP, LLDP, …).
    NonIp,
}

fn atom_family(atom: &Atom) -> Option<Family> {
    let of = |v6: bool| Some(if v6 { Family::V6 } else { Family::V4 });
    match atom {
        Atom::EtherType(ETH_IPV4) => Some(Family::V4),
        Atom::EtherType(ETH_IPV6) => Some(Family::V6),
        Atom::EtherType(_) => Some(Family::NonIp),
        Atom::SrcHost(ip) | Atom::DstHost(ip) | Atom::AnyHost(ip) => of(ip.is_ipv6()),
        Atom::SrcNet(net) | Atom::DstNet(net) | Atom::AnyNet(net) => of(net.is_ipv6()),
        _ => None,
    }
}

/// Atoms the builder lowers to IP-header (or deeper) loads.
fn is_ip_atom(atom: &Atom) -> bool {
    !matches!(atom, Atom::EtherType(_) | Atom::VlanId(_))
}

/// Atoms the IPv6 templates read past the fixed header (next-header, ports).
fn reads_past_ipv6_header(atom: &Atom) -> bool {
    matches!(
        atom,
        Atom::Proto(_) | Atom::SrcPort(_) | Atom::DstPort(_) | Atom::AnyPort(_)
    )
}

fn push_unique(out: &mut Vec<Vec<Atom>>, clause: Vec<Atom>) {
    if !out.contains(&clause) {
        out.push(clause);
    }
}

/// Rewrite a DNF so every IP-dependent conjunction carries an explicit IPv4 /
/// IPv6 EtherType atom. The cBPF builder defaults an IP-aware chain without
/// one to IPv4, but userspace (flowscope's extractors) accepts both families —
/// so `tcp && port 443` used to compile to `ether 0x0800 && …` and every IPv6
/// TLS / DNS / … frame was shed in-kernel on live capture.
///
/// Per conjunction:
/// - no IP atom (EtherType / VLAN only), or a non-IP EtherType → unchanged;
/// - IPv4 and IPv6 pins at once (e.g. a v4 and a v6 host) → dropped: no frame
///   has both families, so userspace can't want one;
/// - pinned to one family → that family only;
/// - unpinned → one IPv4 copy and the IPv6 lowering below.
///
/// The IPv6 copy over-approximates where the templates can't see: the builder
/// reads the IPv6 next-header and ports at fixed offsets, which miss a
/// transport header behind extension headers. So unless it reads nothing past
/// the fixed header, it also passes any IPv6 frame whose first next-header is
/// an [`IPV6_EXT_HEADERS`] entry ([`V6Lowering::Precise`]), or simply every
/// IPv6 frame of its hosts ([`V6Lowering::Coarse`]). Protocol atoms are
/// family-agnostic here (userspace reports `Icmp` / `IcmpV6` by protocol
/// number in either family).
fn split_families(dnf: &[Vec<Atom>], v6: V6Lowering) -> Vec<Vec<Atom>> {
    let mut out: Vec<Vec<Atom>> = Vec::with_capacity(dnf.len() * 2);
    for clause in dnf {
        let fams: Vec<Family> = clause.iter().filter_map(atom_family).collect();
        if !clause.iter().any(is_ip_atom) || fams.contains(&Family::NonIp) {
            push_unique(&mut out, clause.clone());
            continue;
        }
        let (pin_v4, pin_v6) = (fams.contains(&Family::V4), fams.contains(&Family::V6));
        if pin_v4 && pin_v6 {
            continue;
        }
        // Everything but the EtherType atoms; the family is re-added below.
        let rest = clause.iter().filter(|a| !matches!(a, Atom::EtherType(_)));
        if !pin_v6 {
            let mut v4 = vec![Atom::EtherType(ETH_IPV4)];
            v4.extend(rest.clone().cloned());
            push_unique(&mut out, v4);
        }
        if pin_v4 {
            continue;
        }
        let mut exact = vec![Atom::EtherType(ETH_IPV6)];
        exact.extend(rest.clone().cloned());
        if !clause.iter().any(reads_past_ipv6_header) {
            push_unique(&mut out, exact);
            continue;
        }
        // Address and VLAN atoms: fixed offsets, exact behind extension headers.
        let fixed = rest.filter(|a| !reads_past_ipv6_header(a)).cloned();
        match v6 {
            V6Lowering::Precise => {
                push_unique(&mut out, exact);
                for ext in IPV6_EXT_HEADERS {
                    let mut escape =
                        vec![Atom::EtherType(ETH_IPV6), Atom::Proto(L4Proto::Other(ext))];
                    escape.extend(fixed.clone());
                    push_unique(&mut out, escape);
                }
            }
            V6Lowering::Coarse => {
                let mut any = vec![Atom::EtherType(ETH_IPV6)];
                any.extend(fixed);
                push_unique(&mut out, any);
            }
        }
    }
    out
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
            // The family comes from the conjunction's EtherType atom, which
            // `split_families` always adds to an IP-dependent conjunction.
            L4Proto::IcmpV6 => b.ip_proto(58),
            L4Proto::Sctp => b.ip_proto(132),
            L4Proto::Other(n) => b.ip_proto(*n),
            // flowscope 0.18 made `L4Proto` #[non_exhaustive]. A future named
            // variant we can't map to an IP proto number → bail to no kernel
            // filter for this atom (fail-open capture-all, never drops a frame).
            _ => return None,
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
        Atom::EtherType(ty) => b.eth_type(*ty),
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

    /// The union with the default lowering.
    fn union(interests: impl IntoIterator<Item = Predicate>) -> Option<BpfFilter> {
        compile_union(interests, KernelOpts::default())
    }

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

    /// A minimal broadcast ARP-request Ethernet frame (EtherType 0x0806).
    fn arp_frame() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xff; 6]); // dst mac: broadcast
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // src mac
        f.extend_from_slice(&[0x08, 0x06]); // ethertype: ARP
        f.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]); // htype/ptype/hlen/plen/oper
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // sha
        f.extend_from_slice(&[10, 0, 0, 1]); // spa
        f.extend_from_slice(&[0; 6]); // tha
        f.extend_from_slice(&[10, 0, 0, 2]); // tpa
        f
    }

    #[test]
    fn ethertype_arp_passes_arp_sheds_ip() {
        // Issue #20: an ARP-only interest compiles to a real cBPF filter that
        // passes ARP and sheds IP traffic — the alternative to capture-all.
        let pred = packet().arp().into_predicate();
        let bpf = predicate_to_bpf(&pred.kernel_approx(), KernelOpts::default())
            .expect("ethertype compiles");
        assert!(bpf.matches(&arp_frame()), "ARP frame should pass");
        assert!(!bpf.matches(&frame(17, 53)), "UDP frame should be shed");
        assert!(!bpf.matches(&frame(6, 80)), "TCP frame should be shed");
    }

    #[test]
    fn ethertype_unions_with_ip_interests() {
        // ARP OR (tcp/443): an ARP-watching monitor that also subscribes to
        // HTTPS captures both — not capture-all.
        let bpf = union([
            packet().arp().into_predicate(),
            packet().tcp().dst_port(443).into_predicate(),
        ])
        .expect("union compiles");
        assert!(bpf.matches(&arp_frame()), "ARP in union");
        assert!(bpf.matches(&frame(6, 443)), "tcp/443 in union");
        assert!(!bpf.matches(&frame(17, 53)), "udp/53 not in union");
    }

    #[test]
    fn compiles_conjunction_and_matches_only_target() {
        // udp AND dst_port 53.
        let pred = packet().udp().dst_port(53).into_predicate();
        let bpf = predicate_to_bpf(&pred.kernel_approx(), KernelOpts::default()).expect("compiles");
        assert!(bpf.matches(&frame(17, 53)), "udp/53 should pass");
        assert!(!bpf.matches(&frame(17, 80)), "udp/80 should not pass");
        assert!(!bpf.matches(&frame(6, 53)), "tcp/53 should not pass");
    }

    #[test]
    fn compiles_or_union_of_two_interests() {
        // interest A: udp/53 ; interest B: tcp/80 → union matches either.
        let bpf = union([
            packet().udp().dst_port(53).into_predicate(),
            packet().tcp().dst_port(80).into_predicate(),
        ])
        .expect("union compiles");
        assert!(bpf.matches(&frame(17, 53)), "udp/53 in union");
        assert!(bpf.matches(&frame(6, 80)), "tcp/80 in union");
        assert!(!bpf.matches(&frame(6, 53)), "tcp/53 not in union");
        assert!(!bpf.matches(&frame(17, 80)), "udp/80 not in union");
    }

    #[test]
    fn unfiltered_interest_yields_no_kernel_filter() {
        // An Always interest → union is Always → None (capture everything).
        assert!(union([packet().into_predicate()]).is_none());
    }

    #[test]
    fn mixed_union_with_one_unfiltered_interest_is_none() {
        // One narrow interest + one match-everything interest ⇒ union is
        // everything ⇒ capture all (a consumer can only widen).
        assert!(
            union([
                packet().tcp().dst_port(443).into_predicate(),
                packet().into_predicate(),
            ])
            .is_none()
        );
    }

    #[test]
    fn negation_falls_back_to_none() {
        // not(tcp) is kernel-pushable as a predicate but not lowerable here.
        let pred = packet().tcp().into_predicate().negate();
        assert!(predicate_to_bpf(&pred.kernel_approx(), KernelOpts::default()).is_none());
    }

    #[test]
    fn empty_interests_is_none() {
        assert!(union(Vec::<Predicate>::new()).is_none());
    }

    /// `(port 1 or port 2) and …` repeated `pairs` times, then `and tcp`.
    fn or_pair_chain(pairs: usize) -> Predicate {
        let expr = "(port 1 or port 2) and ".repeat(pairs) + "tcp";
        packet()
            .expr(&expr)
            .expect("well under the parser's MAX_NODES")
            .into_predicate()
    }

    #[test]
    fn dnf_blowup_widens_to_none_without_materialising_it() {
        // Audit A2: 30 OR-pairs is 61 leaves — far below the `.expr()` parser's
        // MAX_NODES, i.e. a legal untrusted config string — but its DNF has
        // 2^30 conjunctions. The budget must stop the cross product before it
        // is built (it used to be checked only on the finished DNF → OOM).
        let pred = or_pair_chain(30);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(union([pred]).is_none());
        });
        let widened = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("compile_union must bail out instead of expanding 2^30 clauses");
        assert!(widened, "an over-budget DNF falls back to capture-all");
    }

    #[test]
    fn dnf_budget_is_inclusive() {
        // 2^6 = 64 conjunctions is exactly MAX_KERNEL_CLAUSES: still lowered.
        // One more pair (128) is over budget: `None`, i.e. capture-all.
        let at = to_dnf(&or_pair_chain(6).kernel_approx(), MAX_KERNEL_CLAUSES)
            .expect("64 clauses fit the budget");
        assert_eq!(at.len(), MAX_KERNEL_CLAUSES);
        assert!(to_dnf(&or_pair_chain(7).kernel_approx(), MAX_KERNEL_CLAUSES).is_none());
    }

    // ── Signature dispatch (0.30, the `Http2` marker) ───────────────────────

    /// Stand-in for a real signature check; `dispatch_interest` never calls it.
    fn never_matches(_: &[u8]) -> crate::protocol::SignatureMatch {
        crate::protocol::SignatureMatch::NoMatch
    }

    #[test]
    fn signature_dispatch_is_capture_all() {
        // A signature cannot be evaluated in the kernel — the bytes have to
        // reach userspace — so the only sound interest is `Always`. Narrowing
        // this (e.g. to "h2 is TCP-only") would silently drop every non-TCP
        // consumer registered alongside it.
        assert!(matches!(
            dispatch_interest(&Dispatch::Signature(never_matches)),
            Predicate::Always
        ));
    }

    #[test]
    fn signature_dispatch_widens_a_narrow_union() {
        // The documented cost of registering a signature-dispatched protocol:
        // whatever else is registered, the kernel prefilter disappears.
        let narrow = [dispatch_interest(&Dispatch::Tcp(vec![443]))];
        assert!(
            union(narrow.clone()).is_some(),
            "a port dispatch alone still compiles to a BPF filter"
        );

        let widened = [
            dispatch_interest(&Dispatch::Tcp(vec![443])),
            dispatch_interest(&Dispatch::Signature(never_matches)),
        ];
        assert!(
            union(widened).is_none(),
            "a signature in the union must collapse it to capture-all",
        );
    }

    // ── Address families (audit A1) ─────────────────────────────────────────

    use std::net::IpAddr;

    use super::super::packet::{PacketFields, packet_field_extractor};

    const V4_A: &str = "10.0.0.1";
    const V4_B: &str = "192.0.2.7";
    const V6_A: &str = "2001:db8::1";
    const V6_B: &str = "2001:db8::2";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A well-formed Ethernet frame: IPv4 or IPv6 (optionally behind a
    /// Hop-by-Hop extension header) carrying a TCP / UDP header, or an
    /// 8-byte ICMP-shaped body for any other `proto`.
    fn ip_frame(
        src: IpAddr,
        dst: IpAddr,
        hop_by_hop: bool,
        proto: u8,
        sport: u16,
        dport: u16,
    ) -> Vec<u8> {
        let mut l4 = Vec::new();
        match proto {
            6 => {
                l4.extend_from_slice(&sport.to_be_bytes());
                l4.extend_from_slice(&dport.to_be_bytes());
                l4.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]); // seq, ack
                l4.extend_from_slice(&[0x50, 0x02, 0x20, 0x00, 0, 0, 0, 0]); // SYN
            }
            17 => {
                l4.extend_from_slice(&sport.to_be_bytes());
                l4.extend_from_slice(&dport.to_be_bytes());
                l4.extend_from_slice(&8u16.to_be_bytes());
                l4.extend_from_slice(&[0, 0]);
            }
            _ => l4.extend_from_slice(&[8, 0, 0, 0, 0, 1, 0, 1]),
        }
        let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                assert!(!hop_by_hop, "IPv4 has no extension headers");
                f.extend_from_slice(&[0x08, 0x00, 0x45, 0]);
                f.extend_from_slice(&(20 + l4.len() as u16).to_be_bytes());
                f.extend_from_slice(&[0, 0, 0, 0, 64, proto, 0, 0]);
                f.extend_from_slice(&s.octets());
                f.extend_from_slice(&d.octets());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let ext: &[u8] = if hop_by_hop {
                    // next header, length 0 (8 bytes), PadN over the rest.
                    &[proto, 0, 1, 4, 0, 0, 0, 0]
                } else {
                    &[]
                };
                f.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
                f.extend_from_slice(&((ext.len() + l4.len()) as u16).to_be_bytes());
                f.push(if hop_by_hop { 0 } else { proto });
                f.push(64);
                f.extend_from_slice(&s.octets());
                f.extend_from_slice(&d.octets());
                f.extend_from_slice(ext);
            }
            _ => panic!("mixed address families"),
        }
        f.extend_from_slice(&l4);
        f
    }

    /// `frame` with VLAN tags (`tpid`, VID) inserted after the MACs,
    /// outermost first — what a packet tap sees of a frame whose tags the
    /// kernel left in the data (a QinQ inner tag, a 0x9100 tag, …), and
    /// what userspace sees once a stripped tag was re-inserted.
    fn tagged(frame: &[u8], tags: &[(u16, u16)]) -> Vec<u8> {
        let mut f = frame[..12].to_vec();
        for (tpid, vid) in tags {
            f.extend_from_slice(&tpid.to_be_bytes());
            f.extend_from_slice(&vid.to_be_bytes());
        }
        f.extend_from_slice(&frame[12..]);
        f
    }

    /// Every frame of a small cartesian product — both families, IPv6 with
    /// and without a Hop-by-Hop header, TCP / UDP / ICMP / ICMPv6 (including
    /// the cross-family proto numbers userspace also accepts), a handful of
    /// well-known and ephemeral ports in both directions; each untagged and
    /// with VLAN tags (single 802.1Q VID 100 and 300, QinQ 100 / 200,
    /// 0x9100).
    fn frame_corpus() -> Vec<Vec<u8>> {
        let untagged = untagged_corpus();
        let mut out = untagged.clone();
        for tags in [
            &[(0x8100, 100)][..],
            &[(0x8100, 300)],
            &[(0x88a8, 100), (0x8100, 200)],
            &[(0x9100, 100)],
        ] {
            out.extend(untagged.iter().map(|f| tagged(f, tags)));
        }
        out
    }

    /// What the socket filter sees of `frame` on a live capture: Linux
    /// strips an outer 802.1Q / 802.1ad tag before packet taps run (#208)
    /// and hands it to the filter as metadata. `None` when `frame` has no
    /// such outer tag (the filter then sees the frame as is).
    fn kernel_stripped(frame: &[u8]) -> Option<(Vec<u8>, crate::config::BpfAncillary)> {
        use crate::config::{BpfAncillary, VlanProto, VlanTag};
        let tpid = u16::from_be_bytes([frame[12], frame[13]]);
        let proto = match tpid {
            0x8100 => VlanProto::Dot1Q,
            0x88a8 => VlanProto::Dot1Ad,
            _ => return None,
        };
        let tci = u16::from_be_bytes([frame[14], frame[15]]);
        let mut f = frame[..12].to_vec();
        f.extend_from_slice(&frame[16..]);
        Some((f, BpfAncillary::stripped(VlanTag::new(tci, proto))))
    }

    fn untagged_corpus() -> Vec<Vec<u8>> {
        let ports = [
            (54321, 443),
            (8443, 40000),
            (33000, 53),
            (80, 1234),
            (5000, 5001),
        ];
        let mut out = Vec::new();
        for (src, dst) in [(V4_A, V4_B), (V4_B, V4_A), (V6_A, V6_B), (V6_B, V6_A)] {
            let (src, dst) = (ip(src), ip(dst));
            for hbh in [false, true] {
                if hbh && src.is_ipv4() {
                    continue;
                }
                for proto in [6u8, 17, 1, 58] {
                    for (sp, dp) in ports {
                        out.push(ip_frame(src, dst, hbh, proto, sp, dp));
                    }
                }
            }
        }
        out
    }

    /// The prefilter's contract: a frame any interest accepts in userspace
    /// must pass the kernel filter (`None` = no filter = passes everything)
    /// — both when its tags reach the filter in the frame and when the
    /// kernel stripped the outer one (the filter sees the untagged rest plus
    /// the tag as metadata; userspace sees the re-inserted frame).
    fn assert_superset(name: &str, interests: &[Predicate]) {
        let bpf = union(interests.to_vec());
        assert!(
            bpf.is_some(),
            "{name}: expected a real filter, not capture-all"
        );
        let ex = packet_field_extractor();
        let mut wanted = 0;
        for f in frame_corpus() {
            let view = flowscope::PacketView::new(&f, flowscope::Timestamp::new(0, 0));
            let Some((_key, fields)) = PacketFields::extract(view, &ex) else {
                panic!("{name}: corpus frame did not parse: {f:02x?}");
            };
            if interests.iter().any(|p| p.eval(&fields)) {
                wanted += 1;
                assert!(
                    bpf.as_ref().is_none_or(|b| b.matches(&f)),
                    "{name}: userspace wants this frame but the kernel prefilter \
                     drops it\n  frame: {f:02x?}\n  filter: {:?}",
                    bpf.as_ref().map(|b| b.to_human()),
                );
                if let Some((seen, anc)) = kernel_stripped(&f) {
                    assert!(
                        bpf.as_ref().is_none_or(|b| b.matches_with(&seen, &anc)),
                        "{name}: userspace wants this frame but the kernel prefilter \
                         drops it once the kernel stripped its outer tag\n  \
                         frame: {f:02x?}\n  filter: {:?}",
                        bpf.as_ref().map(|b| b.to_human()),
                    );
                }
            }
        }
        assert!(wanted > 0, "{name}: corpus exercises nothing");
    }

    #[test]
    fn prefilter_is_a_superset_of_userspace_for_both_families() {
        let tls = || dispatch_interest(&Dispatch::Tcp(vec![443, 8443]));
        let dns = || dispatch_interest(&Dispatch::Udp(vec![53]));
        use super::super::builder::{PacketTier, SubscriptionBuilder};
        let p = |b: SubscriptionBuilder<PacketTier>| b.into_predicate();
        let cases: Vec<(&str, Vec<Predicate>)> = vec![
            ("tls", vec![tls()]),
            ("tls+dns", vec![tls(), dns()]),
            (
                "all_l4",
                vec![
                    dispatch_interest(&Dispatch::AllTcp),
                    dispatch_interest(&Dispatch::AllUdp),
                    dispatch_interest(&Dispatch::Icmp),
                ],
            ),
            ("icmp", vec![dispatch_interest(&Dispatch::Icmp)]),
            ("tcp dst 443", vec![p(packet().tcp().dst_port(443))]),
            ("vlan 100", vec![p(packet().vlan(100))]),
            (
                "vlan 100 + udp 53",
                vec![p(packet().vlan(100).udp().port(53))],
            ),
            (
                "vlan 100 or tcp 443",
                vec![p(packet().vlan(100)), p(packet().tcp().dst_port(443))],
            ),
            ("udp port 53", vec![p(packet().udp().port(53))]),
            ("v6 host", vec![p(packet().host(ip(V6_A)))]),
            ("tcp + v6 host", vec![p(packet().tcp().host(ip(V6_A)))]),
            ("v6 src + udp", vec![p(packet().src_host(ip(V6_B)).udp())]),
            ("v4 src + udp", vec![p(packet().src_host(ip(V4_B)).udp())]),
            (
                "expr",
                vec![p(packet()
                    .expr("tcp and (port 443 or port 80) or udp and dst port 53")
                    .unwrap())],
            ),
            (
                "mixed hosts",
                vec![
                    p(packet().tcp().dst_host(ip(V4_B))),
                    p(packet().udp().dst_host(ip(V6_B))),
                ],
            ),
        ];
        for (name, interests) in &cases {
            assert_superset(name, interests);
        }
    }

    #[test]
    fn ipv6_tls_and_dns_pass_including_behind_extension_headers() {
        let bpf = union([
            dispatch_interest(&Dispatch::Tcp(vec![443, 8443])),
            dispatch_interest(&Dispatch::Udp(vec![53])),
        ])
        .expect("tls + dns still lowers to a real filter");
        let (a, b) = (ip(V6_A), ip(V6_B));
        assert!(
            bpf.matches(&ip_frame(a, b, false, 6, 54321, 443)),
            "v6 tcp/443"
        );
        assert!(
            bpf.matches(&ip_frame(a, b, true, 6, 54321, 443)),
            "v6 hbh tcp/443"
        );
        assert!(
            bpf.matches(&ip_frame(a, b, false, 17, 33000, 53)),
            "v6 udp/53"
        );
        assert!(
            bpf.matches(&ip_frame(a, b, true, 17, 33000, 53)),
            "v6 hbh udp/53"
        );
        // Still a filter, for IPv6 as for IPv4: no extension header and an
        // uninteresting port is shed.
        assert!(
            !bpf.matches(&ip_frame(a, b, false, 6, 54321, 80)),
            "v6 tcp/80"
        );
        assert!(
            !bpf.matches(&ip_frame(a, b, false, 17, 33000, 123)),
            "v6 udp/123"
        );
        let (a4, b4) = (ip(V4_A), ip(V4_B));
        assert!(
            bpf.matches(&ip_frame(a4, b4, false, 6, 54321, 443)),
            "v4 tcp/443"
        );
        assert!(
            !bpf.matches(&ip_frame(a4, b4, false, 6, 54321, 80)),
            "v4 tcp/80"
        );
    }

    #[test]
    fn over_budget_ipv6_lowering_degrades_to_coarse_not_to_none() {
        // 30 TCP ports: 30 IPv4 + 30 IPv6 + 5 extension-header clauses is over
        // MAX_KERNEL_CLAUSES, so IPv6 widens to "all of ip6" — IPv4 stays
        // filtered rather than the whole prefilter collapsing to capture-all.
        let ports: Vec<u16> = (1000..1030).collect();
        let bpf = union([dispatch_interest(&Dispatch::Tcp(ports))])
            .expect("the coarse IPv6 lowering fits the budget");
        let (a, b) = (ip(V6_A), ip(V6_B));
        assert!(bpf.matches(&ip_frame(a, b, false, 6, 40000, 1000)));
        assert!(
            bpf.matches(&ip_frame(a, b, false, 17, 40000, 9)),
            "coarse: all v6"
        );
        let (a4, b4) = (ip(V4_A), ip(V4_B));
        assert!(bpf.matches(&ip_frame(a4, b4, false, 6, 40000, 1029)));
        assert!(!bpf.matches(&ip_frame(a4, b4, false, 6, 40000, 1030)));
    }

    #[test]
    fn host_pins_the_family_and_keeps_the_other_one_out() {
        // A v4-host interest stays IPv4-only, a v6-host one IPv6-only.
        let v4 = union([packet().udp().src_host(ip(V4_A)).into_predicate()]).unwrap();
        let v6 = union([packet().udp().src_host(ip(V6_A)).into_predicate()]).unwrap();
        let f4 = ip_frame(ip(V4_A), ip(V4_B), false, 17, 1, 2);
        let f6 = ip_frame(ip(V6_A), ip(V6_B), false, 17, 1, 2);
        assert!(v4.matches(&f4) && !v4.matches(&f6));
        assert!(v6.matches(&f6) && !v6.matches(&f4));
    }

    #[test]
    fn contradictory_family_clause_is_dropped_not_fatal() {
        // `host v4 and host v6` matches no frame; the other interest must still
        // get a real filter rather than a build error → capture-all.
        let bpf = union([
            packet().host(ip(V4_A)).host(ip(V6_A)).into_predicate(),
            packet().tcp().dst_port(443).into_predicate(),
        ])
        .expect("the satisfiable interest still lowers");
        assert!(bpf.matches(&ip_frame(ip(V4_A), ip(V4_B), false, 6, 1, 443)));
        assert!(!bpf.matches(&ip_frame(ip(V4_A), ip(V4_B), false, 17, 1, 53)));
    }
}
