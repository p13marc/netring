---
to: netring maintainers
from: nlink-lab team
subject: Typed cBPF filter builder — proposal + recipe confirmation
netring version surveyed: 0.2.0
date: 2026-04-30
---

# Typed cBPF filter builder — netring proposal

## TL;DR

netring 0.2.0 exposes `BpfFilter::new(Vec<BpfInsn>)` as the only
way to build a kernel-level filter. The doc comment says "generate
instructions with `tcpdump -dd \"expression\"`" — i.e., netring's
official recommendation for non-trivial filtering is a runtime
shell-out to libpcap's compiler.

We're hitting that path in nlink-lab and it forces an unnecessary
runtime dependency on `tcpdump` on every host that uses our
`capture --filter "..."` feature. Per our [Plan 156][p156]
analysis, the C-dependency surface of nlink-lab + netring is
*one shell-out away* from being completely C-dep-free.

We'd like to upstream a small, focused **typed `BpfFilter::builder()`**
to netring that handles the common cases (tcp/udp port, host, net,
vlan, AND/OR/NOT composition) and emits `Vec<BpfInsn>` directly.

Same shape as the [Plan 128][p128] proposal we sent the nlink team
that became `PerPeerImpairer`: when our consumer code needs a
primitive in your library's domain, the right home is the library,
not us hand-rolling something downstream.

[p156]: https://github.com/p13marc/nlink-lab/blob/master/docs/plans/156-eliminate-tcpdump-runtime-dep.md
[p128]: https://github.com/p13marc/nlink-lab/commit/f366c0c

What we'd like from the netring team:

1. **Primary ask:** add `BpfFilter::builder() -> BpfFilterBuilder`
   with typed matchers for the common cases. Sketch below; we're
   happy to iterate on shape.
2. **Confirm scope** — we propose covering ~95% of real-world
   filter expressions and explicitly *not* trying for parity with
   libpcap's full grammar. We want netring to stay small.
3. **Discuss whether the existing `BpfFilter::new(Vec<BpfInsn>)`
   stays as the escape hatch** for advanced cases (we think yes;
   small but explicit).

Below: use case, proposed API, the fragment compiler design,
backward compat, tests, open questions.

---

## 1. Use case

nlink-lab uses `netring::Capture` for namespace-bound packet
capture during lab tests and the `nlink-lab capture` CLI. Real
filter expressions seen in our cookbook + integration suite:

| Expression | Frequency in our test surface |
|------------|------------------------------|
| `tcp port 80` | ~30% |
| `udp port 53` | ~15% |
| `host 10.0.0.1` | ~15% |
| `tcp` | ~10% |
| `not arp` | ~5% |
| `tcp port 443 and host 10.0.0.5` | ~10% |
| `vlan and tcp port 80` | ~5% |
| Other (regex/state, advanced) | ~10% |

The first six rows (90%+) are mechanical compositions of a tiny
fragment vocabulary. None of them need libpcap's full
expression grammar.

Today every consumer has to either:

- Generate `Vec<BpfInsn>` by hand (impractical for non-experts).
- Shell out to `tcpdump -dd "..."` (introduces a runtime tooling
  dep on tcpdump + libpcap).

Neither is a great default for a pure-Rust AF_PACKET crate.

---

## 2. Proposed API

```rust
use netring::{BpfFilter, EthType, IpProto, IpAddr};
use std::net::Ipv4Addr;

let f = BpfFilter::builder()
    .tcp()
    .dst_port(80)
    .src_net("10.0.0.0/24".parse().unwrap())
    .build();

let f = BpfFilter::builder()
    .any_of(|b| b
        .tcp().dst_port(80).build()
    )
    .or(|b| b
        .udp().dst_port(53).build()
    )
    .build();

// Existing API still works as the escape hatch:
let f = BpfFilter::new(some_hand_written_insns);
```

Sketch:

```rust
impl BpfFilter {
    pub fn builder() -> BpfFilterBuilder { /* ... */ }
}

pub struct BpfFilterBuilder {
    fragments: Vec<MatchFrag>,
    combinator: Combinator,    // And / Or / Custom
    negated: bool,
}

#[derive(Debug, Clone)]
enum MatchFrag {
    EthType(u16),                // 0x0800, 0x86dd, 0x0806, 0x8100
    IpProto(u8),                 // 6, 17, 1, 47, ...
    SrcIp(Ipv4Addr, u8),         // address + prefix_len
    DstIp(Ipv4Addr, u8),
    AnyIp(Ipv4Addr, u8),         // src OR dst
    SrcIp6(Ipv6Addr, u8),
    DstIp6(Ipv6Addr, u8),
    SrcPort(u16),                // L4 src port (TCP/UDP)
    DstPort(u16),
    AnyPort(u16),
    VlanId(u16),
}

impl BpfFilterBuilder {
    pub fn tcp(mut self) -> Self { /* push EthType(IPv4) AND IpProto(TCP) */ self }
    pub fn udp(mut self) -> Self { /* … */ self }
    pub fn icmp(mut self) -> Self { /* … */ self }
    pub fn arp(mut self) -> Self { self.fragments.push(MatchFrag::EthType(0x0806)); self }

    pub fn ipv4(mut self) -> Self { self.fragments.push(MatchFrag::EthType(0x0800)); self }
    pub fn ipv6(mut self) -> Self { self.fragments.push(MatchFrag::EthType(0x86dd)); self }
    pub fn vlan(mut self) -> Self { self.fragments.push(MatchFrag::EthType(0x8100)); self }

    pub fn src_port(mut self, port: u16) -> Self { /* … */ self }
    pub fn dst_port(mut self, port: u16) -> Self { /* … */ self }
    pub fn port(mut self, port: u16) -> Self { /* AnyPort */ self }

    pub fn src_host(mut self, addr: IpAddr) -> Self { /* … */ self }
    pub fn dst_host(mut self, addr: IpAddr) -> Self { /* … */ self }
    pub fn host(mut self, addr: IpAddr) -> Self { /* AnyIp */ self }

    pub fn src_net(mut self, net: IpNet) -> Self { /* … */ self }
    pub fn dst_net(mut self, net: IpNet) -> Self { /* … */ self }
    pub fn net(mut self, net: IpNet) -> Self { /* … */ self }

    pub fn vlan_id(mut self, id: u16) -> Self { /* … */ self }

    /// Negate the entire builder so far.
    pub fn negate(mut self) -> Self { self.negated = !self.negated; self }

    /// Compose two sub-filters with OR.
    pub fn or(self, build: impl FnOnce(BpfFilterBuilder) -> BpfFilter) -> Self {
        let other = build(BpfFilterBuilder::new());
        // Combine self.fragments with other.instructions via Or
        // ... implementation detail ...
    }

    /// Compile to instructions and return the immutable filter.
    pub fn build(self) -> BpfFilter { /* runs the compiler */ }
}
```

`IpNet` is a simple `(Ipv4Addr, u8)` / `(Ipv6Addr, u8)` pair. We
can use the [`ipnet`](https://crates.io/crates/ipnet) crate or a
small in-tree wrapper — your call.

---

## 3. The fragment compiler

For each `MatchFrag`, emit a small bytecode template that loads
the relevant byte/half/word from the packet and jumps to either
the next fragment's start or a global `reject` (return 0) /
`accept` (return 0xffff_ffff) tail.

**Worked examples** — all verified against `tcpdump -dd` output
on a 6.13 kernel:

### `tcp` → ethtype IPv4 AND ip_proto 6

```
ldh   [12]                   ; ethertype
jne   #0x0800, drop          ; not IPv4? reject
ldb   [23]                   ; IP proto
jne   #6, drop               ; not TCP? reject
ret   #65535                 ; accept
drop: ret #0
```

5 instructions. The IPv6 variant adds a parallel branch for
0x86dd → load proto from offset 20 (next-header).

### `dst_port 80` (TCP/UDP) → ethtype IPv4 + len-aware port load

```
ldh   [12]                   ; ethertype
jne   #0x0800, drop
ldb   [23]                   ; IP proto
jne   #6, check_udp          ; if not TCP, try UDP
                             ; (same destination-port offset)
ldh   [20]                   ; flags+frag
jset  #0x1fff, drop          ; reject fragments
ldxb  4*([14]&0xf)           ; IHL → X
ldh   [x + 16]               ; dst port
jeq   #80, accept
ret   #0
check_udp: jne #17, drop
   ; same shape as TCP
accept: ret #65535
```

12-15 instructions per fragment. Standard pattern; libpcap emits
something nearly identical.

### `host 10.0.0.1`

```
ldh   [12]
jne   #0x0800, drop
ld    [26]                   ; src IP
jeq   #0x0a000001, accept
ld    [30]                   ; dst IP
jne   #0x0a000001, drop
accept: ret #65535
drop: ret #0
```

7 instructions. Subnet match adds an `and` mask before the
compare.

### Composition (AND / OR / NOT)

- **AND**: append fragments. Each fragment's `drop` target is the
  next fragment's first instruction; the final fragment's accept
  target is the global accept.
- **OR**: each branch ends with `ret #65535` on success; the
  global drop is reached only if every branch fails.
- **NOT**: swap the global accept/drop tails.

Implementation lives in a single `compile()` function, ~200 LOC.
Roughly the same complexity as the existing `BpfFilter::new`
boilerplate but with structure.

---

## 4. Scope (what we are *not* asking for)

We explicitly do **not** want to recreate libpcap's full grammar.
Things that should stay out of scope:

- Slice notation: `tcp[13] & 0x0f != 0`.
- Stateful matching (TCP flags, conntrack).
- IPv6 extension header walking beyond first hop.
- MPLS label matching.
- Geneve/VXLAN inner headers.

Users with these needs can still:

- Pass a hand-built `Vec<BpfInsn>` to `BpfFilter::new`.
- Use eBPF via `attach_ebpf_filter` (already exposed).
- Shell out to tcpdump themselves.

The typed builder covers the cases worth optimizing for the
common-path; the escape hatches stay for the long tail.

---

## 5. Backward compatibility

`BpfFilter::new(Vec<BpfInsn>)` stays unchanged. The builder is
purely additive.

Documentation update in netring's `BpfFilter` doc comment:

```diff
- /// Generate instructions with `tcpdump -dd "expression"`.
- /// For eBPF, use `aya` and attach to the socket fd via `AsFd`.
+ /// For most use cases, prefer the typed builder:
+ /// `BpfFilter::builder().tcp().dst_port(80).build()`.
+ /// For advanced expressions outside the builder's scope,
+ /// hand-roll instructions or generate them with
+ /// `tcpdump -dd "expression"`. For eBPF, use `aya` and
+ /// attach via `attach_ebpf_filter`.
```

---

## 6. Tests

Each fragment compiler runs golden-output tests against expected
bytecode (matching what `tcpdump -dd` produces) and dynamic tests
that synthesize a few packet bytes and assert the program
accepts/rejects:

```rust
#[test]
fn tcp_dst_port_80_accepts_http() {
    let f = BpfFilter::builder().tcp().dst_port(80).build();
    let pkt = synth_tcp_packet(80, ..); // dst_port = 80
    assert!(f.matches(&pkt));
}

#[test]
fn tcp_dst_port_80_rejects_https() {
    let f = BpfFilter::builder().tcp().dst_port(80).build();
    let pkt = synth_tcp_packet(443, ..);
    assert!(!f.matches(&pkt));
}
```

A `BpfFilter::matches(&[u8]) -> bool` test helper would be
extremely useful for downstream consumers writing unit tests
without spinning up an AF_PACKET socket. We'd be happy to
contribute the runtime BPF interpreter (or upstream from ours
once we land it locally).

Test surface for the proposed builder ~6 fragment templates × 3
test cases each + 5 composition tests = ~25 unit tests. All run
without root.

---

## 7. Open questions for the netring team

1. **API style — chained vs collected?** We sketched chained
   (`builder().tcp().dst_port(80)`). A collected form
   (`BpfFilter::compile(&[Frag::Tcp, Frag::DstPort(80)])`) is
   uglier but more amenable to runtime construction. Preference?

2. **Where should `IpNet` come from?** Options:
   - `(Ipv4Addr, u8)` / `(Ipv6Addr, u8)` tuples (zero deps).
   - `ipnet` crate (small, well-maintained, adds a dep).
   - In-tree `pub struct IpNet { addr: IpAddr, prefix: u8 }`.

   We lean toward the in-tree wrapper for zero-deps, but defer to
   your taste.

3. **Builder vs `Self` ownership**. The sketch above uses
   `.tcp(mut self) -> Self` — caller-friendly chaining but
   allocates a new builder per call. An `&mut self -> &mut Self`
   form composes better with conditional logic. Either is fine
   downstream; pick the one that matches netring's existing
   builder style elsewhere (the `Capture::builder()` chain uses
   the `mut self` form, so we'd suggest matching that).

4. **`matches(&[u8])` interpreter**. As mentioned in §6, a
   runtime BPF interpreter would let downstream consumers
   unit-test their filters without hitting the kernel. ~50 LOC.
   Worth including in the same PR, or split?

5. **Naming**. We've been calling it `BpfFilterBuilder`. If you'd
   prefer `BpfFilterDsl` / `BpfProgram::Builder` / something else
   to match netring's conventions, say the word.

---

## 8. What we'll do on our side once this lands

Plan 156 in nlink-lab is currently scoped as an in-tree typed
builder + the legacy tcpdump fallback. Once netring 0.3 ships
the upstream version, we'll:

1. Bump `netring = "0.2"` → `"0.3"` in our Cargo.toml.
2. Replace `nlink_lab::capture::compile_bpf_filter` (the
   `tcpdump -dd` shell-out) with calls into the netring builder.
3. Expose the builder via NLL `filter { ... }` blocks and CLI
   flags (`--filter-tcp`, `--filter-dst-port`, etc.).
4. Gate the legacy `--filter "<tcpdump-syntax>"` path behind a
   `legacy-tcpdump-filter` Cargo feature, off by default.
5. Drop the runtime `tcpdump` dependency from our default path.

Net result: nlink-lab's full default capture path becomes
**zero non-Rust runtime dependencies** (modulo libc/kernel), and
any other future netring consumer gets the same typed surface.

---

## 9. Why netring is the right home

This mirrors the Plan 128 `PerPeerImpairer` arc with the nlink
team. The pattern:

| When nlink-lab needs a primitive in domain X | The right home is X's owning library |
|---|---|
| netlink TC trees (per-pair impair) | nlink → shipped 0.15.1 |
| AF_PACKET / cBPF | netring → this proposal |
| Flow analysis / TCP reassembly | flowscope → future proposal |

The benefits we saw with the nlink path apply here:

- The primitive lives where its tests run (kernel-shape tests
  belong with the kernel-shape code).
- Other consumers benefit. Anyone using netring for capture in
  the future gets a typed filter without re-implementing it.
- nlink-lab's surface stays focused on labs, not packet plumbing.
- Future evolutions (e.g. eBPF builder, `flowscope` integration,
  `match()`-based interpreter for testing) compose naturally
  with the upstream surface.

---

## 10. Context pointers

- nlink-lab call site:
  [`crates/nlink-lab/src/capture.rs:217`](https://github.com/p13marc/nlink-lab/blob/master/crates/nlink-lab/src/capture.rs#L217)
  — the `compile_bpf_filter` function we want to remove.
- nlink-lab plan: [`docs/plans/156-eliminate-tcpdump-runtime-dep.md`](156-eliminate-tcpdump-runtime-dep.md).
- The Plan 128 precedent letter to the nlink team — see
  `git log --grep "Plan 128"` in nlink-lab and the resulting
  nlink 0.15.1 ship.

We're happy to draft the netring PR if you'd like to set the
shape and have us implement it. Or if you'd rather take the work
yourselves, we'd be glad to review.

Thanks!
