# Plan 18 — Typed cBPF filter builder

## Summary

Add `BpfFilter::builder()` — a typed, in-tree compiler from a small
match vocabulary (TCP/UDP/ICMP/ARP, src/dst host, port, net, VLAN,
NOT, OR, AND) to classic-BPF bytecode. Goal: cover ~90 % of the
expression surface that consumers reach for, replace runtime
`tcpdump -dd "..."` shell-outs, keep `BpfFilter::new(Vec<BpfInsn>)`
as the explicit escape hatch for anything outside the builder's
vocabulary.

After this plan, downstream crates that today must shell out to
`tcpdump` to build a filter (`nlink-lab`, others) can drop that
runtime dependency and use a typed Rust API instead. The user-side
surface looks like this:

```rust
let f = BpfFilter::builder()
    .tcp()
    .dst_port(80)
    .src_net("10.0.0.0/24".parse()?)
    .build()?;
```

## Status

Not started.

## Prerequisites

- None. Additive over `BpfFilter::new` (which stays unchanged).
- `BpfInsn` (in `src/config.rs`) already has the same memory layout
  as `libc::sock_filter` and the conversion impls; the new compiler
  just emits `Vec<BpfInsn>`.

## Out of scope

- **Full libpcap grammar.** No string parser, no slice notation
  (`tcp[13] & 0x0f != 0`), no protocol-aware match keywords beyond
  the vocabulary listed below. Users with those needs continue to
  use `BpfFilter::new(Vec<BpfInsn>)` (hand-rolled or tcpdump-
  generated) — that path stays as the explicit escape hatch.
- **Stateful matching** (TCP flag tracking, conntrack, payload
  regex). cBPF can't do these anyway; users reach for eBPF + aya.
- **IPv6 extension header walking past the first hop.** Inner-
  protocol matching after Hop-by-Hop or Routing extensions: out.
  IPv6 traffic with extension headers will fail-closed (build a
  filter that drops everything) so users get a clear behaviour
  rather than silently-wrong matches.
- **Geneve / VXLAN / GRE inner headers**, MPLS label matching,
  802.1ad (Q-in-Q). Mention in docs as known gaps.
- **eBPF emission.** This compiler emits cBPF (`SO_ATTACH_FILTER`
  socket option). eBPF socket filters are a separate path
  (`SO_ATTACH_BPF` / aya); not in scope.

---

## Design context

This plan implements the proposal in
`plans/156a-netring-bpf-builder-proposal.md` from the nlink-lab
team. Proposal is well-scoped — we accept it whole, with five
nudges baked into the plan below:

1. **`IpNet` is in-tree, zero-dep.** ~40 LOC for
   `pub struct IpNet { addr: IpAddr, prefix: u8 }` + `FromStr`. No
   `ipnet` crate dependency.
2. **Expose `eth_type(u16)` as a public primitive.** Higher-level
   methods (`tcp`, `udp`, `arp`, `ipv4`, `ipv6`) compose on top.
   Lets users hit exotic ethertypes (LLDP `0x88cc`, EAPOL `0x888e`,
   PPPoE-Discovery `0x8863`, …) without per-protocol builder
   methods.
3. **Validate at `build()`.** Conflicting fragments
   (`.tcp().udp()`), instruction count > 4096 (kernel `BPF_MAXINSNS`
   cap), out-of-range ports / prefixes — return
   `Result<BpfFilter, BuildError>`. The escape hatch
   (`BpfFilter::new`) gains a length check too.
4. **Document IP-fragment + VLAN semantics loudly.**
   `dst_port` / `src_port` reject IPv4 fragments by default
   (`jset #0x1fff, drop`) — matching tcpdump. VLAN compilation
   shifts subsequent offsets by 4 bytes; users must include `.vlan()`
   in the chain if they want VLAN-tagged traffic to match.
5. **Tests against `tcpdump -dd` golden output.** Embed expected
   bytecode as fixtures, byte-for-byte assert. If the kernel
   verifier or our compiler regresses, tests catch it. Reference
   tcpdump version is locked (see §11).

---

## Where it lives — `netring`

All new code in:

```
netring/src/config/                  # convert config.rs into a module
├── mod.rs                           # re-exports current public surface
├── bpf.rs                           # existing BpfInsn / BpfFilter (moved from config.rs)
├── bpf_builder.rs                   # NEW — BpfFilterBuilder, IR, compile()
├── bpf_compile.rs                   # NEW — fragment templates + symbolic-label resolver
├── bpf_interp.rs                    # NEW — runtime interpreter (pub for downstream tests)
└── ipnet.rs                         # NEW — minimal IpNet struct + FromStr
```

`config.rs` becomes a directory module. Existing public path
(`netring::BpfFilter`, `netring::BpfInsn`, `netring::FanoutMode`,
…) is preserved via `pub use` in `mod.rs`.

### Dependency rules — hard project constraints

This work explicitly preserves netring's stance: pure Rust, no
native deps, no FFI in the new code paths.

- **No new external Rust crates.** Only crates already in
  netring's tree: `thiserror`, `bitflags`, `libc`. The compiler,
  IR, interpreter, and `IpNet` are all written from scratch in
  this crate.
- **No native/C libraries** at compile time, build time, or
  runtime. No `libpcap`, no `libbpf`, no `bpftool`, no `clang`.
  The kernel's classic-BPF execution engine is the only
  "external" code involved, via the existing `setsockopt(SO_ATTACH_FILTER)`
  call netring already makes.
- **`libc` involvement is unchanged.** `libc::sock_filter` is
  still used for the `From<BpfInsn>` conversion at `setsockopt`
  time; that conversion is pre-existing and survives untouched.
  The new builder emits `BpfInsn` (netring's repr-equivalent
  type) and never crosses the FFI boundary itself.
- **`tcpdump` is a maintainer-side tool, not a runtime or build
  dependency.** The plan uses `tcpdump -dd "..."` to *generate*
  golden fixtures committed under `tests/fixtures/bpf/`. End
  users compiling, installing, or running netring never invoke
  `tcpdump`. Regenerating fixtures (rare — only after libpcap
  version bumps) is the maintainer's job, documented in the
  fixtures' README.
- **No `unsafe` in any new code path.** The compiler, the
  fragment templates, the symbolic-label resolver, the runtime
  interpreter, and `IpNet` all stay in safe Rust. `BpfInsn`'s
  `#[repr(C)]` (pre-existing) is the only memory-layout contract
  in the file tree, and it's at the public-API edge for
  `setsockopt`-compatible array passing — not in the new code.

---

## Files

### NEW

```
netring/src/config/bpf_builder.rs      # ~250 LOC
netring/src/config/bpf_compile.rs      # ~350 LOC
netring/src/config/bpf_interp.rs       # ~150 LOC
netring/src/config/ipnet.rs            # ~70 LOC
netring/tests/bpf_builder_golden.rs    # ~250 LOC golden bytecode tests
netring/tests/bpf_builder_match.rs     # ~150 LOC interpreter-driven tests
netring/tests/bpf_builder_proptest.rs  # ~100 LOC splitting + composition invariants
netring/tests/fixtures/bpf/            # tcpdump -dd reference outputs
├── tcp_dst_port_80.txt
├── udp_port_53.txt
├── host_10_0_0_1.txt
├── tcp.txt
├── tcp_or_udp_port_53.txt
├── vlan_tcp_port_80.txt
└── ipv6_tcp.txt
netring/tests/fixtures/bpf/README.md   # how to regenerate
netring/examples/bpf_filter.rs         # ~80 LOC end-to-end example
```

### MODIFIED

```
netring/src/config.rs   →   netring/src/config/mod.rs    # split into dir module
netring/src/lib.rs                                       # extend pub use
netring/Cargo.toml                                       # no changes (no new deps)
netring/CLAUDE.md                                        # mention builder under "Key files"
README.md                                                # update example using builder
CHANGELOG.md                                             # 0.x.0 entry
plans/INDEX.md                                           # register plan 18
```

---

## API

### Public surface

```rust
// re-exported from netring::
pub use config::{BpfFilter, BpfFilterBuilder, BpfInsn, BuildError, IpNet};

impl BpfFilter {
    /// Maximum instruction count enforced by the kernel
    /// (`BPF_MAXINSNS` in `<linux/bpf_common.h>`).
    pub const MAX_INSNS: usize = 4096;

    /// Construct from raw instructions. Validates that
    /// `instructions.len() <= Self::MAX_INSNS`. **Tiny breaking
    /// change** vs 0.x: previously returned `Self` infallibly;
    /// now returns `Result` so we can surface the kernel limit
    /// at construction time rather than at `setsockopt` time.
    /// Existing callers typically `?`-propagate from the
    /// surrounding `Capture::build()`, so the migration is a
    /// single character at most call sites.
    pub fn new(instructions: Vec<BpfInsn>) -> Result<Self, BuildError>;

    /// New entry point — typed builder.
    pub fn builder() -> BpfFilterBuilder;

    /// Run the filter against `frame` in software. See the
    /// `Runtime interpreter` section below for behaviour on
    /// unknown opcodes (fail-closed, no panics).
    pub fn matches(&self, frame: &[u8]) -> bool;

    /// Pre-existing accessor, unchanged.
    pub fn instructions(&self) -> &[BpfInsn];
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    #[error("conflicting protocol fragments: {a:?} and {b:?}")]
    ConflictingProtocols { a: &'static str, b: &'static str },

    #[error("filter exceeds {} instructions (kernel BPF_MAXINSNS limit)", BpfFilter::MAX_INSNS)]
    TooManyInstructions { count: usize },

    #[error("port out of range: {0}")]
    PortOutOfRange(u32),

    #[error("invalid IP prefix length: {0} (max 32 for IPv4, 128 for IPv6)")]
    InvalidPrefix(u8),

    #[error("ipv6 + extension headers not supported by builder; use BpfFilter::new")]
    Ipv6ExtHeader,

    #[error("OR of zero branches")]
    EmptyOr,
}
```

### Builder methods

```rust
impl BpfFilterBuilder {
    /// Empty builder (matches every packet).
    pub fn new() -> Self;

    // ── ethertype / link layer ──────────────────────────────
    pub fn eth_type(self, ty: u16) -> Self;
    pub fn ipv4(self) -> Self;        // eth_type(0x0800)
    pub fn ipv6(self) -> Self;        // eth_type(0x86dd)
    pub fn arp(self) -> Self;         // eth_type(0x0806)
    pub fn vlan(self) -> Self;        // eth_type(0x8100), shifts subsequent offsets +4

    // ── IP-layer ────────────────────────────────────────────
    pub fn ip_proto(self, proto: u8) -> Self;
    pub fn tcp(self) -> Self;         // ip_proto(6) + ipv4 (or ipv6 chain via .ipv6().tcp())
    pub fn udp(self) -> Self;         // ip_proto(17)
    pub fn icmp(self) -> Self;        // ip_proto(1) (IPv4 only; ICMPv6 = ip_proto(58))

    pub fn src_host(self, addr: IpAddr) -> Self;
    pub fn dst_host(self, addr: IpAddr) -> Self;
    pub fn host(self, addr: IpAddr) -> Self;       // src OR dst

    pub fn src_net(self, net: IpNet) -> Self;
    pub fn dst_net(self, net: IpNet) -> Self;
    pub fn net(self, net: IpNet) -> Self;

    // ── L4 ports (TCP/UDP) ──────────────────────────────────
    pub fn src_port(self, port: u16) -> Self;
    pub fn dst_port(self, port: u16) -> Self;
    pub fn port(self, port: u16) -> Self;          // src OR dst

    // ── VLAN id (only meaningful after .vlan()) ─────────────
    pub fn vlan_id(self, id: u16) -> Self;

    // ── composition ─────────────────────────────────────────
    /// Negate the entire builder so far.
    pub fn negate(self) -> Self;

    /// Compose with another sub-filter via OR.
    /// Either branch can match independently.
    pub fn or(self, build: impl FnOnce(BpfFilterBuilder) -> BpfFilterBuilder) -> Self;

    /// Compile + validate. Returns the filter or a BuildError.
    pub fn build(self) -> Result<BpfFilter, BuildError>;
}
```

The chained `mut self` form matches netring's existing
`CaptureBuilder` / `XdpSocketBuilder` / `InjectorBuilder` style.

### Convenience FromStr for IpNet

```rust
impl FromStr for IpNet {
    type Err = ParseIpNetError;
    /// Parses `"10.0.0.0/24"`, `"2001:db8::/32"`, or a bare IP
    /// (defaults to /32 for v4, /128 for v6).
    fn from_str(s: &str) -> Result<Self, Self::Err>;
}
```

### Examples — golden user-facing

```rust
// "tcp dst port 80"
let f = BpfFilter::builder().tcp().dst_port(80).build()?;

// "host 10.0.0.1 and tcp"
let f = BpfFilter::builder().tcp().host([10,0,0,1].into()).build()?;

// "tcp port 80 or udp port 53"
let f = BpfFilter::builder()
    .tcp().port(80)
    .or(|b| b.udp().port(53))
    .build()?;

// "vlan and tcp port 443"
let f = BpfFilter::builder().vlan().tcp().port(443).build()?;

// "not arp"
let f = BpfFilter::builder().arp().negate().build()?;
```

---

## Internal design

### 1. Fragment IR

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
enum MatchFrag {
    EthType(u16),
    Vlan,                     // marker — adjusts offsets by +4
    VlanId(u16),
    IpProto(u8),
    SrcHost(IpAddr),
    DstHost(IpAddr),
    AnyHost(IpAddr),
    SrcNet(IpNet),
    DstNet(IpNet),
    AnyNet(IpNet),
    SrcPort(u16),             // TCP/UDP — IpProto must precede or be inferred
    DstPort(u16),
    AnyPort(u16),
}

pub struct BpfFilterBuilder {
    fragments: Vec<MatchFrag>,
    or_branches: Vec<BpfFilterBuilder>,   // for `.or(...)` composition
    negated: bool,
}
```

### 2. Symbolic labels

To compose fragments without managing relative jump offsets by
hand, each fragment emits **symbolic** instructions. A final pass
resolves labels to numeric offsets.

```rust
#[derive(Debug, Clone, Copy)]
enum Label {
    /// Next instruction (fall through). Used for AND chaining.
    Fallthrough,
    /// Global accept tail.
    Accept,
    /// Global drop tail.
    Drop,
    /// Numbered branch — used by OR composition. The resolver
    /// computes its position once all fragments are emitted.
    Branch(BranchId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BranchId(u32);

#[derive(Debug, Clone)]
struct SymInsn {
    code: u16,
    /// Resolved by the linker. For non-jump instructions, both
    /// fields are `Fallthrough`.
    jt: Label,
    jf: Label,
    k: u32,
}
```

The linker (`bpf_compile::resolve`) walks the symbolic stream
once, computes label positions, then emits real `BpfInsn`s with
8-bit relative `jt`/`jf`. cBPF jumps are *forward-only* (kernel
verifier rejects backward jumps), so the linker must emit
fragments in topological order. The fragment templates below all
respect this.

### 3. Compiler pipeline

```
BpfFilterBuilder
   │
   ▼
normalize_fragments()           — sort + dedupe MatchFrag entries so
                                  user's chain order doesn't matter for AND;
                                  detect conflicts (e.g. tcp + udp without OR)
   │
   ▼
compile_and_chain()             — emit per-fragment SymInsn vectors
                                  with Fallthrough on success and Drop on failure
   │   (or for each OR branch independently, emit with Accept/next-branch instead)
   ▼
link_branches()                 — concatenate AND chain with OR branches:
                                  AND chain first, OR branches each labelled,
                                  global accept/drop tails appended
   │
   ▼
resolve_labels()                — first pass: walk symbolic stream computing
                                  positions; second pass: rewrite each jump's
                                  jt/jf to relative offsets
   │
   ▼
validate()                      — assert len ≤ 4096; check no out-of-range
                                  jumps (jt/jf fit in u8 — i.e. forward jump
                                  distance ≤ 255 instructions)
   │
   ▼
Vec<BpfInsn>  →  BpfFilter
```

### 4. AND vs OR

**AND** (default): each fragment falls through on success, jumps
to `Drop` on failure. All fragments together; final
`ret #65535` (accept) tail.

```
[fragment 1]  ; success → fall through; failure → Drop
[fragment 2]  ; same
[fragment N]  ; same
ret #65535    ; Accept tail (all fragments matched)
ret #0        ; Drop tail
```

**OR**: each branch ends with `ret #65535` on success; failure
falls through to the next branch. The last branch's failure
reaches the global `Drop`.

```
[branch 1 fragments]  ; success → Accept; failure → branch 2 start
ret #65535            ; Accept tail (used by branch 1)
[branch 2 fragments]  ; success → Accept; failure → branch 3 (or Drop)
ret #65535            ; Accept tail (used by branch 2)
...
ret #0                ; Drop tail
```

The `Accept` tail is shared via the resolver — there's only one
in the final program. Each branch's success target points to it.

**NOT** (negation of the whole builder): swap `Accept` and `Drop`
in the resolver. The fragment templates don't change.

### 5. VLAN handling

When `MatchFrag::Vlan` appears in the AND chain, all subsequent
loads use `+4` offsets:
- ethertype check moves from `[12]` to `[16]` (inner ethertype)
- IP fields shift: proto byte at `[14+9+4] = [27]` instead of `[23]`
- Frag check at `[20+4] = [24]`
- IHL load: `4*([14+4]&0xf) = 4*([18]&0xf)`
- L4 port load: `[x + 14+4] = [x + 18]` for src, `[x + 20]` for dst

Implementation: `BpfFilterBuilder` carries an `vlan_offset: u8`
(0 or 4). Set to 4 when `.vlan()` is in the fragment list.
Fragment compilers add `vlan_offset` to all base offsets.

Q-in-Q (`.vlan().vlan()`) is rejected with a `BuildError`. Users
who need it use `BpfFilter::new`.

### 6. IPv6 path

`.ipv6()` sets a flag that fragments consult to emit IPv6
bytecode templates instead of IPv4. The IPv4 and IPv6 templates
are disjoint — there's no single bytecode that matches both.

If the user wants "TCP on either v4 or v6":

```rust
BpfFilter::builder()
    .ipv4().tcp().port(80)
    .or(|b| b.ipv6().tcp().port(80))
    .build()?
```

The OR composition produces two parallel branches; second branch
checks ethertype 0x86dd, loads next-header from `[20]`, checks 6,
loads ports from `[14 + 40 + 0]` = `[54]` and `[14 + 40 + 2]` =
`[56]`. No IHL trick needed for IPv6 (fixed 40-byte header).

If `.ipv6()` is followed by `MatchFrag::SrcPort` or similar **and
no extension headers are guaranteed absent**, we emit a check
against `next_header == 6` (TCP) or `17` (UDP). If next-header is
anything else (Hop-by-Hop, Routing, Fragment, ESP, AH, etc.), the
filter rejects the packet. Document this loudly: it's *correct*
fail-closed behaviour for the common case but won't match
TCP-after-extensions traffic.

### 7. Conflict detection

`normalize_fragments()` rejects:

- `.tcp().udp()` without OR — both protocols in one AND chain,
  packet can't be both. Returns `BuildError::ConflictingProtocols`.
- `.ipv4().ipv6()` — same reason.
- Different `ip_proto(N)` values in one AND chain.
- `.eth_type(A).eth_type(B)` with `A != B`.
- More than one `.vlan()` (Q-in-Q is out of scope).

Same-value duplicates are silently deduplicated:

- `.tcp().tcp()` → one TCP check.
- `.dst_port(80).dst_port(80)` → one check.

---

## Per-fragment bytecode templates

Each template is annotated with the symbolic label it jumps to
on failure (`Drop`) and on success (`Fallthrough`). Where two
fragments are bundled (e.g. `tcp` = ethtype + ip_proto), the
template comment shows it.

All templates assume `vlan_offset` is folded into the constants
shown. With `.vlan()`, add 4 to every offset in the IP / L4
sections.

### `eth_type(N)`

```
ldh   [12]                   ; load ethertype
jeq   #N, fall, Drop         ; if ethertype != N, drop
```

2 instructions.

### `vlan` (marker)

The marker compiles to the same `eth_type(0x8100)` bytecode and
sets `vlan_offset = 4` for subsequent fragments. Adds 2
instructions to the program.

### `ip_proto(P)` — IPv4 path

```
ldb   [23]                   ; IP proto byte (Ethernet 14 + IP offset 9)
jeq   #P, fall, Drop
```

2 instructions. Assumes ethertype IPv4 was already verified by a
preceding `eth_type(0x0800)` fragment. The normaliser inserts
`eth_type(0x0800)` automatically if `ip_proto` appears without it.

### `ip_proto(P)` — IPv6 path

```
ldb   [20]                   ; IPv6 next-header (Ethernet 14 + IPv6 offset 6)
jeq   #P, fall, Drop
```

Note: this only matches packets without extension headers. If
the IPv6 packet uses Hop-by-Hop, Routing, etc., next-header at
`[20]` is the extension type (not the L4 proto). Documented gap.

### `src_host(IPv4)` and `dst_host(IPv4)`

```
ld    [26]                   ; src IP (offset 14 + 12)
jeq   #addr, fall, Drop
```

For `dst_host` use offset `[30]`. 2 instructions.

### `host(IPv4)` — src OR dst

```
ld    [26]                   ; src IP
jeq   #addr, fall, check_dst ; if src matches, fall to next AND fragment
ld    [30]                   ; dst IP
jeq   #addr, fall, Drop
```

4 instructions.

### `src_net(IPv4 + prefix)` and friends

```
ld    [26]                   ; src IP
and   #mask                  ; mask = !0 << (32 - prefix); top bits only
jeq   #addr, fall, Drop      ; addr already pre-masked
```

3 instructions for src-or-dst-only; 6 for `any_net` (two parallel
load+mask+jeq).

### `dst_port(P)` (TCP or UDP after `ip_proto` set)

This is the trickiest fragment. Composition:

```
ldh   [20]                   ; flags + frag offset
jset  #0x1fff, Drop, fall    ; if fragment, drop (ports only valid in 1st)
ldxb  4*([14]&0xf)           ; X = IPv4 IHL * 4
ldh   [x + 16]               ; dst port (Ethernet 14 + IHL X + L4 offset 2)
jeq   #P, fall, Drop
```

5 instructions. For IPv6, no IHL trick:

```
ldh   [56]                   ; dst port at fixed offset (Ethernet 14 + IPv6 40 + 2)
jeq   #P, fall, Drop
```

2 instructions.

### `src_port(P)` — same shape, port at offset 14 (IPv4) or 54 (IPv6).

### `port(P)` — src OR dst

```
ldh   [20]                   ; flags + frag
jset  #0x1fff, Drop, fall
ldxb  4*([14]&0xf)
ldh   [x + 14]               ; src port
jeq   #P, Accept, fall       ; if src matches, accept right away
ldh   [x + 16]               ; dst port
jeq   #P, fall, Drop
```

7 instructions. The early-`Accept` jump saves emitting two
parallel paths.

### `vlan_id(id)`

After `.vlan()`, the VLAN tag's TCI is at `[14]`:

```
ldh   [14]                   ; VLAN TCI
and   #0x0fff                ; low 12 bits = VLAN id
jeq   #id, fall, Drop
```

3 instructions.

---

## Validation

`build()` runs four checks:

1. **Empty AND with no OR** → returns the trivial all-accept
   filter (`ret #65535`). Documented as "matches every packet."
2. **Fragment conflicts** → `BuildError::ConflictingProtocols`.
3. **Instruction count** → `BuildError::TooManyInstructions` if
   final length > 4096.
4. **Jump distance** → if any resolved `jt`/`jf` overflows `u8`
   (forward distance > 255), surface `BuildError`. This is
   primarily a guard against malformed compiler output; for the
   vocabulary above we never produce > ~30 instructions per
   fragment, so the limit isn't reachable in practice.

`BpfFilter::new(Vec<BpfInsn>)` (the escape hatch) gains the same
length check (4096) and returns `Result<Self, BuildError>`. This
is a tiny breaking change but the error type is new — almost no
users construct from `Vec` directly.

---

## Runtime interpreter (`matches`)

A small cBPF interpreter for unit tests and for downstream
crates that want to verify their filters without spinning up an
AF_PACKET socket.

```rust
impl BpfFilter {
    /// Run this filter against `frame` in software. Returns true
    /// iff the program would `ret #non-zero` (i.e. the kernel
    /// would deliver this packet to userspace).
    ///
    /// Out-of-bounds loads, instruction-counter overruns, and
    /// opcodes outside the supported subset are treated as
    /// fail-closed (returns `false`) — this mirrors what the
    /// kernel verifier does at `setsockopt(SO_ATTACH_FILTER)`
    /// time: an unknown opcode means the program never runs in
    /// the first place.
    ///
    /// The supported opcode subset is exactly what
    /// `BpfFilter::builder()` emits, plus the parser-layer ALU
    /// instructions enumerated below. Hand-rolled programs from
    /// `BpfFilter::new` that use opcodes outside this set will
    /// match nothing under `matches()`; the kernel remains the
    /// source of truth for those.
    pub fn matches(&self, frame: &[u8]) -> bool {
        // Walk instructions; maintain (A: u32, X: u32, pc: usize).
        // Match opcode → operation. Supported opcodes:
        //   BPF_LD  | BPF_W | BPF_ABS    (0x20)
        //   BPF_LD  | BPF_H | BPF_ABS    (0x28)
        //   BPF_LD  | BPF_B | BPF_ABS    (0x30)
        //   BPF_LD  | BPF_W | BPF_IND    (0x40)
        //   BPF_LD  | BPF_H | BPF_IND    (0x48)
        //   BPF_LDX | BPF_B | BPF_MSH    (0xb1)   ← 4*([k]&0xf) helper
        //   BPF_ALU | BPF_AND | BPF_K    (0x54)
        //   BPF_JMP | BPF_JEQ | BPF_K    (0x15)
        //   BPF_JMP | BPF_JGT | BPF_K    (0x25)
        //   BPF_JMP | BPF_JSET | BPF_K   (0x45)
        //   BPF_JMP | BPF_JA             (0x05)
        //   BPF_RET | BPF_K              (0x06)
        //
        // Anything else → fall through to the unknown-opcode
        // branch, return false. No panics, no Result, no errors:
        // an interpretation that can't be done correctly is the
        // same as a "drop" verdict. Same shape as kernel reject.
    }
}
```

~150 LOC, no `unsafe`, no allocations, no panics on any input.

Behaviour rationale: the interpreter is a **testing aid**, not a
verifier. The kernel is the source of truth for whether a filter
runs and what it returns. The interpreter exists so downstream
crates can write `assert!(filter.matches(&frame))` in unit tests
without binding an AF_PACKET socket. If a hand-rolled program
contains opcodes the interpreter doesn't know, the kernel still
runs it correctly; only the local assertion misbehaves
(fail-closed). Documented in the rustdoc.

---

## Implementation steps

### Phase A — IR + IpNet

1. Convert `netring/src/config.rs` to `netring/src/config/mod.rs`
   directory module. Preserve every public path (`netring::BpfFilter`,
   etc.) via `pub use`.
2. Move existing `BpfInsn` / `BpfFilter` types to
   `netring/src/config/bpf.rs`.
3. Add `netring/src/config/ipnet.rs` — `IpNet` struct + `FromStr`
   + tests. ~70 LOC.
4. Add `netring/src/config/bpf_builder.rs` skeleton — empty
   `BpfFilterBuilder`, `MatchFrag` enum, no-op `build()`.
5. Verify `cargo build`, `cargo test`. No behaviour change yet.

### Phase B — symbolic compiler

6. Add `bpf_compile.rs` — `Label`, `SymInsn`, `compile_fragment()`,
   `resolve_labels()`. Per-fragment templates one at a time, each
   with an inline tcpdump-equivalent comment.
7. Wire `BpfFilterBuilder::build()` to call the compiler. Empty
   builder produces `ret #65535` only.
8. AND chain compilation. Test against `tcp`, `udp`, `ip_proto(N)`,
   `host`, etc.
9. OR composition. Test against `tcp port 80 or udp port 53`.
10. NOT (`negate()`). Test against `not arp`.

### Phase C — VLAN + IPv6

11. `MatchFrag::Vlan` marker + offset-shift in fragment compiler.
    Test `vlan and tcp port 80`.
12. IPv6 path. `MatchFrag::EthType(0x86dd)` triggers IPv6
    templates. Test `ipv6 and tcp port 80`.

### Phase D — runtime interpreter

13. `bpf_interp.rs` — `BpfFilter::matches(&[u8]) -> bool`.
14. Synth-packet helpers in tests (`tests/bpf_builder_match.rs`):
    `synth_eth_ip_tcp(...)`, `synth_eth_ip_udp(...)`,
    `synth_eth_vlan_ip_tcp(...)`, `synth_eth_ipv6_tcp(...)`.

### Phase E — golden tests

15. Generate reference bytecode with `tcpdump -dd "<expr>"` for
    each test in §11; commit as text files under
    `tests/fixtures/bpf/`. Document the tcpdump version
    in `tests/fixtures/bpf/README.md` so a future regen can
    reproduce.
16. `tests/bpf_builder_golden.rs` — read each fixture, parse the
    `{ 0xCC, jt, jf, 0xKKKK }` array, run the builder for the
    same expression, byte-for-byte assert.

### Phase F — proptest invariants

17. `tests/bpf_builder_proptest.rs` — for each (random valid
    fragment combination):
    - Builder doesn't panic.
    - Output instruction count > 0.
    - Output passes the same packets as a hand-coded reference for
      a small, exhaustive packet set.
    - AND-of-(A, B) accepts the intersection of (A accepts, B
      accepts).
    - OR-of-(A, B) accepts the union.
    - `negate(F)` accepts ⌐F.
    - `negate(negate(F))` accepts the same set as F.

### Phase G — docs + examples + migration

18. `netring/examples/bpf_filter.rs` — a demo that opens a Capture
    on `lo`, applies a typed filter, prints what survives.
19. Update `BpfFilter` rustdoc to lead with the builder and
    demote the tcpdump path to "advanced / escape hatch".
20. Update `README.md` Filter section.
21. `CHANGELOG.md` 0.x.0 entry.
22. `plans/INDEX.md` — register plan 18 as ✅ done.
23. Notify the nlink-lab team (per their proposal §8) that
    netring 0.x is shipped.

---

## Tests

### Unit (no privileges, no kernel)

- `IpNet::from_str` round-trips for IPv4 / IPv6 addresses with
  and without prefix.
- `IpNet::from_str` rejects malformed input
  (`"10.0.0.0/33"`, `"::/129"`, `"foo"`).
- `MatchFrag` normalisation: dedup, sort, conflict detection.
- Each fragment template emits the expected SymInsn count.
- Resolver: `Label` → numeric jump offsets, including jump-back
  detection (must error, kernel rejects backward jumps).

### Golden bytecode (tests/bpf_builder_golden.rs)

For each expression, run `BpfFilter::builder()...build()` and
assert the resulting `Vec<BpfInsn>` is byte-for-byte identical to
the tcpdump reference (committed under `tests/fixtures/bpf/`).
Coverage:

| Expression | tcpdump command | Fixture |
|---|---|---|
| `tcp` | `tcpdump -dd "tcp"` | `tcp.txt` |
| `udp` | `tcpdump -dd "udp"` | `udp.txt` |
| `arp` | `tcpdump -dd "arp"` | `arp.txt` |
| `tcp dst port 80` | `tcpdump -dd "tcp and dst port 80"` | `tcp_dst_port_80.txt` |
| `udp port 53` | `tcpdump -dd "udp and port 53"` | `udp_port_53.txt` |
| `host 10.0.0.1` | `tcpdump -dd "host 10.0.0.1"` | `host_10_0_0_1.txt` |
| `tcp port 80 or udp port 53` | `tcpdump -dd "(tcp port 80) or (udp port 53)"` | `tcp_or_udp.txt` |
| `vlan and tcp port 80` | `tcpdump -dd "vlan and tcp port 80"` | `vlan_tcp_port_80.txt` |
| `ip6 and tcp` | `tcpdump -dd "ip6 and tcp"` | `ipv6_tcp.txt` |
| `not arp` | `tcpdump -dd "not arp"` | `not_arp.txt` |

Locked tcpdump version: `tcpdump 4.99.x` (libpcap 1.10.x). Newer
versions occasionally tweak emission patterns; test fixtures lock
us to a stable reference. README in `tests/fixtures/bpf/`
documents how to regenerate and what to check after a libpcap
bump.

### Runtime / interpreter (tests/bpf_builder_match.rs)

For each expression, build the filter, then run `matches()` on
~10 synthetic packets per expression covering accept and reject
cases:

- `tcp dst port 80` accepts a TCP/IPv4 frame with dst port 80.
- Same filter rejects a TCP/IPv4 frame with dst port 443.
- Same filter rejects a UDP/IPv4 frame with dst port 80.
- `vlan and tcp port 80` accepts a VLAN-tagged TCP/IPv4 frame.
- Same filter rejects an unwrapped TCP/IPv4 frame with the same
  ports (no VLAN tag).
- IPv4 fragment (frag offset != 0) is rejected by any port-based
  filter.
- IPv6 + TCP + dst port: accepts a synthetic IPv6/TCP frame.
- `not arp` accepts non-ARP frames, rejects ARP.

### Property tests (tests/bpf_builder_proptest.rs)

10 properties × 256 cases each (256 = proptest default; bump via
`PROPTEST_CASES` env for stress runs):

1. Builder doesn't panic on any random valid sequence of
   fragments.
2. Output instruction count is bounded by `4 * fragment_count + 8`
   (rough upper bound — interpreter validates exact, this is a
   sanity ceiling).
3. `build()` is idempotent: building the same fragment list twice
   produces identical `Vec<BpfInsn>`.
4. Empty builder accepts every random packet.
5. `negate(F)` accepts a packet iff `F` rejects it (for the
   exhaustive synthetic packet set).
6. `F.or(G)` accepts a packet iff `F` accepts OR `G` accepts.
7. AND-of-(F, G) accepts iff F accepts AND G accepts.
8. Adding a fragment never increases the matched packet set
   (monotonic narrowing).
9. Random VLAN sequences with `.vlan()` always emit valid
   bytecode and the offsets shift correctly (verified by feeding
   VLAN-tagged synthetic frames).
10. `BpfFilter::new(builder.instructions().to_vec())` round-trips
    (escape hatch consumes builder output cleanly).

---

## Acceptance criteria

- [ ] `BpfFilter::builder().tcp().dst_port(80).build()` produces
      a working filter, byte-for-byte matching `tcpdump -dd "tcp
      and dst port 80"`.
- [ ] All 10 golden tests pass.
- [ ] All 10 proptest invariants pass at 256 cases each.
- [ ] Runtime interpreter accepts/rejects all synthetic test
      cases correctly.
- [ ] `BpfFilter::new(Vec<BpfInsn>)` still works (escape hatch
      preserved); now returns `Result` for length validation.
- [ ] Existing `Capture::builder().bpf_filter(...)` callers
      compile unchanged.
- [ ] No new external dependencies added to `Cargo.toml`.
- [ ] CHANGELOG entry, README example, doc rewrite of
      `BpfFilter`.
- [ ] `cargo doc --no-deps` clean (zero warnings, no broken intra-
      doc links).
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
      clean.

---

## Risks

1. **OR composition jump-offset relocation.** The trickiest
   compiler bug surface. Mitigation: symbolic-label IR + linker
   pass (covered in §3). Proptest invariant 6 (OR semantics)
   catches regressions.
2. **VLAN offset arithmetic off-by-N.** Easy to miscount the +4
   shift across multiple fragments. Mitigation: the
   `vlan_offset` field is added consistently in fragment
   compilers; golden test for `vlan and tcp port 80` catches
   any drift.
3. **IPv6 extension headers silently mismatch.** Documented as a
   known gap; failing closed (no match) is the safer behaviour.
   The plan ships test packets with extension headers
   demonstrating the rejection.
4. **tcpdump-version drift in golden fixtures.** Mitigation:
   commit fixtures, document version in README. On libpcap
   updates, re-run regeneration script and review the diff.
5. **`BpfFilter::new` becoming `Result` is technically breaking.**
   Mitigation: the existing path through
   `Capture::builder().bpf_filter(BpfFilter::new(insns))` was
   already wrapping in a `Result` higher up; downstream typically
   `?`-propagates from `Capture::build`. Audit pre-publish.
6. **8-bit relative jump distance overflow.** With OR composition
   over many branches the forward jump from the first branch's
   "fail → next" can exceed 255 instructions. Mitigation:
   surface `BuildError::JumpTooFar` with a clear message
   pointing the user at AND chain re-ordering or
   `BpfFilter::new`. Realistic vocabulary keeps us well below the
   limit, but the check is cheap.

---

## Effort

- IpNet: ~70 LOC (incl. tests).
- Builder + IR: ~250 LOC.
- Compiler + linker + per-fragment templates: ~350 LOC.
- Runtime interpreter: ~150 LOC.
- Golden tests + 10 fixtures: ~250 LOC + 10 small text files.
- Match-driven tests: ~150 LOC.
- Proptest invariants: ~100 LOC.
- Example: ~80 LOC.
- Documentation (README, BpfFilter rustdoc, CLAUDE.md, CHANGELOG):
  ~200 LOC.
- **Total**: ~1600 LOC.
- **Time**: 3–4 days, dominated by golden-test fixture
  generation + the OR/jump-relocation correctness pass.

---

## Migration path for downstream consumers

For nlink-lab specifically (per proposal §8):

```diff
  // crates/nlink-lab/src/capture.rs
- pub fn compile_bpf_filter(expr: &str) -> Result<Vec<BpfInsn>, Error> {
-     let out = Command::new("tcpdump")
-         .args(["-dd", expr])
-         .output()?;
-     // … parse `{ 0xNN, x, y, 0xKKKK }` lines …
- }

+ pub fn compile_bpf_filter(filter: &Filter) -> Result<BpfFilter, Error> {
+     let mut b = BpfFilter::builder();
+     match filter {
+         Filter::Tcp { port } => b = b.tcp().port(*port),
+         Filter::Udp { port } => b = b.udp().port(*port),
+         Filter::Host(addr) => b = b.host(*addr),
+         // …
+     }
+     b.build().map_err(Into::into)
+ }
```

Other downstream paths (any consumer that calls
`Capture::builder().bpf_filter(...)`):

- If they already used `BpfFilter::new(tcpdump_dd_output)`, they
  can continue. The escape hatch stays.
- If they called `BpfFilter::new(...)` and want to switch, the
  builder vocabulary covers their case 9 times in 10. Show the
  decision flow in the new docs:

```text
Want to filter packets?

  ┌─ Common case (TCP/UDP/ARP/IP/host/port/net/VLAN)?
  │      → BpfFilter::builder()...build()
  │
  ├─ Need libpcap grammar (slice notation, complex composition)?
  │      → run tcpdump -dd in your build script, paste into
  │        BpfFilter::new(vec![...])
  │
  └─ Need stateful matching (TCP flags, payload regex, conntrack)?
         → use eBPF via `aya` and attach via `attach_ebpf_filter`
```

Documented in the rewritten `BpfFilter` rustdoc.

---

## Out of scope / follow-ups

- **eBPF emitter (`BpfFilter::compile_ebpf()`).** Different
  bytecode, different constraints, different verifier. If anyone
  asks, do it as a separate plan; no shared compiler logic.
- **`bpf-builder` macro.** A `bpf_filter!()` proc-macro for
  literal-friendly construction. Not needed; the chained builder
  is short enough.
- **Filter combinators on the tracker.**
  `FlowTracker::with_filter(builder)` to filter at the tracker
  layer rather than the kernel. Different problem (kernel filters
  cap kernel→userspace bandwidth; tracker filters cap CPU).
  Separate plan if it ever surfaces.
- **JIT pre-validation.** Linux kernel JITs cBPF on x86_64 and
  arm64 if `net.core.bpf_jit_enable=1`. Pre-validating that our
  output passes the in-kernel verifier would require either a
  kernel-side test harness or a pure-Rust verifier port. Out of
  scope.

---

## Sources

- [BPF Instruction Set Architecture (Linux kernel docs)][isa]
- [Linux Socket Filtering aka Berkeley Packet Filter (BPF)][filter]
- [RFC 9669 — BPF Instruction Set Architecture][rfc9669]
- [`include/uapi/linux/filter.h`][hdr] (kernel UAPI for opcode
  constants)
- tcpdump 4.99.x manual (`-d` / `-dd` flags)
- Proposal: `plans/156a-netring-bpf-builder-proposal.md`
- nlink-lab call site documented in proposal §10

[isa]: https://docs.kernel.org/bpf/standardization/instruction-set.html
[filter]: https://www.kernel.org/doc/html/latest/networking/filter.html
[rfc9669]: https://www.rfc-editor.org/rfc/rfc9669.html
[hdr]: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/filter.h
