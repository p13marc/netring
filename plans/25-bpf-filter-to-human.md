# Plan 25 — `BpfFilter::to_human()` — pcap-filter-style display

## Summary

Add a `Display` impl on `BpfFilter` (and the equivalent
`to_human() -> String` shortcut) that renders the compiled filter
as a canonical pcap-filter expression: `"tcp and (port 443 or port 80)"`
etc. Powers operator tooling like `simple-nms diag filter` that
needs to print "the filter the agent is actually running" without
re-reading the source TOML.

Closes simple-nms wishlist item **N1.6**.

This requires storing the builder's `MatchFrag` IR on `BpfFilter`
alongside the compiled bytecode — the compiled bytecode alone is
too lossy to disassemble.

## Status

Done — landed in 0.15.0 (rode with plan 24).

## Prerequisites

- Plan 18 (`BpfFilter::builder()` + the `MatchFrag` IR + the
  symbolic-IR compiler) — shipped in 0.11.0.

## Out of scope

- **Bytecode disassembly for filters constructed via
  `BpfFilter::new(insns)`** (the raw-bytecode escape hatch). When
  there's no builder-side IR, `to_human()` returns
  `"<raw bytecode, N instructions>"`. Disassembling cBPF into pcap
  expressions is a different (and harder) problem; not in scope.
- **Round-trip parsing** (`BpfFilter::from_human(&str)`). Parsing
  pcap-filter expressions is what libpcap's `pcap_compile()` does;
  reproducing it in pure Rust is out of scope. The escape hatch is
  the typed builder.
- **Variant matching with libpcap's actual output** (no `pcap_compile()`
  round-trip equivalence). We render a canonical form per the
  pcap-filter(7) grammar; we don't promise byte-identical
  matches with `tcpdump -dd` output.

---

## Background — design

### Why the IR has to ride along on `BpfFilter`

Today:

```
BpfFilterBuilder::build() -> BpfFilter { insns: Vec<BpfInsn> }
```

The builder's `fragments: Vec<MatchFrag>` / `or_branches: Vec<BpfFilterBuilder>`
/ `negated: bool` IR is dropped during `build()`. To rebuild a
human-readable expression from `Vec<BpfInsn>` would mean writing
a cBPF disassembler that *also* understands the symbolic structure
the compiler emitted — possible but lossy and out of scope.

Cleanest answer: store the IR alongside the bytecode.

```rust
pub struct BpfFilter {
    insns: Vec<BpfInsn>,
    source: Option<BpfFilterIr>,   // NEW — None for raw-bytecode users
}

#[derive(Debug, Clone)]
pub(crate) struct BpfFilterIr {
    fragments: Vec<MatchFrag>,
    or_branches: Vec<BpfFilterIr>,
    negated: bool,
}
```

`BpfFilterBuilder::build()` captures itself into the `Option<BpfFilterIr>`.
`BpfFilter::new(insns)` (raw bytecode) leaves it `None`. `to_human()`
checks `self.source` and either renders or returns the fallback.

Pattern matches what `regex::Regex` does (stores the source string
alongside the NFA/DFA for `Debug` and pattern access).

### Why `MatchFrag` must become `pub` (or `pub use`-able)

The IR struct holds `Vec<MatchFrag>`. If `BpfFilterIr` is
`pub(crate)`, fine. But `BpfFilter::to_human` is a method on a
`pub` type, so the IR must at least be `pub(crate)`-reachable —
which it already is.

`MatchFrag` itself can stay `pub(crate)`. Plan 25 doesn't expose
it.

### Why we emit canonical pcap-filter syntax (not custom)

The simple-nms operator workflow is `diag filter` → human reads the
expression → optionally pastes into `tcpdump -i lo <expr>`. Standard
pcap-filter(7) syntax is the obvious target — operators already
know it, and it round-trips through `tcpdump -d "<expr>"` for
verification. Per the
[pcap-filter(7) man page](https://www.tcpdump.org/manpages/pcap-filter.7.html),
the grammar uses primitives (`host`, `net`, `port`, `portrange`)
preceded by qualifiers (`src`, `dst`) and combined with `and` / `or`
/ `not`.

### MatchFrag → pcap-filter token mapping

| `MatchFrag` | pcap-filter output |
|---|---|
| `EthType(0x0800)` | `ip` |
| `EthType(0x86DD)` | `ip6` |
| `EthType(0x0806)` | `arp` |
| `EthType(other)` | `ether proto 0xNNNN` |
| `Vlan` | `vlan` |
| `VlanId(id)` | `vlan {id}` |
| `IpProto(6)` | `tcp` |
| `IpProto(17)` | `udp` |
| `IpProto(1)` | `icmp` |
| `IpProto(58)` | `icmp6` |
| `IpProto(n)` | `ip proto {n}` |
| `SrcHost(addr)` | `src host {addr}` |
| `DstHost(addr)` | `dst host {addr}` |
| `AnyHost(addr)` | `host {addr}` |
| `SrcNet(net)` | `src net {addr}/{prefix}` |
| `DstNet(net)` | `dst net {addr}/{prefix}` |
| `AnyNet(net)` | `net {addr}/{prefix}` |
| `SrcPort(port)` | `src port {port}` |
| `DstPort(port)` | `dst port {port}` |
| `AnyPort(port)` | `port {port}` |

Fragments in the same builder join with ` and `. OR branches join
with ` or `, each branch wrapped in parens if it contains more than
one fragment. `negated` prefixes with `not `, wrapping in parens if
the body is composite.

Edge cases:
- Empty builder (no fragments, no OR branches): `""` (empty
  string, meaning "match all" in pcap-filter).
- Single-fragment OR branch: bare — no parens. `tcp or udp` not
  `(tcp) or (udp)`.
- `negated` on a single fragment: `not tcp` not `not (tcp)`.

---

## Files

### MODIFY

```
netring/netring/src/config/bpf.rs                    (BpfFilter::source field + Display + to_human)
netring/netring/src/config/bpf_builder.rs            (BpfFilterIr type + build() captures it)
netring/netring/src/config/bpf_humanize.rs           (NEW — IR-to-string renderer)
netring/netring/src/config/mod.rs                    (mod bpf_humanize)
netring/CHANGELOG.md
```

### NEW

```
netring/netring/tests/bpf_humanize_roundtrip.rs      (corpus-driven test)
```

No public type changes except the new `Display` impl + accessor.

---

## API delta

### `Display` + `to_human` on `BpfFilter`

```rust
// netring/src/config/bpf.rs

impl std::fmt::Display for BpfFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            Some(ir) => crate::config::bpf_humanize::render(ir, f),
            None => write!(
                f,
                "<raw bytecode, {} instructions>",
                self.insns.len()
            ),
        }
    }
}

impl BpfFilter {
    /// Render the filter as a canonical pcap-filter expression
    /// (e.g. `"tcp and (port 443 or port 80)"`). For filters
    /// constructed via [`BpfFilter::new`] with raw bytecode,
    /// returns `"<raw bytecode, N instructions>"` since the
    /// symbolic IR is unavailable.
    ///
    /// Best-effort: the output is guaranteed to be a syntactically
    /// valid pcap-filter expression when constructed via the
    /// builder; no claim of byte-identical match with libpcap's
    /// `tcpdump -dd` output.
    pub fn to_human(&self) -> String {
        format!("{self}")
    }
}
```

### `BpfFilterIr` — new internal type

```rust
// netring/src/config/bpf_builder.rs

/// Symbolic source of a compiled [`BpfFilter`]. Captured during
/// `BpfFilterBuilder::build()` and stored on the resulting
/// `BpfFilter` so [`BpfFilter::to_human`] can render a
/// pcap-filter-style expression post-compile.
#[derive(Debug, Clone)]
pub(crate) struct BpfFilterIr {
    pub(crate) fragments: Vec<MatchFrag>,
    pub(crate) or_branches: Vec<BpfFilterIr>,
    pub(crate) negated: bool,
}

impl From<&BpfFilterBuilder> for BpfFilterIr {
    fn from(b: &BpfFilterBuilder) -> Self {
        Self {
            fragments: b.fragments.clone(),
            or_branches: b.or_branches.iter().map(Self::from).collect(),
            negated: b.negated,
        }
    }
}
```

### Renderer module

```rust
// netring/src/config/bpf_humanize.rs

use std::fmt;
use super::bpf_builder::{BpfFilterIr, MatchFrag};

pub(crate) fn render(ir: &BpfFilterIr, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if ir.negated {
        let body_is_composite = ir.fragments.len() > 1 || !ir.or_branches.is_empty();
        if body_is_composite {
            write!(f, "not (")?;
            render_body(ir, f)?;
            write!(f, ")")
        } else {
            write!(f, "not ")?;
            render_body(ir, f)
        }
    } else {
        render_body(ir, f)
    }
}

fn render_body(ir: &BpfFilterIr, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut parts: Vec<String> = ir.fragments.iter().map(frag_to_string).collect();
    for branch in &ir.or_branches {
        parts.push(format!("({})", render_to_string(branch)));
    }
    let body = parts.join(" and ");
    if body.is_empty() {
        Ok(())   // empty builder = match all
    } else {
        f.write_str(&body)
    }
}

fn frag_to_string(frag: &MatchFrag) -> String {
    use MatchFrag::*;
    match frag {
        EthType(0x0800) => "ip".to_string(),
        EthType(0x86DD) => "ip6".to_string(),
        EthType(0x0806) => "arp".to_string(),
        EthType(n) => format!("ether proto 0x{:04x}", n),
        Vlan => "vlan".to_string(),
        VlanId(id) => format!("vlan {id}"),
        IpProto(6) => "tcp".to_string(),
        IpProto(17) => "udp".to_string(),
        IpProto(1) => "icmp".to_string(),
        IpProto(58) => "icmp6".to_string(),
        IpProto(n) => format!("ip proto {n}"),
        SrcHost(addr) => format!("src host {addr}"),
        DstHost(addr) => format!("dst host {addr}"),
        AnyHost(addr) => format!("host {addr}"),
        SrcNet(net) => format!("src net {net}"),
        DstNet(net) => format!("dst net {net}"),
        AnyNet(net) => format!("net {net}"),
        SrcPort(p) => format!("src port {p}"),
        DstPort(p) => format!("dst port {p}"),
        AnyPort(p) => format!("port {p}"),
    }
}

fn render_to_string(ir: &BpfFilterIr) -> String {
    let mut s = String::new();
    let _ = render(ir, &mut std::fmt::Formatter::new(&mut s));
    // Formatter::new is unstable; in practice use a small private wrapper.
    // (Implementation detail; the public Display path is what matters.)
    s
}
```

(Implementation note: `std::fmt::Formatter::new` is private; the
shipped renderer uses a small `Wrapper(String): fmt::Write`
wrapper to drive `fmt` against. Doesn't affect the public surface.)

---

## Implementation steps

1. **`bpf_builder.rs`**: define `BpfFilterIr` + `From<&BpfFilterBuilder>`.
2. **`bpf.rs`**: add `source: Option<BpfFilterIr>` field to
   `BpfFilter`. Update `BpfFilter::new` to set it `None`. Update
   any other internal constructors (if any) to thread the IR
   through.
3. **`bpf_builder.rs::build()`**: at the start, snapshot
   `BpfFilterIr::from(&self)`. At end, set the resulting filter's
   `source = Some(ir)`.
4. **`bpf_humanize.rs`**: implement `render`, `render_body`,
   `frag_to_string`. Use a private `WriteWrapper` to drive
   nested-context formatting.
5. **`bpf.rs`**: `impl Display for BpfFilter` + `to_human(&self)`.
6. **`config/mod.rs`**: `mod bpf_humanize;` (private; no re-export).
7. **CHANGELOG entry** under 0.15.0.
8. **Test corpus** (see below).

---

## Tests

### Corpus test: `tests/bpf_humanize_roundtrip.rs`

Each case: build via the typed builder, capture `to_human()`,
assert equality with the expected canonical string. ~20 cases
covering the table in Background plus AND chains, OR branches,
negation, nesting, VLAN, etc.

```rust
#[test]
fn empty_filter_renders_as_empty_string() {
    let f = BpfFilter::builder().build().unwrap();
    assert_eq!(f.to_human(), "");
}

#[test]
fn tcp_dst_port_443() {
    let f = BpfFilter::builder().tcp().dst_port(443).build().unwrap();
    assert_eq!(f.to_human(), "tcp and dst port 443");
}

#[test]
fn http_or_https() {
    let f = BpfFilter::builder()
        .tcp()
        .dst_port(443)
        .or(|b| b.udp().dst_port(53))
        .build()
        .unwrap();
    assert_eq!(f.to_human(), "tcp and dst port 443 and (udp and dst port 53)");
}

#[test]
fn not_arp() {
    let f = BpfFilter::builder().eth_type(0x0806).negate().build().unwrap();
    assert_eq!(f.to_human(), "not arp");
}

#[test]
fn raw_bytecode_falls_back_to_count() {
    let raw = BpfFilter::new(vec![/* a few BpfInsn */]).unwrap();
    assert!(raw.to_human().starts_with("<raw bytecode,"));
}

#[test]
fn src_net() {
    let f = BpfFilter::builder()
        .src_net("10.0.0.0/8".parse().unwrap())
        .build()
        .unwrap();
    assert_eq!(f.to_human(), "src net 10.0.0.0/8");
}

#[test]
fn vlan_with_id() {
    let f = BpfFilter::builder().vlan_id(100).build().unwrap();
    assert_eq!(f.to_human(), "vlan 100");
}
```

### Proptest (bonus, low priority)

Existing `tests/bpf_builder_proptest.rs` could grow a property
"build → to_human → eyeball-conformance" but verifying
**libpcap-compatible** is its own can of worms. Skip for v1.

---

## Acceptance criteria

- [ ] `BpfFilter` implements `Display` rendering canonical
      pcap-filter syntax.
- [ ] `BpfFilter::to_human() -> String` exists as a convenience.
- [ ] Empty builder renders as `""`.
- [ ] Single-fragment filters omit unnecessary parens.
- [ ] OR branches wrap in parens.
- [ ] `negate()` prefixes with `not ` (or `not (...)` for composite
      bodies).
- [ ] All 20+ corpus cases match expected strings.
- [ ] `BpfFilter::new(raw_insns)` returns the fallback string.
- [ ] `cargo test --all-features` passes.
- [ ] `cargo clippy --all-features --tests -- -D warnings` clean.
- [ ] CHANGELOG entry under 0.15.0.

---

## Risks

- **Storage bloat on `BpfFilter`**: the IR is a few `Vec`s. For a
  typical filter (~5 fragments) that's ~200 bytes alongside the
  bytecode (`Vec<BpfInsn>` is itself ~32 bytes per insn). Trivial
  overhead.
- **Drift from libpcap canonicalisation**: pcap-filter syntax has
  multiple equivalent renderings (`tcp dst port 443` ≡
  `tcp and dst port 443`). We pick the explicit-and form. Document.
- **Corpus completeness**: 20 cases cover the named fragments;
  hand-roll for any new fragments added in future
  (`SrcMac` / `DstMac`, etc.). The proptest could catch missing
  cases automatically — defer to a follow-up.
- **`std::fmt::Formatter` doesn't expose a public constructor**.
  Workaround: a tiny `WriteWrapper(&mut String)` impl of
  `fmt::Write` for the nested-context case in `render_body`. Adds
  10 LoC; pure mechanics.

---

## Effort

- Code: ~200 LoC (renderer + IR plumbing).
- Test: ~150 LoC corpus.
- CHANGELOG: 4 lines.
- **Estimate**: 1 day.

---

## Sources

- [pcap-filter(7) — TCPDUMP & LIBPCAP](https://www.tcpdump.org/manpages/pcap-filter.7.html)
- [Pcap Filter Syntax Reference (Kaitotek)](https://www.kaitotek.com/resources/documentation/concepts/packet-filter/pcap-filter-syntax)
- [tcpdump(1)](https://www.tcpdump.org/manpages/tcpdump.1.html)
