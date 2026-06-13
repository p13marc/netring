# miri & fuzzing in netring

netring has a fair amount of `unsafe` (mmap pointer math, zero-copy lifetime
erasure, type-erased dispatch). Two CI gates guard it.

## miri (UB / provenance)

The `miri` CI job runs the **pure-logic surface** (no syscalls/mmap — miri can't
execute those) under the **Tree Borrows** aliasing model:

```
MIRIFLAGS="-Zmiri-tree-borrows" cargo +nightly miri test -p netring --lib config::
MIRIFLAGS="-Zmiri-tree-borrows" cargo +nightly miri test -p netring --lib packet:: -- --skip afpacket
```

- `config::` — the in-tree cBPF compiler + interpreter. **UB-clean under
  strict-provenance Stacked Borrows** (the strictest setting).
- `packet::` — the zero-copy `BatchIter` / `Packet` pointer walk over synthetic
  TPACKET_v3 blocks.

### Stacked Borrows vs Tree Borrows (important for the 0.24 keystone)

The `BatchIter` raw-pointer iteration is **sound under Tree Borrows** (all tests
pass) but **trips the stricter, legacy Stacked Borrows** with a retag error. This
is a known SB-vs-TB discrepancy — SB is too strict for some legitimate
raw-pointer-from-slice iteration patterns, and the ecosystem is converging on Tree
Borrows as the realistic model. We therefore validate against **Tree Borrows**.

**Implication for the 0.24 Phase B (zero-copy borrowed run loop):** the borrowed
`drain_batch` path builds on exactly this `BatchIter`/`Packet` code. Validate it
under Tree Borrows; where feasible, prefer provenance-preserving patterns
(`addr_of!`, a single base pointer + offsets) so it also satisfies Stacked
Borrows. The "safer `for_each` surface" the plan keeps in reserve is the fallback
if a future change can't stay TB-clean.

### Running locally
`rustup component add --toolchain nightly miri && cargo +nightly miri setup` once,
then the commands above. Tests that open sockets/mmap are excluded (miri can't run
syscalls); the surface grows as more pure-logic tests are added.

## Fuzzing (cargo-fuzz / libFuzzer)

`netring/fuzz/` has two targets (the `fuzz` CI job runs a 60 s smoke of each):

- **`bpf_matches`** — the cBPF *interpreter* (`BpfFilter::matches`) against
  arbitrary, untrusted frame bytes. It walks L2–L4 offsets into the frame and must
  never panic / read OOB / loop forever. (200k runs clean.)
- **`bpf_builder`** — the typed `BpfFilterBuilder` → compiler. Arbitrary builder
  programs must compile without panicking, and any compiled filter must evaluate
  deterministically. (300k runs clean.)

Run: `cargo +nightly fuzz run bpf_matches` (from `netring/`). Corpus/artifacts are
git-ignored.

### Findings from the initial run (both fixed)
1. **miri:** `build_synthetic_block` (test helper) cast a 1-aligned `Vec<u8>` to an
   8-aligned `tpacket` struct → real alignment UB. Fixed by backing it with
   `Vec<u64>` (`AlignedBlock`).
2. **fuzz:** `BpfFilterBuilder::ports([])` asserts (documented non-empty
   precondition). Not a bug, but a footgun for a typed builder — flagged for a
   possible 0.25 API hardening (empty = no-op, or a non-empty argument type).
