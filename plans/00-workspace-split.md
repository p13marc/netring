# Plan 00 — Workspace split

## Summary

Convert the single-crate repo into a Cargo workspace containing
`netring/` (existing capture/inject) and a new empty `netring-flow/`
crate. Move `Timestamp` to `netring-flow`, re-export from `netring`.
No new functionality; all existing tests must still pass.

This phase is mechanical but blocks every other plan.

## Status

Not started.

## Prerequisites

None.

## Out of scope

- New types beyond moving `Timestamp`. (No `PacketView`, no
  `FlowExtractor` — those land in plan 01.)
- New deps. (No `etherparse`, `ahash`, etc. yet.)
- Public release. We tag alpha versions on git, no crates.io publish
  until plan 04.

---

## Target repo layout

```
netring/                        ← workspace root (was the crate)
├── Cargo.toml                  ← [workspace] manifest (NEW)
├── Cargo.lock
├── README.md                   ← stays at root
├── CHANGELOG.md                ← stays at root
├── LICENSE-*                   ← stays at root
├── justfile                    ← UPDATED (cargo commands need -p)
├── deny.toml                   ← stays at root
├── .github/workflows/          ← UPDATED (workspace-aware)
├── plans/                      ← unchanged
├── docs/                       ← stays at root
├── netring/                    ← MOVED from root
│   ├── Cargo.toml
│   ├── src/
│   ├── tests/
│   ├── examples/
│   └── benches/
└── netring-flow/               ← NEW skeleton
    ├── Cargo.toml
    └── src/
        ├── lib.rs              ← only re-exports + Timestamp for now
        └── timestamp.rs        ← MOVED from netring/src/packet.rs
```

`README.md`, `CHANGELOG.md`, license files, `docs/`, `plans/` stay at
the workspace root — they describe the project as a whole.

---

## Files

### NEW

- `Cargo.toml` (workspace root) — `[workspace]` manifest
- `netring-flow/Cargo.toml` — minimal manifest, no deps
- `netring-flow/src/lib.rs` — `pub use timestamp::Timestamp;`
- `netring-flow/src/timestamp.rs` — moved Timestamp definition
- `.github/workflows/ci.yml` — adjust cargo commands (`-p netring`,
  `-p netring-flow`, or `--workspace`)

### MOVED

- All of `src/`, `tests/`, `examples/`, `benches/`, `Cargo.toml` →
  `netring/src/`, `netring/tests/`, etc.
- Per-crate `Cargo.toml`, with package metadata identical to today's
  except `[package]` keeps the existing `name = "netring"` and
  `version = "0.7.0-alpha.0"`.

### MODIFIED

- `netring/src/packet.rs` — remove `Timestamp` definition, replace
  with `pub use netring_flow::Timestamp;` (or re-export at lib.rs
  level — see below).
- `netring/src/lib.rs` — add `pub use netring_flow::Timestamp;` at
  crate root so `netring::Timestamp` keeps working.
- `netring/Cargo.toml` — add
  `netring-flow = { version = "0.1.0-alpha.0", path = "../netring-flow", default-features = false }`
- `justfile` — update recipes (see below).
- `.github/workflows/ci.yml` — update commands.

### UNCHANGED

- All test code, all example code, all source modules in `netring`
  except `packet.rs` (one-line change).

---

## Cargo manifests

### `Cargo.toml` (workspace root)

```toml
[workspace]
members = [
    "netring",
    "netring-flow",
]
resolver = "2"

[workspace.package]
edition = "2024"
rust-version = "1.85"
license = "MIT OR Apache-2.0"
repository = "https://github.com/p13marc/netring"
authors = ["Marc Pardo <p13marc@gmail.com>"]

[workspace.dependencies]
# Shared deps. Member crates inherit via `dep.workspace = true`.
# We're conservative for plan 00 — only add what's already used.
libc       = "0.2"
nix        = { version = "0.31", features = ["socket", "mman", "poll", "net", "ioctl"] }
thiserror  = "2"
tracing    = { version = "0.1", default-features = false, features = ["std"] }
bitflags   = "2"
tokio      = { version = "1", features = ["io-util", "net", "macros", "rt-multi-thread", "time", "signal", "sync"] }
futures-core = { version = "0.3", default-features = false, features = ["std"] }
crossbeam-channel = "0.5"
etherparse = "0.16"
pcap-file  = "2"
metrics    = "0.24"
```

### `netring/Cargo.toml`

```toml
[package]
name        = "netring"
version     = "0.7.0-alpha.0"
description = "High-performance zero-copy packet I/O for Linux (AF_PACKET TPACKET_V3 + AF_XDP)"
keywords    = ["packet", "capture", "af_packet", "af_xdp", "zero-copy"]
categories  = ["network-programming", "os::linux-apis"]
readme      = "../README.md"
documentation = "https://docs.rs/netring"
homepage    = "https://github.com/p13marc/netring"
edition.workspace      = true
rust-version.workspace = true
license.workspace      = true
repository.workspace   = true
authors.workspace      = true
exclude     = ["CLAUDE.md", "SPEC.md"]

[dependencies]
netring-flow = { version = "0.1.0-alpha.0", path = "../netring-flow", default-features = false }

libc      = { workspace = true }
nix       = { workspace = true }
thiserror = { workspace = true }
tracing   = { workspace = true }
bitflags  = { workspace = true }

tokio        = { workspace = true, optional = true }
futures-core = { workspace = true, optional = true }
crossbeam-channel = { workspace = true, optional = true }
etherparse   = { workspace = true, optional = true }
pcap-file    = { workspace = true, optional = true }
metrics      = { workspace = true, optional = true }

[dev-dependencies]
env_logger = "0.11"
divan      = "0.1"
criterion  = { version = "0.5", features = ["html_reports"] }
etherparse = "0.16"
core_affinity = "0.8"
futures    = "0.3"

[features]
default = []
tokio   = ["dep:tokio", "dep:futures-core"]
channel = ["dep:crossbeam-channel"]
parse   = ["dep:etherparse"]
pcap    = ["dep:pcap-file"]
metrics = ["dep:metrics"]
af-xdp  = []
nightly = []
integration-tests = []

[package.metadata.docs.rs]
all-features = true
rustdoc-args = ["--cfg", "docsrs"]

# Examples and benches unchanged from today.
```

### `netring-flow/Cargo.toml`

```toml
[package]
name        = "netring-flow"
version     = "0.1.0-alpha.0"
description = "Pluggable flow & session tracking for packet capture (cross-platform, runtime-free)"
keywords    = ["flow", "session", "tcp", "packet", "tracking"]
categories  = ["network-programming"]
readme      = "../README.md"     # shared workspace README for now
edition.workspace      = true
rust-version.workspace = true
license.workspace      = true
repository.workspace   = true
authors.workspace      = true

# Plan 00: zero deps. Plan 01 adds etherparse/ahash/smallvec/bitflags
# behind features.
[dependencies]

[features]
default = []
```

---

## API changes

Only one user-visible change: `Timestamp` lives in `netring-flow`,
re-exported from `netring`.

### `netring-flow/src/timestamp.rs`

Verbatim move of the existing `netring/src/packet.rs` Timestamp code:

```rust
//! Nanosecond-precision timestamp shared across the netring family.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    pub sec: u32,
    pub nsec: u32,
}

impl Timestamp {
    #[inline]
    pub const fn new(sec: u32, nsec: u32) -> Self { Self { sec, nsec } }

    #[inline]
    pub fn to_system_time(self) -> SystemTime {
        UNIX_EPOCH + Duration::new(self.sec as u64, self.nsec)
    }

    #[inline]
    pub fn to_duration(self) -> Duration {
        Duration::new(self.sec as u64, self.nsec)
    }
}

impl From<Timestamp> for SystemTime { fn from(ts: Timestamp) -> Self { ts.to_system_time() } }
impl From<Timestamp> for Duration   { fn from(ts: Timestamp) -> Self { ts.to_duration() } }

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:09}", self.sec, self.nsec)
    }
}

#[cfg(test)]
mod tests {
    // Move the existing 6 Timestamp tests verbatim from netring/src/packet.rs.
}
```

### `netring-flow/src/lib.rs`

```rust
//! netring-flow — pluggable flow & session tracking.
//!
//! Cross-platform, runtime-free library used by `netring` (Linux
//! AF_PACKET / AF_XDP) and any other packet source (pcap, tun-tap,
//! replay, embedded). No tokio, no futures, no async runtime
//! dependency.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod timestamp;

pub use timestamp::Timestamp;
```

### `netring/src/packet.rs` change

Delete the existing `Timestamp` struct + impls + tests. Add:

```rust
pub use netring_flow::Timestamp;
```

Tests moved to `netring-flow/src/timestamp.rs`.

### `netring/src/lib.rs` change

Add (near the top of the public re-exports):

```rust
pub use netring_flow::Timestamp;
```

(Leaves `netring::Timestamp` working for downstream users.)

---

## Implementation steps

1. **Create the workspace root manifest.**
   - `git mv Cargo.toml netring/Cargo.toml`
   - `git mv src netring/src`
   - `git mv tests netring/tests`
   - `git mv examples netring/examples`
   - `git mv benches netring/benches`
   - `git mv Cargo.lock netring/` then `mv netring/Cargo.lock .`
     (Cargo.lock lives at workspace root; only one for the whole
     workspace.)
   - Write the new `Cargo.toml` at the workspace root.
   - Edit `netring/Cargo.toml` to inherit workspace fields and depend
     on `netring-flow`.
2. **Create `netring-flow` skeleton.**
   - `mkdir -p netring-flow/src`
   - Write `netring-flow/Cargo.toml` (minimal).
   - Write `netring-flow/src/lib.rs` with `pub use timestamp::Timestamp;`.
   - Write `netring-flow/src/timestamp.rs` (verbatim move from
     `netring/src/packet.rs`, including the 6 Timestamp tests).
3. **Wire up the re-export.**
   - In `netring/src/packet.rs`: delete the local `Timestamp` struct
     + impls + tests; add `pub use netring_flow::Timestamp;` at the
     top.
   - In `netring/src/lib.rs`: add `pub use netring_flow::Timestamp;`
     (only if it isn't already re-exported there transitively).
4. **Update justfile.**
   - All `cargo` commands gain `-p netring` (or `--workspace` for ops
     that should hit both crates: `clippy`, `fmt`, `test`).
   - New recipe: `test-flow:` → `cargo test -p netring-flow`.
   - `ci` and `ci-full` recipes use `--workspace`.
5. **Update CI.**
   - `.github/workflows/ci.yml`: change `cargo build`/`cargo test`/
     `cargo clippy` invocations to operate on the workspace.
   - Add a job (or step) that builds `netring-flow` standalone with
     `cargo build -p netring-flow --no-default-features` to prove the
     "no deps" claim.
6. **Build + test sanity check.**
   - `cargo build --workspace` succeeds.
   - `cargo test --workspace` passes (all existing 71 tests + 6
     Timestamp tests = 77).
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
     passes.
   - `cargo build -p netring-flow --no-default-features` succeeds and
     produces a tiny `.rlib` (proves no deps).
7. **Bump version + tag (no publish).**
   - `netring/Cargo.toml`: `version = "0.7.0-alpha.0"`.
   - `netring-flow/Cargo.toml`: `version = "0.1.0-alpha.0"`.
   - Commit message: `0.7.0-alpha.0: workspace split, netring-flow skeleton`.
   - Tag: `0.7.0-alpha.0` (no `v` prefix — see CLAUDE.md / past
     feedback).
8. **CHANGELOG entry.**
   - Add a section to `CHANGELOG.md`:
     ```
     ## [Unreleased] / 0.7.0-alpha.0 — workspace split
     ### Changed
     - Repo is now a Cargo workspace with two members:
       - `netring` (this crate) — capture + inject.
       - `netring-flow` — empty skeleton, will host flow/session tracking.
     - `Timestamp` moved to `netring-flow`. `netring::Timestamp`
       continues to work via re-export.
     ### Notes
     - No new functionality. Subsequent `0.7.0-alpha.N` releases will
       add the flow API piece by piece.
     ```

---

## Tests

This phase is movement-only. Acceptance is "everything that worked
before still works."

- `cargo test --workspace --features "integration-tests,tokio,channel" -- --test-threads=1`
  passes (all existing tests + 6 Timestamp tests in `netring-flow`).
- `cargo build -p netring-flow` succeeds with a tiny output.
- `cargo build -p netring-flow --no-default-features` succeeds.
- `cargo test -p netring-flow` passes (just the Timestamp tests).
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  is clean.
- `cargo doc --workspace --no-deps` builds docs for both crates.

---

## Acceptance criteria

- [ ] Workspace root `Cargo.toml` exists with `[workspace]` and
      `[workspace.dependencies]`.
- [ ] `netring/` and `netring-flow/` exist as workspace members.
- [ ] `cargo build --workspace` succeeds.
- [ ] `cargo test --workspace --features "integration-tests,tokio,channel" -- --test-threads=1`
      passes — same count as before, +6 Timestamp tests in
      `netring-flow`.
- [ ] `cargo build -p netring-flow --no-default-features` succeeds
      without pulling any external deps (verify with `cargo tree -p
      netring-flow --no-default-features` shows only `netring-flow`).
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
      passes.
- [ ] `netring::Timestamp` resolves to `netring_flow::Timestamp`
      (verify via `cargo doc` rustdoc output).
- [ ] `justfile` recipes work (`just test`, `just clippy`,
      `just ci`).
- [ ] CI green on master.
- [ ] Tag `0.7.0-alpha.0` pushed; no crates.io publish yet.

---

## Risks

1. **`Cargo.lock` placement.** Workspaces use a single root lockfile.
   If the move leaves a stale `netring/Cargo.lock` Cargo will warn.
   Delete any per-crate lockfile.
2. **`exclude = ["plans/"]` removed from netring's manifest.** It was
   useful when plans/ was inside the crate dir; with workspace
   layout, plans/ is at root, outside `netring/`. Remove that
   exclude.
3. **`docs/` and `README.md` references.** Examples in README use
   `netring::Capture::open(...)`. Still work post-split. Verify with
   `cargo test --doc -p netring`.
4. **CI matrix doubles.** Each job needs to run for both crates (or
   `--workspace`). Adjust `cargo` invocations carefully to avoid
   silently skipping `netring-flow`.
5. **`docs.rs` config.** `[package.metadata.docs.rs]` lives in each
   crate's manifest. `netring-flow` needs its own once we add
   features (plan 01).
6. **`integration-tests` feature is `netring`-only.** It gates AF_PACKET
   tests. Don't try to enable it on `netring-flow`.

---

## Effort

- LOC: 0 net new (verbatim moves + ~20 lines of new manifests).
- Time: 0.5 day. Half of that is shaking out CI.

---

## Out of plan: dedup integration

If we want to ship dedup in the same release as the workspace split,
plan 10 can land between this plan and plan 01. The split is a clean
boundary: dedup before/after doesn't matter, but doing it after the
split lets dedup live in the right crate (`netring-flow` if we
decide it should be reusable, `netring` if it stays AF_PACKET-tied).
That's a plan-10 decision, not a plan-00 decision.
