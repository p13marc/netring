# Plan 12 — Built-in XDP program loader (via `aya`)

## Summary

Make AF_XDP self-contained in netring by loading a default XDP program
from inside the crate, using [`aya`](https://github.com/aya-rs/aya)
(pure Rust, BTF/CO-RE) as the userspace loader.

Today: opening an `XdpSocket` in netring requires the user to load an
XDP program externally (via `aya`, `libxdp`, `bpftool`) that contains a
`bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS)` call and
attaches it to the interface. Without it, AF_XDP receives no packets —
the socket is created but the kernel never redirects traffic to it.
This is the #2 most-asked AF_XDP question across the ecosystem.

This plan ships the missing 100 % of the path:

1. Add an optional `xdp-loader` feature on `netring`. When enabled,
   pulls `aya` and exposes the types below.
2. **`XskMap`** — thin wrapper around `aya::maps::XskMap`.
3. **`XdpDefaultProgram`** — pre-compiled redirect-all eBPF object
   (BTF-relocatable), embedded as a `static [u8]` byte array. Loaded
   via aya with `Bpf::load()`. No `clang`/`bpf-linker` at build time
   for the netring crate itself; we vendor the compiled `.o` and
   regenerate it through a separate dev-only workflow.
4. **`XdpAttachment`** — RAII guard for the kernel-side program
   attachment. aya does the netlink call; we wrap its handle so the
   program detaches when the `XdpSocket` drops.
5. **Builder integration** — `XdpSocketBuilder::with_default_program()`
   turns the four steps above into one call.

After this plan, `XdpSocket::builder("eth0").queue_id(0).
with_default_program().build()` is a complete capture-on-AF_XDP
recipe. No external program loading, no native libs.

## Status

✅ Phase 1 done (default program + RAII attachment + builder, 0.8.0).
✅ Phase 2 `with_program(prog)` for caller-loaded programs (0.11.0)
  — `XdpProgram::from_aya(...)` + `XdpSocketBuilder::with_program(...)`
  with mutual-exclusivity enforcement against `with_default_program()`.
Deferred to follow-ups: `with_xsk_map(&map)` for multi-queue
shared-map sharing (manual `XdpProgram::register` + `attach` already
covers this case for now), hardware offload validation.

## Prerequisites

- Plan 11 (busy-poll trio) is independent.
- Working AF_XDP path, which already exists.
- Decision to add `aya` as an optional dependency. (Confirmed.
  Pure Rust, in the same dep-tree-shape category as `etherparse` and
  `nix`. ~5–10 s cold-compile cost, gated behind the `xdp-loader`
  feature so users who load programs externally pay nothing.)

## Out of scope

- **Custom XDP programs as part of v1.** Phase A ships only the
  built-in redirect-all program. `XdpSocketBuilder::with_program(prog)`
  for caller-loaded `aya` programs is a one-method follow-up (§10).
- **eBPF compilation toolchain in CI.** The redirect-all program's
  pre-compiled `.o` lives in `netring/src/afxdp/programs/` as
  committed bytes. Regenerating it requires `clang` + `bpf-linker`
  + a tiny aya-bpf source file, but only when *changing* the program.
  Routine builds don't need a BPF toolchain.
- **Hardware offload (`XDP_FLAGS_HW_MODE`).** API surface includes the
  flag but the default program isn't validated for SmartNICs. Users
  with Netronome/Mellanox NICs write their own.
- **Kernel-side `aya-bpf` crate** in netring's tree. Belongs in a
  one-shot generation step, not in routine compilation.

---

## Design context

### Why `aya`

aya is pure Rust, BTF/CO-RE-aware, no native dependencies (no
`libbpf`, no `clang` at consumer compile time), and has become the
de-facto Rust eBPF stack — Cilium-adjacent projects, Anza/Agave
(Solana), and Deepfence run it in production. It handles three things
that hand-rolled `bpf(2)` + netlink code repeatedly gets wrong:

1. **`bpf_attr` union layout across kernel versions.** Fields keep
   being added; aya tracks them.
2. **Verifier log buffer growth on E2BIG.** Critical for debugging
   custom programs.
3. **`IFLA_XDP` netlink attribute layout.** Stable since 4.18 but
   subtly different across attach modes.

Reimplementing those in netring is ~600 LOC of unsafe FFI we'd own
forever. Reuse beats rewrite.

### Why a built-in default program is enough

`bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS)` covers
the common case: capture every packet on a queue. Filtering or
classification in XDP is a tier-2 concern; users who need it know
they need it and reach for aya directly. A library that "just works"
on the simple case is worth more than a library with a bigger but
unfamiliar API. v1 ships the simple case; v2 (when demand surfaces)
adds `with_program(...)` for caller-loaded programs.

### Why pre-compile and vendor the `.o`

Two reasons to vendor instead of compiling at consumer build time:

- **No `clang`/`bpf-linker` in user CI.** Adding a build.rs that
  invokes clang would force every netring user to install the BPF
  toolchain, even if they never enable `xdp-loader`. Vendoring lets
  the optional feature stay genuinely optional.
- **Reproducibility.** A vendored `.o` is byte-stable across
  toolchain versions. The maintainer regenerates it intentionally;
  end users get deterministic behaviour.

The program is small (5 instructions) and stable (BPF ISA, redirect
helper, XSKMAP all stable since 4.18). Re-generation is a manual
step taken roughly never.

### Lifetime and ownership

Same as the previous draft: RAII `XdpAttachment` ties program
detachment to socket drop. `SIGKILL` leaves a stale program, which
the next build catches as `EBUSY`; `force_replace(true)` recovers.

---

## Where it lives — `netring`

- `xdp-loader` feature on `netring` (default: off).
- All loader code in `netring/src/afxdp/loader/`.
- `aya` dep is `optional = true`.

A future split into a separate `netring-xdp` companion crate is
possible if compile-time concerns surface, but starting in-tree keeps
the API surface minimal and lets us iterate without an extra
publishing step.

---

## Files

### NEW (in `netring/src/afxdp/loader/`, gated by `xdp-loader`)

```
netring/src/afxdp/loader/
├── mod.rs                          # public API: XskMap, XdpProgram, XdpAttachment
├── default_program.rs              # bytecode + load helper
└── programs/
    ├── README.md                   # how to regenerate
    ├── redirect_all.bpf.c          # source (NOT compiled at build time)
    └── redirect_all.bpf.o          # vendored, committed binary
```

### NEW (dev-only, not part of release builds)

```
xdp-tools/                          # workspace-root tool, opt-in
├── Cargo.toml                      # uses aya-bpf
└── src/
    └── bin/
        └── compile_redirect_all.rs # build.rs-style helper that
                                    # invokes bpf-linker on
                                    # redirect_all.bpf.c
```

`xdp-tools` is its own workspace-internal binary, not a netring dep.
Maintainer runs it on intentional bytecode changes.

### MODIFIED

- `netring/Cargo.toml`:
  ```toml
  [dependencies]
  aya = { version = "0.13", optional = true }

  [features]
  xdp-loader = ["af-xdp", "dep:aya"]
  ```
- `netring/src/afxdp/mod.rs` — `XdpSocketBuilder::with_default_program()`,
  `with_xsk_map()`, `xdp_attach_flags()`, `force_replace()`.
- `netring/CLAUDE.md` — note the optional feature.
- `CHANGELOG.md`.

### NEW (examples)

- `netring/examples/async_xdp_self_loaded.rs` — minimal capture using
  `with_default_program()`. `required-features = ["tokio", "xdp-loader"]`.

### NEW (tests)

- `netring/tests/xdp_loader.rs` — gated by `integration-tests` +
  `xdp-loader`. Requires CAP_BPF + CAP_NET_ADMIN.

---

## API

```rust
use netring::{XdpSocketBuilder, XdpSocket, XdpFlags};

// Simplest case: one socket, one queue, redirect-all program.
let xsk = XdpSocketBuilder::new("eth0")?
    .queue_id(0)
    .with_default_program()       // creates XskMap, loads, attaches, registers
    .build()?;
// On Drop: detach program, close XSKMAP, close socket.

// Multi-queue, shared map (advanced):
use netring::xdp::{XskMap, default_program};

let map = XskMap::new(8)?;          // size = num queues
let prog = default_program(&map)?;
let attach = prog.attach("eth0", XdpFlags::DRV_MODE)?;
let mut sockets = Vec::new();
for q in 0..8 {
    let xsk = XdpSocketBuilder::new("eth0")?
        .queue_id(q)
        .with_xsk_map(&map)
        .build()?;
    map.set(q, &xsk)?;
    sockets.push(xsk);
}
// `attach` drops last → program detached after all sockets are gone.
```

### Key types

```rust
/// `BPF_MAP_TYPE_XSKMAP`. Maps queue_id → AF_XDP socket fd.
/// Wrapper over `aya::maps::XskMap`.
pub struct XskMap {
    inner: aya::maps::XskMap<aya::maps::MapData>,
}

impl XskMap {
    /// Create a new XSKMAP with capacity `max_entries`.
    pub fn new(max_entries: u32) -> Result<Self, Error>;

    /// Register an AF_XDP socket at index `queue_id`.
    pub fn set(&mut self, queue_id: u32, xsk: &XdpSocket) -> Result<(), Error>;

    /// Remove the socket at `queue_id`.
    pub fn unset(&mut self, queue_id: u32) -> Result<(), Error>;
}

/// A loaded XDP program ready to be attached.
pub struct XdpProgram {
    inner: aya::programs::Xdp,
}

impl XdpProgram {
    /// Attach to interface `iface` with the given mode.
    /// On Drop the program is detached.
    pub fn attach(self, iface: &str, flags: XdpFlags)
        -> Result<XdpAttachment, Error>;
}

/// RAII guard. Drop detaches the program from the interface.
pub struct XdpAttachment {
    link_id: aya::programs::xdp::XdpLinkId,
    _prog: XdpProgram,
}

bitflags! {
    pub struct XdpFlags: u32 {
        const SKB_MODE = aya::programs::XdpFlags::SKB_MODE.bits();
        const DRV_MODE = aya::programs::XdpFlags::DRV_MODE.bits();
        const HW_MODE  = aya::programs::XdpFlags::HW_MODE.bits();
        const REPLACE  = aya::programs::XdpFlags::REPLACE.bits();
    }
}

/// Build the default redirect-all program targeting `xsk_map`.
/// Loads the vendored `redirect_all.bpf.o` via aya.
pub fn default_program(xsk_map: &XskMap) -> Result<XdpProgram, Error>;
```

### Builder additions on `XdpSocketBuilder`

```rust
impl XdpSocketBuilder {
    /// Create a private XSKMAP, load the default redirect-all program,
    /// attach it, and register this socket on the map. Program detaches
    /// when the resulting `XdpSocket` drops.
    ///
    /// Available with the `xdp-loader` feature.
    #[cfg(feature = "xdp-loader")]
    pub fn with_default_program(self) -> Self {
        self.attach_default = true;
        self
    }

    /// Use a caller-supplied XSKMAP. After `build()`, the caller is
    /// responsible for `map.set(queue_id, &xsk)`. Mutually exclusive
    /// with `with_default_program()`.
    #[cfg(feature = "xdp-loader")]
    pub fn with_xsk_map(self, map: &XskMap) -> Self {
        self.shared_map = Some(map.clone_handle());
        self
    }

    /// Override default attach mode (DRV preferred when supported).
    #[cfg(feature = "xdp-loader")]
    pub fn xdp_attach_flags(mut self, flags: XdpFlags) -> Self {
        self.attach_flags = flags;
        self
    }

    /// Allow replacing an existing program on the interface.
    /// Default: false (build fails with EBUSY if a program exists).
    #[cfg(feature = "xdp-loader")]
    pub fn force_replace(mut self, force: bool) -> Self {
        self.force = force;
        self
    }
}
```

`XdpSocket` gains an optional `_attachment: Option<XdpAttachment>`
field that holds the program lifetime.

---

## The redirect-all eBPF program

Source (committed, not compiled at consumer build time):

```c
// netring/src/afxdp/loader/programs/redirect_all.bpf.c
//
// Built once with: clang -O2 -target bpf -c redirect_all.bpf.c -o redirect_all.bpf.o
// (or via the xdp-tools workspace bin; either way the result is committed.)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx) {
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
```

Compiled output (`redirect_all.bpf.o`, ~3 KiB ELF) is loaded by aya at
runtime:

```rust
const REDIRECT_ALL_BYTECODE: &[u8] =
    include_bytes!("programs/redirect_all.bpf.o");

pub fn default_program(xsk_map: &XskMap) -> Result<XdpProgram, Error> {
    let mut bpf = aya::EbpfLoader::new()
        .set_global("xsks_map_size", &xsk_map.max_entries(), true)
        .load(REDIRECT_ALL_BYTECODE)?;
    let prog: &mut aya::programs::Xdp = bpf
        .program_mut("xdp_sock_prog")
        .ok_or(Error::ProgramNotFound)?
        .try_into()?;
    prog.load()?;
    // The XSKMAP is referenced by name from the .o; aya patches in
    // our XskMap fd via the BPF map relocation system.
    bpf.map_mut("xsks_map")
        .ok_or(Error::MapNotFound)?
        .pin(xsk_map.fd())?;
    Ok(XdpProgram { inner: ... })
}
```

(Full code is more careful around relocations and the
`map_mut`/`pin` choreography; this is the shape.)

### How the `.o` is regenerated

A separate `xdp-tools` workspace binary (not a netring dep) compiles
the source to `.o`. The README in `programs/` documents the workflow:

```
$ cd xdp-tools
$ cargo run --bin compile_redirect_all
   ↳ invokes clang via xtask, writes redirect_all.bpf.o to
     ../netring/src/afxdp/loader/programs/redirect_all.bpf.o
$ git diff --stat
   netring/src/afxdp/loader/programs/redirect_all.bpf.o | Bin
```

Maintainer runs this only when the program source changes. CI does
not invoke it; users who clone netring and run `cargo build` don't
need clang.

---

## Implementation steps

### Phase A — feature plumbing

1. Add `aya` (optional) and the `xdp-loader` feature to
   `netring/Cargo.toml`.
2. Skeleton `netring/src/afxdp/loader/mod.rs` behind
   `#[cfg(feature = "xdp-loader")]`.

### Phase B — the program

3. Author `redirect_all.bpf.c` (5-line program, see above).
4. Set up `xdp-tools/` (one-time compilation harness using
   `bpf-linker` + clang). Document.
5. Compile once, commit `redirect_all.bpf.o`.
6. Add an integrity test: a unit test reads the vendored `.o`,
   asserts ELF magic, asserts the `xdp_sock_prog` symbol exists, and
   asserts the `.maps` section declares `xsks_map`. Catches accidental
   commits of the wrong file.

### Phase C — user-facing types

7. `XskMap` wrapping `aya::maps::XskMap`.
8. `default_program()` returns `XdpProgram` wrapping
   `aya::programs::Xdp`.
9. `XdpAttachment` RAII (drops `XdpLinkId` on detach).
10. `XdpFlags` re-exporting aya's flag bits.

### Phase D — builder integration

11. Builder fields + methods on `XdpSocketBuilder`.
12. `build()` flow: create AF_XDP socket → if `attach_default` then
    create XSKMAP → load + attach default program → register socket
    on map → stash `XdpAttachment` in returned `XdpSocket`.
13. Drop ordering: socket fd → XSKMAP → attachment → program. Verify
    via test.

### Phase E — examples + docs

14. `examples/async_xdp_self_loaded.rs`.
15. `docs/AF_XDP_GETTING_STARTED.md`.
16. CLAUDE.md note.
17. CHANGELOG.

---

## Tests

### Unit (no privileges, no kernel)

- Bytecode integrity: ELF magic, symbol presence, map name.
- Builder methods chain correctly.
- `XdpFlags` bit composition.

### Integration (gated by `integration-tests` + `xdp-loader`)

CI grants CAP_BPF + CAP_NET_ADMIN. Each test runs against `lo`
(SKB mode) since DRV mode requires real hardware.

- **Loopback round-trip**:
  1. Open `XdpSocket` on `lo` queue 0 with
     `with_default_program()` and `xdp_attach_flags(SKB_MODE)`.
  2. Spawn a userspace TCP echo server on `lo:55555`.
  3. Open a TCP client; send 1 packet.
  4. Assert ≥1 frame appears in the AF_XDP RX ring.
  5. Drop socket; reopen without the program → no frames (program
     successfully detached).

- **Conflict**:
  1. Attach with `force_replace(false)`.
  2. Attach again → `EBUSY`.
  3. Same with `force_replace(true)` → succeeds.

- **Multi-queue shared-map**:
  1. `XskMap::new(4)`.
  2. 4 sockets on queues 0..4 with `with_xsk_map(&map)`.
  3. Manually `map.set(q, &xsk)` for each.
  4. Send 4 traffic flows with hash-pinning to different queues.
  5. Each socket sees its own queue's frames.

- **Drop ordering** (no kernel needed):
  Use mock `OwnedFd`s; assert close order via tracing.

### CI

- New job: `xdp-loader` matrix entry under existing
  `test-integration`. Same setcap workflow. Skip on kernels < 5.5
  (XDP-on-lo requirement).

---

## Acceptance criteria

- [ ] `XdpSocketBuilder::new("eth0").queue_id(0).with_default_program().build()`
      produces a working AF_XDP capture on a real interface (DRV
      preferred, SKB fallback).
- [ ] Program is detached on `XdpSocket::drop`, verified by
      `ip link show eth0` showing no XDP attachment.
- [ ] `xdp-loader` is opt-in via Cargo feature; default builds don't
      pull `aya`.
- [ ] No `clang` / `bpf-linker` required for routine
      `cargo build --features xdp-loader`.
- [ ] Integration tests pass on kernel ≥ 5.5.
- [ ] "From zero to capture" example doesn't reference any external
      tool.
- [ ] CHANGELOG and rustdoc updated.

---

## Risks

1. **`aya` API churn pre-1.0.** aya is at 0.13.x as of 2025. Public
   API has been stabilising but still gets touched between versions.
   Mitigation: pin to a specific minor (`aya = "0.13"`), watch the
   changelog, bump intentionally with each netring release.

2. **`aya` compile time.** ~5–10 s cold compile, mostly from
   `object`. Behind `xdp-loader` feature so users opting out pay
   nothing. Acceptable.

3. **`.o` regeneration drift.** If we update kernel constants in the
   `.c` source but forget to regenerate the `.o`, the runtime
   verifier catches it. Mitigation: integrity test asserts the
   bytecode covers a known instruction shape; CI runs the
   integration test against the committed bytecode.

4. **BTF support across kernel versions.** aya handles BTF/CO-RE
   well, but a kernel that lacks BTF for `struct xdp_md` blocks
   loading. Linux ≥ 5.4 has BTF for the kernel itself, but distros
   sometimes strip it. Document the requirement.

5. **`SIGKILL` leaves stale program.** Same as previous draft:
   document `force_replace(true)` for restart scenarios; make the
   error message specifically suggest it.

6. **Multi-process loaders on the same interface.** XDP programs are
   per-interface, so two netring processes calling
   `with_default_program` conflict. Correct behaviour; document.

7. **DRV mode requires real hardware.** Most CI runners can't
   exercise DRV mode (virtual interfaces fall back to SKB). The
   acceptance check for DRV mode is manual on a dev box; CI tests
   SKB mode only.

8. **`object` crate's parse-time work on every load.** Loading the
   3 KiB `.o` parses ELF on each call. Negligible (~µs) but worth
   noting; cache the parsed program at top-level if it ever shows up
   in profiles.

---

## Effort

- Feature plumbing + Cargo.toml: ~10 LOC.
- `xdp-tools` one-time compilation harness: ~150 LOC (workspace bin).
- `redirect_all.bpf.c`: 12 lines.
- `XskMap` wrapper: ~60 LOC.
- `default_program` + `XdpProgram` + `XdpAttachment`: ~120 LOC.
- Builder additions: ~80 LOC.
- Drop ordering + lifetime: ~50 LOC.
- Unit tests: ~80 LOC (incl. ELF integrity).
- Integration test: ~150 LOC.
- Example: ~80 LOC.
- Docs: ~150 LOC (rustdoc + AF_XDP getting-started).
- **Total in `netring`**: ~700 LOC (down from ~1100 in the
  hand-roll variant).
- **Time**: 1–1.5 days. Most of it in aya's API ergonomics for
  XSKMAP-from-already-loaded-program (the relocation choreography is
  the only fiddly bit).

---

## Out of scope follow-ups

- **`XdpSocketBuilder::with_program(program)`** for caller-loaded
  custom aya programs. Trivial extension; ~30 LOC and one builder
  method. Add when a user requests custom XDP filtering inside
  netring's flow.
- **`flowscope-prefilter`** companion crate (per the DPI architecture
  research) that ships higher-level XDP programs (5-tuple bypass map,
  first-packet hint) on top of this loader. Lives in flowscope, not
  netring.
- **Hardware offload validation** for SmartNICs. Per-vendor; deferred
  until a user with the hardware can co-design.
- **`BTF Hub` integration** for kernels lacking BTF. Out of scope; aya
  surfaces this as a clear error.

---

## Sources

- aya — https://github.com/aya-rs/aya · book https://aya-rs.dev/book/
- aya XDP example — https://github.com/aya-rs/book/tree/main/examples/xdp-hello
- aya XskMap — https://docs.rs/aya/latest/aya/maps/struct.XskMap.html
- Linux AF_XDP — https://docs.kernel.org/networking/af_xdp.html
- BPF map types (XSKMAP) — https://docs.kernel.org/userspace-api/ebpf/map_xskmap.html
- BPF instruction set — https://docs.kernel.org/bpf/standardization/instruction-set.html
- `bpf_redirect_map` helper — https://docs.kernel.org/bpf/redirect.html
- libxdp source for cross-checking layout —
  https://github.com/xdp-project/xdp-tools/tree/master/lib/libxdp
- Suricata's AF_XDP capture (reference user) —
  https://docs.suricata.io/en/latest/capture-hardware/af-xdp.html
