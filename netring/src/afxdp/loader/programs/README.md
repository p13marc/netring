# `programs/`

Vendored, pre-compiled BPF objects loaded by netring's XDP loader.

`redirect_all.bpf.o` is the canonical "redirect every packet on the
bound RX queue to its AF_XDP socket" program. The userspace loader
(`netring/src/afxdp/loader/`) loads this object via aya, attaches the
program to an interface, and registers AF_XDP sockets onto its
embedded XSKMAP.

## Why vendored?

Compiling BPF C requires `clang`. Vendoring the compiled object
keeps the toolchain out of consumer builds — `cargo build --features
xdp-loader` works on any system, even one without clang installed.
We regenerate the object only when the program source changes,
which is rare.

## Regenerating

From this directory:

```bash
# -g is REQUIRED: it emits BTF (.BTF/.BTF.ext). The `.maps` BTF-style map
# definition can only be parsed by libbpf/aya from BTF, so a BTF-less object
# fails to load at runtime with "no BTF parsed for object" (aya >= 0.13).
clang -O2 -g -target bpf -c -D__TARGET_ARCH_x86 \
    redirect_all.bpf.c -o redirect_all.bpf.o
# Strip DWARF but KEEP BTF (.BTF/.BTF.ext are not .debug_* sections):
llvm-strip -g redirect_all.bpf.o
```

This produces a ~2.3 KB ELF object containing:

- `xdp` section: the redirect program.
- `.maps` section: the XSKMAP definition (`max_entries = 256`).
- `.BTF` / `.BTF.ext`: type info for the map definition (**load-critical**).
- `license` section: `"GPL"` (required for the redirect helper).

Verify with `readelf -h redirect_all.bpf.o` (`Machine: Linux BPF`) and
`readelf -S redirect_all.bpf.o | grep BTF` (must show `.BTF`).

`redirect_all` is intentionally minimal. For in-kernel filtering, the
sibling `filter_redirect.bpf.{c,o}` (0.25 W1a) is a table-driven
program — see below — or write your own with `aya-bpf` and load it
via `XdpSocketBuilder::with_program(...)`.

## `filter_redirect.bpf.o` — table-driven filter+redirect (0.25 W1a / S5)

Same plumbing as `redirect_all`, but consults a `BPF_MAP_TYPE_HASH`
named `filter_map` keyed by `{proto, port}` to decide, in-kernel,
whether each frame is interesting: a hit is redirected to the AF_XDP
socket, a miss is `XDP_PASS`ed up the normal stack ("shed"). Both the
source and destination L4 port are probed. Userspace populates the map
via `XdpProgram::set_filter(proto, port, on)` from the subscription
union's kernel-pushable `{proto, port}` atoms.

Regenerate the same way (the `-g` + `llvm-strip -g` BTF dance is
mandatory here too):

```bash
clang -O2 -g -target bpf -c -D__TARGET_ARCH_x86 \
    filter_redirect.bpf.c -o filter_redirect.bpf.o
llvm-strip -g filter_redirect.bpf.o
```

Sections: `xdp` (`xdp_filter_prog`), `.maps` (`xsks_map` + `filter_map`),
`.BTF`/`.BTF.ext`, `license`.

## ⚠ Alignment: load via `aya::include_bytes_aligned!`, NOT `include_bytes!`

aya-obj parses the ELF zero-copy through the `object` crate, whose
header reads require the byte slice to be aligned. A plain
`include_bytes!` static has **no alignment guarantee**, so it loaded
only in builds where the static happened to land aligned and failed
with `"error parsing ELF data"` in others — notably any build that
also pulls `tokio` (every Monitor build), where feature unification
shifts the static's address. `default_program.rs` embeds both objects
with `aya::include_bytes_aligned!`, which pins the alignment regardless
of the dependency graph. The `vendored_programs_parse_under_aya` unit
test (runs in the default `cargo test` build, which has `tokio`) guards
this. If you re-vendor, keep the aligned macro.

## Source ownership

`redirect_all.bpf.c` defines:

- `xsks_map`: `BPF_MAP_TYPE_XSKMAP` of capacity 256.
- `xdp_sock_prog`: calls `bpf_redirect_map(&xsks_map,
  ctx->rx_queue_index, XDP_PASS)`.

`filter_redirect.bpf.c` adds `filter_map`
(`BPF_MAP_TYPE_HASH`, key `struct filter_key { u16 port; u8 proto; u8 pad }`)
and `xdp_filter_prog`. The Rust `FilterKey` in `program.rs` must keep the
same layout.

If you change any program/map name or a map's `max_entries`, also update
the constants in `default_program.rs` and the integrity-check unit tests
in `loader/mod.rs`.
