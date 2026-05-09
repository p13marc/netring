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
clang -O2 -target bpf -c -D__TARGET_ARCH_x86 \
    redirect_all.bpf.c -o redirect_all.bpf.o
```

This produces a ~1 KB ELF object containing:

- `xdp` section: the 5-instruction program.
- `.maps` section: the XSKMAP definition (`max_entries = 256`).
- `license` section: `"GPL"` (required for the redirect helper).

Verify with `readelf -h redirect_all.bpf.o` (`Machine: Linux BPF`).

The program is intentionally minimal. If you want filtering or
classification in XDP, write your own program with `aya-bpf` and
load it via the future `XdpSocketBuilder::with_program(...)` API.

## Source ownership

The C source defines:

- `xsks_map`: `BPF_MAP_TYPE_XSKMAP` of capacity 256.
- `xdp_sock_prog`: the program. Calls `bpf_redirect_map(&xsks_map,
  ctx->rx_queue_index, XDP_PASS)`.

If you change either name or the map's `max_entries`, also update
the constants in `default_program.rs` and the integrity-check unit
test in `loader/mod.rs`.
