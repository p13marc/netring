# Public-API lock

`netring.txt` and `netring-exporters.txt` are checked-in snapshots of each
crate's **entire public API** (every feature enabled), produced by
[`cargo-public-api`](https://github.com/cargo-public-api/cargo-public-api). The
`public-api` CI job in `.forgejo/workflows/ci.yml` regenerates both and fails
the build if either differs — so **every change to the public surface shows up
as a reviewed diff** to these files. This is the §F automation of the 1.0
API-stability sweep ([#37]): it catches accidental breaks (and documents
intentional ones) before they reach a release.

## When CI fails on this

The job prints the diff. If the API change is **intentional**, regenerate the
relevant lock and commit it alongside your change:

```sh
rustup toolchain install nightly-2026-08-18        # the pinned toolchain
cargo install cargo-public-api --version 0.51.0 --locked
cargo +nightly-2026-08-18 public-api -p netring           --all-features -ss > public-api/netring.txt
cargo +nightly-2026-08-18 public-api -p netring-exporters --all-features -ss > public-api/netring-exporters.txt
```

Pass `+nightly-2026-08-18` explicitly. Without it `cargo-public-api` picks
whatever nightly is installed, and the rendering differs between them — `std::io`
vs `core::io` in every signature, for instance — which produces a diff of
hundreds of lines that says nothing about the API.

(`netring-exporters --all-features` builds the `kafka` feature, which needs
`cmake` + a C toolchain for bundled librdkafka.)

If it's **not** intentional, you introduced an unplanned API change — fix the
code instead of the snapshot.

## Why pinned

`cargo-public-api` renders nightly rustdoc JSON, whose output can shift between
toolchain/tool versions. The CI job pins **`nightly-2026-08-18`** and
**`cargo-public-api 0.51.0`** so the snapshot is byte-reproducible. To move to a
newer toolchain, bump both pins in `.forgejo/workflows/ci.yml` *and* regenerate
this file in the same commit.

**The pin has a floor:** it must satisfy the workspace MSRV in
`Cargo.toml`/`rust-toolchain.toml`. The previous pin, `nightly-2026-04-09`, is
rustc 1.96.0-nightly, and it stopped being able to build the workspace at all
the moment the MSRV moved to 1.97 — regeneration failed with
`rustc 1.96.0-nightly is not supported by the following packages`. Bump this pin
whenever the MSRV moves.

The `-ss` flag omits blanket-impl and auto-trait-impl noise (`impl<T> Any for
T`, `impl Send for …`) so the lock tracks the meaningful surface — functions,
types, trait methods, manual and derived impls.

[#37]: https://git.marcpardo.eu/marcpardo/netring/issues/37
