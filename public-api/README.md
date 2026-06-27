# Public-API lock

`netring.txt` and `netring-exporters.txt` are checked-in snapshots of each
crate's **entire public API** (every feature enabled), produced by
[`cargo-public-api`](https://github.com/cargo-public-api/cargo-public-api). The
`public-api lock` CI job regenerates both and fails the build if either differs
— so **every change to the public surface shows up as a reviewed diff** to these
files. This is the §F automation of the 1.0 API-stability sweep ([#37]): it
catches accidental breaks (and documents intentional ones) before they reach a
release.

## When CI fails on this

The job prints the diff. If the API change is **intentional**, regenerate the
relevant lock and commit it alongside your change:

```sh
rustup toolchain install nightly-2026-04-09        # the pinned toolchain
cargo install cargo-public-api --version 0.51.0 --locked
cargo public-api -p netring            --all-features -ss > public-api/netring.txt
cargo public-api -p netring-exporters  --all-features -ss > public-api/netring-exporters.txt
```

(`netring-exporters --all-features` builds the `kafka` feature, which needs
`cmake` + a C toolchain for bundled librdkafka.)

If it's **not** intentional, you introduced an unplanned API change — fix the
code instead of the snapshot.

## Why pinned

`cargo-public-api` renders nightly rustdoc JSON, whose output can shift between
toolchain/tool versions. The CI job pins **`nightly-2026-04-09`** and
**`cargo-public-api 0.51.0`** so the snapshot is byte-reproducible. To move to a
newer toolchain, bump both pins in `.github/workflows/ci.yml` *and* regenerate
this file in the same commit.

The `-ss` flag omits blanket-impl and auto-trait-impl noise (`impl<T> Any for
T`, `impl Send for …`) so the lock tracks the meaningful surface — functions,
types, trait methods, manual and derived impls.

[#37]: https://github.com/p13marc/netring/issues/37
