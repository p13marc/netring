# netring 0.21 release gates

## 1. Summary

All technical work for netring 0.21 is shipped on `0.21-dev` (28
commits, A through I, plus the audit-fix batch). What's left
before the `0.21.0` tag can be cut is purely release-prep
plumbing the user explicitly held back when they said "do not
release":

1. **Cargo.toml version bump** `0.20.0` → `0.21.0`.
2. **`netring/CLAUDE.md` refresh** — currently still describes
   the 0.20 module map.
3. **Git tag** `0.21.0` (no `v` prefix per the user's
   convention).
4. **`cargo publish`** (only on explicit user approval per
   project memory).

All other Phase H items (H.1 flowscope 0.13 bump, H.2 Send
sweep, H.3 deprecation markers, H.4 monitor-quickstart feature,
H.6 migration guide, H.7 CHANGELOG) are already in.

This plan exists so the gates are visible from a clean
`plans/` directory; it deletes itself when the tag lands.

## 2. Status

Held. The user has been told the work is ready. The user
controls when (and whether) to push the trigger.

## 3. Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `netring/Cargo.toml` | bump version |
| Modify | `netring/CLAUDE.md` | reflect 0.21 module map + Recent additions block |
| Modify | `CHANGELOG.md` | flip the 0.21 entry's title from drafted-on-`0.21-dev` to released (date stamp) |
| New (tag) | `git tag 0.21.0` | no `v` prefix |
| Run | `cargo publish -p netring` | only on explicit user approval |

## 4. Pre-flight checklist

Before any of the above:

- [ ] `git status` clean
- [ ] On `0.21-dev`, rebased on latest `master` (or merged
      to `master` via fast-forward)
- [ ] `cargo nextest run --features monitor-quickstart` green
- [ ] `cargo +stable clippy --features monitor-quickstart --all-targets -- -D warnings` clean
- [ ] `cargo bench --features bench-zero-alloc --bench zero_alloc` reports Δ 0 / 0
- [ ] `cargo build --examples --features monitor-quickstart` clean
- [ ] flowscope 0.13.0 is on crates.io (it is)
- [ ] `cargo publish -p netring --dry-run` clean

Per `netring/CLAUDE.md` "Pre-publish checklist" — also check
`~/.cargo/credentials.toml` is a file, not the empty
root-owned directory that bites this dev machine.

## 5. CLAUDE.md update outline

The CLAUDE.md "Recent additions" block currently caps at the
0.20 Phase A–E + F.1 + F.2 entries. Append:

- **netring 0.21 Phase A–I summary** (one paragraph per phase),
  cross-referencing the new Cargo features (`monitor-quickstart`,
  `eve-sink`, `file-hash`), the new builder methods (`name`,
  `fanout`, `with_broadcast`, `pcap_source`, `pcap_speed_factor`,
  `drain_timeout`, `flow_state`), and the new top-level types
  (`ShardedRunner`, `EventStream<M>`).
- **flowscope dep version**: `0.11.1` → `0.13.0` in the
  Architecture section.
- **Implementation Status** header: bump from `0.20.0 prepared`
  to `0.21.0 released` (or `0.21.0 prepared` if the publish
  is still queued).
- **Pre-publish checklist** note: clarify it now applies to
  `0.21.x` patch releases too.

The "Recent additions (netring 0.20 — declarative Monitor API)"
block stays as-is — historical context for future maintainers.

## 6. CHANGELOG date stamp

The shipped 0.21 entry header currently reads `## 0.21.0 —
Send Monitor + sharding + …`. On tag day, replace with
`## 0.21.0 — YYYY-MM-DD — Send Monitor + sharding + …` matching
the existing 0.20.0 / 0.19.0 / … format.

## 7. Risks

- **R1 — `monitor-quickstart` feature inflation.** Pulls 14
  flags. Embedded users still have the granular path; document
  in CLAUDE.md that lean builds should *not* enable this.
- **R2 — `0.22.0` legacy deletion.** Already announced in the
  deprecation notes; the migration guide is in place. No work
  on this branch.

## 8. Provenance

Original H.8 + H.10 + H.11 + H.12 from
`plans/netring-0.21-phase-H-release.md` (deleted on ship). The
content was renamed and re-scoped to "what's actually left
after H.1 + H.2 + H.3 + H.4 + H.6 + H.7 landed" — i.e. the
strictly release-gate slice.
