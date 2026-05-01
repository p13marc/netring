# netring — fix plans

Detailed remediation plans for the 45 issues identified during the deep code review.
Each phase is independently mergeable; later phases depend on earlier ones only where
explicitly noted.

## Phase order

| Phase | File | Theme | Issue IDs | Risk |
|-------|------|-------|-----------|------|
| 1 | [01-critical-correctness.md](01-critical-correctness.md) | Critical correctness bugs | #1, #2, #3, #4 | High — fixes unsound/broken paths |
| 2 | [02-api-consistency.md](02-api-consistency.md) | Silent failures, missing setters, error semantics | #5, #6, #7, #8, #9, #10, #11, #16, #17, #18 | Medium |
| 3 | [03-afxdp-completeness.md](03-afxdp-completeness.md) | AF_XDP feature parity & safety | #12, #13, #14, #21, #22, #31, #32, #33 | Medium — large surface |
| 4 | [04-bridge-tx-hardening.md](04-bridge-tx-hardening.md) | Bridge & TX semantics | #15, #20, #24, #34, #35 | Low–Medium |
| 5 | [05-api-tightening.md](05-api-tightening.md) | API safety & doc accuracy | #19, #23, #25, #26 | Medium — one breaking change |
| 6 | [06-feature-gaps.md](06-feature-gaps.md) | New surface area | #27, #28, #29, #30, #36, #37, #38, #44, #45 | Low |
| 7 | [07-tests-cleanup.md](07-tests-cleanup.md) | Tests, dead code, tracking | #39, #40, #41, #42, #43 | Low |

## Versioning

| Phase | Suggested version bump |
|-------|------------------------|
| 1, 2, 3, 4, 6, 7 | `0.2.x` patch (no breaking API) |
| 5 | `0.3.0` (one breaking signature: `attach_ebpf_filter`) |

`#19` is the only hard breaking change; the rest of phase 5 is soft. If `0.3.0` ships,
bundle the soft API tightening into it to amortize the SemVer bump.

## Cross-cutting infrastructure

Several phases share helpers; introduce them once in phase 2:
- `src/syscall.rs` — `eintr_loop()` wrapper for `poll`/`sendto`/`recvfrom`.
- `tests/helpers.rs` extensions — `unique_port`, `paired_veth`, `xdp_compatible_iface`.
- `src/internal/mod.rs` (private) — shared TX-completion scanning helper.

## Tracking

Each fix has a checklist line in its phase file:

```
- [ ] Implementation
- [ ] Unit test
- [ ] Integration test (where applicable)
- [ ] Doc update
- [ ] CHANGELOG entry
```

Mark complete as you go. Each fix should land as a single PR unless explicitly bundled.
