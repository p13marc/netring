# Plan 12 — Test infrastructure (fixtures + property-based + fuzz)

## Summary

Three foundations:

1. **Pcap fixtures** — small, real-traffic captures committed to the
   repo so examples and integration tests can run reproducibly.
2. **Property-based tests** via `proptest` + `proptest-state-machine`
   — verify the TCP state machine doesn't deadlock and that
   bidirectional canonicalization is consistent.
3. **`cargo-fuzz` harnesses** for the parsers (extractor, decap
   combinators) — catch panics on malformed frames.

Without these, regressions in Tier 2 (companion crates) are caught
by users instead of CI.

## Status

Not started.

## Prerequisites

- Plans 00–04 complete.

## Out of scope

- Differential testing against gopacket / Suricata. Worthy goal but
  separate plan; way too much glue for v1.
- Continuous fuzzing infrastructure (OSS-Fuzz integration). Manual
  `cargo fuzz run` for now; OSS-Fuzz is a separate effort.

---

## Part A — Pcap fixtures

### What to commit

Three small captures (~10 KB each) under `netring-flow/tests/data/`:

- **`http_session.pcap`** — single bidirectional TCP/HTTP/1.1
  exchange (SYN/SYN-ACK/ACK, GET, 200 OK, FIN/FIN/ACK). ~50 packets.
- **`dns_queries.pcap`** — UDP/53 query/response pairs, IPv4 + IPv6,
  one with NXDOMAIN. ~20 packets.
- **`mixed_short.pcap`** — small slice of mixed traffic: TCP, UDP,
  ICMP, one ARP. ~30 packets.

Total repo size impact: ~30 KB.

### How to generate

Use `scapy` or `tcpdump -i lo -w` while running synthetic clients
(curl, dig, ping). Strip MACs (so privacy isn't a concern) and trim
to the minimal exchange. Document the generation recipe in
`netring-flow/tests/data/README.md`.

### How tests use them

```rust
const HTTP_SESSION_PCAP: &[u8] = include_bytes!("data/http_session.pcap");

#[test]
fn http_session_full_lifecycle() {
    let reader = PcapReader::new(std::io::Cursor::new(HTTP_SESSION_PCAP)).unwrap();
    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut events = Vec::new();
    for pkt in reader { /* drive tracker */ }
    // Assert: 1 flow Started, 1 Established, 1 Ended with reason=Fin
    assert_eq!(events.iter().filter(|e| matches!(e, FlowEvent::Established { .. })).count(), 1);
    // ... etc
}
```

`include_bytes!` keeps fixtures inline so test binaries are
self-contained; no `tests/data/` directory dependency at runtime.

---

## Part B — Property-based tests

### Properties to verify

1. **Round-trip canonicalization**: for any pair of (packet, swapped-packet),
   `FiveTuple::bidirectional().extract` produces the same key with
   opposite orientations.
2. **TCP state monotonicity**: starting from `Active`, no sequence
   of TCP flag combinations can reach `Closed` without passing
   through `Established` (or going via `Reset`).
3. **TCP state machine reaches a terminal state** for every valid
   FIN/RST sequence within ≤ 10 transitions.
4. **`FlowTracker` invariants**: `flow_count() ≤ max_flows` always;
   `stats().flows_created == flows_ended + flow_count() + flows_evicted`.
5. **`BufferedReassembler` ordering**: feeding in-order segments
   produces concatenated bytes regardless of segment sizing.

### Implementation

```toml
# netring-flow/Cargo.toml
[dev-dependencies]
proptest = "1"
proptest-state-machine = "0.5"
```

Tests in `netring-flow/tests/proptest_invariants.rs`:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn five_tuple_canonicalizes(
        a in any_socket_addr(),
        b in any_socket_addr(),
        proto in prop_oneof![Just(L4Proto::Tcp), Just(L4Proto::Udp)],
    ) {
        // Construct synthetic frame for (a -> b) and (b -> a)
        // Extract keys
        // Assert: keys equal, orientations differ
    }

    #[test]
    fn tcp_state_terminates(seq in tcp_flag_sequence(20)) {
        let mut state = FlowState::Active;
        for (flags, side) in seq {
            state = tcp_state::transition(state, flags, side).state;
        }
        // Either reached terminal or stayed in handshake/data
        // Assert: never panicked, state is one of the known variants
    }
}
```

For the TCP state machine specifically, use `proptest-state-machine`:

```rust
struct TcpStateMachine;
impl ReferenceStateMachine for TcpStateMachine {
    type State = FlowState;
    type Transition = (TcpFlags, FlowSide);

    fn init_state() -> BoxedStrategy<Self::State> { Just(FlowState::Active).boxed() }
    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        // generate plausible flag sequences for current state
        ...
    }
    fn apply(state: Self::State, transition: &Self::Transition) -> Self::State {
        tcp_state::transition(state, transition.0, transition.1).state
    }
}
```

---

## Part C — Fuzz harnesses

### Targets

```
netring-flow/fuzz/
├── Cargo.toml
└── fuzz_targets/
    ├── extract_five_tuple.rs       # FiveTuple::extract on arbitrary bytes
    ├── extract_strip_vlan.rs       # StripVlan(FiveTuple)
    ├── extract_strip_mpls.rs       # StripMpls(FiveTuple)
    ├── extract_inner_vxlan.rs      # InnerVxlan
    ├── extract_inner_gtpu.rs       # InnerGtpU
    └── parse_eth.rs                # internal parse_eth helper
```

### Each target

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use netring_flow::extract::FiveTuple;
use netring_flow::{FlowExtractor, PacketView, Timestamp};

fuzz_target!(|data: &[u8]| {
    let view = PacketView::new(data, Timestamp::default());
    // Should never panic, even on malformed input.
    let _ = FiveTuple::bidirectional().extract(view);
});
```

### Invariants

- **No panics** on any input.
- **No infinite loops** (libfuzzer detects via timeout).
- **No unbounded memory growth** (libfuzzer detects via OOM).

### CI integration

Add a CI job that runs each fuzz target for ~30 seconds on PR. Not
exhaustive but catches obvious regressions:

```yaml
fuzz:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v5
    - uses: dtolnay/rust-toolchain@nightly
    - run: cargo install cargo-fuzz
    - run: |
        cd netring-flow
        for target in $(ls fuzz/fuzz_targets/*.rs | xargs -n1 basename | sed 's/.rs$//'); do
          cargo +nightly fuzz run "$target" -- -max_total_time=30
        done
```

### Local workflow

```
just fuzz-extract       # 60-second pass over all extractor targets
just fuzz-target X      # single target, runs until interrupted
```

---

## Files

### NEW

```
netring-flow/tests/data/
├── README.md           # how the fixtures were generated
├── http_session.pcap
├── dns_queries.pcap
└── mixed_short.pcap

netring-flow/tests/
├── pcap_http.rs        # HTTP fixture-driven test
├── pcap_dns.rs         # DNS fixture-driven test
├── pcap_mixed.rs       # Mixed fixture
└── proptest_invariants.rs  # proptest properties

netring-flow/fuzz/
├── Cargo.toml
├── .gitignore          # ignore corpus artifacts
└── fuzz_targets/
    ├── extract_five_tuple.rs
    ├── extract_strip_vlan.rs
    ├── extract_strip_mpls.rs
    ├── extract_inner_vxlan.rs
    ├── extract_inner_gtpu.rs
    └── parse_eth.rs
```

### MODIFIED

- `netring-flow/Cargo.toml` — add `proptest`, `proptest-state-machine`
  to `[dev-dependencies]`.
- `justfile` — add `fuzz-*` recipes.
- `.github/workflows/ci.yml` — add `fuzz` job (PR-only, not merge).
- `netring-flow/src/extract/parse.rs` — promote `test_frames` from
  `#[cfg(test)] pub(crate)` to a proper `pub mod` gated behind a
  `test-helpers` feature so benches and proptest helpers can use it.

---

## Implementation steps

### Part A — Fixtures

1. Generate the three pcaps locally:
   - `http_session.pcap`: `tcpdump -i lo -w http_session.pcap` while
     running `curl http://127.0.0.1:8000/`.
   - `dns_queries.pcap`: similar with `dig`.
   - `mixed_short.pcap`: capture a few seconds of normal traffic
     and trim with `editcap -F pcap -r http_session.pcap mixed_short.pcap 1-30`.
2. Verify with Wireshark; trim down.
3. Commit under `netring-flow/tests/data/`.
4. Write fixture-driven tests.

### Part B — Property-based tests

5. Add `proptest` + `proptest-state-machine` dev deps.
6. Write `proptest_invariants.rs`:
   - 5 properties as listed above.
   - 1000 iterations per property by default.
7. Run locally: `cargo test -p netring-flow --test proptest_invariants`.

### Part C — Fuzz

8. `cd netring-flow && cargo fuzz init` — creates the `fuzz/` subdir.
9. Write the 6 fuzz targets.
10. Build the corpus: each target gets a tiny seed corpus from
    existing test frames (write a script that dumps test_frames into
    `fuzz/corpus/$target/`).
11. Run each for 60 seconds locally; ensure no panics.
12. Add CI job (not on every push — too slow; gate on PR + nightly cron).

### Test_frames promotion

13. In `netring-flow/Cargo.toml`:
    ```toml
    [features]
    test-helpers = []
    ```
14. In `netring-flow/src/extract/parse.rs`:
    ```rust
    #[cfg(any(test, feature = "test-helpers"))]
    pub mod test_frames { ... }
    ```
15. In `netring-flow/src/lib.rs`:
    ```rust
    #[cfg(feature = "test-helpers")]
    pub use extract::parse::test_frames;
    ```
16. Proptest will activate `test-helpers` via dev-deps in its
    Cargo.toml.

---

## Tests

This plan IS testing infrastructure. Acceptance is:

- `cargo test --workspace --all-features` includes the 3 new
  fixture-driven tests + the proptest module.
- Each fuzz target builds: `cargo +nightly fuzz build --fuzz-dir netring-flow/fuzz`.
- A 60-second fuzz run completes without panics on every target.

---

## Acceptance criteria

- [ ] 3 pcap fixtures committed (`http_session`, `dns_queries`, `mixed_short`).
- [ ] 3 fixture-driven integration tests pass.
- [ ] `proptest_invariants.rs` covers 5 properties; runs in `cargo test`.
- [ ] 6 fuzz targets build under `cargo +nightly fuzz`.
- [ ] CI fuzz job (≤2 min) added to PR workflow.
- [ ] `test_frames` module is `pub` under `test-helpers` feature.
- [ ] Total repo size grows by < 50 KB.

---

## Risks

1. **Pcap fixture privacy.** Generate from synthetic localhost
   traffic only; never commit a capture from real network gear.
   Document this in `tests/data/README.md`.
2. **`proptest-state-machine` API churn.** It's pre-1.0; pin to a
   specific version. If it's painful, fall back to plain `proptest`
   with a hand-rolled state machine.
3. **Fuzz CI flakes.** Set a strict 30s timeout per target. If one
   target finds a real bug, mark the bug fix as a separate PR; do
   not block the test-infra plan landing.
4. **`include_bytes!` vs file path tradeoff.** `include_bytes!`
   bloats the test binary. For 30 KB total it's fine. If fixtures
   grow > 1 MB, switch to runtime-loaded files in `target/test-data/`.

---

## Effort

- LOC: ~800.
  - Tests + fixtures: ~300
  - Proptest: ~200
  - Fuzz targets: ~150
  - CI job: ~30
  - Doc/README updates: ~120
- Time: 1.5 days.

---

## What this unlocks

- Tier 2 companion crates (HTTP, TLS, DNS) get free integration tests
  via the pcap fixtures.
- Plan 31 (SessionParser) gets confidence-boosting property tests
  before the trait is locked.
- Future PRs that touch parsing get fuzz coverage for free.
