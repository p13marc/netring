# Plan 15 — Dedup stress test and pcap nanosecond round-trip

## Summary

Two small hardening additions, both prompted by `des-rs`'s wishlist
(F4 and F5 in `plans/feedback-from-des-rs-2026-05-09.md`):

1. A 10k-packet stress test for `Dedup::loopback()` that drives
   structured-payload TCP-shaped frames at 1 kHz with same-direction
   sub-millisecond cadence, asserting zero false-positive drops.
2. An explicit nanosecond round-trip test for `CaptureWriter` that
   asserts `ts_in == ts_out` to nanosecond precision after a
   write → read cycle.

No new public API. No new modules. Both ride along in the same
0.9.0 release as plans 13 + 14.

## Status

Done — landed in 0.9.0.

## Prerequisites

- None. Independent of plans 13 and 14.

## Out of scope

- A `Dedup::loopback_exact()` constructor that filters only on
  `PacketDirection::Outgoing` and skips content hashing. The
  `des-rs` feedback document offers this as Option 2 to F4 only "if
  the stress test shows real false positives." Defer until that
  trigger fires; the user-level workaround documented in F4 already
  covers any user who needs zero-tolerance exactness.

- Bumping pcap to PCAPNG. The current writer is legacy PCAP with
  `ts_resolution = NanoSecond` — the format already carries nanosecond
  timestamps; the only ask is to verify the round-trip. (The feedback
  document's example mentions `pcap_file::pcapng::PcapNgReader` and
  `block.enhanced_packet().unwrap().timestamp` — that doesn't apply
  here because netring writes legacy PCAP, not PCAPNG. The reader in
  the new test uses `pcap_file::pcap::PcapReader`.)

---

## Background

### F4 — Dedup stress test

`netring/src/dedup.rs:74-76` `Dedup::loopback()` is a 1 ms / 256-entry
xxh3-64 ring with direction-aware Outgoing↔Host pairing. Existing
tests in `dedup.rs:200-282`:

- `loopback_drops_outgoing_then_host_within_window` — 1 packet pair.
- `loopback_keeps_same_direction_repeats` — 1 packet pair, same direction.
- `loopback_keeps_outside_window` — 1 packet pair across the window.
- and several content-mode / edge-case tests.

None drives volume. The des-rs concern is specifically: structured
TCP-shaped payloads (lots of header overlap), same-direction, two
packets within < 2 ms (e.g., 500 Hz on a single connection). xxh3-64
collision probability is astronomical even for non-uniform input
distributions, so the expected outcome is `dropped() == 0` — but a
test fixture closes the question for evidence-pipeline users.

### F5 — pcap nanosecond round-trip

`netring/src/pcap.rs:59-72` constructs a legacy `PcapHeader` with
`ts_resolution = NanoSecond`. The packet-write path at lines 79-86
(`write_packet`) and 90-96 (`write_owned`) builds a `PcapPacket` from
`Duration::new(ts.sec as u64, ts.nsec)` — `Duration::new`'s second
argument is nanoseconds, so the fractional precision is preserved.

Existing test `round_trip_owned_packet` (`pcap.rs:142-156`) reads back
the data and `orig_len` but not the timestamp. Add an explicit assert.

---

## Files

### MODIFY

```
netring/netring/src/pcap.rs                     (extend existing test)
```

### NEW

```
netring/netring/tests/dedup_stress.rs           (volume / cadence test)
```

No CHANGELOG noise — both are pure-test additions.

---

## API delta

None. Test-only.

---

## Implementation steps

### F4 — `tests/dedup_stress.rs`

```rust
//! Stress test for `Dedup::loopback()` at sub-millisecond,
//! same-direction cadence with structurally-similar TCP-shaped
//! payloads. Asserts zero false-positive drops.

use std::time::Duration;
use netring::{Dedup, PacketDirection, Timestamp};

/// Build a TCP-shaped 1500-byte payload with deterministic-but-distinct
/// content per `seq`. The first ~54 bytes mimic Ethernet+IPv4+TCP
/// headers (heavily-similar across packets); the rest is unique.
fn synth_packet(seq: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 1500];
    // Ethernet header (14 B): same for every packet
    buf[0..6].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    buf[6..12].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x02]);
    buf[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4
    // IPv4 header (20 B): same src/dst, varying ID
    buf[14] = 0x45;
    buf[18..20].copy_from_slice(&(seq as u16).to_be_bytes()); // IP id
    buf[26..30].copy_from_slice(&[10, 0, 0, 1]); // src
    buf[30..34].copy_from_slice(&[10, 0, 0, 2]); // dst
    // TCP header (20 B): same ports, varying seq
    buf[34..36].copy_from_slice(&12345u16.to_be_bytes());
    buf[36..38].copy_from_slice(&80u16.to_be_bytes());
    buf[38..42].copy_from_slice(&seq.to_be_bytes());
    // Payload: deterministic-but-unique. Use seq as a varying byte
    // every 16 B so the body has structure without being identical.
    for i in 54..1500 {
        buf[i] = ((i as u32).wrapping_add(seq) & 0xff) as u8;
    }
    buf
}

#[test]
fn loopback_dedup_no_false_positives_at_1khz_same_direction() {
    let mut d = Dedup::loopback();
    let mut kept = 0u64;
    let mut ts_ns: u64 = 0;
    for seq in 0u32..10_000 {
        let pkt = synth_packet(seq);
        let ts = Timestamp::new((ts_ns / 1_000_000_000) as u32, (ts_ns % 1_000_000_000) as u32);
        if d.keep_raw(&pkt, PacketDirection::Outgoing, ts) {
            kept += 1;
        }
        ts_ns += 1_000_000; // 1 ms tick → 1 kHz
    }
    assert_eq!(d.dropped(), 0, "false positives at 1 kHz cadence");
    assert_eq!(kept, 10_000);
}

#[test]
fn loopback_dedup_no_false_positives_at_500hz_subms() {
    // Two packets ~1 ms apart on every tick — definitely inside the
    // 1 ms ring window. Stresses the same-direction "legitimate
    // retransmit" path.
    let mut d = Dedup::loopback();
    let mut ts_ns: u64 = 0;
    for seq in 0u32..10_000 {
        let pkt = synth_packet(seq);
        let ts = Timestamp::new((ts_ns / 1_000_000_000) as u32, (ts_ns % 1_000_000_000) as u32);
        assert!(
            d.keep_raw(&pkt, PacketDirection::Outgoing, ts),
            "dedup dropped distinct packet seq={seq}"
        );
        ts_ns += 500_000; // 500 µs tick → 2 kHz
    }
    assert_eq!(d.dropped(), 0);
}
```

Two tests because they probe slightly different concerns (1 ms cadence
matches the documented window edge; 500 µs cadence is well *inside*
it, where collisions would surface fastest).

If either fails, the next step is option 2 from F4 (`loopback_exact()`),
not adjusting the test.

### F5 — extend `pcap.rs::round_trip_owned_packet`

Modify the existing test (or add a sibling `round_trip_nanosecond_timestamp`):

```rust
#[test]
fn round_trip_owned_packet_preserves_nanosecond_timestamp() {
    let mut buf = Vec::new();
    let ts_in = Timestamp::new(1_700_000_000, 123_456_789);
    {
        let cursor = Cursor::new(&mut buf);
        let mut w = CaptureWriter::create(cursor).expect("create");
        let mut pkt = make_owned(vec![1, 2, 3, 4, 5]);
        pkt.timestamp = ts_in;
        w.write_owned(&pkt).expect("write");
    }
    let cursor = Cursor::new(&buf);
    let mut reader = pcap_file::pcap::PcapReader::new(cursor).expect("reader");
    let record = reader.next_packet().expect("first").expect("record");
    let ts_out = record.timestamp;
    assert_eq!(
        ts_out,
        Duration::new(ts_in.sec as u64, ts_in.nsec),
        "nanosecond precision lost across pcap round-trip"
    );
    // Sanity: data preserved too.
    assert_eq!(record.data.as_ref(), &[1, 2, 3, 4, 5]);
}
```

Keep the existing `round_trip_owned_packet` test as-is (it asserts on
data + orig_len; the new test focuses on the timestamp). Or fold the
two — either is fine; folding is one fewer test name.

---

## Tests

(Implementation steps above ARE the tests — this plan is test-only.)

---

## Acceptance criteria

- [ ] `cargo test -p netring dedup_stress` passes (both tests).
- [ ] `cargo test -p netring round_trip_owned_packet_preserves_nanosecond_timestamp`
      passes.
- [ ] `cargo test --all-features` passes overall.
- [ ] No CHANGELOG entry needed (test-only).

---

## Risks

- **xxh3-64 collision in the 10k stress test**. If we hit one, the
  test fails and we ship the `loopback_exact()` API as a follow-up.
  The synthetic generator is deterministic, so a failure is
  reproducible. Probability is ~2⁻⁵⁰ — for practical purposes, zero.

- **Timestamp precision in `pcap_file` 2.x**. Confirm the crate
  exposes timestamps as `Duration` with nanosecond resolution
  (it does, per its docs and the existing `Duration::new` write
  path). If `record.timestamp` turns out to be microsecond-truncated
  for some reason, the test catches it — and the fix is in the writer,
  not the test.

---

## Effort

- Code: 0 LoC (no public API changes).
- Test: ~80 LoC (one new test file + one new test in `pcap.rs`).
- **Estimate**: 1 hour total. Same as the feedback document's
  estimate for F4 option 1 + F5.
