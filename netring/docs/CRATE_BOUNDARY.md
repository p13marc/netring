# netring ↔ flowscope — the crate boundary

netring and [`flowscope`](https://github.com/p13marc/flowscope) are deliberately split
along one contract. Keep new code on the correct side of it.

## The rule

| | **flowscope** | **netring** |
|---|---|---|
| Nature | computational, **no-tokio** | async, capture/runtime |
| Depends on tokio? | **never** | yes (behind `tokio`) |
| Owns | L2–L7 parsing, flow/session tracking, TCP reassembly, fingerprints (JA3/JA4/JA4S), correlate primitives, `Timestamp`/`PacketView` | capture backends (AF_PACKET/AF_XDP/pcap), the `Monitor`/subscription engine + run loop, `Ctx`/dispatch, sinks/exporters, sharding, observability |
| Test with | synthetic byte buffers, pcaps | live loopback (root-gated), pcaps |

**Why:** the hot computational paths must stay dependency-light and reusable without an
async runtime (embedded analysis, offline tools, other consumers). netring layers the
async capture + orchestration on top.

## Where things live

- **A new protocol parser / fingerprint / flow-stat / correlation primitive** → flowscope.
  netring surfaces it through a `Protocol` marker (`src/protocol/builtin/`) or a `Ctx`
  accessor. Example: JA4 lives in `flowscope::tls`; netring exposes it via `on_fingerprint`.
- **A new sink / exporter / capture backend / run-loop feature / subscription tier** → netring.
- **A correlate primitive** is the one grey area: `correlate::TimeBucketedCounter` etc. are
  re-exported *from* flowscope; `correlate::KeyIndexed` stays **netring-side** on purpose
  (flowscope's `KeyIndexed` is an LRU cache; netring needs immutable-get + TTL semantics for
  "expected-B-after-A" detectors).

## Versioning

netring pins a flowscope floor (currently `>= 0.15.0`). Computational work that netring
needs lands in a flowscope release first (lockstep publish), then netring bumps the floor.
See `CHANGELOG.md` for the per-release flowscope floor bumps.
