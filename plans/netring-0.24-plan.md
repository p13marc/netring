# netring 0.24 — Zero-Copy Core + Production Trust

> First of two pre-1.0 releases of the new architecture
> ([`netring-architecture.md`](./netring-architecture.md) — read it first). **0.24 is
> the keystone + credibility release:** rewrite the I/O core so the high-level `Monitor`
> is finally **zero-copy + `Send` + AF_XDP-capable** (Phase B), make it **resilient**,
> and make netring trustworthy in production (telemetry, observability, the export
> formats downstream tools ingest, JA4). The redesigned *API* (subscriptions, async
> effects) follows in 0.25; both are field-tested before 1.0.
>
> Additive-with-shims (arch §7): existing 0.23 monitors compile unchanged. Grounded in
> code audits (file:line inline).

## Scope & locked decisions
- **0.24 =** foundations + I/O keystone + production trust. (0.25 = subscriptions +
  async-effect redesign + perf numbers + TX.)
- **0.23 (Send)** ships first as a small low-risk interim; 0.24 builds on it.
- **OTLP/Kafka** → a separate **`netring-exporters` companion crate** (heavy async/C deps out
  of core); **syslog + IPFIX in-tree** (minimal encoder; `netgauze-flow-pkt` = documented
  alternative).
- **`Packets` miri:** if strict-provenance flags the lifetime-erasure transmute, ship the
  safer borrowed `for_each`/closure surface (Phase B) — don't ship a known miri failure.
- **Health endpoint:** netring exposes a `MonitorHealth` struct/handle; the embedder serves HTTP.

## Cross-cutting invariants (every commit)
1. clippy `--all-features -D warnings` · `fmt --check` · `RUSTDOCFLAGS="-D warnings" doc` — clean.
2. `benches/zero_alloc.rs` reads **Δ 0 / 0** **and** a live-capture test reads **0 heap
   allocs/packet** in the run loop.
3. Run-loop future stays **`Send + 'static`** (`tests/monitor_send.rs`).
4. **miri** green on the pure-logic suite; **cargo-fuzz** smoke green.
5. flowscope dep floor `>= 0.15.0`.

## Status table
| Phase | Item | Breaking | Status |
|---|---|---|---|
| A | non-Linux `compile_error!` | no | ✅ |
| A | feature-graph flatten + crate-boundary contract + `monitor-lite` | yes | ✅ |
| A | miri CI + cargo-fuzz + loom scaffold | no | ✅ (loom→0.25) |
| A | docs consolidation (one tree) + `FEATURES.md` | no | ✅ |
| A | perf-gate harness (pps/latency bench + baseline + live-alloc) | no | ✅ |
| **B** | **borrowed zero-copy + Send run loop** (per-packet copy eliminated) | no | ✅ |
| B | `AnyBackend` enum + AF_XDP + pcap unify (AF_XDP reaches the Monitor) | shim | ☐ |
| B | resilience: handler-isolation + backend-error policy | no | ✅ (panic-catch + Reopen → AnyBackend) |
| B | AF_XDP UMEM hugepages + NUMA + ZC/cloud-fallback detect | no | ☐ |
| B | io_uring ZC-RX seam (design only) | no | ✅ (`docs/BACKENDS.md`) |
| C | `CaptureTelemetry` + run-loop sampling + `on_capture_stats` + `CaptureHealth` | minor | ☐ |
| C | bounded `ChannelSink` + lag/error counters; backpressure contract | minor | ☐ |
| C | `MonitorHealth` + readiness/liveness + tracing JSON + `METRICS.md` | no | ☐ |
| D | exporter taxonomy + `FlowRecord`/`FlowExporter` + `.export_flows()` | no | ☐ |
| D | `SyslogSink` (RFC 5424) + IPFIX/NetFlow v10 (in-tree) | no | ☐ |
| D | `netring-exporters` companion crate: OTLP + Kafka | no | ☐ |
| E | JA4/JA4S surfacing (`on_fingerprint`, EVE fields) + flowscope 0.15 | no | ☐ |
| R | flowscope 0.15 lockstep · CHANGELOG · migration · publish | — | ☐ |

**Order:** A (de-risk) → **B** (keystone) → C → D, with E parallel. Release gated on the
flowscope 0.15 publish (Phase E lockstep).

---

## Phase A — Foundations & Hardening
*Independent; first; cheap, high-leverage.*

- **A1 non-Linux guard** — `src/lib.rs` (after `#![warn(missing_docs)]`):
  `#[cfg(not(target_os="linux"))] compile_error!("netring requires Linux … use the `pcap` crate.")`.
  Off-Linux today dies deep in libc/nix/aya (`afpacket/ffi.rs:11`).
- **A2 feature flatten *(breaking)*** — orthogonal axes documented in `Cargo.toml` + a new
  `netring/docs/FEATURES.md` (matrix + recipes) and `CRATE_BOUNDARY.md` (flowscope =
  computational/no-tokio; netring = async/capture/sinks). Add
  `monitor-lite = ["tokio","channel","flow"]`. New export features `syslog`/`ipfix`. CI
  `check` builds `--no-default-features`, `--features flow`, `af-xdp`, `monitor-lite`,
  `tokio,flow,dns,http`. Keep `correlate::KeyIndexed` netring-side (flowscope's LRU variant
  is deliberately different).
- **A3 miri + fuzz + loom** — miri (nightly) over the ~13 audit-listed pure-logic test files
  + miri-safe lib tests (`#[cfg_attr(miri, ignore)]` the socket/mmap ones); cargo-fuzz
  `fuzz_bpf_builder` + `fuzz_bpf_matches` (`BpfFilter::matches` walks untrusted offsets), seed
  from `synth_eth_ipv4_tcp`; loom scaffold over `monitor/merge.rs`. **If miri flags the
  `Packets` transmute → Phase B ships the safer surface.**
- **A4 docs consolidation** — move root `docs/*` (8 files) into `netring/docs/`; keep the
  `README → netring/README` symlink; fix `../docs/` vs `docs/` links; add `docs/INDEX.md`.
- **A5 perf-gate harness** — root-gated loopback/`veth` pktgen → pps/latency/drop + baseline
  JSON + permissive CI regression gate; **live-alloc test** harness (counting allocator/dhat
  over real packets) that Phase B uses to prove 0 allocs/packet.
- **Accept:** off-Linux friendly error; `monitor-lite` + 5 combos build; miri/fuzz green;
  one docs tree, no dangling links; perf+alloc harness runs on `lo`.

## Phase B — I/O Core Rewrite (THE KEYSTONE) — arch §3, §6
*The single most important piece. `backend()` axis is additive (shim for `interface()`).*

**Findings:** (1) the Monitor copies every packet (`tokio_adapter.rs:498`
`to_owned().collect()`, `packet.rs:254`); (2) AF_XDP never reaches the Monitor (`run.rs:106-115`
opens AF_PACKET only; `AsyncXdpSocket` unwired; pcap is a 3rd path).

- **B1 `AnyBackend` enum** (arch §3) — concrete enum (AfPacket/Xdp/Pcap, cfg-gated) with
  `async fn readable` (concrete ⇒ `Send`, avoiding the AFIT `!Send` trap) + a generic
  `drain_batch(impl FnMut(PacketView))` (monomorphized; not object-safe but that's fine on an
  enum) + `stats`/`set_filter`/`kind`. `MonitorBuilder::backend(Backend::{AfPacket{fanout} |
  Xdp{mode,queue} | Pcap{path,speed}})`; `interface()`/`fanout()`/`pcap_source()`/`replay()`
  become `#[deprecated]` shims. The three loops collapse into one generic loop over
  `Vec<AnyBackend>`; `replay_loop` deleted.
- **B2 borrowed zero-copy + Send loop** (arch §3) — `select!{shutdown | ready_backend |
  tick | merge | telemetry}` → `backends[i].drain_batch(|view| { track_into; packet-tier;
  lifecycle (sync mut + collect async futures); slot messages })` → drop batch → await the
  collected `'static` `Effects`-futures + apply. **0 packet copies**; `Send` preserved. If
  miri flagged the transmute, the `drain_batch(|view|)` closure shape is the safer surface
  (forbids `.collect()`). Public `PacketStream`/`recv()` stay for owned users.
- **B3 AF_XDP + pcap backends** — `AsyncXdpSocket` arm (zero-copy UMEM batch + batched fill
  refill, `afxdp/batch.rs:168-178`; per-queue XSKs); pcap arm folds in `replay_loop`. **First
  time the declarative API runs on AF_XDP.**
- **B4 resilience** (arch §6) — `backend_error_policy(FailFast|SkipSource|Reopen{backoff})`,
  `handler_error_policy(Propagate|Isolate)`, opt-in `catch_handler_panics`; all emit telemetry
  counters (Phase C). (Today `run.rs:185` returns `Err` on first backend error.)
- **B5 UMEM hugepages + NUMA + mode** — `UmemBuilder::hugepages(TwoMiB|OneGiB)` (`MAP_HUGETLB`,
  fallback like `MAP_LOCKED`), `::numa_node(n)` (`mbind`); `XdpSocket::mode()->{ZeroCopy|Copy}`
  + `tracing::warn!` on silent copy-mode fallback (virtio/cloud). (`afxdp/umem.rs:26-55`.)
- **B6 io_uring seam** — `BACKENDS.md` documents how an `IoUringZcRx` arm fits `AnyBackend`
  for session-tier later. No code.
- **Tests:** live-alloc 0/packet; `monitor_send` green; multi-interface fairness; AF_XDP
  end-to-end (rig); resilience (SkipSource keeps other sources; Reopen recovers; Isolate +
  panic-catch counts and continues); hugepage/NUMA fallback; `mode()` correct.
- **Accept:** one generic loop; `replay_loop` gone; 0 allocs/packet; AF_XDP runs; resilience
  policies + counters; `BACKENDS.md`.

## Phase C — Telemetry & Self-Observability — arch §1, §6
*Run-loop-level (capture handles aren't in `Ctx`). Minor breaking (one new `ChannelSink` ctor).*

- **C1 `CaptureTelemetry`** (`src/monitor/telemetry.rs`) — per-source packets/drops/freezes/
  ring-full + drop_rate; sampled by a **gated** run-loop interval (zero cost unused, like the
  tick/merge branches). AF_PACKET destructive-read accumulated; AF_XDP monotonic.
- **C2 hooks** — `.on_capture_stats(period, |telemetry, ctx|)` + built-in `CaptureHealth:
  Report` (`.capture_health(period)`) over the report stream; Prometheus gauges
  `netring_capture_{packets,drops,freezes,drop_rate}{source}` + the Phase B resilience counters.
- **C3 backpressure honesty** — `ChannelSink::bounded(cap)` (today unbounded
  `shipped_sinks.rs:252-270`) drop-with-count; broadcast `Lagged` surfaced; contract documented
  in `ASYNC_GUIDE.md` ("capture task never blocks on a slow sink").
- **C4 `MonitorHealth`** — `Arc`-backed handle (telemetry + active-flow count + uptime +
  last-event age); readiness (sockets open + first packet/grace) vs liveness (ticked within
  N×period); `examples/monitor/health_endpoint.rs` (axum dev-dep).
- **C5** `tracing` JSON example + `METRICS.md` (every `netring_*` metric, cardinality-safe).
- **Tests:** induced drops surface through `on_capture_stats`+report+Prometheus; bounded sink
  shows bounded memory + drop count; readiness flips on first packet; dhat Δ0 when telemetry off.

## Phase D — Exporters — arch §1
*All additive, feature-gated. Reuses the sink/report rails; flow records need `FlowEnded` stats.*

- **D1 taxonomy + `FlowRecord`** (`src/export/mod.rs`) — name the three shapes (anomaly/
  report/**flow** exporters); `FlowRecord` from `FlowEnded<P>` (`key` + flowscope `FlowStats`:
  bytes/pkts/start-end/flags) + active-flow timeout; `FlowExporter` trait; `.export_flows(e)`.
  **Verify** flowscope `FlowStats` directional counts; if totals-only, ship totals in 0.24 +
  file flowscope follow-up.
- **D2 `SyslogSink`** (RFC 5424, `feature="syslog"`) — hand-rolled, no deps, `EveSink<W>` shape.
- **D3 IPFIX/NetFlow v10** (`feature="ipfix"`) — minimal in-tree encoder for ~12 core IANA IEs;
  template + data sets over a `Write`; `netgauze-flow-pkt` documented as the full alternative.
- **D4 `netring-exporters` companion crate** — `OtlpAnomalySink` (anomalies→OTLP logs,
  telemetry→OTLP metrics) + `KafkaSink` (over `ChannelSink`); core dep graph unchanged.
- **Tests:** IPFIX golden bytes (roundtrip via tiny parser/dev-dep); syslog RFC-5424 format;
  examples `ipfix_export.rs`/`syslog_alerts.rs` on `lo`.

## Phase E — JA4 / JA4S — arch §1
*Mostly already built. The flowscope half gates the publish (lockstep).*

flowscope 0.14.1 **already ships JA4(client)+JA3**; `TlsHandshake` exposes `.ja4`/`.ja3`,
surfaced via `on::<TlsHandshake>`. Gaps:
- **E1 flowscope 0.15** (companion plan; ~410 LoC, 0 deps, additive): ServerHello extension +
  sig-alg extraction → `TlsServerHello`; `ja4s` module + `Ja4s` variant + `TlsHandshake.ja4s`;
  QUIC transport marker (`'q'`/`'t'`). Publish **flowscope 0.15.0**.
- **E2 netring surfacing** (after the publish): bump `flowscope = "0.15"`;
  `on_fingerprint(|fp: &TlsFingerprint, ctx|)` bundling `{ja3,ja4,ja4s,sni,alpn,key}`;
  JA4/JA4S/SNI in EVE `tls` records; `examples/monitor/ja4_fingerprint.rs` (IOC match);
  `FINGERPRINTS.md` notes JA4 = BSD-3, JA4+ = FoxIO 1.1 (future feature-gate, not 0.24).

## Phase R — Release
1. flowscope 0.15.0 published first; netring dep `>= 0.15`. 2. All gates green (fmt — don't
skip; clippy; doc; dhat Δ0 + 0-allocs/packet; miri; fuzz; perf regression; root-gated tests).
3. Version `0.23 → 0.24`; CHANGELOG `## 0.24.0`; `docs/MIGRATING_0.23_TO_0.24.md` (backend axis
+ shim, bounded channel, feature flatten, telemetry/export hooks); publish `netring-exporters`
0.1. **No SemVer promise (that's 1.0).** 4. `cargo publish` (both crates); tag `0.24.0`; push;
delete this plan + the 0.24 phase notes (delete-on-ship).

## Grounding (file:line)
`run.rs:100-117,116,143-185,199-236,480-520` · `tokio_adapter.rs:257,480-505` ·
`packet.rs:245-266(:254),481-536` · `afpacket/rx.rs:199-215,249-280` · `tokio_xdp.rs` ·
`afxdp/{umem.rs:26-55,ring.rs:195-232,batch.rs:168-178,socket.rs,stats.rs:15-32}` ·
`stats.rs:10-17` · `traits.rs:99-101` · `anomaly/{sink.rs:65-89,eve_sink.rs:51-127,
metrics_sink.rs:60-137,shipped_sinks.rs:252-270}` · `report/mod.rs:31-111` ·
`ctx/mod.rs:70-163` · `Cargo.toml:76-149` · `.github/workflows/ci.yml` ·
`tests/{monitor_send.rs,bpf_builder_proptest.rs}`. flowscope: `src/tls/{ja4,types,session,
handshake,parser,mod}.rs`. netring TLS: `protocol/builtin/{tls,tls_handshake}.rs`.
