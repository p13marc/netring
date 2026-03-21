# Phase 7: Tests, Benchmarks, Examples, Documentation

## Goal

Comprehensive test coverage, performance benchmarks, runnable examples, and
production-quality documentation.

## Prerequisites

Phases 1-6 complete.

## Cargo.toml Additions

```toml
[features]
integration-tests = []

[dev-dependencies]
divan = "0.1"
criterion = { version = "0.5", features = ["html_reports"] }
socket2 = "0.5"

[[bench]]
name = "poll_throughput"
harness = false

[[bench]]
name = "e2e_capture"
harness = false
```

## 1. Unit Tests (No Privileges)

Located as `#[cfg(test)] mod tests` in each source file.

### src/afpacket/ffi.rs

- `test_tpacket_block_desc_size` — size_of matches kernel (48 bytes)
- `test_tpacket3_hdr_size` — size_of matches kernel
- `test_tpacket_req3_size_and_offsets` — 28 bytes, all field offsets
- `test_sockaddr_ll_size` — 20 bytes
- `test_tpacket_stats_v3_size` — 12 bytes
- `test_constants_match_kernel` — all constant values from spec appendix
- `test_tpacket_align` — tpacket_align(1)=16, tpacket_align(16)=16, tpacket_align(17)=32

### src/packet.rs

**Test infrastructure:** `build_synthetic_block(packets: &[(usize, &[u8])]) -> Vec<u8>`
— constructs a properly formatted TPACKET_V3 block with chained tpacket3_hdr entries.

- `test_batch_iter_single_packet` — 1 packet, verify len/data
- `test_batch_iter_multiple_packets` — 3 chained packets, verify order and content
- `test_batch_iter_empty_block` — num_pkts=0, yields nothing
- `test_batch_iter_bounds_check_bad_next_offset` — offset past block end, stops safely
- `test_batch_iter_bounds_check_bad_snaplen` — snaplen past block end, stops safely
- `test_packet_status_flags` — each TP_STATUS flag decodes correctly
- `test_packet_to_owned` — data, timestamp, original_len match
- `test_batch_timed_out_flag` — TP_STATUS_BLK_TMO detection
- `test_batch_seq_num` — reads seq_num from header
- `test_timestamp_conversions` — to_system_time, to_duration, Display, Ord

### src/config.rs

- `test_fanout_mode_as_raw` — each variant → correct kernel constant
- `test_fanout_flags_bitwise` — ROLLOVER | DEFRAG = 0x9000
- `test_timestamp_source_default` — Software
- `test_bpf_insn_layout` — size_of == 8, matches sock_filter

### src/capture.rs

- `test_builder_defaults` — verify 4 MiB, 64, 2048, 60ms
- `test_builder_validation_block_size_not_pow2` — Error::Config
- `test_builder_validation_frame_size_not_aligned` — Error::Config
- `test_builder_validation_missing_interface` — Error::Config

### src/error.rs

- `test_error_is_send_sync`
- `test_error_display` — each variant

## 2. Integration Tests (CAP_NET_RAW, feature: `integration-tests`)

### tests/helpers/mod.rs

- `send_udp_to_loopback(port, payload, count)` — sends known UDP packets
- `unique_port() -> u16` — atomic counter for port allocation
- `LOOPBACK = "lo"`

### tests/loopback_capture.rs

- `test_capture_loopback_basic` — send 10 UDP, capture, verify payload match
- `test_capture_with_bpf_filter` — filter by port, verify only matching packets
- `test_low_level_rx_next_batch` — AfPacketRx directly, verify PacketBatch
- `test_capture_promiscuous` — no crash on loopback

### tests/block_timeout.rs

- `test_block_timeout_triggers` — timeout_ms=10, 1 packet, batch.timed_out() == true

### tests/statistics.rs

- `test_capture_stats_basic` — send N, verify stats.packets >= N, drops == 0
- `test_stats_reset_on_read` — second read shows 0

### tests/injector.rs

- `test_inject_loopback` — inject frame, capture on separate socket, verify
- `test_inject_allocate_send_flush` — 10 frames, flush returns 10
- `test_inject_drop_without_send` — dropped slot not sent

### tests/fanout.rs

- `test_fanout_two_sockets` — 2 sockets, FanoutMode::Hash, both receive some packets

### tests/async_capture.rs (features: `integration-tests` + `tokio`)

- `test_async_capture_recv` — tokio::test, recv().await returns batch

### tests/channel_capture.rs (features: `integration-tests` + `channel`)

- `test_channel_capture_recv` — spawn, send, recv OwnedPacket
- `test_channel_capture_drop` — drop stops thread

### tests/error_conditions.rs

- `test_interface_not_found` — Error::InterfaceNotFound
- `test_enomem_retry` — huge ring, graceful degradation

## 3. Benchmarks

### benches/poll_throughput.rs (divan)

- `bench_next_batch_loopback` — batches/sec with UDP flood
- `bench_batch_iter` — packets/sec iterating pre-captured batch
- `bench_packet_to_owned` — copy throughput
- `bench_timestamp_conversion` — Timestamp → SystemTime

### benches/e2e_capture.rs (criterion)

- `bench_e2e_mpps` — end-to-end Mpps, parameterized by block_size
- `bench_e2e_varying_block_count` — parameterized by block_count
- `bench_e2e_injector_throughput` — TX path Mpps

## 4. Examples

### examples/capture.rs

Basic capture from spec section 12. Interface from CLI arg. Print timestamp + length.

### examples/fanout.rs

Multi-threaded fanout from spec. N threads, FanoutMode::Cpu, per-thread counters.

### examples/inject.rs

Packet injection from spec. Build Ethernet frames, send, flush.

### examples/batch_processing.rs

Low-level API: sequence gap detection, per-batch stats.

### examples/async_capture.rs (requires `tokio` feature)

Async capture with tokio from spec.

### examples/ebpf_filter.rs (optional — demonstrates `aya` integration)

Shows attaching an eBPF socket filter via `Capture::as_fd()`. From spec section 12.
Documents that `AsFd` on all handles enables external eBPF without raw fds.

## 5. Documentation

### System Requirements (in README.md)

Document required Linux capabilities:
- `CAP_NET_RAW` — creating AF_PACKET sockets
- `CAP_IPC_LOCK` — `MAP_LOCKED` (or sufficient `RLIMIT_MEMLOCK`)
- `CAP_NET_ADMIN` — promiscuous mode
- Alternative: `setcap cap_net_raw+ep /path/to/binary`

Include tuning profiles table from spec section 10.

### src/lib.rs

- `#![doc = include_str!("../README.md")]`
- Module-level docs for each `pub mod`

### Cargo.toml

```toml
[package.metadata.docs.rs]
all-features = true
rustdoc-args = ["--cfg", "docsrs"]
```

### Doc comment requirements for all public items

- Summary line
- `# Examples` with `no_run` doctests
- `# Errors` on fallible methods
- `# Safety` on all `unsafe fn`
- `# Panics` where applicable

### README.md

- Overview, quick start, feature flags, system requirements, license

## Implementation Order

1. Test helpers + synthetic block builder
2. FFI layout assertion tests
3. Config/builder validation tests
4. Packet module tests (BatchIter synthetic)
5. Integration test infrastructure
6. Integration tests
7. Examples
8. Benchmarks
9. Documentation pass

## Verification

```bash
cargo test                                        # unit tests
cargo test --features integration-tests           # + integration (needs CAP_NET_RAW)
cargo test --features "integration-tests,tokio"   # + async tests
cargo test --features "integration-tests,channel" # + channel tests
cargo bench                                       # benchmarks
cargo doc --all-features --no-deps                # docs build
```
