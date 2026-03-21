# Phase 1: FFI Layer & Foundations

## Goal

Set up the project structure, dependencies, error types, FFI kernel struct definitions,
configuration types, and value types (Timestamp, PacketStatus, OwnedPacket).

## Files

### Cargo.toml (modify)

- `edition = "2024"`, `rust-version = "1.85"`
- Dependencies: `libc = "0.2"`, `nix = { version = "0.31", features = ["socket", "mman", "poll", "net"] }`, `thiserror = "2"`, `log = "0.4"`, `bitflags = "2"`
- Feature stubs: `tokio`, `channel`, `nightly`, `integration-tests`
- docs.rs metadata: `all-features = true`

### src/lib.rs (replace)

- Module declarations: `error`, `config`, `stats`, `packet`, `afpacket`
- Re-exports of all public types at crate root
- `#![deny(unsafe_op_in_unsafe_fn)]`, `#![warn(missing_docs)]`

### src/error.rs (new)

- `Error` enum with `thiserror` 2.x: `Socket`, `Mmap`, `Config`, `InterfaceNotFound`, `Bind`, `SockOpt { option, source }`, `PermissionDenied`, `Io`
- `pub type Result<T> = std::result::Result<T, Error>`
- Tests: `Error` is `Send + Sync`, Display output, From<io::Error>

### src/afpacket/mod.rs (new)

- `pub mod ffi;` (other submodules added in later phases)

### src/afpacket/ffi.rs (new)

**Re-export from `libc` 0.2.183** (verified — libc exports ALL TPACKET_V3 types):
- Structs: `tpacket_req3`, `tpacket3_hdr`, `tpacket_hdr_variant1`, `tpacket_block_desc`, `tpacket_bd_header_u`, `tpacket_hdr_v1`, `tpacket_bd_ts`, `tpacket_stats_v3`, `sockaddr_ll`, `sock_filter`, `sock_fprog`
- Constants: `SOL_PACKET` (263), `PACKET_VERSION` (10), `PACKET_RX_RING` (5), `PACKET_TX_RING` (13), `PACKET_FANOUT` (18), `PACKET_STATISTICS` (6), `PACKET_ADD_MEMBERSHIP` (1), `PACKET_MR_PROMISC` (1), `PACKET_QDISC_BYPASS` (20), `PACKET_IGNORE_OUTGOING` (23), `PACKET_TIMESTAMP` (17), `ETH_P_ALL` (0x0003), `TPACKET_ALIGNMENT` (16), `TPACKET3_HDRLEN` (68), `TP_FT_REQ_FILL_RXHASH` (0x01), all `TP_STATUS_*`, all `PACKET_FANOUT_*`

**Caveat: `tpacket_bd_ts.ts_usec`** — libc flattened the kernel union to just `ts_usec`. TPACKET_V3 always provides nanosecond resolution, so read `ts_usec` as nanoseconds. Add a doc comment.

**Define ourselves (not in libc)**:
- `TP_STATUS_GSO_TCP: u32 = 0x100`
- `TPACKET_V3_INT: c_int = 2` (convenience for setsockopt)
- TX status: `TP_STATUS_AVAILABLE: u32 = 0`, `TP_STATUS_SEND_REQUEST: u32 = 1`, `TP_STATUS_SENDING: u32 = 2`, `TP_STATUS_WRONG_FORMAT: u32 = 4`
- `pub const fn tpacket_align(x: usize) -> usize`

**Unit tests (critical FFI layout assertions)**:
- `size_of` and `offset_of!` for every `#[repr(C)]` struct against kernel header values
- Constant value assertions against spec appendix
- `tpacket_align()` correctness

### src/config.rs (new)

- `FanoutMode` enum: Hash, LoadBalance, Cpu, Rollover, Random, QueueMapping + `as_raw() -> u32`
- `FanoutFlags` (bitflags 2.x): ROLLOVER, UNIQUE_ID, IGNORE_OUTGOING, DEFRAG
- `TimestampSource` enum with `#[default] Software`, RawHardware, SysHardware + `as_raw() -> c_int`
- `BpfInsn` (`#[repr(C)]`): code, jt, jf, k — same layout as `libc::sock_filter`, with `From` conversions
- `BpfFilter`: wraps `Vec<BpfInsn>`, `new()`, `instructions()`, `len()`, `is_empty()`
- Tests: FanoutMode::as_raw values, FanoutFlags bitwise ops, BpfInsn layout == sock_filter, roundtrip conversions

### src/stats.rs (new)

- `CaptureStats`: packets, drops, freeze_count (all u32)
- `impl From<tpacket_stats_v3>`, `impl Display`
- Tests: default is zero, From conversion, Display format

### src/packet.rs (new — value types only)

- `Timestamp { sec: u32, nsec: u32 }`: to_system_time(), to_duration(), From impls, Display
- `PacketStatus { truncated, losing, vlan_valid, vlan_tpid_valid, csum_valid, csum_not_ready, gso_tcp }`: `from_raw(u32)`
- `OwnedPacket { data: Vec<u8>, timestamp: Timestamp, original_len: usize }`
- Tests: Timestamp conversions/ordering, PacketStatus flag decoding, OwnedPacket clone

## Implementation Order

1. Cargo.toml
2. src/afpacket/mod.rs + src/afpacket/ffi.rs (kernel types)
3. src/error.rs
4. src/config.rs (depends on ffi constants)
5. src/stats.rs (depends on libc tpacket_stats_v3)
6. src/packet.rs (depends on ffi TP_STATUS constants)
7. src/lib.rs (wires everything)

## Verification

```bash
cargo build
cargo test
cargo clippy -- --deny warnings
```
