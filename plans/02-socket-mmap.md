# Phase 2: Socket Setup & MmapRing

## Goal

Implement the AF_PACKET socket lifecycle, mmap ring buffer management, BPF filter
attachment, and fanout join. All building blocks for Phase 3 (RX) and Phase 4 (TX).

## Prerequisites

Phase 1 complete: ffi.rs, error.rs, config.rs

## Files

### src/afpacket/socket.rs (new)

**Shared helper** (used by filter.rs and fanout.rs):

```
pub(super) fn raw_setsockopt<T>(
    fd: BorrowedFd<'_>, level: c_int, optname: c_int,
    val: &T, option_name: &'static str
) -> Result<(), Error>
```
Wraps `libc::setsockopt`, maps errors to `Error::SockOpt`.

**Functions:**

| Function | Syscall | Error Variant |
|----------|---------|--------------|
| `create_packet_socket() -> Result<OwnedFd>` | `socket(AF_PACKET, SOCK_RAW \| SOCK_CLOEXEC, htons(ETH_P_ALL))` | `Socket` or `PermissionDenied` (EPERM/EACCES) |
| `set_packet_version(fd)` | `setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V3)` | `SockOpt` |
| `set_rx_ring(fd, &tpacket_req3)` | `setsockopt(SOL_PACKET, PACKET_RX_RING, req)` | `SockOpt` (caller handles ENOMEM) |
| `set_tx_ring(fd, &tpacket_req3)` | `setsockopt(SOL_PACKET, PACKET_TX_RING, req)` | `SockOpt` |
| `bind_to_interface(fd, ifindex)` | `libc::bind` with `sockaddr_ll` | `Bind` |
| `resolve_interface(name) -> Result<i32>` | `nix::net::if_::if_nametoindex` | `InterfaceNotFound` |
| `set_promiscuous(fd, ifindex)` | `setsockopt(PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC)` | `SockOpt` |
| `set_ignore_outgoing(fd)` | `setsockopt(PACKET_IGNORE_OUTGOING, &1)` | `SockOpt` |
| `set_busy_poll(fd, us)` | `setsockopt(SOL_SOCKET, SO_BUSY_POLL, &us)` | `SockOpt` |
| `set_timestamp_source(fd, source)` | `setsockopt(SOL_PACKET, PACKET_TIMESTAMP, val)` | `SockOpt` |

All functions take `BorrowedFd<'_>`. Each `unsafe` call gets its own `unsafe {}` block with SAFETY comment.

**Error handling**: `EPERM`/`EACCES` on socket creation → `Error::PermissionDenied`. All others → specific variant.

### src/afpacket/ring.rs (new)

**MmapRing struct:**

```rust
struct MmapRing {
    base: NonNull<u8>,    // strict provenance
    size: usize,
    block_size: usize,
    block_count: usize,
}
```

**Methods:**

| Method | Description |
|--------|-------------|
| `new(fd: BorrowedFd, size, block_size, block_count) -> Result<Self>` | `nix::sys::mman::mmap(None, NonZeroUsize, ProtFlags, MapFlags, fd, 0)` — nix 0.31 takes `F: AsFd` directly (not Option). Returns `NonNull<c_void>`, cast to `NonNull<u8>`. Flags: `MAP_SHARED \| MAP_LOCKED \| MAP_POPULATE`. On EPERM for MAP_LOCKED, retry without it + log warning. |
| `block_ptr(&self, index) -> NonNull<tpacket_block_desc>` | Strict provenance: `self.base.as_ptr().map_addr(\|a\| a + index * self.block_size)`. Panics if `index >= block_count`. |
| `base(&self) -> NonNull<u8>` | Accessor |
| `size(&self) -> usize` | Accessor |
| `block_size(&self) -> usize` | Accessor |
| `block_count(&self) -> usize` | Accessor |

**Drop**: `nix::sys::mman::munmap(self.base, self.size).ok()`

**Free functions — block status helpers:**

| Function | Description |
|----------|-------------|
| `read_block_status(bd: NonNull<tpacket_block_desc>) -> u32` | Uses `addr_of!((*bd).hdr.bh1.block_status)` cast to `&AtomicU32`, loads with `Ordering::Acquire` |
| `release_block(bd: NonNull<tpacket_block_desc>)` | Same pointer, stores `TP_STATUS_KERNEL` with `Ordering::Release` |

### src/afpacket/filter.rs (new)

| Function | Description |
|----------|-------------|
| `attach_bpf_filter(fd, &BpfFilter)` | Constructs `sock_fprog`, calls `setsockopt(SOL_SOCKET, SO_ATTACH_FILTER)`. Validates: non-empty, len <= 4096. |
| `detach_bpf_filter(fd)` | `setsockopt(SOL_SOCKET, SO_DETACH_FILTER)` |

### src/afpacket/fanout.rs (new)

| Function | Description |
|----------|-------------|
| `join_fanout(fd, group_id: u16, mode: FanoutMode, flags: FanoutFlags)` | Encodes `val = group_id \| ((mode \| flags) << 16)`, calls `setsockopt(SOL_PACKET, PACKET_FANOUT)`. Must be called AFTER bind. |

### src/afpacket/mod.rs (modify)

Add: `pub(crate) mod socket;`, `pub(crate) mod ring;`, `pub(crate) mod filter;`, `pub(crate) mod fanout;`

## Implementation Order

1. socket.rs (raw_setsockopt helper first, then each function)
2. ring.rs (MmapRing + block status helpers) — parallel with socket.rs
3. filter.rs (depends on socket.rs raw_setsockopt)
4. fanout.rs (depends on socket.rs raw_setsockopt)

## Testing

**Unit tests (no privileges):**
- `resolve_interface("lo")` succeeds, `resolve_interface("nonexistent_xyz")` returns InterfaceNotFound
- Fanout `u32` encoding: verify known mode+flags+group_id combos
- Empty BPF filter validation
- `tpacket_align()` helper correctness

**Integration tests (CAP_NET_RAW):**
- Full sequence: create_packet_socket → set_version → set_rx_ring → mmap → bind("lo") → read_block_status (all TP_STATUS_KERNEL initially)
