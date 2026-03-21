# Phase G.1: AF_XDP FFI Constants + Socket Setup

## Goal

Re-export all AF_XDP kernel types/constants from libc and implement the
socket creation + setsockopt wrappers. Same pattern as `afpacket/ffi.rs`
and `afpacket/socket.rs`.

## File: `src/afxdp/ffi.rs`

Re-export from `libc` 0.2.183 (all verified present):

**Constants:**
```rust
pub use libc::AF_XDP;            // 44
pub use libc::SOL_XDP;           // 283
pub use libc::XDP_MMAP_OFFSETS;  // 1
pub use libc::XDP_RX_RING;      // 2
pub use libc::XDP_TX_RING;      // 3
pub use libc::XDP_UMEM_REG;     // 4
pub use libc::XDP_UMEM_FILL_RING;      // 5
pub use libc::XDP_UMEM_COMPLETION_RING; // 6
pub use libc::XDP_STATISTICS;    // 7

// mmap page offsets
pub use libc::XDP_PGOFF_RX_RING;              // 0x000000000
pub use libc::XDP_PGOFF_TX_RING;              // 0x080000000
pub use libc::XDP_UMEM_PGOFF_FILL_RING;       // 0x100000000
pub use libc::XDP_UMEM_PGOFF_COMPLETION_RING;  // 0x180000000

// bind flags
pub use libc::XDP_SHARED_UMEM;       // 1
pub use libc::XDP_COPY;             // 2
pub use libc::XDP_ZEROCOPY;         // 4
pub use libc::XDP_USE_NEED_WAKEUP;  // 8

// Structs
pub use libc::sockaddr_xdp;
pub use libc::xdp_desc;
pub use libc::xdp_mmap_offsets;
pub use libc::xdp_ring_offset;
pub use libc::xdp_umem_reg;
pub use libc::xdp_statistics;
```

**Define ourselves (ring flag):**
```rust
pub const XDP_RING_NEED_WAKEUP: u32 = 1;
```

**Unit tests:**
- `AF_XDP == 44`, `SOL_XDP == 283`
- `size_of::<xdp_umem_reg>() == 32`
- `size_of::<sockaddr_xdp>() == 16`
- `size_of::<xdp_desc>() == 16`
- `size_of::<xdp_mmap_offsets>() == 128`
- `size_of::<xdp_ring_offset>() == 32`

## File: `src/afxdp/socket.rs`

Socket lifecycle wrappers (same pattern as `afpacket/socket.rs`):

```rust
pub(crate) fn create_xdp_socket() -> Result<OwnedFd, Error>
// socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0)

pub(crate) fn register_umem(fd: BorrowedFd, reg: &xdp_umem_reg) -> Result<(), Error>
// setsockopt(SOL_XDP, XDP_UMEM_REG)

pub(crate) fn set_fill_ring_size(fd: BorrowedFd, size: u32) -> Result<(), Error>
pub(crate) fn set_completion_ring_size(fd: BorrowedFd, size: u32) -> Result<(), Error>
pub(crate) fn set_rx_ring_size(fd: BorrowedFd, size: u32) -> Result<(), Error>
pub(crate) fn set_tx_ring_size(fd: BorrowedFd, size: u32) -> Result<(), Error>
// setsockopt(SOL_XDP, XDP_*_RING, &size)

pub(crate) fn get_mmap_offsets(fd: BorrowedFd) -> Result<xdp_mmap_offsets, Error>
// getsockopt(SOL_XDP, XDP_MMAP_OFFSETS)

pub(crate) fn bind_xdp(fd: BorrowedFd, ifindex: u32, queue_id: u32, flags: u16) -> Result<(), Error>
// bind(&sockaddr_xdp)

pub(crate) fn get_statistics(fd: BorrowedFd) -> Result<xdp_statistics, Error>
// getsockopt(SOL_XDP, XDP_STATISTICS)
```

All use the existing `raw_setsockopt` pattern from `afpacket/socket.rs`.
Reuse `resolve_interface()` from `afpacket/socket.rs`.
