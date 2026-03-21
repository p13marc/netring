# Phase G.1: AF_XDP FFI Constants + Socket Setup

## File: `src/afxdp/ffi.rs`

Re-export from `libc` 0.2.183 (all verified present):

```rust
// Socket family + option level
pub use libc::AF_XDP;            // 44 (c_int — cast to u16 for sockaddr_xdp.sxdp_family)
pub use libc::SOL_XDP;           // 283

// setsockopt/getsockopt options
pub use libc::XDP_MMAP_OFFSETS;           // 1
pub use libc::XDP_RX_RING;               // 2
pub use libc::XDP_TX_RING;               // 3
pub use libc::XDP_UMEM_REG;              // 4
pub use libc::XDP_UMEM_FILL_RING;        // 5
pub use libc::XDP_UMEM_COMPLETION_RING;   // 6
pub use libc::XDP_STATISTICS;             // 7

// mmap page offsets (u64/c_ulonglong — cast to off_t for nix::mmap)
pub use libc::XDP_PGOFF_RX_RING;               // 0x000000000
pub use libc::XDP_PGOFF_TX_RING;               // 0x080000000
pub use libc::XDP_UMEM_PGOFF_FILL_RING;        // 0x100000000
pub use libc::XDP_UMEM_PGOFF_COMPLETION_RING;   // 0x180000000

// Bind flags (for sockaddr_xdp.sxdp_flags)
pub use libc::XDP_SHARED_UMEM;        // 1
pub use libc::XDP_COPY;              // 2
pub use libc::XDP_ZEROCOPY;          // 4
pub use libc::XDP_USE_NEED_WAKEUP;   // 8

// Structs
pub use libc::sockaddr_xdp;       // 16 bytes: sxdp_family(u16), sxdp_flags(u16), sxdp_ifindex(u32), sxdp_queue_id(u32), sxdp_shared_umem_fd(u32)
pub use libc::xdp_desc;           // 16 bytes: addr(u64), len(u32), options(u32)
pub use libc::xdp_mmap_offsets;   // 128 bytes: rx, tx, fr, cr (each xdp_ring_offset)
                                  // NOTE: fill ring field is .fr (not .fill)
                                  // NOTE: completion ring field is .cr (not .completion)
pub use libc::xdp_ring_offset;    // 32 bytes: producer(u64), consumer(u64), desc(u64), flags(u64)
pub use libc::xdp_umem_reg;       // 32 bytes: addr, len, chunk_size, headroom, flags, tx_metadata_len
pub use libc::xdp_statistics;

// Ring flag (not in libc)
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

```rust
pub(crate) fn create_xdp_socket() -> Result<OwnedFd, Error>
// socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0)
// Error: PermissionDenied on EPERM/EACCES

pub(crate) fn register_umem(fd: BorrowedFd, reg: &xdp_umem_reg) -> Result<(), Error>
// setsockopt(SOL_XDP, XDP_UMEM_REG, reg, sizeof(xdp_umem_reg))
// Older kernels accept sizeof(xdp_umem_reg_v1) automatically

pub(crate) fn set_ring_size(fd: BorrowedFd, opt: c_int, size: u32) -> Result<(), Error>
// Generic: setsockopt(SOL_XDP, opt, &size, 4)
// Used for XDP_RX_RING, XDP_TX_RING, XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING
// Ring sizes must be power of 2

pub(crate) fn get_mmap_offsets(fd: BorrowedFd) -> Result<xdp_mmap_offsets, Error>
// getsockopt(SOL_XDP, XDP_MMAP_OFFSETS, &mut offsets, &mut 128)

pub(crate) fn bind_xdp(fd: BorrowedFd, ifindex: u32, queue_id: u32, flags: u16) -> Result<(), Error>
// bind(&sockaddr_xdp { sxdp_family: AF_XDP as u16, sxdp_flags: flags, sxdp_ifindex, sxdp_queue_id, sxdp_shared_umem_fd: 0 })
// flags=0 for auto-negotiate (kernel tries zero-copy, falls back to copy)
// flags=XDP_USE_NEED_WAKEUP to enable NEED_WAKEUP optimization
// XDP_ZEROCOPY bind failure returns EOPNOTSUPP

pub(crate) fn get_statistics(fd: BorrowedFd) -> Result<xdp_statistics, Error>
// getsockopt(SOL_XDP, XDP_STATISTICS, &mut stats, &mut sizeof)
```

Reuse `raw_setsockopt` pattern and `resolve_interface()` from `afpacket/socket.rs`.
