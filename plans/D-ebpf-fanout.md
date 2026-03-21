# Phase D: eBPF Fanout & Socket Filter Helpers

## Goal

Add `FanoutMode::Ebpf` for eBPF-based packet distribution across fanout groups,
and a helper method to attach eBPF socket filters without raw setsockopt.

## 1. FanoutMode::Ebpf

### Config change

Location: `src/config.rs`

```rust
pub enum FanoutMode {
    Hash,
    LoadBalance,
    Cpu,
    Rollover,
    Random,
    QueueMapping,
    /// eBPF program selects the target socket.
    ///
    /// The program receives the packet and returns the socket index
    /// (0-based) within the fanout group. Requires attaching the program
    /// fd after joining the fanout group.
    Ebpf,
}
```

Add `as_raw()` mapping: `Ebpf => PACKET_FANOUT_EBPF` (value 7, may need to define
in `ffi.rs` if not in libc — check `libc::PACKET_FANOUT_EBPF`).

### Fanout eBPF program attachment

After `join_fanout()` with `FanoutMode::Ebpf`, the user must attach an eBPF program.
This is done via `setsockopt(SOL_PACKET, PACKET_FANOUT_DATA, &prog_fd)`.

Add to `src/afpacket/fanout.rs`:

```rust
/// Attach an eBPF program to the fanout group for custom distribution.
///
/// Must be called after `join_fanout()` with `FanoutMode::Ebpf`.
/// The program receives packets and returns the socket index (0-based).
///
/// `prog_fd` is the fd of a loaded `BPF_PROG_TYPE_SOCKET_FILTER` program.
pub(crate) fn attach_fanout_ebpf(fd: BorrowedFd<'_>, prog_fd: RawFd) -> Result<(), Error>
```

### Builder integration

```rust
impl CaptureBuilder {
    /// Join a fanout group with eBPF-based distribution.
    ///
    /// `prog_fd` is the fd of a loaded eBPF program (e.g., from `aya`).
    pub fn fanout_ebpf(mut self, group_id: u16, prog_fd: RawFd) -> Self;
}
```

The builder stores `fanout_ebpf_fd: Option<RawFd>` and calls `attach_fanout_ebpf()`
after `join_fanout()` in `build()`.

## 2. eBPF Socket Filter Helper

### Public method on all handles

Add to `AfPacketRx`:

```rust
impl AfPacketRx {
    /// Attach an eBPF socket filter program.
    ///
    /// Replaces any existing filter (classic BPF or eBPF). The program
    /// must be `BPF_PROG_TYPE_SOCKET_FILTER`. Packets not accepted by
    /// the program are dropped before reaching the ring.
    ///
    /// `prog_fd` is the fd of a loaded eBPF program (e.g., from `aya`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::SockOpt`] if the program attachment fails.
    pub fn attach_ebpf_filter(&self, prog_fd: RawFd) -> Result<(), Error>;

    /// Detach any attached BPF/eBPF filter.
    pub fn detach_filter(&self) -> Result<(), Error>;
}
```

Implementation: `setsockopt(SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(c_int))`

Also add to `Capture`:
```rust
impl Capture {
    pub fn attach_ebpf_filter(&self, prog_fd: RawFd) -> Result<(), Error>;
    pub fn detach_filter(&self) -> Result<(), Error>;
}
```

### Socket helper in afpacket/filter.rs

```rust
pub(crate) fn attach_ebpf_socket_filter(fd: BorrowedFd<'_>, prog_fd: RawFd) -> Result<(), Error> {
    raw_setsockopt(fd, libc::SOL_SOCKET, libc::SO_ATTACH_BPF, &prog_fd, "SO_ATTACH_BPF")
}
```

## 3. Constants check

Verify in `ffi.rs`:
- `PACKET_FANOUT_EBPF` = 7 (check if libc exports it, else define)
- `PACKET_FANOUT_CBPF` = 6 (for completeness)
- `PACKET_FANOUT_DATA` (for attaching the eBPF program to fanout)
- `SO_ATTACH_BPF` (should be in libc)

## Tests

- Unit: `FanoutMode::Ebpf.as_raw() == 7`
- Unit: fanout encoding with Ebpf mode
- Integration (needs eBPF program): optional, document as manual test
- Update `examples/ebpf_filter.rs` to show `attach_ebpf_filter()` usage

## Exports

- `FanoutMode::Ebpf` (already exported via enum)
- `AfPacketRx::attach_ebpf_filter()`, `Capture::attach_ebpf_filter()`
- Update docs
