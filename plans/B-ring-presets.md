# Phase B: Ring Presets & Snap Length

## Goal

Users shouldn't need to know what block_size/block_count/frame_size/timeout mean.
Provide named presets and a snap length option.

## 1. RingProfile enum

Location: `src/config.rs`

```rust
/// Pre-configured ring buffer profiles for common workloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingProfile {
    /// Balanced defaults (4 MiB blocks × 64, 60ms timeout).
    /// Good for general-purpose capture up to ~500 Kpps.
    Default,

    /// Maximum throughput (4 MiB blocks × 256, 60ms timeout).
    /// Pair with FanoutMode::Cpu for multi-core capture.
    /// Uses ~1 GiB of ring memory.
    HighThroughput,

    /// Minimal latency (256 KiB blocks × 64, 1ms timeout).
    /// Smaller blocks retire faster. Pair with busy_poll_us().
    LowLatency,

    /// Minimal memory footprint (1 MiB blocks × 16, 100ms timeout).
    /// 16 MiB total ring. For memory-constrained environments.
    LowMemory,

    /// Large frames / jumbo MTU (4 MiB blocks × 64, frame_size=65536).
    /// For interfaces with MTU > 1500 or GRO/GSO enabled.
    JumboFrames,
}
```

Each profile returns a `(block_size, block_count, frame_size, block_timeout_ms)` tuple
via a `pub(crate) fn params(&self)` method.

## 2. CaptureBuilder::profile()

```rust
impl CaptureBuilder {
    /// Apply a ring buffer profile. Individual settings can be overridden
    /// after calling this.
    pub fn profile(mut self, profile: RingProfile) -> Self {
        let (bs, bc, fs, timeout) = profile.params();
        self.block_size = bs;
        self.block_count = bc;
        self.frame_size = fs;
        self.block_timeout_ms = timeout;
        self
    }
}
```

Same for `AfPacketRxBuilder`.

## 3. Snap length (packet slicing)

Capture only the first N bytes of each packet. Reduces memory pressure and
increases batch density when full payload isn't needed (e.g., header-only analysis).

### Builder method

```rust
impl CaptureBuilder {
    /// Capture only the first `len` bytes of each packet.
    /// Packets larger than `len` will have `original_len() > len()`.
    /// Default: no limit (capture full packets).
    pub fn snap_len(mut self, len: u32) -> Self;
}
```

### Implementation

Snap length in AF_PACKET TPACKET_V3 is controlled by `setsockopt(SOL_SOCKET, SO_RCVBUF)`
combined with `frame_size`. The kernel truncates packets to `frame_size - header_overhead`.

Alternatively, use `PACKET_RESERVE` to set the headroom, or rely on the fact that
`tp_snaplen` in the per-packet header already reflects truncation.

The simplest approach: set `frame_size` to `snap_len + TPACKET3_HDRLEN` (aligned up).
Document that snap_len affects frame_size.

## 4. Re-export and docs

- Add `RingProfile` to `lib.rs` re-exports
- Add `RingProfile` to `docs/API_OVERVIEW.md` configuration reference
- Add `RingProfile` to `docs/TUNING_GUIDE.md` with when-to-use guidance
- Update README.md tuning section

## Tests

- Unit: verify each profile's params are valid (power-of-2, aligned, etc.)
- Unit: verify snap_len sets frame_size correctly
- Unit: verify profile + individual override works (profile then block_count(128))
