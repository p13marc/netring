# Plan 11 — `SO_PREFER_BUSY_POLL` + budget

## Summary

Expose Linux 5.11+ AF_XDP / AF_PACKET busy-poll knobs that close most of
the latency gap to DPDK on packet-touching workloads:

- `SO_PREFER_BUSY_POLL` — tell the kernel to prefer busy-polling over
  softirq/NAPI scheduling for this socket.
- `SO_BUSY_POLL_BUDGET` — cap the per-poll packet count so a busy-poll
  thread doesn't monopolise the core.

Both go alongside the existing `SO_BUSY_POLL` (timeout in microseconds).
The trio is what Suricata, the AF_XDP arxiv paper (2402.10513), and the
upstream kernel docs all recommend for low-latency AF_XDP capture.

After this plan, AF_XDP captures opened through netring can be tuned
identically to Suricata's `af-xdp.busy-poll`, `af-xdp.busy-poll-budget`,
and `af-xdp.prefer-busy-poll` — closing the only socket-option gap
between netring and SOTA capture configurations.

## Status

✅ Done.

## Prerequisites

None. Independent of every other plan. Self-contained inside `netring`.

## Out of scope

- Auto-tuning busy-poll values based on traffic. The user picks numbers.
- Changing the AF_PACKET I/O path to be busy-poll-only (i.e., remove
  `poll(2)`). The existing default behaviour keeps backwards
  compatibility; busy-poll is opt-in.
- Per-CPU `napi_defer_hard_irqs` and `gro_flush_timeout` tuning. These
  are sysfs knobs, not socket options — they're the user's
  responsibility (a documentation note suffices).

---

## Design context

The AF_XDP arxiv paper (https://arxiv.org/html/2402.10513v1) measured
the gap between AF_XDP and DPDK on payload-touching workloads. The two
capture stacks converge to within 5–10 % of each other once AF_XDP is
running with:

```
SO_BUSY_POLL              = ~50 µs   (existing in netring as busy_poll_us)
SO_PREFER_BUSY_POLL       = 1        (new — this plan)
SO_BUSY_POLL_BUDGET       = 64       (new — this plan)
```

The Linux kernel docs for AF_XDP
(https://docs.kernel.org/networking/af_xdp.html) describe the same
combination as the canonical low-latency configuration.

`SO_PREFER_BUSY_POLL` was added in kernel 5.11 (commit
`7fd3253a7de6f1c14eccdcd24a1c2d1e9c3df0c5`, "net: Introduce preferred
busy-polling"). `SO_BUSY_POLL_BUDGET` was added in the same series.

---

## Where it lives — `netring`

Both options are setsockopt calls on the AF_PACKET and AF_XDP sockets.
They belong squarely in `netring/src/afpacket/` and `netring/src/afxdp/`.
No new crate.

---

## Files

### MODIFIED

```
netring/src/afpacket/
├── ffi.rs            # add SO_PREFER_BUSY_POLL, SO_BUSY_POLL_BUDGET constants
├── socket.rs         # add set_prefer_busy_poll, set_busy_poll_budget helpers
└── rx.rs             # add CaptureBuilder fields + methods + apply on build
```

```
netring/src/afxdp/
├── socket.rs         # apply setsockopts during socket create
└── mod.rs            # add XdpSocketBuilder fields + methods
```

### NEW (examples)

- `netring/examples/async_xdp_busy_poll.rs` — minimal AF_XDP RX with the
  full busy-poll trio configured. Logs latency histogram via `hdrhistogram`.

### MODIFIED (docs)

- `netring/CLAUDE.md` — note the trio under "Design Constraints".
- `CHANGELOG.md` — entry.

---

## API

### AF_PACKET — `Capture::builder()`

```rust
let cap = netring::Capture::builder()
    .interface("eth0")
    .busy_poll_us(50)              // existing — kernel ≥ 4.5
    .prefer_busy_poll(true)        // NEW — kernel ≥ 5.11
    .busy_poll_budget(64)          // NEW — kernel ≥ 5.11
    .build()?;
```

### AF_XDP — `XdpSocketBuilder`

```rust
let xsk = netring::XdpSocketBuilder::new("eth0")?
    .queue_id(0)
    .zero_copy(true)
    .needs_wakeup(true)
    .busy_poll_us(50)              // NEW — not currently exposed on AF_XDP
    .prefer_busy_poll(true)        // NEW
    .busy_poll_budget(64)          // NEW
    .build()?;
```

(`busy_poll_us` is already on `Capture::builder()` for AF_PACKET; this
plan brings the same knob to AF_XDP.)

### Constants

```rust
// netring/src/afpacket/ffi.rs

/// `SO_PREFER_BUSY_POLL` — kernel 5.11+. Re-export from libc when it
/// gains the constant, fall back to the literal otherwise.
#[cfg(any())] // libc as of 0.2.183 does not export it
pub use libc::SO_PREFER_BUSY_POLL;
#[cfg(not(any()))]
pub const SO_PREFER_BUSY_POLL: libc::c_int = 69;

/// `SO_BUSY_POLL_BUDGET` — kernel 5.11+.
#[cfg(any())]
pub use libc::SO_BUSY_POLL_BUDGET;
#[cfg(not(any()))]
pub const SO_BUSY_POLL_BUDGET: libc::c_int = 70;
```

(Once `libc` exports these, the `cfg(any())` becomes a real version
check; until then we ship the literals. Both are stable kernel ABI.)

### Socket helpers

```rust
// netring/src/afpacket/socket.rs

/// Set `SO_PREFER_BUSY_POLL`. Kernel ≥ 5.11.
///
/// Tells the kernel to prefer the busy-polling path over softirq for
/// this socket. Pair with [`set_busy_poll`] (timeout) and
/// [`set_busy_poll_budget`] (per-poll cap) for the full low-latency
/// configuration documented in
/// <https://docs.kernel.org/networking/af_xdp.html>.
pub(crate) fn set_prefer_busy_poll(fd: BorrowedFd<'_>, enable: bool)
    -> Result<(), Error>
{
    let val: libc::c_int = if enable { 1 } else { 0 };
    raw_setsockopt(
        fd,
        libc::SOL_SOCKET,
        ffi::SO_PREFER_BUSY_POLL,
        &val,
        "SO_PREFER_BUSY_POLL",
    )
}

/// Set `SO_BUSY_POLL_BUDGET`. Kernel ≥ 5.11.
///
/// Cap on the per-poll packet count, so a busy-polling thread can't
/// monopolise the core. The default budget when unset is 8 in 6.x
/// kernels; 64 is a common production value for AF_XDP.
///
/// Note: values larger than `/proc/sys/net/core/busy_poll_budget_max`
/// require `CAP_NET_ADMIN`. Setting beyond that returns EPERM.
pub(crate) fn set_busy_poll_budget(fd: BorrowedFd<'_>, budget: u16)
    -> Result<(), Error>
{
    let val: libc::c_int = budget as libc::c_int;
    raw_setsockopt(
        fd,
        libc::SOL_SOCKET,
        ffi::SO_BUSY_POLL_BUDGET,
        &val,
        "SO_BUSY_POLL_BUDGET",
    )
}
```

### Builder field plumbing — `Capture::builder()`

```rust
pub struct CaptureBuilder {
    // ... existing ...
    busy_poll_us: Option<u32>,
    prefer_busy_poll: Option<bool>,
    busy_poll_budget: Option<u16>,
}

impl CaptureBuilder {
    /// Enable `SO_PREFER_BUSY_POLL`. Kernel ≥ 5.11.
    pub fn prefer_busy_poll(mut self, enable: bool) -> Self {
        self.prefer_busy_poll = Some(enable);
        self
    }

    /// Set `SO_BUSY_POLL_BUDGET` (per-poll packet cap). Kernel ≥ 5.11.
    pub fn busy_poll_budget(mut self, budget: u16) -> Self {
        self.busy_poll_budget = Some(budget);
        self
    }
}
```

The build path applies them after `set_busy_poll`:

```rust
// in finish_setup_capture
if let Some(us) = b.busy_poll_us {
    socket::set_busy_poll(fd.as_fd(), us)?;
}
if let Some(prefer) = b.prefer_busy_poll {
    socket::set_prefer_busy_poll(fd.as_fd(), prefer)?;
}
if let Some(budget) = b.busy_poll_budget {
    socket::set_busy_poll_budget(fd.as_fd(), budget)?;
}
```

### AF_XDP mirror

`netring/src/afxdp/socket.rs` already calls `setsockopt` for the XDP
flags. Add the three socket-level options on the same socket fd. The
options go on the socket itself, not the AF_XDP-specific ring fd.

```rust
// netring/src/afxdp/mod.rs — XdpSocketBuilder
pub struct XdpSocketBuilder {
    // ... existing ...
    busy_poll_us: Option<u32>,
    prefer_busy_poll: Option<bool>,
    busy_poll_budget: Option<u16>,
}

// builder methods identical to CaptureBuilder

// applied during build, after the socket is created and before the
// rings are mapped
if let Some(us) = b.busy_poll_us {
    afpacket_socket::set_busy_poll(fd.as_fd(), us)?;
}
if let Some(prefer) = b.prefer_busy_poll {
    afpacket_socket::set_prefer_busy_poll(fd.as_fd(), prefer)?;
}
if let Some(budget) = b.busy_poll_budget {
    afpacket_socket::set_busy_poll_budget(fd.as_fd(), budget)?;
}
```

(The existing AF_PACKET helpers in `afpacket/socket.rs` are reused
since these are SOL_SOCKET options that work on both socket families.
No need to duplicate.)

---

## Implementation steps

1. **Constants.** Add `SO_PREFER_BUSY_POLL = 69` and
   `SO_BUSY_POLL_BUDGET = 70` to `netring/src/afpacket/ffi.rs`.
   Include unit-test asserts that match Linux's
   `include/uapi/asm-generic/socket.h`.

2. **Socket helpers.** Add `set_prefer_busy_poll` and
   `set_busy_poll_budget` to `netring/src/afpacket/socket.rs`.

3. **AF_PACKET builder.** Add the two `Option<...>` fields,
   `prefer_busy_poll(bool)` and `busy_poll_budget(u16)` methods, and
   apply during build. Document the kernel version requirement on each
   method.

4. **AF_XDP builder.** Mirror the trio
   (`busy_poll_us`/`prefer_busy_poll`/`busy_poll_budget`) on
   `XdpSocketBuilder`. Reuse the AF_PACKET socket helpers (SOL_SOCKET
   options work on both).

5. **Default behaviour.** None of the three are set by default; users
   opt in. Existing code paths are unchanged.

6. **Example.** `netring/examples/async_xdp_busy_poll.rs` — opens an
   AF_XDP socket on a queue with the trio enabled, runs for 30 s,
   prints capture rate.

7. **Documentation.** Add a docs/TUNING.md note (or extend an existing
   one) describing when to use the trio. Cross-reference Suricata's
   `af-xdp` config keys so users coming from Suricata recognise the
   knobs.

8. **CHANGELOG entry** under the next netring release.

---

## Tests

### Unit (no privileges)

- `ffi::SO_PREFER_BUSY_POLL == 69`
- `ffi::SO_BUSY_POLL_BUDGET == 70`
- Builder methods chain correctly (existing pattern).

### Integration (require CAP_NET_ADMIN — gated by `integration-tests`)

- Open an AF_PACKET socket with `prefer_busy_poll(true)` + 
  `busy_poll_budget(64)` on a kernel ≥ 5.11. Assert no error.
- Same on AF_XDP socket. Assert RX still works.

### Compatibility (gated by `integration-tests` + a kernel-version check)

- On a kernel < 5.11, builder calls succeed but `setsockopt` returns
  ENOPROTOOPT. Document this — netring's current convention is to
  surface setsockopt errors, so the user sees the failure.

### Doctests

- `prefer_busy_poll`'s rustdoc has a runnable doctest building a
  capture with the full trio.

---

## Acceptance criteria

- [ ] `Capture::builder().prefer_busy_poll(true).busy_poll_budget(64)`
      compiles and works on kernel ≥ 5.11.
- [ ] Same for `XdpSocketBuilder`.
- [ ] Existing AF_PACKET / AF_XDP unit + integration tests still pass.
- [ ] No new external dependencies.
- [ ] CI workflow runs the new integration test gated behind
      `integration-tests` feature.
- [ ] CHANGELOG and rustdoc updated.

---

## Risks

1. **`libc` may eventually export the constants.** When it does, the
   `cfg(any())` shim becomes dead code. Add a short comment so a future
   contributor switches to the libc constant. Pure paperwork.

2. **`SO_BUSY_POLL_BUDGET` requires CAP_NET_ADMIN above the system
   default.** The kernel rejects values > `busy_poll_budget_max`
   (default 64 on most distros) without privilege. Builder surfaces
   the EPERM directly; document that values ≤ 64 are safe without
   privilege.

3. **Kernel < 5.11.** Setting either option fails with ENOPROTOOPT.
   netring's existing convention is to fail loudly on setsockopt
   errors. Some users may want soft fallback. **Decision**: keep the
   current loud-failure convention; users on kernel < 5.11 detect the
   environment themselves before opting in. A `try_*` variant can be
   added later if demand surfaces.

4. **No way to actually validate it's working.** Busy-polling shows up
   as reduced softirq CPU and reduced poll-syscall counts, neither of
   which is observable from inside the process easily. The example
   demonstrates the configuration; benchmark interpretation is on the
   user.

---

## Effort

- Constants + socket helpers: ~30 LOC.
- AF_PACKET builder fields + methods: ~40 LOC (including docs).
- AF_XDP builder fields + methods: ~40 LOC.
- Tests: ~80 LOC (3 unit, 2 integration, 1 doctest).
- Example: ~80 LOC.
- Docs: ~50 LOC (tuning notes + cross-reference to Suricata).
- **Total**: ~320 LOC.
- **Time**: 2–4 hours including review.

---

## Out of scope follow-ups

- A `try_set` variant that returns `Result<bool, Error>` (Ok(false) on
  ENOPROTOOPT) for soft kernel-version detection. Add when a user asks.
- Sysfs tuning (`napi_defer_hard_irqs`, `gro_flush_timeout`) wrappers.
  Different layer (interface, not socket); separate concern.
