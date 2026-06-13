# 0.22 Send-future investigation — decision

**Question:** can the future returned by `Monitor::run_for(d).await` be
made `Send` (so it can be `tokio::spawn`'d)?

**Decision: status quo for 0.22** — keep the run loop on the main task
(`tokio::select!`), document the constraint, ship the
`multi_thread_default` example. File the deeper fix as a 0.23 follow-up.
Below is the evidence and why.

## Evidence (captured from rustc, not assumed)

A throwaway `tokio::spawn(async move { monitor.run_for(d).await })`
fails to compile. The **actual** root cause differs from the 0.21
retrospective's assumption ("the `!Sync` mmap ring"):

```
error[E0277]: `*const ()` cannot be sent between threads safely
  note: required because it's used within this `async` fn body
        --> src/monitor/dispatcher.rs:131  (dispatch_async)
        --> src/monitor/run.rs:554         (fire_tick)
        --> src/monitor/run.rs:66          (run_loop)
error[E0277]: `dyn Future<Output = Result<(), Error>>` cannot be sent ...
```

Two `!Send` sources, both on the **async-handler dispatch path**, not
the capture ring:

1. **`*const ()`** — `Dispatcher::dispatch_async::<P>` casts the payload
   to a type-erased `*const ()` and holds it **across the `.await`** of
   each boxed async handler (`dispatcher.rs:131`). A raw pointer is
   `!Send`, so the enclosing future is `!Send`.
2. **`dyn Future`** — `AsyncHandler`'s boxed future
   (`BoxFuture = Pin<Box<dyn Future<…>>>`) is not `Send`-bounded.

The mmap-ring borrow (`AsyncCapture` across `next_packet().await`) is
*also* `!Sync`/`!Send` in the live path, but the compiler reports the
dispatch-path errors first — so a complete fix needs **both** addressed.

## Options

### Option A — make the async path `Send` (partial fix)

- `dispatch_async`: don't hold `*const ()` across the await — reconstruct
  the `&P` reference on each side of the await, or restructure so the
  raw pointer's lifetime ends before `.await`.
- `BoxFuture` / `AsyncHandler`: add a `Send` bound
  (`Pin<Box<dyn Future<…> + Send>>`).

This removes the *dispatch-path* `!Send`, but **not** the capture-ring
borrow — so `run_for`'s future stays `!Send` until Option B too. Worth
doing on its own merits (it's a real latent constraint on async
handlers), but it doesn't unlock `spawn` alone. **Breaking:** async
handlers must return `Send` futures.

### Option B — owned-batch run path (ring fix)

Switch the live path to `AsyncCapture::recv() -> Vec<OwnedPacket>`
(`Send`) instead of borrowing the ring across awaits. **Breaks the dhat
Δ0 invariant** — one copy per packet. Must be benched
(`benches/zero_alloc.rs` + `throughput.rs`) before committing; offer as
an opt-in run mode, never the default.

### Option C — status quo + docs (chosen)

`ChannelSink` and `monitor.subscribe::<P>()` are already `Send`, so the
cross-spawn use cases (websocket/graph consumers, collators) are
covered without a `Send` run-loop future. No shipped pattern needs
`tokio::spawn(monitor.run_for(..))`. Keep the loop on the main task via
`tokio::select!`.

## Recommendation

Ship **Option C** for 0.22 (zero risk, covers the real use cases) + the
`examples/monitor/multi_thread_default.rs` demo + the migration-guide
caveat. Record this corrected evidence.

**0.23 follow-up:** do **Option A** unconditionally (it's a clean
breaking change that makes async handlers `Send` and removes one of the
two blockers), then evaluate **Option B** with real numbers. If both
land, `run_for`'s future becomes `Send` and `spawn` works. Filed; not
0.22 scope.
