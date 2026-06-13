# Migrating netring 0.22 → 0.23

A small, focused release. One breaking change, one new capability.

## TL;DR

The `Monitor` run-loop future is now **`Send + 'static`** — you can
`tokio::spawn` it. In exchange, `on_async` handlers must return `Send`
futures. If your async handlers capture `Arc<…>` and do I/O (the usual
case), **nothing changes for you**.

## New: spawn the run loop

In 0.22 the future returned by `run_for` / `run_until` /
`run_until_signal` / `run_until_idle` was `!Send`, so it had to stay on
the task that owned it (`tokio::select!` on the main task). In 0.23 it
is `Send + 'static`:

```rust
// 0.23 — runs the capture loop on its own worker task.
let monitor = Monitor::builder()
    .interface("eth0")
    .protocol::<Tcp>()
    /* … */
    .build()?;

let handle = tokio::spawn(monitor.run_for(Duration::from_secs(30)));
// … do other async work on this task meanwhile …
handle.await??; // JoinError, then the run loop's Result
```

Keeping the loop on the main task with `tokio::select!` still works
exactly as before — spawning is now an *option*, not a requirement.
See `examples/monitor/multi_thread_default.rs`.

## Breaking: `on_async` futures must be `Send`

`BoxFuture<T>` is now `Pin<Box<dyn Future<Output = T> + Send>>` and the
`AsyncHandler` blanket impl bounds `Fut: Send`. This is the same rule
`tokio::spawn` imposes.

**No change needed** for the canonical async handler:

```rust
.on_async::<Http, _>(move |msg: &flowscope::http::HttpMessage| {
    let pool = Arc::clone(&pool);          // Send
    async move { pool.publish(msg).await } // Send future — compiles
})
```

**If you hit `future cannot be sent between threads safely`,** your
handler holds a `!Send` value (e.g. an `Rc`, or a `MutexGuard` from a
non-`Send` lock) across its own `.await`. Fixes:

- Replace `Rc<T>` / `RefCell<T>` captures with `Arc<T>` /
  `Arc<Mutex<T>>`.
- Don't hold a lock guard across `.await`; clone the data out first.
- Or move the non-`Send` work to a dedicated consumer task and feed it
  from a sync handler via a `ChannelSink` / `tokio::mpsc`.

## Why this was safe to do at zero cost

The two `!Send` sources were both on the async-dispatch path (a
type-erased `*const ()` and a non-`Send` boxed future held across
`.await`). The capture's mmap ring was already `Send`, so the run loop
needed **no per-packet copy** — the dhat zero-alloc steady state
(`Δ 0 bytes / 0 blocks`) is unchanged.
