# Plan 21 — `netring-flow-protolens` companion crate

## Summary

Productize the `protolens` bridge that was sketched in plan 03's
example. Ship a real crate that gives users one-line access to
`protolens`'s TCP reassembler + L7 analyzers (HTTP, SMTP, FTP, TLS,
…) as a drop-in `AsyncReassembler` for `FlowStream`.

## Status

Not started.

## Prerequisites

- Plans 00–04 published.
- `netring-flow` + `netring` `flow` feature stable.

## Out of scope

- Implementing TCP reassembly ourselves (that's protolens's job).
- L7 protocols `protolens` doesn't support (HTTP/2, QUIC, gRPC).
  Users who need those use Plan 22 (HTTP) / a custom parser.

---

## Why this crate (not just an example)

The plan-03 example showed how to wire protolens behind
`AsyncReassembler`, but it wasn't a published artifact. Users still
have to hand-write the bridge, deal with `protolens`'s callback API,
and figure out the per-task lifetime story.

This crate ships:
- `ProtolensReassembler` (impls `AsyncReassembler`).
- `ProtolensFactory` (impls `AsyncReassemblerFactory`).
- A pluggable handler trait for receiving parsed events
  (`ProtolensHandler::on_http_request`, `on_smtp_user`, etc.) — wraps
  protolens's `set_cb_*` methods behind a single trait.
- One-call construction:
  ```rust
  cap.flow_stream(...).with_async_reassembler(
      ProtolensFactory::with_handler(MyHandler::new())
  );
  ```

---

## Files

### NEW

```
netring-flow-protolens/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── handler.rs      # ProtolensHandler trait
│   ├── packet.rs       # impl protolens::Packet for our adapter
│   ├── reassembler.rs  # ProtolensReassembler (AsyncReassembler impl)
│   └── factory.rs      # ProtolensFactory + with_handler
└── examples/
    └── http_extract.rs # Live capture, print HTTP requests
```

### MODIFIED

- Workspace `Cargo.toml`: add member.

---

## Architecture

### The protolens shape

protolens's API is:

1. User creates a `Prolens<P>` instance per thread.
2. User calls `prolens.new_task(TransProto::Tcp)` to get a `Task<P>`.
3. User calls `prolens.set_task_parser(&task, L7Proto::Http)` to set
   the protocol.
4. User registers callbacks: `prolens.set_cb_http_request(callback)`,
   `set_cb_smtp_body(callback)`, etc.
5. User feeds packets: `prolens.run_task(&task, packet)`.
6. Callbacks fire on the calling thread when the parser detects
   protocol events.

The user also has to provide a `P: protolens::Packet` impl that
exposes seq/syn/fin/payload from their packet representation.

### Our bridge

```rust
// netring-flow-protolens/src/packet.rs

/// Adapter implementing `protolens::Packet` over a `Bytes`-owned
/// payload. Constructed per segment by `ProtolensReassembler::segment`.
pub(crate) struct ProtolensPacket {
    seq: u32,
    payload: Bytes,
    fin: bool,
    rst: bool,
}

impl protolens::Packet for ProtolensPacket {
    fn seq(&self) -> u32 { self.seq }
    fn syn(&self) -> bool { false }  // we don't see SYN at the byte-stream layer
    fn fin(&self) -> bool { self.fin }
    fn payload(&self) -> &[u8] { &self.payload }
    // ... etc per protolens::Packet trait
}
```

The reassembler:

```rust
// netring-flow-protolens/src/reassembler.rs

pub struct ProtolensReassembler {
    prolens: Arc<Mutex<protolens::Prolens<ProtolensPacket>>>,
    task: protolens::Task<ProtolensPacket>,
    side: FlowSide,
    initial_seq: Option<u32>,
}

impl AsyncReassembler for ProtolensReassembler {
    fn segment(
        &mut self,
        seq: u32,
        payload: Bytes,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let prolens = self.prolens.clone();
        let task = self.task.clone(); // Task is Clone in protolens
        Box::pin(async move {
            let pkt = ProtolensPacket { seq, payload, fin: false, rst: false };
            // protolens runs synchronously inside the spawn_blocking
            // because its callbacks are sync — we don't want to hold
            // up the FlowStream's poll loop on a CPU-heavy parse.
            tokio::task::spawn_blocking(move || {
                prolens.lock().unwrap().run_task(&task, pkt);
            }).await.ok();
        })
    }

    fn fin(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let prolens = self.prolens.clone();
        let task = self.task.clone();
        Box::pin(async move {
            let pkt = ProtolensPacket {
                seq: 0,
                payload: Bytes::new(),
                fin: true,
                rst: false,
            };
            tokio::task::spawn_blocking(move || {
                prolens.lock().unwrap().run_task(&task, pkt);
            }).await.ok();
        })
    }

    // rst() similar
}
```

### The handler abstraction

protolens has a callback per protocol field. We wrap that into a
handler trait:

```rust
// netring-flow-protolens/src/handler.rs

/// User implements this to receive parsed protocol events.
pub trait ProtolensHandler: Send + Sync + 'static {
    fn on_http_request(&self, _req: &HttpRequest) {}
    fn on_http_response(&self, _resp: &HttpResponse) {}
    fn on_smtp_from(&self, _from: &str) {}
    fn on_smtp_to(&self, _to: &str) {}
    fn on_smtp_subject(&self, _subj: &str) {}
    fn on_smtp_body(&self, _body: &[u8]) {}
    fn on_ftp_user(&self, _user: &str) {}
    fn on_ftp_pass(&self, _pass: &str) {}
    fn on_tls_sni(&self, _sni: &str) {}
    // ... etc — one method per protolens callback
}
```

The factory wires the handler's methods into protolens's `set_cb_*`
on construction:

```rust
// netring-flow-protolens/src/factory.rs

pub struct ProtolensFactory<H: ProtolensHandler> {
    handler: Arc<H>,
    /// One Prolens instance per (key, side) — protolens is single-thread
    /// per instance.
    prolens_per_flow: Arc<Mutex<HashMap<(K, FlowSide), Arc<Mutex<Prolens<ProtolensPacket>>>>>>,
}

impl<H: ProtolensHandler> ProtolensFactory<H> {
    pub fn with_handler(handler: H) -> Self;
}

impl<K, H> AsyncReassemblerFactory<K> for ProtolensFactory<H>
where
    K: Eq + std::hash::Hash + Clone + Send + Sync + 'static,
    H: ProtolensHandler,
{
    type Reassembler = ProtolensReassembler;

    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> ProtolensReassembler {
        let mut prolens = Prolens::new(Default::default());
        let h = self.handler.clone();
        // Wire all the callbacks — clone the Arc into each closure.
        prolens.set_cb_http_request({
            let h = h.clone();
            move |req| h.on_http_request(req)
        });
        // ... repeat for every protolens callback ...
        let task = prolens.new_task(protolens::TransProto::Tcp);
        ProtolensReassembler {
            prolens: Arc::new(Mutex::new(prolens)),
            task,
            side,
            initial_seq: None,
        }
    }
}
```

---

## Cargo.toml

```toml
[package]
name = "netring-flow-protolens"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "protolens bridge for netring-flow async reassembly"
keywords = ["protolens", "netring", "tcp", "reassembly"]
categories = ["network-programming"]

[dependencies]
netring-flow = { version = "0.1", path = "../netring-flow", default-features = false, features = ["tracker", "reassembler"] }
protolens = "0.x"  # pin once we land
bytes = { workspace = true }
tokio = { workspace = true, features = ["rt", "sync"] }
```

---

## Implementation steps

1. **Survey protolens's current public API.** Pin to a specific
   minor version after reading the full callback list.
2. **Create the workspace member.** `mkdir + Cargo.toml + lib.rs`.
3. **Implement `ProtolensPacket`** — adapter type implementing
   `protolens::Packet`.
4. **Implement `ProtolensReassembler`** — wraps a `Prolens` instance
   + task, dispatches segments via `spawn_blocking`.
5. **Implement `ProtolensHandler` trait.** Default method per callback.
6. **Implement `ProtolensFactory::with_handler`.** On `new_reassembler`,
   creates a fresh Prolens instance, registers all callbacks
   (cloning the Arc<H> handler into each closure), returns a
   reassembler.
7. **Write `examples/http_extract.rs`** — implements
   `ProtolensHandler::on_http_request`, prints method+path.
8. **Write integration test** using `http_session.pcap` from Plan 12.
9. **README** with usage example + link to upstream protolens docs.

---

## Tests

### Integration (`netring-flow-protolens/tests/`)

- `http_request_extracted` — feed `http_session.pcap` from Plan 12,
  expect ≥1 `on_http_request` callback fires with the expected URL.
- `factory_creates_per_flow_instance` — synthetic, verify each
  (key, side) gets its own Prolens.

---

## Acceptance criteria

- [ ] Crate builds, ≥2 tests pass.
- [ ] `examples/http_extract.rs` runs against the HTTP fixture and
      prints the request line.
- [ ] README links to upstream protolens, explains scope.
- [ ] `cargo publish -p netring-flow-protolens --dry-run` succeeds.

---

## Risks

1. **protolens's threading model.** Each Prolens instance is
   single-threaded. Our factory creates one per (flow, side), so we
   end up with potentially many instances. Memory: ~few KB per
   instance. For 1000 concurrent TCP flows that's a few MB; fine.
   Document the cost.
2. **`spawn_blocking` per segment.** Each TCP packet's segment
   triggers a blocking task spawn. tokio's blocking pool is bounded
   (default 512 threads); high packet rates could saturate it.
   **Mitigation**: use a dedicated bounded blocking pool (a single
   tokio task with its own worker thread per Prolens instance), not
   `spawn_blocking` directly. v1: spawn_blocking is simpler; if it
   shows up in profiling, switch.
3. **protolens API churn.** It's pre-1.0; the callback set may
   change. Pin the dep to a specific version range.
4. **Callback wiring boilerplate.** ~30 callbacks to wire. Consider
   a macro, but boilerplate is fine for v1.
5. **Mutex contention on Prolens.** Each Prolens is wrapped in
   Mutex; segment + fin each take the lock. Single-threaded per
   flow but contention is technically possible if `segment` future
   and `fin` future race. In practice the FlowStream serializes
   them (one future at a time), so no contention.
6. **License compatibility.** protolens is MIT-OR-Apache-2.0 (verify
   on crates.io). Compatible with our dual license.

---

## Effort

- LOC: ~600 (factory + reassembler + handler trait + boilerplate
  for ~30 callbacks).
- Time: 2 days.

---

## What this unlocks

- One-line TCP reassembly + L7 parsing for HTTP/SMTP/FTP/POP3/IMAP/
  TLS/SIP/SMB users.
- A reference for how to wrap callback-style C-or-other libraries
  behind our `AsyncReassembler` trait (i.e. spawn_blocking bridging).
- Real-world stress test: protolens at 1+ Gbps validates our
  backpressure model.
