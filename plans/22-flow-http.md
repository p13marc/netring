# Plan 22 — `netring-flow-http` companion crate

## Summary

Ship an `httparse`-based HTTP/1.x bridge that consumes the byte
streams from `FlowStream`'s reassembler and emits parsed
`HttpRequest` / `HttpResponse` events. Pure-Rust, zero-copy, no
async runtime dep at the parser level.

## Status

Not started.

## Prerequisites

- Plans 00–04 published.
- Plan 12 ideally landed first — its `http_session.pcap` fixture is
  the integration test.

## Out of scope

- HTTP/2. `h2` exists but is async/runtime-bound. Passive HTTP/2
  observation is a fundamentally different problem (HPACK state
  per connection); separate plan if there's demand.
- HTTP/3 (QUIC). Way out of scope.
- Decompressing `Content-Encoding: gzip` bodies. We give the user
  raw body bytes; they pipe through `flate2` if needed.
- Mocking responses or rewriting headers. Read-only observation.

---

## Files

### NEW

```
netring-flow-http/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── parser.rs        # incremental HTTP/1.x state machine over Bytes
│   ├── reassembler.rs   # impl AsyncReassembler -> emits HTTP events
│   └── factory.rs       # HttpFactory<H>: AsyncReassemblerFactory
└── examples/
    └── http_log.rs      # live capture, log every HTTP request line
```

---

## API

### Public events

```rust
/// Parsed HTTP/1.x request line + headers.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: HttpVersion,
    pub headers: Vec<(String, Vec<u8>)>,  // header values are bytes (RFC 7230 §3.2.4)
    pub body: Bytes,                       // empty if Content-Length=0 or Transfer-Encoding: chunked
}

/// Parsed HTTP/1.x response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub version: HttpVersion,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion { Http1_0, Http1_1 }

/// User implements one of these to receive parsed events.
pub trait HttpHandler: Send + Sync + 'static {
    fn on_request(&self, _req: &HttpRequest) {}
    fn on_response(&self, _resp: &HttpResponse) {}
    /// Called when a body is too large to buffer — see size_limit
    /// option. The default implementation drops silently.
    fn on_body_chunk(&self, _is_request: bool, _chunk: &[u8]) {}
}
```

### Factory

```rust
pub struct HttpFactory<H: HttpHandler> {
    handler: Arc<H>,
    config: HttpConfig,
}

impl<H: HttpHandler> HttpFactory<H> {
    pub fn with_handler(handler: H) -> Self;
    pub fn with_config(handler: H, config: HttpConfig) -> Self;
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Max request/response size (headers + body). Larger messages
    /// emit `on_body_chunk` instead of accumulating. Default: 1 MiB.
    pub max_message_size: usize,
    /// Max number of headers to parse. Default: 64.
    pub max_headers: usize,
    /// Treat the connection as request-only (e.g., one-way capture).
    /// Default: false (parses both directions).
    pub request_only: bool,
}

impl<K, H> AsyncReassemblerFactory<K> for HttpFactory<H>
where
    K: Eq + std::hash::Hash + Clone + Send + Sync + 'static,
    H: HttpHandler,
{
    type Reassembler = HttpReassembler;

    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> HttpReassembler;
}

/// AsyncReassembler that buffers bytes and emits HTTP events as
/// complete messages parse.
pub struct HttpReassembler { /* internal */ }
```

### Usage

```rust
struct MyHandler;
impl HttpHandler for MyHandler {
    fn on_request(&self, req: &HttpRequest) {
        println!("{} {}", req.method, req.path);
    }
}

let mut stream = cap
    .flow_stream(FiveTuple::bidirectional())
    .with_async_reassembler(HttpFactory::with_handler(MyHandler));
```

The handler fires for every complete HTTP request/response
detected on a TCP byte stream. Backpressure: if the handler is slow
(e.g., logging to disk), reassembly slows, FlowStream slows, kernel
ring fills.

---

## Parsing strategy

### State machine

Each `HttpReassembler` owns a per-direction `BytesMut` buffer +
state:

```rust
enum State {
    /// Waiting for request/response start line + headers.
    Headers,
    /// In Content-Length body; bytes_remaining left to read.
    ContentLengthBody { remaining: usize },
    /// In chunked Transfer-Encoding; tracks chunk-size parsing.
    ChunkedSize,
    ChunkedData { remaining: usize },
    ChunkedTrailer,
    /// Done with one message; back to Headers.
}
```

The parser drives via `httparse`:

```rust
fn try_parse_message(buf: &mut BytesMut) -> Result<Option<Message>, Error> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf)? {
        httparse::Status::Complete(header_len) => {
            // Headers done. Check Content-Length / Transfer-Encoding.
            // If body is fully present, split off and emit.
            // If body is partial, retain headers + transition state.
        }
        httparse::Status::Partial => Ok(None),
    }
}
```

### Per-direction handling

Each side of a TCP flow gets its own `HttpReassembler` instance.
The Initiator side sees requests, the Responder side sees responses.
Internal logic decides which based on side hint passed at
construction.

### Buffer management

Use `BytesMut` for the staging buffer. Append on `segment`, parse
forward, `BytesMut::split_to(consumed_len)` to release parsed
bytes. When converting to a `Bytes` for the body field, this is
zero-copy via `BytesMut::freeze()`.

### Cap on message size

If a message exceeds `max_message_size`, switch to streaming mode
and emit `on_body_chunk` per segment instead of accumulating.
Avoids unbounded memory on degenerate sessions.

---

## Cargo.toml

```toml
[package]
name = "netring-flow-http"
version = "0.1.0"
edition.workspace = true
# ... workspace inheritance

description = "HTTP/1.x bridge for netring-flow async reassembly"
keywords = ["http", "netring", "flow", "passive"]
categories = ["network-programming", "parser-implementations"]

[dependencies]
netring-flow = { version = "0.1", path = "../netring-flow", default-features = false, features = ["tracker", "reassembler"] }
httparse = "1.10"
bytes = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
netring-flow-pcap = { version = "0.1", path = "../netring-flow-pcap" }  # for fixture-driven tests

[[example]]
name = "http_log"
required-features = []
```

---

## Implementation steps

1. **Skeleton crate.** `mkdir`, `Cargo.toml`, `lib.rs`. Add to
   workspace members.
2. **Define event types** (`HttpRequest`, `HttpResponse`, `HttpVersion`,
   `HttpHandler`).
3. **Define `HttpConfig`** with sensible defaults.
4. **Implement the per-direction state machine** in `parser.rs`.
   Use `httparse::Request::parse` and `httparse::Response::parse`.
   Handle:
   - Headers complete (transition to body state)
   - Content-Length body
   - Chunked Transfer-Encoding (parse chunk sizes from buffer)
   - Connection: close case (response body extends to FIN)
5. **Implement `HttpReassembler`**. Owns: `side: FlowSide`,
   `buffer: BytesMut`, `state: State`, `handler: Arc<H>`,
   `config: HttpConfig`.
6. **Implement `HttpFactory`** with `AsyncReassemblerFactory`.
   - On `new_reassembler`, return fresh `HttpReassembler`.
7. **Write `examples/http_log.rs`** — minimal logger.
8. **Write integration test** using Plan 12's `http_session.pcap`.
9. **README** with usage + link to httparse docs.

---

## Edge cases to handle

- **Pipelined requests** (multiple requests on one connection) —
  parser loops, emitting one event per parsed message until buffer
  is partial.
- **Trailing CRLF after Content-Length body** — `httparse` reports
  body length; we trim accordingly.
- **Chunked encoding with trailers** — parse `Transfer-Encoding:
  chunked`, walk chunk sizes, end on `0\r\n` (with optional trailer
  headers).
- **HEAD response** — body is implicitly empty even with non-zero
  `Content-Length`. We can't always detect HEAD reliably without
  request correlation; document as a known limitation. Users who
  need it implement their own correlation in the handler.
- **Malformed input** — parser error → emit nothing, advance buffer
  past the bad byte? Or terminate the stream? **Decision**: on
  parse error, increment a counter and clear the buffer. The TCP
  flow continues but HTTP for this direction is considered desynced.
- **Body bytes after FIN** — the responder may close the connection
  before the body finishes (per RFC, body length is determined by
  EOF in HTTP/1.0). Emit a partial response with whatever was
  buffered.

---

## Tests

### Unit (`netring-flow-http/tests/parser.rs`)

- `parse_simple_request` — `GET / HTTP/1.1\r\nHost: x\r\n\r\n`
- `parse_simple_response` — `HTTP/1.1 200 OK\r\n...`
- `parse_pipelined_requests` — 2 requests in one buffer, expect 2 events
- `parse_chunked_response`
- `parse_content_length_response`
- `parse_partial_then_complete` — feed in 3 chunks, expect 1 event
  on the 3rd
- `body_size_cap_streams_chunks` — over-cap message uses
  `on_body_chunk` instead of accumulating

### Integration (`netring-flow-http/tests/pcap.rs`)

- `http_session_full` — using the Plan-12 fixture, assert ≥1 request
  + 1 response detected.

### Example smoke

- `cargo run -p netring-flow-http --example http_log -- lo`
  builds and starts (no assertion on captured traffic).

---

## Acceptance criteria

- [ ] Crate builds.
- [ ] ≥7 unit tests pass.
- [ ] ≥1 integration test passes against the HTTP pcap fixture.
- [ ] `examples/http_log.rs` builds.
- [ ] README documents the limitation list (HEAD, HTTP/2, decompression).
- [ ] `cargo publish -p netring-flow-http --dry-run` succeeds.

---

## Risks

1. **`httparse` is push-style with header arrays.** We allocate a
   `Vec<httparse::Header>` per parse attempt. For high-throughput
   passive observation this is one Vec alloc per HTTP message —
   probably fine. If profiling says otherwise, use `arrayvec` for a
   stack-resident header array.
2. **Header copy cost.** We copy header names + values into owned
   `String` / `Vec<u8>` for the event. To avoid: emit borrowed
   views (`&str` / `&[u8]`) into the BytesMut buffer, with a
   lifetime tied to the handler call. But the handler is a sync
   trait method, so borrowing across await isn't an issue. Use
   `Bytes` for header values and `&str` (via Bytes::ascii) for
   names. v1: copy is fine.
3. **HTTP/2 demand.** If many users pin H2, defer the rewrite until
   demand is real. The crate's name doesn't preclude H2; it's the
   API shape that does.
4. **Half-closed connections.** Server sends 200, then client sends
   another request before responder fully delivers. Pipelining
   handles it. Document.

---

## Effort

- LOC: ~700 (parser ~300, reassembler ~150, factory ~50, tests ~200).
- Time: 2 days.

---

## What this unlocks

- Real-world demonstration of the L7-bridge pattern. Plan 31
  (SessionParser) generalizes from this concrete impl.
- HTTP request logging, traffic analysis, security inspection — the
  most common L7 use case in an immediate single-line API.
