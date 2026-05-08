# Plan 31 — `SessionParser<P>` trait + `session_stream()`

## Summary

The pre-1.0 strategic abstraction. Generalize the
`HttpFactory<H>` / `TlsFactory<H>` / `DnsFactory<H>` patterns from
Tier 2 into a single trait — `SessionParser` — so users get a
**stream of L7 messages** rather than a stream of bytes.

```rust
let mut messages = cap
    .flow_stream(FiveTuple::bidirectional())
    .session_stream(MyParser);

while let Some(msg) = messages.next().await {
    match msg? {
        SessionMessage::Application(parsed) => process(parsed),
        SessionMessage::Closed { stats, .. } => log_close(stats),
        _ => {}
    }
}
```

This is the abstraction that justifies the **1.0.0** release.

## Status

Not started — design phase only.

## Prerequisites

- Tier 2 plans (22-flow-http, 23-flow-tls, 24-flow-dns) ideally
  shipped first. We need ≥2 concrete L7 parsers in production
  before locking the trait shape.
- Plan 30 (Conversation) provides the underlying concept this
  generalizes; its byte-stream-per-flow primitive gets reused.

## Out of scope

- Replacing the existing handler-based bridges (HttpFactory etc.).
  They stay; SessionParser is an alternative for users who want
  an iterator/stream model.
- Decryption / active session tampering.

---

## Why this abstraction

Look at what the Tier-2 parsers have in common:

| Crate | Per-flow state | Input | Events emitted |
|-------|----------------|-------|----------------|
| HTTP  | `BytesMut` buffer + state machine | TCP byte stream | `HttpRequest`, `HttpResponse` |
| TLS   | `BytesMut` buffer + handshake state | TCP byte stream | `TlsClientHello`, `TlsServerHello`, `TlsAlert` |
| DNS (TCP) | `BytesMut` buffer | TCP byte stream | `DnsQuery`, `DnsResponse` |
| DNS (UDP) | None (per-packet) | Raw UDP payload | `DnsQuery`, `DnsResponse` |

Each ships a per-protocol `*Factory` + `*Handler` trait. The trait
shapes are nearly identical. SessionParser unifies them:

```rust
pub trait SessionParser: Send + Sync + 'static {
    /// The application-layer message type emitted by this parser.
    type Message: Send + 'static;

    /// Per-flow state. The parser is constructed fresh per session.
    fn new() -> Self where Self: Sized;

    /// Feed bytes from the initiator side. Return any complete
    /// messages parsed.
    fn feed_initiator(&mut self, bytes: &[u8]) -> SmallVec<[Self::Message; 2]>;

    /// Feed bytes from the responder side.
    fn feed_responder(&mut self, bytes: &[u8]) -> SmallVec<[Self::Message; 2]>;

    /// Initiator side has FIN'd.
    fn fin_initiator(&mut self) -> SmallVec<[Self::Message; 2]> { SmallVec::new() }

    /// Responder side has FIN'd.
    fn fin_responder(&mut self) -> SmallVec<[Self::Message; 2]> { SmallVec::new() }
}
```

And the entry point:

```rust
impl<S, E> FlowStream<S, E, ()> {
    pub fn session_stream<P: SessionParser>(self, parser: P) -> SessionStream<S, E, P>;
}

pub struct SessionStream<S, E, P> { /* internal */ }

impl<S, E, P> Stream for SessionStream<S, E, P>
where ...
{
    type Item = Result<SessionEvent<E::Key, P::Message>, Error>;
}

#[derive(Debug)]
pub enum SessionEvent<K, M> {
    Started { key: K, ts: Timestamp },
    Application { key: K, side: FlowSide, message: M, ts: Timestamp },
    Closed { key: K, reason: EndReason, stats: FlowStats },
}
```

A user implementing `SessionParser` for HTTP doesn't write a
factory + handler; just one trait. The `with_handler` style remains
available via `impl SessionParser for FactoryWithHandler<H>`.

---

## Design tensions

### 1. `Self: Sized` + `new()` vs factory-based construction

`new()` is convenient: `cap.flow_stream(...).session_stream(MyParser)`
creates fresh parsers per session via `MyParser::new()`. But some
parsers need configuration (e.g., `max_message_size`, `ja3: true`).

**Resolution**: split into two traits:

```rust
pub trait SessionParser: Send + Sync + 'static {
    type Message;
    fn feed_initiator(&mut self, bytes: &[u8]) -> ...;
    fn feed_responder(&mut self, bytes: &[u8]) -> ...;
    fn fin_initiator(&mut self) -> ... { ... }
    fn fin_responder(&mut self) -> ... { ... }
}

pub trait SessionParserFactory: Send + 'static {
    type Parser: SessionParser;
    fn new_parser(&mut self, key: &impl Hash) -> Self::Parser;
}

// Auto-impl: any Default parser is automatically a factory.
impl<P: SessionParser + Default + Clone> SessionParserFactory for P {
    type Parser = P;
    fn new_parser(&mut self, _: &impl Hash) -> P { self.clone() }
}
```

Now users can pass either a `Default + Clone` parser or a custom
factory.

### 2. UDP-only protocols (DNS over UDP)

The trait is byte-stream-shaped. UDP DNS doesn't have a stream;
each packet is a complete message. We have two options:

(a) **Hybrid trait**: add a `feed_packet(&mut self, view: PacketView)`
    method that runs at the extractor stage instead of the
    reassembler stage. The trait gains complexity.

(b) **Two traits**: `SessionParser` for stream protocols,
    `DatagramParser` for per-packet protocols. Different entry points
    on `FlowStream`: `session_stream` vs `datagram_stream`.

**Resolution**: Option (b). A clean abstraction beats a
do-everything trait. UDP-DNS users use `datagram_stream(DnsParser)`;
TCP-DNS users use `session_stream(DnsParser)`. The DNS crate ships
both impls.

```rust
pub trait DatagramParser: Send + Sync + 'static {
    type Message;
    fn parse(&mut self, payload: &[u8], side: FlowSide) -> SmallVec<[Self::Message; 2]>;
}

impl<S, E> FlowStream<S, E, ()> {
    pub fn datagram_stream<P: DatagramParser>(self, parser: P) -> DatagramStream<S, E, P>;
}
```

### 3. Error reporting

A parser fails on malformed bytes — what's the right behavior?

- **Bubble up via Stream::Item** (`Result<SessionEvent, Error>`).
  Pro: explicit. Con: spammy on noisy traffic.
- **Drop and count** (parser increments an internal counter, stream
  doesn't surface it). Pro: clean. Con: silent failures.
- **Both**: stream returns `Result<SessionEvent>` for stream-level
  errors (capture failure, etc.) but the parser's internal errors
  are surfaced via a separate `parser.error_count()` accessor.

**Resolution**: third option. The Stream's `Result` is for
infrastructure (capture errors). Parser-internal errors are
introspectable via the parser handle.

### 4. Parser state introspection

Users sometimes want to peek at the parser's internal state mid-flow
(e.g., "how many bytes buffered for this flow's responder side?").

**Resolution**: parsers can expose state via trait extensions,
e.g.:

```rust
pub trait SessionParserStats: SessionParser {
    fn stats(&self) -> ParserStats;
}

#[derive(Debug, Clone)]
pub struct ParserStats {
    pub bytes_buffered_initiator: usize,
    pub bytes_buffered_responder: usize,
    pub messages_emitted: u64,
    pub parse_errors: u64,
}
```

Optional; not required to implement.

### 5. Cancellation safety

If the user drops the SessionStream mid-flow, the inner FlowStream's
existing cleanup runs (parsers' `fin_*` methods are called). But
since these are sync, they can't await on cleanup. **Resolution**:
sync trait, sync cleanup, no awaits. If a parser needs async
cleanup (rare), it implements that via `tokio::spawn` in
`fin_initiator`.

### 6. Backpressure

Currently the user's `Handler::on_*` methods are sync — they can't
backpressure. With `SessionStream`, the user gets messages via
async iteration, so they CAN backpressure. The Stream impl
internally:

1. Pulls from FlowStream.
2. Calls parser's sync `feed_*` to extract messages.
3. Yields them one at a time via `poll_next`.
4. If the user is slow, internal buffer of pending messages grows
   (bounded by VecDeque size; we cap at 1000 per flow before
   backpressure kicks in).

---

## Files

### NEW

```
netring/src/async_adapters/
└── session_stream.rs    # SessionParser, SessionStream, DatagramParser, DatagramStream
```

```
netring-flow-http/src/
└── session.rs           # impl SessionParser for HttpParser

netring-flow-tls/src/
└── session.rs           # impl SessionParser for TlsParser

netring-flow-dns/src/
├── session.rs           # impl SessionParser for DnsTcpParser
└── datagram.rs          # impl DatagramParser for DnsUdpParser
```

### MODIFIED

- The Tier-2 crates gain `session::*` modules that bridge their
  existing factory pattern into `SessionParser`. The Handler-based
  factories remain available; users pick whichever fits their
  pattern.

---

## API surface (full)

```rust
// netring-flow-core (or netring's flow module)

pub trait SessionParser: Send + Sync + 'static {
    type Message: Send + 'static;
    fn feed_initiator(&mut self, bytes: &[u8]) -> SmallVec<[Self::Message; 2]>;
    fn feed_responder(&mut self, bytes: &[u8]) -> SmallVec<[Self::Message; 2]>;
    fn fin_initiator(&mut self) -> SmallVec<[Self::Message; 2]> { SmallVec::new() }
    fn fin_responder(&mut self) -> SmallVec<[Self::Message; 2]> { SmallVec::new() }
    fn rst_initiator(&mut self) {}
    fn rst_responder(&mut self) {}
}

pub trait SessionParserFactory: Send + 'static {
    type Parser: SessionParser;
    fn new_parser(&mut self) -> Self::Parser;
}

impl<P: SessionParser + Default + Clone> SessionParserFactory for P {
    type Parser = P;
    fn new_parser(&mut self) -> P { self.clone() }
}

pub trait DatagramParser: Send + Sync + 'static {
    type Message: Send + 'static;
    fn parse(&mut self, payload: &[u8], side: FlowSide) -> SmallVec<[Self::Message; 2]>;
}

#[derive(Debug)]
pub enum SessionEvent<K, M> {
    Started { key: K, ts: Timestamp },
    Application { key: K, side: FlowSide, message: M, ts: Timestamp },
    Closed { key: K, reason: EndReason, stats: FlowStats },
}

// netring-flow-stream (in netring crate, gated by flow + tokio)

impl<S, E> FlowStream<S, E, (), NoReassembler> {
    pub fn session_stream<F: SessionParserFactory>(self, factory: F)
        -> SessionStream<S, E, F>;

    pub fn datagram_stream<P: DatagramParser>(self, parser: P)
        -> DatagramStream<S, E, P>;
}

pub struct SessionStream<S, E, F> { ... }
impl<S, E, F> Stream for SessionStream<S, E, F>
where ...
{
    type Item = Result<SessionEvent<E::Key, <<F as SessionParserFactory>::Parser as SessionParser>::Message>, Error>;
}
```

---

## Concrete bridges (in each Tier-2 crate)

### `netring-flow-http/src/session.rs`

```rust
use netring_flow_stream::{SessionParser, SessionParserFactory};

#[derive(Default, Clone)]
pub struct HttpParser {
    initiator: HttpDirectionParser,
    responder: HttpDirectionParser,
    config: HttpConfig,
}

#[derive(Debug, Clone)]
pub enum HttpMessage {
    Request(HttpRequest),
    Response(HttpResponse),
}

impl SessionParser for HttpParser {
    type Message = HttpMessage;
    fn feed_initiator(&mut self, b: &[u8]) -> SmallVec<...> {
        // run httparse on initiator's BytesMut, accumulate complete
        // messages into a SmallVec, return.
    }
    // ... etc
}
```

Then users do:

```rust
let mut messages = cap
    .flow_stream(FiveTuple::bidirectional())
    .session_stream(HttpParser::default());

while let Some(evt) = messages.next().await {
    if let SessionEvent::Application { message: HttpMessage::Request(req), .. } = evt? {
        println!("{} {}", req.method, req.path);
    }
}
```

### Similar for TLS, DNS.

---

## Implementation steps

1. **Land `SessionParser` + `DatagramParser` traits + types** in
   `netring/src/async_adapters/session_stream.rs` (initially in
   `netring`; if it grows substantial, factor out into
   `netring-flow-stream` or back into `netring-flow`).
2. **Land `SessionStream`** — wraps a `FlowStream` + a
   per-flow HashMap of parser instances. On each `FlowEvent::Packet`
   with TCP payload, dispatch bytes via tracker's
   `track_with_payload`.
   - Note: this might require extending `FlowStream` to expose
     `track_with_payload` semantics through a different slot type,
     similar to how AsyncReassemblerSlot works today.
3. **Land `DatagramStream`** — wraps a `FlowStream` whose extractor
   has been wrapped to also intercept UDP payloads (similar to
   `DnsUdpObserver` in Plan 24, but generic).
4. **Migrate Plan 22 (HTTP) to also offer `HttpParser: SessionParser`**.
   The existing `HttpFactory<H>` stays; we add a parallel API.
5. **Migrate Plan 23 (TLS) to also offer `TlsParser: SessionParser`**.
6. **Migrate Plan 24 (DNS):**
   - `DnsTcpParser: SessionParser` (TCP/53, DoT)
   - `DnsUdpParser: DatagramParser` (UDP/53)
7. **Stress-test** with property tests against synthetic message
   sequences (Plan 12 fuzz harnesses extended).
8. **Document** the trait shape, the choice between `Handler`-based
   factories and `SessionParser`, error semantics, backpressure.

---

## Tests

### Property tests (proptest)

- For each parser: any sequence of correct + incorrect feed sizes
  produces the same set of messages as feeding the whole buffer
  at once.
- Empty input produces empty output.
- Oversized messages don't panic.

### Integration

- Run each Plan-12 fixture through `session_stream` with the
  corresponding parser; assert the same messages emerge as via the
  Handler-based path.

---

## Acceptance criteria

- [ ] `SessionParser` + `DatagramParser` traits compile.
- [ ] `SessionStream` + `DatagramStream` impl `Stream`.
- [ ] HttpParser, TlsParser, DnsTcpParser, DnsUdpParser ship in
      their respective crates with the new trait impls.
- [ ] Property tests passing on each parser.
- [ ] Doctest in each crate showing the unified API.
- [ ] Migration guide in `docs/SESSION_GUIDE.md`.

---

## Risks

1. **Trait churn before 1.0.** Once `SessionParser` is in the
   public API, breaking changes require a major version bump.
   We need ≥2 production parsers (HTTP + one of TLS/DNS) running
   in real workloads before we lock the trait shape.
2. **`SmallVec<[Message; 2]>` return type leakage.** Exposes the
   `smallvec` crate in our public API. Alternative: return `impl
   Iterator<Item = Message>` (ergonomic) or `Vec<Message>`
   (allocates). **Decision**: `Vec<Message>` for stability + clarity.
   Performance: one alloc per parser call; acceptable.
3. **Two-trait split** (`SessionParser` vs `DatagramParser`)
   creates surface-area discoverability problems. Mitigation:
   pair them in docs, cross-reference, ship a comparison table.
4. **HTTP/2 & QUIC don't fit either trait cleanly.** They have
   stream multiplexing (HTTP/2) or are over UDP-but-with-streams
   (QUIC). v1: out of scope. v2 might add `MultiplexedSessionParser`
   if demand surfaces.
5. **Handler vs Parser choice will confuse users.** Mitigation:
   in each Tier-2 crate's README, state the rule:
   - "Use Parser when you want async iteration over messages."
   - "Use Handler when you want callback-driven processing."
   Show one-line examples of each.

---

## Effort

- Trait + types + Stream impl: ~600 LOC
- Per-Tier-2-crate bridge: ~150 LOC each = ~600 LOC across 4 crates
- Tests: ~400 LOC
- Docs: ~300 LOC
- **Total**: ~1900 LOC
- **Time**: 5 days

---

## What this unlocks

- The cleanest API: one stream, async iteration, message-typed
  events.
- Pre-1.0 stability proof: if `SessionParser` survives 6 months
  in production with multiple parsers, it earns the 1.0 lock.
- Plug in any L7 parser (community-built for QUIC, AMQP, MQTT,
  RTSP, etc.) without rewriting integration.
- Removes the "callback boilerplate" complaint that the
  Handler-based factories invite.
