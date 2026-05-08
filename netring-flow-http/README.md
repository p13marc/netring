# netring-flow-http

Passive HTTP/1.x observer for [`netring-flow`](https://crates.io/crates/netring-flow).

[![crates.io](https://img.shields.io/crates/v/netring-flow-http.svg)](https://crates.io/crates/netring-flow-http)
[![docs.rs](https://img.shields.io/docsrs/netring-flow-http)](https://docs.rs/netring-flow-http)

## What it is

A `netring-flow::ReassemblerFactory` impl that takes the per-flow
TCP byte stream produced by `netring-flow`'s reassembler and emits
parsed [`HttpRequest`] / [`HttpResponse`] events via a user-supplied
[`HttpHandler`] callback.

Backed by [`httparse`](https://crates.io/crates/httparse) (zero-copy
HTTP/1.x parser, no async dep).

## Quick start

```rust,no_run
use netring_flow_http::{HttpFactory, HttpHandler, HttpRequest, HttpResponse};

struct Logger;
impl HttpHandler for Logger {
    fn on_request(&self, req: &HttpRequest) {
        println!("→ {} {}", req.method, req.path);
    }
    fn on_response(&self, resp: &HttpResponse) {
        println!("← {} {}", resp.status, resp.reason);
    }
}

// Wire into a netring FlowStream:
//   cap.flow_stream(FiveTuple::bidirectional())
//      .with_reassembler(HttpFactory::with_handler(Logger));
```

Or with `netring-flow-pcap`:

```rust,no_run
use netring_flow::{FlowDriver, extract::FiveTuple};
use netring_flow_http::{HttpFactory, HttpHandler, HttpRequest, HttpResponse};
use netring_flow_pcap::PcapFlowSource;

# struct L; impl HttpHandler for L {}
let factory = HttpFactory::with_handler(L);
let mut driver: FlowDriver<FiveTuple, _, ()> =
    FlowDriver::new(FiveTuple::bidirectional(), factory);

# fn _ex() -> Result<(), Box<dyn std::error::Error>> {
for view in PcapFlowSource::open("trace.pcap")?.views() {
    for _ev in driver.track(view?.as_view()) { /* lifecycle */ }
}
# Ok(()) }
```

## What's supported

- HTTP/1.0 and HTTP/1.1.
- Request line + headers + body via `Content-Length`.
- Pipelined requests on one connection (multiple events per
  buffer pass).
- `Connection: close` body terminated by FIN.
- HTTP messages split across multiple TCP segments (the parser
  buffers and resumes incrementally).

## What's not (yet)

- **HTTP/2** — different protocol entirely; would be a separate
  crate. `h2` exists but is async-runtime-bound.
- **HTTP/3 (QUIC)** — out of scope.
- **Chunked Transfer-Encoding** — deferred to v0.2. Bodies with
  `Transfer-Encoding: chunked` parse the headers correctly but
  the body bytes are not de-chunked. Track [#issue] when filed.
- **HEAD response correlation** — parsed as a normal response;
  the body field will erroneously consume bytes intended for the
  next response on the same connection. Workaround: implement
  request/response correlation in your handler.
- **Body decompression** — bodies with `Content-Encoding: gzip`
  etc. are surfaced as raw bytes. Pipe through `flate2` if needed.

## Configuration

```rust
use netring_flow_http::{HttpConfig, HttpFactory};
# struct H; impl netring_flow_http::HttpHandler for H {}
let factory = HttpFactory::with_config(H, HttpConfig {
    max_buffer: 1024 * 1024,  // per-direction buffer cap
    max_headers: 64,
});
```

## License

Dual MIT / Apache-2.0 (your choice).
