//! Unit-style tests for the HTTP parser, driven via a synthetic
//! handler.

use std::sync::{Arc, Mutex};

use netring_flow::{FlowSide, Reassembler, ReassemblerFactory};
use netring_flow_http::{HttpFactory, HttpHandler, HttpRequest, HttpResponse};

#[derive(Default)]
struct Captured {
    reqs: Vec<HttpRequest>,
    resps: Vec<HttpResponse>,
}

#[derive(Clone)]
struct CapturingHandler {
    inner: Arc<Mutex<Captured>>,
}
impl CapturingHandler {
    fn new() -> (Self, Arc<Mutex<Captured>>) {
        let inner = Arc::new(Mutex::new(Captured::default()));
        (
            Self {
                inner: inner.clone(),
            },
            inner,
        )
    }
}
impl HttpHandler for CapturingHandler {
    fn on_request(&self, req: &HttpRequest) {
        self.inner.lock().unwrap().reqs.push(req.clone());
    }
    fn on_response(&self, resp: &HttpResponse) {
        self.inner.lock().unwrap().resps.push(resp.clone());
    }
}

fn build(
    side: FlowSide,
) -> (
    netring_flow_http::HttpReassembler<CapturingHandler>,
    Arc<Mutex<Captured>>,
) {
    let (h, captured) = CapturingHandler::new();
    let mut factory = HttpFactory::with_handler(h);
    let r = factory.new_reassembler(&(), side);
    (r, captured)
}

#[test]
fn simple_get_request() {
    let (mut r, captured) = build(FlowSide::Initiator);
    r.segment(0, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let c = captured.lock().unwrap();
    assert_eq!(c.reqs.len(), 1);
    assert_eq!(c.reqs[0].method, "GET");
    assert_eq!(c.reqs[0].path, "/index.html");
    assert!(c.reqs[0].body.is_empty());
}

#[test]
fn pipelined_requests() {
    let (mut r, captured) = build(FlowSide::Initiator);
    r.segment(0, b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    r.segment(0, b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n");
    r.segment(0, b"GET /c HTTP/1.1\r\nHost: x\r\n\r\n");
    let c = captured.lock().unwrap();
    assert_eq!(c.reqs.len(), 3);
    assert_eq!(c.reqs[0].path, "/a");
    assert_eq!(c.reqs[1].path, "/b");
    assert_eq!(c.reqs[2].path, "/c");
}

#[test]
fn response_with_content_length_body() {
    let (mut r, captured) = build(FlowSide::Responder);
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!";
    r.segment(0, raw);
    let c = captured.lock().unwrap();
    assert_eq!(c.resps.len(), 1);
    assert_eq!(c.resps[0].status, 200);
    assert_eq!(&*c.resps[0].body, b"Hello, world!");
}

#[test]
fn split_across_segments() {
    let (mut r, captured) = build(FlowSide::Initiator);
    r.segment(0, b"GET /index.html HTTP/1.1\r\n");
    r.segment(0, b"Host: ex");
    r.segment(0, b"ample.com\r\n\r\n");
    let c = captured.lock().unwrap();
    assert_eq!(c.reqs.len(), 1);
    assert_eq!(c.reqs[0].path, "/index.html");
}

#[test]
fn body_split_across_segments() {
    let (mut r, captured) = build(FlowSide::Responder);
    r.segment(0, b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello");
    {
        let c = captured.lock().unwrap();
        assert!(c.resps.is_empty(), "should wait for full body");
    }
    r.segment(0, b", world!");
    let c = captured.lock().unwrap();
    assert_eq!(c.resps.len(), 1);
    assert_eq!(&*c.resps[0].body, b"Hello, world!");
}

#[test]
fn connection_close_body_extends_to_fin() {
    let (mut r, captured) = build(FlowSide::Responder);
    r.segment(0, b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n");
    r.segment(0, b"hello");
    {
        let c = captured.lock().unwrap();
        assert!(c.resps.is_empty(), "still waiting for FIN");
    }
    r.segment(0, b" world");
    r.fin();
    let c = captured.lock().unwrap();
    assert_eq!(c.resps.len(), 1);
    assert_eq!(&*c.resps[0].body, b"hello world");
}

#[test]
fn malformed_doesnt_panic() {
    let (mut r, _captured) = build(FlowSide::Initiator);
    // Garbage.
    r.segment(0, b"\xff\xff\xffNOT HTTP\xff\xff\r\n\r\n");
    // Should not panic; reassembler enters Desynced.
    r.fin();
}
