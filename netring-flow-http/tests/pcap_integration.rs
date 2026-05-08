//! End-to-end test: feed the HTTP fixture through netring-flow-pcap +
//! netring-flow's tracker + reassembler, with HttpFactory wired in.
//!
//! Verifies that real HTTP/1.1 traffic (the synthetic exchange in
//! `http_session.pcap`) round-trips through the entire stack.

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use netring_flow::extract::FiveTuple;
use netring_flow::{FlowDriver, FlowEvent};
use netring_flow_http::{HttpFactory, HttpHandler, HttpRequest, HttpResponse};
use netring_flow_pcap::PcapFlowSource;

const HTTP_SESSION: &[u8] = include_bytes!("../../netring-flow/tests/data/http_session.pcap");

#[derive(Default)]
struct Captured {
    reqs: Vec<HttpRequest>,
    resps: Vec<HttpResponse>,
}

#[derive(Clone)]
struct CapHandler(Arc<Mutex<Captured>>);
impl HttpHandler for CapHandler {
    fn on_request(&self, req: &HttpRequest) {
        self.0.lock().unwrap().reqs.push(req.clone());
    }
    fn on_response(&self, resp: &HttpResponse) {
        self.0.lock().unwrap().resps.push(resp.clone());
    }
}

#[test]
fn http_pcap_emits_request_and_response() {
    let captured = Arc::new(Mutex::new(Captured::default()));
    let handler = CapHandler(captured.clone());
    let factory = HttpFactory::with_handler(handler);

    let mut driver: FlowDriver<FiveTuple, _, ()> =
        FlowDriver::new(FiveTuple::bidirectional(), factory);

    let src = PcapFlowSource::from_reader(Cursor::new(HTTP_SESSION)).unwrap();
    let mut last_ts = None;
    for view in src.views() {
        let view = view.unwrap();
        last_ts = Some(view.timestamp);
        for _ev in driver.track(view.as_view()) {
            // lifecycle events are not asserted on here
        }
    }
    // Final sweep so the FIN'd flow's reassemblers fire fin().
    if let Some(ts) = last_ts {
        let far = netring_flow::Timestamp::new(ts.sec.saturating_add(86_400), 0);
        let evts = driver.sweep(far);
        // At least one Ended event expected, but we don't strictly
        // assert here — driver.track() above already sees the FIN
        // and emits Ended { Fin }, so reassembler.fin() fires
        // synchronously inside driver.track().
        let _ = evts;
    }

    let c = captured.lock().unwrap();
    assert_eq!(c.reqs.len(), 1, "expected exactly 1 HTTP request");
    assert_eq!(c.resps.len(), 1, "expected exactly 1 HTTP response");

    assert_eq!(c.reqs[0].method, "GET");
    assert_eq!(c.reqs[0].path, "/index.html");
    assert!(
        c.reqs[0]
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("host")),
        "Host header expected"
    );

    assert_eq!(c.resps[0].status, 200);
    assert_eq!(c.resps[0].reason, "OK");
    assert_eq!(&*c.resps[0].body, b"Hello, world!");
}

// silence unused import lint when feature combinations exclude this
#[allow(dead_code)]
fn _unused(_: FlowEvent<()>) {}
