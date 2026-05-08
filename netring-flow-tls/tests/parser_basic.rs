//! Parser tests using hand-crafted synthetic TLS records.

use std::sync::{Arc, Mutex};

use netring_flow::{FlowSide, Reassembler, ReassemblerFactory};
use netring_flow_tls::{
    TlsAlert, TlsClientHello, TlsFactory, TlsHandler, TlsServerHello, TlsVersion,
};

#[derive(Default, Clone)]
struct Captured {
    client_hellos: Vec<TlsClientHello>,
    server_hellos: Vec<TlsServerHello>,
    alerts: Vec<TlsAlert>,
}

#[derive(Clone)]
struct CapHandler(Arc<Mutex<Captured>>);
impl CapHandler {
    fn new() -> (Self, Arc<Mutex<Captured>>) {
        let inner = Arc::new(Mutex::new(Captured::default()));
        (Self(inner.clone()), inner)
    }
}
impl TlsHandler for CapHandler {
    fn on_client_hello(&self, h: &TlsClientHello) {
        self.0.lock().unwrap().client_hellos.push(h.clone());
    }
    fn on_server_hello(&self, h: &TlsServerHello) {
        self.0.lock().unwrap().server_hellos.push(h.clone());
    }
    fn on_alert(&self, a: &TlsAlert) {
        self.0.lock().unwrap().alerts.push(*a);
    }
}

fn make_reassembler(
    side: FlowSide,
) -> (
    netring_flow_tls::TlsReassembler<CapHandler>,
    Arc<Mutex<Captured>>,
) {
    let (h, captured) = CapHandler::new();
    let mut factory = TlsFactory::with_handler(h);
    let r = factory.new_reassembler(&(), side);
    (r, captured)
}

// ── synthetic TLS record builders ────────────────────────────────────

/// Wrap a payload in a TLS record header.
fn record(content_type: u8, version: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(content_type);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Wrap a body in a Handshake message header (type + 24-bit length).
fn handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    let len = body.len() as u32;
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.extend_from_slice(body);
    out
}

/// A minimal but valid TLS 1.2 ClientHello with an SNI extension
/// for `host`.
fn client_hello_with_sni(host: &str) -> Vec<u8> {
    // ClientHello body
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version = TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id length
    // Cipher suites (one suite: TLS_AES_128_GCM_SHA256 = 0x1301)
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    // Compression methods
    body.push(1);
    body.push(0);

    // Extensions
    let mut exts = Vec::new();

    // server_name extension (type=0)
    let host_bytes = host.as_bytes();
    let mut sni_data = Vec::new();
    let server_name_list_len = (3 + host_bytes.len()) as u16;
    sni_data.extend_from_slice(&server_name_list_len.to_be_bytes());
    sni_data.push(0); // name_type = host_name
    sni_data.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    sni_data.extend_from_slice(host_bytes);

    exts.extend_from_slice(&0u16.to_be_bytes()); // ext type 0 (SNI)
    exts.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_data);

    // ALPN extension (type=16): one protocol "h2"
    let mut alpn_data = Vec::new();
    let alpn_list = b"\x02h2"; // length-prefixed protocol
    let alpn_list_len = alpn_list.len() as u16;
    alpn_data.extend_from_slice(&alpn_list_len.to_be_bytes());
    alpn_data.extend_from_slice(alpn_list);
    exts.extend_from_slice(&16u16.to_be_bytes());
    exts.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
    exts.extend_from_slice(&alpn_data);

    // Extensions length prefix (2 bytes)
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    // Wrap in Handshake (msg_type=1) and Record (content_type=22)
    let hs = handshake(1, &body);
    record(22, 0x0303, &hs)
}

/// Minimal TLS 1.2 ServerHello with TLS_AES_128_GCM_SHA256.
fn server_hello() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // version
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id length
    body.extend_from_slice(&0x1301u16.to_be_bytes()); // cipher
    body.push(0); // compression
    // No extensions (length 0)
    body.extend_from_slice(&0u16.to_be_bytes());

    let hs = handshake(2, &body); // ServerHello
    record(22, 0x0303, &hs)
}

/// Synthetic Alert record.
fn alert_record(level: u8, desc: u8) -> Vec<u8> {
    record(21, 0x0303, &[level, desc])
}

// ── tests ──────────────────────────────────────────────────────────

#[test]
fn parses_client_hello_with_sni() {
    let (mut r, captured) = make_reassembler(FlowSide::Initiator);
    let bytes = client_hello_with_sni("example.com");
    r.segment(0, &bytes);
    let c = captured.lock().unwrap();
    assert_eq!(c.client_hellos.len(), 1);
    assert_eq!(c.client_hellos[0].sni.as_deref(), Some("example.com"));
    assert_eq!(c.client_hellos[0].alpn, vec!["h2".to_string()]);
    assert_eq!(c.client_hellos[0].cipher_suites, vec![0x1301]);
}

#[test]
fn parses_server_hello() {
    let (mut r, captured) = make_reassembler(FlowSide::Responder);
    let bytes = server_hello();
    r.segment(0, &bytes);
    let c = captured.lock().unwrap();
    assert_eq!(c.server_hellos.len(), 1);
    assert_eq!(c.server_hellos[0].cipher_suite, 0x1301);
    assert_eq!(c.server_hellos[0].legacy_version, TlsVersion::Tls1_2);
}

#[test]
fn parses_alert() {
    let (mut r, captured) = make_reassembler(FlowSide::Initiator);
    let bytes = alert_record(2, 40); // fatal handshake_failure
    r.segment(0, &bytes);
    let c = captured.lock().unwrap();
    assert_eq!(c.alerts.len(), 1);
    assert_eq!(c.alerts[0].description, 40);
}

#[test]
fn record_split_across_segments() {
    let (mut r, captured) = make_reassembler(FlowSide::Initiator);
    let bytes = client_hello_with_sni("example.com");
    let mid = bytes.len() / 2;
    r.segment(0, &bytes[..mid]);
    {
        let c = captured.lock().unwrap();
        assert!(c.client_hellos.is_empty(), "should wait for full record");
    }
    r.segment(0, &bytes[mid..]);
    let c = captured.lock().unwrap();
    assert_eq!(c.client_hellos.len(), 1);
    assert_eq!(c.client_hellos[0].sni.as_deref(), Some("example.com"));
}

#[test]
fn change_cipher_spec_stops_parsing() {
    let (mut r, captured) = make_reassembler(FlowSide::Responder);
    // ServerHello, then ChangeCipherSpec, then a fake "encrypted"
    // record (we send another SH but it should NOT be parsed).
    let mut combined = Vec::new();
    combined.extend_from_slice(&server_hello());
    // ChangeCipherSpec record: content_type=20, payload=0x01
    combined.extend_from_slice(&record(20, 0x0303, &[0x01]));
    combined.extend_from_slice(&server_hello());
    r.segment(0, &combined);
    let c = captured.lock().unwrap();
    // Only the first ServerHello should be parsed.
    assert_eq!(c.server_hellos.len(), 1);
}

#[test]
fn malformed_doesnt_panic() {
    let (mut r, _captured) = make_reassembler(FlowSide::Initiator);
    // Garbage: looks like a record (right header), but the body
    // isn't a valid ClientHello.
    let mut bad = vec![22u8, 0x03, 0x03, 0x00, 0x10];
    bad.extend_from_slice(&[0xff; 16]);
    r.segment(0, &bad);
    // Should not panic; reassembler enters Desynced.
}

#[cfg(feature = "ja3")]
#[test]
fn ja3_fires_when_enabled() {
    use netring_flow_tls::TlsConfig;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Captured {
        ja3s: Mutex<Vec<(String, String)>>,
    }
    impl TlsHandler for Captured {
        fn on_ja3(&self, hash: &str, canonical: &str) {
            self.ja3s
                .lock()
                .unwrap()
                .push((hash.to_string(), canonical.to_string()));
        }
    }
    let cap = Arc::new(Captured::default());
    let cap_clone = cap.clone();
    struct H(Arc<Captured>);
    impl TlsHandler for H {
        fn on_ja3(&self, hash: &str, canonical: &str) {
            self.0.on_ja3(hash, canonical);
        }
    }

    let mut factory = TlsFactory::with_config(
        H(cap_clone),
        TlsConfig {
            ja3: true,
            ..Default::default()
        },
    );
    let mut r = factory.new_reassembler(&(), FlowSide::Initiator);
    let bytes = client_hello_with_sni("example.com");
    r.segment(0, &bytes);
    let v = cap.ja3s.lock().unwrap();
    assert_eq!(v.len(), 1);
    assert!(!v[0].0.is_empty(), "expected non-empty hash");
}
