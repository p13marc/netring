//! [`HttpParser`] — `SessionParser` impl that produces
//! [`HttpRequest`] / [`HttpResponse`] events.
//!
//! Equivalent to [`crate::HttpFactory`] but in the typed-stream
//! shape: pair with `netring::FlowStream::session_stream(...)` to
//! get an async iterator of HTTP messages instead of a callback
//! handler.

use netring_flow::SessionParser;

use crate::parser::{self, DirState, ParseOutput};
use crate::types::{HttpConfig, HttpRequest, HttpResponse};

/// Unified message type emitted by [`HttpParser`].
#[derive(Debug, Clone)]
pub enum HttpMessage {
    Request(HttpRequest),
    Response(HttpResponse),
}

/// Per-flow HTTP/1.x parser. Holds independent state for the
/// initiator (request) and responder (response) directions.
///
/// Implements `Default + Clone`, so it can be passed directly as a
/// `SessionParserFactory` — every new flow gets a fresh clone.
#[derive(Debug, Clone)]
pub struct HttpParser {
    config: HttpConfig,
    init_buf: Vec<u8>,
    init_state: DirState,
    resp_buf: Vec<u8>,
    resp_state: DirState,
}

impl Default for HttpParser {
    fn default() -> Self {
        Self::with_config(HttpConfig::default())
    }
}

impl HttpParser {
    /// Construct with explicit config.
    pub fn with_config(config: HttpConfig) -> Self {
        Self {
            config,
            init_buf: Vec::with_capacity(8192),
            init_state: DirState::Headers,
            resp_buf: Vec::with_capacity(8192),
            resp_state: DirState::Headers,
        }
    }

    fn drain(
        state: &mut DirState,
        buf: &mut Vec<u8>,
        is_request: bool,
        cfg: &HttpConfig,
    ) -> Vec<HttpMessage> {
        let mut out = Vec::new();
        loop {
            match parser::step(state, buf, is_request, cfg) {
                Ok(Some(ParseOutput::Request(r))) => out.push(HttpMessage::Request(r)),
                Ok(Some(ParseOutput::Response(r))) => out.push(HttpMessage::Response(r)),
                Ok(None) => break,
                Err(_) => {
                    buf.clear();
                    break;
                }
            }
        }
        out
    }
}

impl SessionParser for HttpParser {
    type Message = HttpMessage;

    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<HttpMessage> {
        if bytes.is_empty() {
            return Vec::new();
        }
        self.init_buf.extend_from_slice(bytes);
        Self::drain(&mut self.init_state, &mut self.init_buf, true, &self.config)
    }

    fn feed_responder(&mut self, bytes: &[u8]) -> Vec<HttpMessage> {
        if bytes.is_empty() {
            return Vec::new();
        }
        self.resp_buf.extend_from_slice(bytes);
        Self::drain(
            &mut self.resp_state,
            &mut self.resp_buf,
            false,
            &self.config,
        )
    }

    fn fin_initiator(&mut self) -> Vec<HttpMessage> {
        match parser::eof(&mut self.init_state, &mut self.init_buf) {
            Some(ParseOutput::Request(r)) => vec![HttpMessage::Request(r)],
            Some(ParseOutput::Response(r)) => vec![HttpMessage::Response(r)],
            None => Vec::new(),
        }
    }

    fn fin_responder(&mut self) -> Vec<HttpMessage> {
        match parser::eof(&mut self.resp_state, &mut self.resp_buf) {
            Some(ParseOutput::Request(r)) => vec![HttpMessage::Request(r)],
            Some(ParseOutput::Response(r)) => vec![HttpMessage::Response(r)],
            None => Vec::new(),
        }
    }

    fn rst_initiator(&mut self) {
        self.init_buf.clear();
        self.init_state = DirState::Headers;
    }

    fn rst_responder(&mut self) {
        self.resp_buf.clear();
        self.resp_state = DirState::Headers;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_request_then_response() {
        let mut p = HttpParser::default();
        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let m = p.feed_initiator(req);
        assert_eq!(m.len(), 1);
        match &m[0] {
            HttpMessage::Request(r) => {
                assert_eq!(r.method, "GET");
                assert_eq!(r.path, "/index.html");
            }
            _ => panic!("expected Request"),
        }

        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let m = p.feed_responder(resp);
        assert_eq!(m.len(), 1);
        match &m[0] {
            HttpMessage::Response(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(r.body.as_ref(), b"hello");
            }
            _ => panic!("expected Response"),
        }
    }

    #[test]
    fn split_segments_concatenate() {
        let mut p = HttpParser::default();
        let m = p.feed_initiator(b"GET /a HTTP/1.1\r\nHo");
        assert!(m.is_empty());
        let m = p.feed_initiator(b"st: x\r\n\r\n");
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn pipelined_requests() {
        let mut p = HttpParser::default();
        let pipelined = b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n";
        let m = p.feed_initiator(pipelined);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn fin_flushes_until_eof_body() {
        let mut p = HttpParser::default();
        // Connection: close response with no Content-Length → UntilEof.
        let h = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhel";
        let m = p.feed_responder(h);
        assert!(m.is_empty()); // body still pending
        let m = p.feed_responder(b"lo");
        assert!(m.is_empty());
        let m = p.fin_responder();
        assert_eq!(m.len(), 1);
        match &m[0] {
            HttpMessage::Response(r) => assert_eq!(r.body.as_ref(), b"hello"),
            _ => panic!("expected Response"),
        }
    }
}
