use bytes::Bytes;

/// Parsed HTTP/1.x request — start line + headers + body.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: HttpVersion,
    /// Header (name, value) pairs in order. Names are ASCII;
    /// values are bytes (RFC 7230 §3.2.4 allows any byte).
    pub headers: Vec<(String, Vec<u8>)>,
    /// Body bytes. Empty if no body or transfer-encoding only signals
    /// EOF semantics with nothing transferred yet.
    pub body: Bytes,
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
pub enum HttpVersion {
    Http1_0,
    Http1_1,
}

/// User implements this to receive parsed HTTP messages.
pub trait HttpHandler: Send + Sync + 'static {
    fn on_request(&self, _req: &HttpRequest) {}
    fn on_response(&self, _resp: &HttpResponse) {}
}

/// Configuration knobs for the HTTP parser.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Cap on the buffered bytes per direction. Once exceeded the
    /// reassembler drops the per-flow buffer to recover memory; the
    /// flow continues at TCP level but HTTP for that direction is
    /// considered desynced.
    pub max_buffer: usize,
    /// Cap on number of headers per message. Default: 64.
    pub max_headers: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            max_buffer: 1024 * 1024, // 1 MiB
            max_headers: 64,
        }
    }
}
