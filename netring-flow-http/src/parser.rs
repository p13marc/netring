use bytes::Bytes;

use crate::types::{HttpConfig, HttpRequest, HttpResponse, HttpVersion};

/// Parser-side errors. Internal to the reassembler — exposed
/// so users can surface a descriptive message if they want.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid HTTP/1.x: {0}")]
    Parse(String),
    #[error("buffer overflow: message exceeded max_buffer={0}")]
    BufferOverflow(usize),
}

/// Per-direction parser state.
#[derive(Debug, Clone)]
pub(crate) enum DirState {
    /// Awaiting a request line + headers (initiator side) or
    /// status line + headers (responder side).
    Headers,
    /// Reading a Content-Length-bounded body. `remaining` is bytes
    /// left to read into the body buffer.
    Body {
        remaining: usize,
        started: BodyStart,
    },
    /// Connection: close — body extends to FIN. Accumulate in
    /// the body buffer until the per-direction buffer hits
    /// `max_buffer`.
    UntilEof { started: BodyStart },
    /// Desync — a previous parse error or buffer overflow forced
    /// us to give up on this direction. Bytes accumulate in vain
    /// until the next clean point (currently never automatically;
    /// users would need to drop the reassembler).
    Desynced,
}

/// Snapshot taken when we transition from Headers → body, so we
/// can rebuild the [`HttpRequest`] / [`HttpResponse`] when the
/// body completes.
#[derive(Debug, Clone)]
pub(crate) struct BodyStart {
    pub is_request: bool,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub reason: String,
    pub version: HttpVersion,
    pub headers: Vec<(String, Vec<u8>)>,
}

impl BodyStart {
    fn into_request(self, body: Bytes) -> HttpRequest {
        HttpRequest {
            method: self.method,
            path: self.path,
            version: self.version,
            headers: self.headers,
            body,
        }
    }

    fn into_response(self, body: Bytes) -> HttpResponse {
        HttpResponse {
            status: self.status,
            reason: self.reason,
            version: self.version,
            headers: self.headers,
            body,
        }
    }
}

/// Output of a parse step.
#[derive(Debug)]
pub(crate) enum ParseOutput {
    Request(HttpRequest),
    Response(HttpResponse),
}

/// Try to advance the parser, possibly emitting one parsed message.
/// Returns:
/// - `Ok(Some(message))` — emitted; the caller should re-call to
///   look for pipelined messages.
/// - `Ok(None)` — need more bytes.
/// - `Err(_)` — desync.
pub(crate) fn step(
    state: &mut DirState,
    buffer: &mut Vec<u8>,
    is_request: bool,
    config: &HttpConfig,
) -> Result<Option<ParseOutput>, Error> {
    if buffer.len() > config.max_buffer {
        *state = DirState::Desynced;
        buffer.clear();
        return Err(Error::BufferOverflow(config.max_buffer));
    }

    loop {
        match state {
            DirState::Desynced => return Ok(None),

            DirState::Headers => {
                let mut headers_storage = vec![httparse::EMPTY_HEADER; config.max_headers];
                if is_request {
                    let mut req = httparse::Request::new(&mut headers_storage);
                    match req.parse(buffer) {
                        Ok(httparse::Status::Complete(hlen)) => {
                            let snapshot = snapshot_request(&req)?;
                            let body_len = body_len_from_headers(&snapshot.headers);
                            advance_to_body(buffer, hlen);
                            transition_to_body(state, snapshot, body_len, true);
                            // Loop: maybe the body is already in the buffer
                            continue;
                        }
                        Ok(httparse::Status::Partial) => return Ok(None),
                        Err(e) => {
                            *state = DirState::Desynced;
                            buffer.clear();
                            return Err(Error::Parse(e.to_string()));
                        }
                    }
                } else {
                    let mut resp = httparse::Response::new(&mut headers_storage);
                    match resp.parse(buffer) {
                        Ok(httparse::Status::Complete(hlen)) => {
                            let snapshot = snapshot_response(&resp)?;
                            let body_len = body_len_from_headers(&snapshot.headers);
                            advance_to_body(buffer, hlen);
                            transition_to_body(state, snapshot, body_len, false);
                            continue;
                        }
                        Ok(httparse::Status::Partial) => return Ok(None),
                        Err(e) => {
                            *state = DirState::Desynced;
                            buffer.clear();
                            return Err(Error::Parse(e.to_string()));
                        }
                    }
                }
            }

            DirState::Body {
                remaining,
                started: _,
            } if *remaining == 0 => {
                // Zero-length body: emit immediately.
                if let DirState::Body { started, .. } = std::mem::replace(state, DirState::Headers)
                {
                    return Ok(Some(emit(started, Bytes::new())));
                }
                unreachable!();
            }

            DirState::Body { remaining, .. } => {
                if buffer.len() < *remaining {
                    return Ok(None);
                }
                let body_len = *remaining;
                let body = Bytes::copy_from_slice(&buffer[..body_len]);
                advance_to_body(buffer, body_len);
                if let DirState::Body { started, .. } = std::mem::replace(state, DirState::Headers)
                {
                    return Ok(Some(emit(started, body)));
                }
                unreachable!();
            }

            DirState::UntilEof { .. } => {
                // Body extends to FIN — we don't know length yet.
                // Wait for `eof()`.
                return Ok(None);
            }
        }
    }
}

/// Force end-of-stream on `state`. If we were in `UntilEof`,
/// produce the message with whatever's buffered.
pub(crate) fn eof(state: &mut DirState, buffer: &mut Vec<u8>) -> Option<ParseOutput> {
    match std::mem::replace(state, DirState::Desynced) {
        DirState::UntilEof { started } => {
            let body = Bytes::copy_from_slice(buffer);
            buffer.clear();
            Some(emit(started, body))
        }
        _ => None,
    }
}

fn emit(started: BodyStart, body: Bytes) -> ParseOutput {
    if started.is_request {
        ParseOutput::Request(started.into_request(body))
    } else {
        ParseOutput::Response(started.into_response(body))
    }
}

fn snapshot_request(req: &httparse::Request<'_, '_>) -> Result<BodyStart, Error> {
    let method = req
        .method
        .ok_or_else(|| Error::Parse("missing method".into()))?
        .to_string();
    let path = req
        .path
        .ok_or_else(|| Error::Parse("missing path".into()))?
        .to_string();
    let version = req
        .version
        .ok_or_else(|| Error::Parse("missing version".into()))?;
    let version = match version {
        0 => HttpVersion::Http1_0,
        1 => HttpVersion::Http1_1,
        _ => return Err(Error::Parse(format!("unknown version: {version}"))),
    };
    let headers: Vec<(String, Vec<u8>)> = req
        .headers
        .iter()
        .filter(|h| !h.name.is_empty())
        .map(|h| (h.name.to_string(), h.value.to_vec()))
        .collect();
    Ok(BodyStart {
        is_request: true,
        method,
        path,
        status: 0,
        reason: String::new(),
        version,
        headers,
    })
}

fn snapshot_response(resp: &httparse::Response<'_, '_>) -> Result<BodyStart, Error> {
    let status = resp
        .code
        .ok_or_else(|| Error::Parse("missing status code".into()))?;
    let reason = resp.reason.unwrap_or("").to_string();
    let version = resp
        .version
        .ok_or_else(|| Error::Parse("missing version".into()))?;
    let version = match version {
        0 => HttpVersion::Http1_0,
        1 => HttpVersion::Http1_1,
        _ => return Err(Error::Parse(format!("unknown version: {version}"))),
    };
    let headers: Vec<(String, Vec<u8>)> = resp
        .headers
        .iter()
        .filter(|h| !h.name.is_empty())
        .map(|h| (h.name.to_string(), h.value.to_vec()))
        .collect();
    Ok(BodyStart {
        is_request: false,
        method: String::new(),
        path: String::new(),
        status,
        reason,
        version,
        headers,
    })
}

/// Parse `Content-Length` from headers. Returns:
/// - `Some(n)` for a numeric Content-Length.
/// - `None` if no Content-Length found (caller decides EOF semantics).
fn body_len_from_headers(headers: &[(String, Vec<u8>)]) -> Option<usize> {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            let s = std::str::from_utf8(value).ok()?;
            return s.trim().parse::<usize>().ok();
        }
    }
    None
}

fn transition_to_body(
    state: &mut DirState,
    snapshot: BodyStart,
    body_len: Option<usize>,
    _is_request: bool,
) {
    match body_len {
        Some(0) => {
            *state = DirState::Body {
                remaining: 0,
                started: snapshot,
            };
        }
        Some(n) => {
            *state = DirState::Body {
                remaining: n,
                started: snapshot,
            };
        }
        None => {
            // Heuristic: GET / HEAD / DELETE on a request usually
            // have no body; for responses, no Content-Length means
            // body extends to FIN.
            if snapshot.is_request
                && matches!(
                    snapshot.method.as_str(),
                    "GET" | "HEAD" | "DELETE" | "OPTIONS"
                )
            {
                *state = DirState::Body {
                    remaining: 0,
                    started: snapshot,
                };
            } else {
                *state = DirState::UntilEof { started: snapshot };
            }
        }
    }
}

fn advance_to_body(buffer: &mut Vec<u8>, n: usize) {
    let rem = buffer.split_off(n);
    *buffer = rem;
}
