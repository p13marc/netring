use std::sync::Arc;

use netring_flow::{FlowSide, Reassembler, ReassemblerFactory};

use crate::parser::{self, DirState, ParseOutput};
use crate::types::{HttpConfig, HttpHandler};

/// `ReassemblerFactory` that produces an [`HttpReassembler`] per
/// (flow, side). Wraps a user-supplied [`HttpHandler`] and shares
/// it across all per-flow reassembler instances.
pub struct HttpFactory<H: HttpHandler> {
    handler: Arc<H>,
    config: HttpConfig,
}

impl<H: HttpHandler> HttpFactory<H> {
    /// Construct with default config.
    pub fn with_handler(handler: H) -> Self {
        Self {
            handler: Arc::new(handler),
            config: HttpConfig::default(),
        }
    }

    /// Construct with explicit config.
    pub fn with_config(handler: H, config: HttpConfig) -> Self {
        Self {
            handler: Arc::new(handler),
            config,
        }
    }
}

impl<K, H> ReassemblerFactory<K> for HttpFactory<H>
where
    K: Send + 'static,
    H: HttpHandler,
{
    type Reassembler = HttpReassembler<H>;

    fn new_reassembler(&mut self, _key: &K, side: FlowSide) -> HttpReassembler<H> {
        HttpReassembler {
            handler: self.handler.clone(),
            config: self.config.clone(),
            buffer: Vec::with_capacity(8192),
            state: DirState::Headers,
            side,
        }
    }
}

/// Per-(flow, side) reassembler. Buffers TCP segment payloads,
/// invokes [`HttpHandler`] when complete messages parse.
pub struct HttpReassembler<H: HttpHandler> {
    handler: Arc<H>,
    config: HttpConfig,
    buffer: Vec<u8>,
    state: DirState,
    side: FlowSide,
}

impl<H: HttpHandler> HttpReassembler<H> {
    /// Drain all complete messages currently in the buffer.
    fn drain(&mut self) {
        // The initiator side parses requests; responder parses
        // responses.
        let is_request = matches!(self.side, FlowSide::Initiator);
        loop {
            match parser::step(&mut self.state, &mut self.buffer, is_request, &self.config) {
                Ok(Some(ParseOutput::Request(req))) => self.handler.on_request(&req),
                Ok(Some(ParseOutput::Response(resp))) => self.handler.on_response(&resp),
                Ok(None) => break,
                Err(_) => {
                    // State transitioned to Desynced; clear buffer
                    // and stop. (Could log via tracing.)
                    self.buffer.clear();
                    break;
                }
            }
        }
    }
}

impl<H: HttpHandler> Reassembler for HttpReassembler<H> {
    fn segment(&mut self, _seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        self.buffer.extend_from_slice(payload);
        self.drain();
    }

    fn fin(&mut self) {
        // Flush any UntilEof body.
        if let Some(out) = parser::eof(&mut self.state, &mut self.buffer) {
            match out {
                ParseOutput::Request(req) => self.handler.on_request(&req),
                ParseOutput::Response(resp) => self.handler.on_response(&resp),
            }
        }
    }

    fn rst(&mut self) {
        // RST = abrupt close; drop the buffer, no flush.
        self.buffer.clear();
    }
}
