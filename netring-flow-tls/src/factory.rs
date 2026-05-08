use std::sync::Arc;

use netring_flow::{FlowSide, Reassembler, ReassemblerFactory};

use crate::parser::{self, DirState, ParseOutput};
use crate::types::{TlsConfig, TlsHandler};

/// `ReassemblerFactory` that produces a [`TlsReassembler`] per
/// (flow, side). Wraps a user-supplied [`TlsHandler`] and shares
/// it across all per-flow reassembler instances.
pub struct TlsFactory<H: TlsHandler> {
    handler: Arc<H>,
    config: TlsConfig,
}

impl<H: TlsHandler> TlsFactory<H> {
    /// Construct with default [`TlsConfig`].
    pub fn with_handler(handler: H) -> Self {
        Self {
            handler: Arc::new(handler),
            config: TlsConfig::default(),
        }
    }

    /// Construct with explicit config.
    pub fn with_config(handler: H, config: TlsConfig) -> Self {
        Self {
            handler: Arc::new(handler),
            config,
        }
    }
}

impl<K, H> ReassemblerFactory<K> for TlsFactory<H>
where
    K: Send + 'static,
    H: TlsHandler,
{
    type Reassembler = TlsReassembler<H>;

    fn new_reassembler(&mut self, _key: &K, side: FlowSide) -> TlsReassembler<H> {
        TlsReassembler {
            handler: self.handler.clone(),
            config: self.config.clone(),
            buffer: Vec::with_capacity(4096),
            state: DirState::Reading,
            is_initiator: matches!(side, FlowSide::Initiator),
        }
    }
}

/// Per-(flow, side) reassembler. Buffers TCP segments, parses TLS
/// records, invokes [`TlsHandler`] for each handshake event.
pub struct TlsReassembler<H: TlsHandler> {
    handler: Arc<H>,
    config: TlsConfig,
    buffer: Vec<u8>,
    state: DirState,
    is_initiator: bool,
}

impl<H: TlsHandler> TlsReassembler<H> {
    fn drain(&mut self) {
        loop {
            match parser::step(
                &mut self.state,
                &mut self.buffer,
                self.is_initiator,
                &self.config,
            ) {
                Ok(Some(out)) => self.dispatch(out),
                Ok(None) => break,
                Err(_) => {
                    self.buffer.clear();
                    break;
                }
            }
        }
    }

    fn dispatch(&self, out: ParseOutput) {
        match out {
            ParseOutput::ClientHello(ch) => {
                #[cfg(feature = "ja3")]
                if self.config.ja3 {
                    let (canonical, hash) = crate::fingerprint::ja3(&ch);
                    self.handler.on_ja3(&hash, &canonical);
                }
                self.handler.on_client_hello(&ch);
            }
            ParseOutput::ServerHello(sh) => self.handler.on_server_hello(&sh),
            ParseOutput::Alert(a) => self.handler.on_alert(&a),
        }
    }
}

impl<H: TlsHandler> Reassembler for TlsReassembler<H> {
    fn segment(&mut self, _seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        if matches!(self.state, DirState::Encrypted | DirState::Desynced) {
            // Already past the visibility window — drop bytes
            // rather than buffering for nothing.
            return;
        }
        self.buffer.extend_from_slice(payload);
        self.drain();
    }

    fn fin(&mut self) {
        self.buffer.clear();
    }

    fn rst(&mut self) {
        self.buffer.clear();
    }
}
