//! TLS record + handshake parsing on top of `tls-parser`.

use bytes::Bytes;
use tls_parser::{
    TlsExtension, TlsMessage, TlsMessageAlert, TlsMessageHandshake, parse_tls_extensions,
    parse_tls_plaintext,
};

use crate::types::{
    TlsAlert, TlsAlertLevel, TlsClientHello, TlsConfig, TlsServerHello, TlsVersion,
};

/// Parser-side errors. Bubbled up to the reassembler, which transitions
/// the per-direction state to [`DirState::Desynced`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid TLS record: {0}")]
    Parse(String),
    #[error("buffer overflow: handshake exceeded max_buffer={0}")]
    BufferOverflow(usize),
}

/// Per-direction parser state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirState {
    /// Awaiting more record bytes.
    Reading,
    /// ChangeCipherSpec observed; subsequent records are encrypted
    /// and we stop trying to parse handshake data.
    Encrypted,
    /// Parser irrecoverably desynced (malformed input).
    Desynced,
}

/// Output of one parse step.
#[derive(Debug)]
pub(crate) enum ParseOutput {
    ClientHello(Box<TlsClientHello>),
    ServerHello(Box<TlsServerHello>),
    Alert(TlsAlert),
}

/// Try to advance the parser, possibly emitting one event.
///
/// Returns:
/// - `Ok(Some(event))` — emitted; caller should re-call to drain
///   any subsequent records that were buffered.
/// - `Ok(None)` — need more bytes (or we transitioned to Encrypted).
/// - `Err(_)` — desync.
pub(crate) fn step(
    state: &mut DirState,
    buffer: &mut Vec<u8>,
    is_initiator: bool,
    config: &TlsConfig,
) -> Result<Option<ParseOutput>, Error> {
    if buffer.len() > config.max_buffer {
        *state = DirState::Desynced;
        buffer.clear();
        return Err(Error::BufferOverflow(config.max_buffer));
    }
    if matches!(*state, DirState::Encrypted | DirState::Desynced) {
        return Ok(None);
    }
    if buffer.len() < 5 {
        return Ok(None);
    }
    // Peek the record length without consuming.
    let record_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
    let total = 5 + record_len;
    if buffer.len() < total {
        return Ok(None);
    }

    // Parse one record. The returned TlsPlaintext borrows from
    // `buffer`; we build owned events before releasing the borrow
    // and mutating the buffer.
    let mut emitted: Option<ParseOutput> = None;
    let mut became_encrypted = false;
    {
        let plaintext = match parse_tls_plaintext(&buffer[..total]) {
            Ok((_, p)) => p,
            Err(e) => {
                let msg = format!("{e:?}");
                *state = DirState::Desynced;
                buffer.clear();
                return Err(Error::Parse(msg));
            }
        };
        let record_version = TlsVersion::from_raw(plaintext.hdr.version.0);

        for msg in &plaintext.msg {
            match msg {
                TlsMessage::Handshake(h) => match h {
                    TlsMessageHandshake::ClientHello(ch) if is_initiator => {
                        let ev = build_client_hello(record_version, ch);
                        emitted = Some(ParseOutput::ClientHello(Box::new(ev)));
                    }
                    TlsMessageHandshake::ServerHello(sh) if !is_initiator => {
                        let ev = build_server_hello(record_version, sh);
                        emitted = Some(ParseOutput::ServerHello(Box::new(ev)));
                    }
                    _ => {}
                },
                TlsMessage::Alert(alert) => {
                    emitted = Some(ParseOutput::Alert(build_alert(alert)));
                }
                TlsMessage::ChangeCipherSpec => {
                    became_encrypted = true;
                }
                TlsMessage::ApplicationData(_) | TlsMessage::Heartbeat(_) => {}
            }
        }
    }

    if became_encrypted {
        *state = DirState::Encrypted;
    }

    // Consume the record we just processed.
    let rest = buffer.split_off(total);
    *buffer = rest;
    Ok(emitted)
}

fn build_client_hello(
    record_version: TlsVersion,
    ch: &tls_parser::TlsClientHelloContents<'_>,
) -> TlsClientHello {
    let legacy_version = TlsVersion::from_raw(ch.version.0);
    let mut random = [0u8; 32];
    let n = ch.random.len().min(32);
    random[..n].copy_from_slice(&ch.random[..n]);
    let session_id = ch
        .session_id
        .map(Bytes::copy_from_slice)
        .unwrap_or_default();
    let cipher_suites: Vec<u16> = ch.ciphers.iter().map(|c| c.0).collect();
    let compression: Vec<u8> = ch.comp.iter().map(|c| c.0).collect();

    let mut sni: Option<String> = None;
    let mut alpn: Vec<String> = Vec::new();
    let mut supported_versions: Vec<TlsVersion> = Vec::new();
    let mut supported_groups: Vec<u16> = Vec::new();
    let mut extension_types: Vec<u16> = Vec::new();

    if let Some(ext_bytes) = ch.ext
        && let Ok((_, exts)) = parse_tls_extensions(ext_bytes)
    {
        for ext in &exts {
            extension_types.push(extension_id(ext));
            match ext {
                TlsExtension::SNI(items) => {
                    for (_kind, host) in items {
                        if let Ok(s) = std::str::from_utf8(host) {
                            sni = Some(s.to_string());
                            break;
                        }
                    }
                }
                TlsExtension::ALPN(protos) => {
                    for p in protos {
                        if let Ok(s) = std::str::from_utf8(p) {
                            alpn.push(s.to_string());
                        }
                    }
                }
                TlsExtension::SupportedVersions(vs) => {
                    for v in vs {
                        supported_versions.push(TlsVersion::from_raw(v.0));
                    }
                }
                TlsExtension::EllipticCurves(groups) => {
                    for g in groups {
                        supported_groups.push(g.0);
                    }
                }
                _ => {}
            }
        }
    }

    TlsClientHello {
        record_version,
        legacy_version,
        random,
        session_id,
        cipher_suites,
        compression,
        sni,
        alpn,
        supported_versions,
        supported_groups,
        extension_types,
    }
}

fn build_server_hello(
    record_version: TlsVersion,
    sh: &tls_parser::TlsServerHelloContents<'_>,
) -> TlsServerHello {
    let legacy_version = TlsVersion::from_raw(sh.version.0);
    let mut random = [0u8; 32];
    let n = sh.random.len().min(32);
    random[..n].copy_from_slice(&sh.random[..n]);
    let session_id = sh
        .session_id
        .map(Bytes::copy_from_slice)
        .unwrap_or_default();
    let cipher_suite = sh.cipher.0;
    let compression = sh.compression.0;

    let mut alpn: Option<String> = None;
    let mut supported_version: Option<TlsVersion> = None;

    if let Some(ext_bytes) = sh.ext
        && let Ok((_, exts)) = parse_tls_extensions(ext_bytes)
    {
        for ext in &exts {
            match ext {
                TlsExtension::ALPN(protos) => {
                    if let Some(p) = protos.first() {
                        if let Ok(s) = std::str::from_utf8(p) {
                            alpn = Some(s.to_string());
                        }
                    }
                }
                TlsExtension::SupportedVersions(vs) => {
                    if let Some(v) = vs.first() {
                        supported_version = Some(TlsVersion::from_raw(v.0));
                    }
                }
                _ => {}
            }
        }
    }

    TlsServerHello {
        record_version,
        legacy_version,
        random,
        session_id,
        cipher_suite,
        compression,
        alpn,
        supported_version,
    }
}

fn build_alert(alert: &TlsMessageAlert) -> TlsAlert {
    let level = match alert.severity.0 {
        1 => TlsAlertLevel::Warning,
        2 => TlsAlertLevel::Fatal,
        v => TlsAlertLevel::Other(v),
    };
    TlsAlert {
        level,
        description: alert.code.0,
    }
}

/// Map a TlsExtension to its IANA type ID. Used for fingerprinting
/// (JA3, JA4) and for the public `extension_types` field.
fn extension_id(ext: &TlsExtension<'_>) -> u16 {
    match ext {
        TlsExtension::SNI(_) => 0,
        TlsExtension::MaxFragmentLength(_) => 1,
        TlsExtension::StatusRequest(_) => 5,
        TlsExtension::EllipticCurves(_) => 10,
        TlsExtension::EcPointFormats(_) => 11,
        TlsExtension::SignatureAlgorithms(_) => 13,
        TlsExtension::Heartbeat(_) => 15,
        TlsExtension::ALPN(_) => 16,
        TlsExtension::SignedCertificateTimestamp(_) => 18,
        TlsExtension::Padding(_) => 21,
        TlsExtension::EncryptThenMac => 22,
        TlsExtension::ExtendedMasterSecret => 23,
        TlsExtension::SessionTicket(_) => 35,
        TlsExtension::PreSharedKey(_) => 41,
        TlsExtension::EarlyData(_) => 42,
        TlsExtension::SupportedVersions(_) => 43,
        TlsExtension::Cookie(_) => 44,
        TlsExtension::PskExchangeModes(_) => 45,
        TlsExtension::KeyShare(_) => 51,
        TlsExtension::NextProtocolNegotiation => 13172,
        TlsExtension::RenegotiationInfo(_) => 65281,
        TlsExtension::EncryptedServerName { .. } => 65486,
        TlsExtension::Grease(..) => 0x0a0a,
        // Unknown extensions: tls-parser keeps the raw type via Unknown.
        TlsExtension::Unknown(t, _) => t.0,
        // Variants we don't track explicitly map to their best-known
        // IANA IDs; for any new variants tls-parser adds, fall back to
        // a sentinel. Users who need exact IDs should walk extensions
        // themselves via parse_tls_extensions.
        _ => u16::MAX,
    }
}
