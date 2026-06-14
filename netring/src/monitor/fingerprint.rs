//! TLS fingerprint bundle (0.24 Phase E).
//!
//! [`TlsFingerprint`] gathers the identity-bearing fields of a completed
//! TLS handshake — SNI, ALPN, and the JA3 / JA4 (client) / JA4S (server)
//! fingerprints — plus the flow key, into one struct handed to an
//! [`on_fingerprint`](crate::monitor::MonitorBuilder::on_fingerprint)
//! handler. It's the "who is talking to whom, with what client/server
//! software" view, the unit IOC-matching and asset-inventory code wants.

use crate::protocol::FlowKey;

/// A completed TLS handshake's fingerprint bundle. Built from
/// [`flowscope::tls::TlsHandshake`] + the flow key.
///
/// `ja4s` is populated only against flowscope ≥ 0.15 with the
/// `tls-fingerprints` feature; the others follow the same feature/config
/// gating as the underlying handshake fields (all `None` if fingerprinting
/// wasn't enabled).
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TlsFingerprint {
    /// Server Name Indication from the ClientHello, if present.
    pub sni: Option<String>,
    /// Negotiated ALPN (the server's pick), falling back to the client's
    /// first offered protocol when the server didn't choose one.
    pub alpn: Option<String>,
    /// JA3 client fingerprint (MD5 hex).
    pub ja3: Option<String>,
    /// JA4 client fingerprint (FoxIO format).
    pub ja4: Option<String>,
    /// JA4S server fingerprint (FoxIO format).
    pub ja4s: Option<String>,
    /// The flow's 5-tuple key (from the dispatch context), if available.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub key: Option<FlowKey>,
}

impl TlsFingerprint {
    /// Build from a flowscope handshake event + the flow key.
    pub(crate) fn from_handshake(hs: &flowscope::tls::TlsHandshake, key: Option<FlowKey>) -> Self {
        Self {
            sni: hs.sni.clone(),
            alpn: hs
                .server_alpn
                .clone()
                .or_else(|| hs.client_alpn.first().cloned()),
            ja3: hs.ja3.clone(),
            ja4: hs.ja4.clone(),
            ja4s: hs.ja4s.clone(),
            key,
        }
    }

    /// `true` when at least one fingerprint (JA3 / JA4 / JA4S) is present.
    /// Cheap guard for handlers that only act on fingerprinted handshakes.
    pub fn has_fingerprint(&self) -> bool {
        self.ja3.is_some() || self.ja4.is_some() || self.ja4s.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowscope::tls::TlsHandshake;

    #[test]
    fn bundles_handshake_fields_and_prefers_server_alpn() {
        // `TlsHandshake` is `#[non_exhaustive]` — build via Default.
        let mut hs = TlsHandshake::default();
        hs.sni = Some("example.com".to_string());
        hs.client_alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        hs.server_alpn = Some("h2".to_string());
        hs.ja3 = Some("abc".to_string());
        hs.ja4 = Some("t13d…".to_string());
        hs.ja4s = Some("t130200_1301_…".to_string());

        let fp = TlsFingerprint::from_handshake(&hs, None);
        assert_eq!(fp.sni.as_deref(), Some("example.com"));
        assert_eq!(fp.alpn.as_deref(), Some("h2")); // server's pick
        assert_eq!(fp.ja4s.as_deref(), Some("t130200_1301_…"));
        assert!(fp.has_fingerprint());
    }

    #[test]
    fn falls_back_to_first_client_alpn_when_server_did_not_choose() {
        let mut hs = TlsHandshake::default();
        hs.client_alpn = vec!["h2".to_string()];
        hs.server_alpn = None;

        let fp = TlsFingerprint::from_handshake(&hs, None);
        assert_eq!(fp.alpn.as_deref(), Some("h2"));
        assert!(!fp.has_fingerprint());
    }

    // `on_fingerprint` auto-registers the TlsHandshake protocol and wires
    // the on_ctx handler — assert the resulting monitor builds (cap-free;
    // build() freezes the dispatcher without opening sockets).
    #[cfg(feature = "tokio")]
    #[test]
    fn on_fingerprint_builds_a_valid_monitor_and_doesnt_double_register() {
        // Auto-register path.
        let m = crate::monitor::Monitor::builder()
            .interface("lo")
            .on_fingerprint(|_fp, _ctx| Ok(()))
            .build();
        assert!(m.is_ok(), "auto-register build failed: {:?}", m.err());

        // Explicit `.protocol::<TlsHandshake>()` first → on_fingerprint must
        // not install a second handshake parser.
        let m = crate::monitor::Monitor::builder()
            .interface("lo")
            .protocol::<crate::protocol::builtin::TlsHandshake>()
            .on_fingerprint(|_fp, _ctx| Ok(()))
            .build();
        assert!(m.is_ok(), "explicit-protocol build failed: {:?}", m.err());
    }
}
