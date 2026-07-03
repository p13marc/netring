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
/// JA3 + JA4 (client) are royalty-free (BSD) and present with the `tls`
/// feature. `ja4s` (the JA4S **server** fingerprint) is **FoxIO License 1.1**
/// (non-commercial; patent pending) and exists only under the opt-in
/// [`ja4plus`](index.html#features) feature — commercial use requires a FoxIO
/// OEM license (see `docs/FINGERPRINTS.md`). All are `None` if fingerprinting
/// wasn't enabled/configured.
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
    /// JA4 client fingerprint (FoxIO format, BSD-licensed).
    pub ja4: Option<String>,
    /// JA4S server fingerprint — **FoxIO License 1.1** (opt-in `ja4plus`
    /// feature; commercial use requires a FoxIO OEM license).
    #[cfg(feature = "ja4plus")]
    pub ja4s: Option<String>,
    /// JA4X fingerprint over the **leaf X.509 certificate** (issuer / subject
    /// / extension OID hashes) — **FoxIO License 1.1** (opt-in `ja4plus`
    /// feature). `None` for TLS 1.3 (the certificate is encrypted) or when the
    /// server didn't present a certificate in the handshake.
    #[cfg(feature = "ja4plus")]
    pub ja4x: Option<String>,
    /// Issue #128: the ClientHello offered a **post-quantum** key-share group
    /// (e.g. X25519MLKEM768 / X25519Kyber768). A cheap PQ-adoption signal for
    /// inventory + policy, independent of the FoxIO fingerprints.
    pub pq_key_share: bool,
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
            #[cfg(feature = "ja4plus")]
            ja4s: hs.ja4s.clone(),
            #[cfg(feature = "ja4plus")]
            ja4x: hs.ja4x.clone(),
            pq_key_share: hs.pq_key_share,
            key,
        }
    }

    /// `true` when at least one fingerprint (JA3 / JA4 / JA4S / JA4X) is
    /// present. Cheap guard for handlers that only act on fingerprinted
    /// handshakes.
    pub fn has_fingerprint(&self) -> bool {
        let any = self.ja3.is_some() || self.ja4.is_some();
        #[cfg(feature = "ja4plus")]
        let any = any || self.ja4s.is_some() || self.ja4x.is_some();
        any
    }
}

/// An HTTP request's client fingerprint bundle — the JA4H FoxIO fingerprint
/// plus the identifying request headers — handed to an
/// [`on_http_fingerprint`](crate::monitor::MonitorBuilder::on_http_fingerprint)
/// handler.
///
/// JA4H is **FoxIO License 1.1** (non-commercial; patent pending), so this
/// type and the hook that produces it live behind the opt-in `ja4plus`
/// feature — commercial use requires a FoxIO OEM license (see
/// `docs/FINGERPRINTS.md`). It is the HTTP analogue of [`TlsFingerprint`]:
/// "which client software issued this request", from the method, ordered
/// header names, cookies, and `Accept-Language`.
#[cfg(all(feature = "http", feature = "ja4plus"))]
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct HttpFingerprint {
    /// JA4H fingerprint (`a_b_c_d` FoxIO format).
    pub ja4h: String,
    /// Request method (`GET`, `POST`, …), if it was valid ASCII.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub method: Option<String>,
    /// First `Host` header value, if present.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub host: Option<String>,
    /// First `User-Agent` header value, if present.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub user_agent: Option<String>,
    /// The flow's 5-tuple key (from the dispatch context), if available.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub key: Option<FlowKey>,
}

#[cfg(all(feature = "http", feature = "ja4plus"))]
impl HttpFingerprint {
    /// Build from a flowscope HTTP request + the flow key, computing JA4H.
    pub(crate) fn from_request(req: &flowscope::http::HttpRequest, key: Option<FlowKey>) -> Self {
        Self {
            ja4h: flowscope::http::ja4h_fingerprint(req),
            method: req.method_str().map(str::to_owned),
            host: req.host().map(str::to_owned),
            user_agent: req.user_agent().map(str::to_owned),
            key,
        }
    }
}

/// A QUIC client fingerprint bundle (issue #128) — handed to an
/// [`on_quic_fingerprint`](crate::monitor::MonitorBuilder::on_quic_fingerprint)
/// handler once per parsed QUIC Initial. The UDP/QUIC analogue of
/// [`TlsFingerprint`]: SNI + ALPN + version, plus the QUIC-flavoured JA4
/// (`q`-prefixed) and the post-quantum key-share signal when the `tls` feature
/// recovers the embedded ClientHello.
#[cfg(feature = "quic")]
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct QuicFingerprint {
    /// Server Name Indication from the Initial's ClientHello, if present.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub sni: Option<String>,
    /// First offered ALPN protocol (e.g. `h3`), if any.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub alpn: Option<String>,
    /// QUIC version label (`v1` / `v2` / a raw `0x…` for others).
    pub version: String,
    /// QUIC JA4 (`q`-prefixed FoxIO format). `None` without the `tls` feature
    /// (the embedded ClientHello is needed) or when it wasn't recoverable.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ja4: Option<String>,
    /// The Initial's ClientHello offered a post-quantum key-share group. Always
    /// `false` without the `tls` feature (no ClientHello to inspect).
    pub pq_key_share: bool,
    /// The flow's 5-tuple key, if available.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub key: Option<FlowKey>,
}

#[cfg(feature = "quic")]
impl QuicFingerprint {
    /// Build from a parsed QUIC Initial + the flow key.
    pub(crate) fn from_initial(initial: &flowscope::QuicInitial, key: Option<FlowKey>) -> Self {
        let version = if initial.version.is_v1() {
            "v1".to_string()
        } else if initial.version.is_v2() {
            "v2".to_string()
        } else {
            format!("0x{:08x}", initial.version.as_u32())
        };
        #[cfg(feature = "tls")]
        let ja4 = flowscope::quic::ja4(initial);
        #[cfg(not(feature = "tls"))]
        let ja4 = None;
        #[cfg(feature = "tls")]
        let pq_key_share = initial
            .client_hello
            .as_ref()
            .is_some_and(|ch| ch.pq_key_share);
        #[cfg(not(feature = "tls"))]
        let pq_key_share = false;
        Self {
            sni: initial.sni.clone(),
            alpn: initial.alpn.first().cloned(),
            version,
            ja4,
            pq_key_share,
            key,
        }
    }
}

/// An SSH fingerprint bundle (issue #128) — the HASSH client + server
/// fingerprints, the version banner(s), and the offered KEX algorithms —
/// handed to an
/// [`on_ssh_fingerprint`](crate::monitor::MonitorBuilder::on_ssh_fingerprint)
/// handler once **both** peers' KEXINIT messages have been observed on a flow.
///
/// HASSH is MD5-based and openly specified (Salesforce, BSD-licensed), so unlike
/// the JA4+ fingerprints it needs no `ja4plus` opt-in.
#[cfg(feature = "ssh")]
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SshFingerprint {
    /// Version banner line(s) seen on the flow (`SSH-2.0-...`). SSH banners
    /// carry no direction upstream, so both peers' banners land here in
    /// arrival order.
    pub banners: Vec<String>,
    /// HASSH (client KEXINIT fingerprint), if the client KEXINIT was seen.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub hassh: Option<String>,
    /// HASSHServer (server KEXINIT fingerprint), if the server KEXINIT was seen.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub hassh_server: Option<String>,
    /// Client `kex_algorithms` name-list (from the client KEXINIT).
    pub kex_algorithms: Vec<String>,
    /// The flow's 5-tuple key, if available.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub key: Option<FlowKey>,
}

/// Per-flow SSH accumulator (issue #128). Lives in the Monitor's flow-state
/// map (auto-evicted on `FlowEnded`); folds banner + KEXINIT messages until
/// both HASSH fingerprints are known, then fires exactly once.
#[cfg(feature = "ssh")]
#[derive(Debug, Default)]
pub(crate) struct SshFpState {
    pub(crate) banners: Vec<String>,
    pub(crate) hassh: Option<String>,
    pub(crate) hassh_server: Option<String>,
    pub(crate) kex_algorithms: Vec<String>,
    /// Set once the handler has fired, so a duplicate KEXINIT can't re-fire.
    pub(crate) fired: bool,
}

#[cfg(feature = "ssh")]
impl SshFpState {
    /// Fold one SSH message. Returns `Some(fingerprint)` exactly once — when
    /// both peers' KEXINIT have been observed and the handler hasn't fired yet.
    pub(crate) fn observe(
        &mut self,
        msg: &flowscope::ssh::SshMessage,
        key: Option<FlowKey>,
    ) -> Option<SshFingerprint> {
        match msg {
            flowscope::ssh::SshMessage::Banner { banner } => {
                self.banners.push(banner.clone());
            }
            flowscope::ssh::SshMessage::KexInit(k) => {
                if k.from_client {
                    self.hassh.get_or_insert_with(|| k.hassh.clone());
                    if self.kex_algorithms.is_empty() {
                        self.kex_algorithms = k.kex_algorithms.clone();
                    }
                } else {
                    self.hassh_server.get_or_insert_with(|| k.hassh.clone());
                }
            }
            _ => {}
        }
        if !self.fired && self.hassh.is_some() && self.hassh_server.is_some() {
            self.fired = true;
            Some(SshFingerprint {
                banners: self.banners.clone(),
                hassh: self.hassh.clone(),
                hassh_server: self.hassh_server.clone(),
                kex_algorithms: self.kex_algorithms.clone(),
                key,
            })
        } else {
            None
        }
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
        hs.pq_key_share = true;
        #[cfg(feature = "ja4plus")]
        {
            hs.ja4s = Some("t130200_1301_…".to_string());
            hs.ja4x = Some("a564fbbd9b48_5e2c5a8f4f17_8c0e391b6d8b".to_string());
        }

        let fp = TlsFingerprint::from_handshake(&hs, None);
        assert_eq!(fp.sni.as_deref(), Some("example.com"));
        assert_eq!(fp.alpn.as_deref(), Some("h2")); // server's pick
        assert!(fp.pq_key_share, "pq_key_share should carry through (#128)");
        #[cfg(feature = "ja4plus")]
        {
            assert_eq!(fp.ja4s.as_deref(), Some("t130200_1301_…"));
            assert_eq!(
                fp.ja4x.as_deref(),
                Some("a564fbbd9b48_5e2c5a8f4f17_8c0e391b6d8b")
            );
        }
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

    // `on_http_fingerprint` auto-registers the Http protocol and wraps an
    // on_ctx handler that computes JA4H over each request — assert the
    // resulting monitor builds, with and without an explicit
    // `.protocol::<Http>()` first (cap-free; build() doesn't open a socket).
    #[cfg(all(feature = "http", feature = "ja4plus", feature = "tokio"))]
    #[test]
    fn on_http_fingerprint_builds_and_doesnt_double_register() {
        let m = crate::monitor::Monitor::builder()
            .interface("lo")
            .on_http_fingerprint(|_fp, _ctx| Ok(()))
            .build();
        assert!(m.is_ok(), "auto-register build failed: {:?}", m.err());

        let m = crate::monitor::Monitor::builder()
            .interface("lo")
            .protocol::<crate::protocol::builtin::Http>()
            .on_http_fingerprint(|_fp, _ctx| Ok(()))
            .build();
        assert!(m.is_ok(), "explicit-protocol build failed: {:?}", m.err());
    }
}
