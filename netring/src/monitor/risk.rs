//! nDPI-style flow-risk scoring (issue #49).
//!
//! [`MonitorBuilder::flow_risk`](crate::monitor::MonitorBuilder::flow_risk) arms
//! a set of passive, **deterministic** risk checks over flowscope's parsed
//! fields and emits a `flow_risk` anomaly per hit. v1 ships the two clearest,
//! judgment-free signals (no threshold tuning, no false-positive heuristics):
//!
//! - **`obsolete_tls`** — a TLS handshake whose **negotiated** version is
//!   SSLv3 / TLS 1.0 / TLS 1.1 (deprecated, RFC 8996). `Severity::Warning`.
//! - **`cleartext_http_credentials`** — an HTTP request carrying an
//!   `Authorization: Basic` header, i.e. a password sent base64'd over
//!   plaintext HTTP. `Severity::Error`.
//!
//! More flags (suspicious/DGA domains, self-signed certs, …) are follow-ups —
//! they involve scoring thresholds and so warrant their own tuning.

#[cfg(any(feature = "tls", feature = "http"))]
use crate::anomaly::Severity;
#[cfg(any(feature = "tls", feature = "http"))]
use crate::ctx::Ctx;

/// `obsolete_tls`: the negotiated TLS version is deprecated (RFC 8996).
#[cfg(feature = "tls")]
pub(crate) fn check_tls_risk(hs: &flowscope::tls::TlsHandshake, ctx: &mut Ctx<'_>) {
    use flowscope::tls::TlsVersion;
    if let Some(v) = hs.version
        && matches!(
            v,
            TlsVersion::Ssl3_0 | TlsVersion::Tls1_0 | TlsVersion::Tls1_1
        )
    {
        ctx.emit("flow_risk", Severity::Warning)
            .with("risk", "obsolete_tls")
            .with("tls_version", format!("{v:?}"))
            .with("sni", hs.sni.clone().unwrap_or_default())
            .emit();
    }
}

/// `cleartext_http_credentials`: an HTTP request with `Authorization: Basic`.
#[cfg(feature = "http")]
pub(crate) fn check_http_risk(msg: &flowscope::http::HttpMessage, ctx: &mut Ctx<'_>) {
    if let flowscope::http::HttpMessage::Request(req) = msg
        && let Some(auth) = req.header("authorization")
        && auth.len() >= 5
        && auth[..5].eq_ignore_ascii_case(b"basic")
    {
        ctx.emit("flow_risk", Severity::Error)
            .with("risk", "cleartext_http_credentials")
            .with("host", req.host().unwrap_or_default().to_string())
            .emit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::Severity;
    use crate::anomaly::key::Key;
    use crate::anomaly::sink::AnomalySink;
    use crate::ctx::{CounterRegistry, Ctx, FlowStateRegistry, SourceIdx, StateMap};
    use flowscope::Timestamp;
    use std::borrow::Cow;

    /// Records the `(kind, "risk" observation)` of each emitted anomaly.
    #[derive(Default)]
    struct RecSink(Vec<(String, String)>);
    impl AnomalySink for RecSink {
        fn write(
            &mut self,
            kind: &'static str,
            _severity: Severity,
            _ts: Timestamp,
            _key: Option<&dyn Key>,
            observations: &[(&'static str, Cow<'_, str>)],
            _metrics: &[(&'static str, f64)],
        ) {
            let risk = observations
                .iter()
                .find(|(l, _)| *l == "risk")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            self.0.push((kind.to_string(), risk));
        }
    }

    fn with_ctx(f: impl FnOnce(&mut Ctx<'_>)) -> Vec<(String, String)> {
        let mut sink = RecSink::default();
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        let mut flow_states = FlowStateRegistry::default();
        let mut ctx = Ctx::new(
            None,
            Timestamp::new(0, 0),
            SourceIdx(0),
            &mut state,
            &mut sink,
            &mut counters,
            &mut flow_states,
        );
        f(&mut ctx);
        sink.0
    }

    #[cfg(feature = "tls")]
    #[test]
    fn obsolete_tls_flags_weak_versions_only() {
        use flowscope::tls::{TlsHandshake, TlsVersion};
        for (v, expect) in [
            (TlsVersion::Tls1_0, true),
            (TlsVersion::Tls1_1, true),
            (TlsVersion::Ssl3_0, true),
            (TlsVersion::Tls1_2, false),
            (TlsVersion::Tls1_3, false),
        ] {
            let mut hs = TlsHandshake::default();
            hs.version = Some(v);
            let out = with_ctx(|ctx| check_tls_risk(&hs, ctx));
            let fired = out
                .iter()
                .any(|(k, r)| k == "flow_risk" && r == "obsolete_tls");
            assert_eq!(fired, expect, "version {v:?}");
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn cleartext_basic_auth_flags_only_basic() {
        use bytes::Bytes;
        use flowscope::http::{HttpMessage, HttpRequest, HttpVersion};

        let req = |auth: &'static [u8]| {
            HttpRequest::new(
                Bytes::from_static(b"GET"),
                Bytes::from_static(b"/"),
                HttpVersion::Http1_1,
                vec![(
                    Bytes::from_static(b"Authorization"),
                    Bytes::from_static(auth),
                )],
                Bytes::new(),
            )
        };

        let basic =
            with_ctx(|ctx| check_http_risk(&HttpMessage::Request(req(b"Basic dXNlcjpwdw==")), ctx));
        assert!(
            basic
                .iter()
                .any(|(k, r)| k == "flow_risk" && r == "cleartext_http_credentials")
        );

        let bearer =
            with_ctx(|ctx| check_http_risk(&HttpMessage::Request(req(b"Bearer abc.def")), ctx));
        assert!(bearer.is_empty(), "Bearer auth is not flagged");
    }
}
