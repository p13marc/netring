//! HTTP/2 protocol marker.

use flowscope::driver::{DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};

use crate::protocol::{Dispatch, MessageProtocol, Protocol, ProtocolInitError, SignatureMatch};

/// The preface signature in netring's [`SignatureMatch`] vocabulary.
///
/// [`Dispatch`] speaks netring's mirror of the enum; the driver wants
/// flowscope's. They are the same three states with a `From` between
/// them, so this is the one-line bridge rather than a second
/// implementation of the check — `register` hands the driver
/// flowscope's function unchanged.
fn preface_signature(bytes: &[u8]) -> SignatureMatch {
    flowscope::detect::signatures::http2_preface(bytes).into()
}

impl MessageProtocol for Http2 {}

/// HTTP/2 — RFC 9113 frames, HPACK, and per-stream events
/// (flowscope 0.23, `#170`/`#171`/`#196`).
///
/// `on::<Http2>(|e: &Http2Event, ctx|)` fires once per stream event:
/// `Head` / `Body` / `Trailers` / `End`, plus `StreamReset` and
/// `GoAway`. Its flow lifecycle is the underlying TCP flow.
///
/// # The stream is the key, not the side
///
/// h2 multiplexes: one connection carries many concurrent requests in
/// both directions. The `ctx` side tells you which peer sent the
/// bytes; what identifies a request is the `stream_id` on the event.
/// A handler that correlates on the flow alone will interleave
/// unrelated requests.
///
/// # Dispatch is by signature, and that has a cost
///
/// Unlike [`Http`](super::Http) there is no port to match on:
/// cleartext h2 (h2c) has no standard port, and h2 over TLS is
/// opaque to a passive tap. So this dispatches on the 24-byte client
/// connection preface via
/// [`flowscope::detect::signatures::http2_preface`] — exact, not
/// heuristic, since every h2 client opens with those same bytes.
///
/// **Registering `Http2` widens the kernel prefilter to
/// `Predicate::Always`**, because a signature cannot be evaluated in
/// the kernel: every packet has to reach userspace for the first
/// bytes to be inspected. On a busy link that is the difference
/// between a narrow BPF filter and none at all. Register it when you
/// actually terminate or observe cleartext h2 — not by reflex.
///
/// That is also why `http2` is in `all-parsers` but not in the
/// curated `monitor` / `monitor-quickstart` umbrellas: enabling the
/// feature is free, but the prefilter cost should be a deliberate
/// `.on::<Http2>()`.
///
/// # Joining late
///
/// The parser is [`flowscope::http2::Http2Session`], which tolerates
/// a *missing* preface — capture may start mid-connection, and the
/// probe that pinned the flow has already consumed the bytes that
/// identified it. It does not resynchronise: bytes that are not
/// frame-aligned still fail, and the driver then drops the parser
/// with `EndReason::ParseError` rather than keep feeding one whose
/// HPACK state is meaningless.
#[derive(Debug, Clone, Copy)]
pub struct Http2;

impl Protocol for Http2 {
    type Message = flowscope::http2::Http2Event;
    const NAME: &'static str = flowscope::http2::PARSER_KIND;

    fn dispatch() -> Dispatch {
        Dispatch::Signature(preface_signature)
    }

    fn register(
        builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        debug_assert!(
            matches!(Self::dispatch(), Dispatch::Signature(_)),
            "Http2::dispatch must stay a signature for the two to agree",
        );
        Ok(builder.session_heuristic(
            flowscope::http2::Http2Session::new(),
            flowscope::detect::signatures::http2_preface,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_is_by_preface_signature() {
        match <Http2 as Protocol>::dispatch() {
            Dispatch::Signature(f) => {
                let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                assert_eq!(f(preface), SignatureMatch::Match);
                // A proper prefix must stay undecided — the preface
                // routinely splits across segments.
                assert_eq!(f(b"PRI * HTTP/2"), SignatureMatch::NeedMoreData);
                // And HTTP/1 must not be claimed.
                assert_eq!(f(b"GET / HTTP/1.1\r\n"), SignatureMatch::NoMatch);
            }
            other => panic!("expected Dispatch::Signature, got {other:?}"),
        }
    }

    /// The dispatch advertised to the subscription engine and the
    /// signature actually handed to the driver must be the same
    /// check — they are separate values, so nothing but a test keeps
    /// them honest.
    #[test]
    fn advertised_dispatch_matches_the_registered_signature() {
        let Dispatch::Signature(advertised) = <Http2 as Protocol>::dispatch() else {
            panic!("expected Dispatch::Signature");
        };
        for probe in [
            &b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..],
            b"PRI * HTTP/2",
            b"GET / HTTP/1.1\r\n",
            b"",
        ] {
            let from_driver: SignatureMatch =
                flowscope::detect::signatures::http2_preface(probe).into();
            assert_eq!(advertised(probe), from_driver, "disagreed on {probe:?}");
        }
    }

    #[test]
    fn name_matches_flowscope_parser_kind() {
        assert_eq!(<Http2 as Protocol>::NAME, flowscope::http2::PARSER_KIND);
        assert_eq!(<Http2 as Protocol>::NAME, "http/2");
    }

    #[test]
    fn register_returns_handle() {
        let mut b = flowscope::driver::Driver::builder(FiveTuple::bidirectional());
        let h = <Http2 as Protocol>::register(&mut b);
        assert!(h.is_ok());
    }
}
