//! Verify a downstream-crate-equivalent custom `Protocol`
//! implementation compiles and reports correctly. This is the
//! agnosticism contract: third parties plug in new protocols
//! without editing netring.

#![cfg(all(feature = "tokio", feature = "flow"))]

use flowscope::driver::{Driver, DriverBuilder, SlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use netring::protocol::{Dispatch, Protocol, ProtocolInitError, SignatureMatch};

/// Imagine this lives in a downstream crate. No netring edit needed.
#[derive(Debug, Clone, Copy)]
struct MyCustomProtocol;

impl Protocol for MyCustomProtocol {
    type Message = ();
    const NAME: &'static str = "my-custom";

    fn dispatch() -> Dispatch {
        Dispatch::Tcp(vec![9999])
    }

    fn register(
        _builder: &mut DriverBuilder<FiveTuple>,
    ) -> Result<SlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError> {
        // Lifecycle-only stand-in for this test; real third-party
        // crates would call `builder.session_on_ports(parser, ports)`.
        Err(ProtocolInitError::new("integration-test stub"))
    }
}

#[test]
fn custom_protocol_compiles_and_dispatches() {
    assert_eq!(<MyCustomProtocol as Protocol>::NAME, "my-custom");
    match <MyCustomProtocol as Protocol>::dispatch() {
        Dispatch::Tcp(ports) => assert_eq!(ports, vec![9999]),
        other => panic!("expected Dispatch::Tcp([9999]), got {other:?}"),
    }
}

#[test]
fn signature_dispatch_uses_flowscope_function_pointer() {
    // Verify SignatureMatch can wrap a real flowscope signature.
    let sig_fn: fn(&[u8]) -> SignatureMatch =
        |bytes: &[u8]| flowscope::detect::signatures::http_request(bytes).into();
    let d = Dispatch::Signature(sig_fn);
    assert!(matches!(d, Dispatch::Signature(_)));
    // Sanity: signature actually fires for a real HTTP prefix.
    assert_eq!(sig_fn(b"GET / HTTP/1.1\r\n"), SignatureMatch::Match);
    assert_eq!(sig_fn(b"XYZ"), SignatureMatch::NoMatch);
}

#[cfg(feature = "http")]
#[test]
fn builtin_http_marker_round_trip() {
    use netring::protocol::builtin::Http;
    assert_eq!(<Http as Protocol>::NAME, "http/1");
    match <Http as Protocol>::dispatch() {
        Dispatch::Tcp(ports) => assert_eq!(ports, vec![80, 8080]),
        other => panic!("expected Dispatch::Tcp([80,8080]), got {other:?}"),
    }
    // register() actually registers a parser with a real builder
    let mut b = Driver::builder(FiveTuple::bidirectional());
    assert!(<Http as Protocol>::register(&mut b).is_ok());
}

#[test]
fn builtin_tcp_and_udp_are_lifecycle_only() {
    use netring::protocol::builtin::{Tcp, Udp};
    assert!(matches!(<Tcp as Protocol>::dispatch(), Dispatch::AllTcp));
    assert!(matches!(<Udp as Protocol>::dispatch(), Dispatch::AllUdp));
    let mut b = Driver::builder(FiveTuple::bidirectional());
    assert!(<Tcp as Protocol>::register(&mut b).is_err());
    assert!(<Udp as Protocol>::register(&mut b).is_err());
}
