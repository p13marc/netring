//! TCP lifecycle marker.

use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

/// TCP lifecycle marker. Registering this protocol enables
/// `FlowStarted<Tcp>`, `FlowEstablished<Tcp>`, `FlowEnded<Tcp>`
/// typed events — no parser slot is registered on flowscope's
/// side because the central flow tracker already emits TCP
/// lifecycle events.
#[derive(Debug, Clone, Copy)]
pub struct Tcp;

impl Protocol for Tcp {
    type Message = ();
    const NAME: &'static str = "tcp";

    fn dispatch() -> Dispatch {
        Dispatch::AllTcp
    }

    fn parser() -> Result<ParserKind<()>, ProtocolInitError> {
        Err(ProtocolInitError(
            "Tcp marker is lifecycle-only — no parser; \
             handled by the central flow tracker"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_is_all_tcp() {
        assert!(matches!(<Tcp as Protocol>::dispatch(), Dispatch::AllTcp));
    }

    #[test]
    fn parser_returns_err_for_lifecycle_only_marker() {
        assert!(<Tcp as Protocol>::parser().is_err());
    }

    #[test]
    fn name_is_stable_slug() {
        assert_eq!(<Tcp as Protocol>::NAME, "tcp");
    }
}
