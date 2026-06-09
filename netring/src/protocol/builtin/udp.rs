//! UDP lifecycle marker.

use crate::protocol::{Dispatch, ParserKind, Protocol, ProtocolInitError};

/// UDP lifecycle marker. Registering this protocol enables
/// `FlowStarted<Udp>`, `FlowEnded<Udp>` typed events — no parser
/// slot is registered on flowscope's side because the central
/// flow tracker already emits UDP lifecycle events.
#[derive(Debug, Clone, Copy)]
pub struct Udp;

impl Protocol for Udp {
    type Message = ();
    const NAME: &'static str = "udp";

    fn dispatch() -> Dispatch {
        Dispatch::AllUdp
    }

    fn parser() -> Result<ParserKind<()>, ProtocolInitError> {
        Err(ProtocolInitError(
            "Udp marker is lifecycle-only — no parser; \
             handled by the central flow tracker"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_is_all_udp() {
        assert!(matches!(<Udp as Protocol>::dispatch(), Dispatch::AllUdp));
    }

    #[test]
    fn parser_returns_err_for_lifecycle_only_marker() {
        assert!(<Udp as Protocol>::parser().is_err());
    }
}
