//! Error types for netring.

/// All errors returned by netring.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Failed to create the AF_PACKET socket.
    #[error("socket creation failed")]
    Socket(#[source] std::io::Error),

    /// `mmap` of the ring buffer failed.
    #[error("mmap failed")]
    Mmap(#[source] std::io::Error),

    /// Configuration is invalid (e.g., block_size not power of 2).
    #[error("invalid configuration: {0}")]
    Config(String),

    /// The named network interface does not exist.
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    /// `bind` to the interface failed.
    #[error("bind failed")]
    Bind(#[source] std::io::Error),

    /// A `setsockopt` call failed.
    #[error("setsockopt({option}) failed")]
    SockOpt {
        /// The socket option that failed (e.g., `"PACKET_VERSION"`).
        option: &'static str,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// Insufficient privileges — typically missing `CAP_NET_RAW`.
    #[error("insufficient privileges (need CAP_NET_RAW)")]
    PermissionDenied,

    /// Generic I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// XDP loader error (only present when the `xdp-loader` feature is enabled).
    #[cfg(feature = "xdp-loader")]
    #[error("XDP loader: {0}")]
    Loader(String),

    /// BPF filter construction failed (e.g., oversize program,
    /// conflicting fragments). Bubbled up from
    /// [`BpfFilter::new`](crate::BpfFilter::new) and the typed builder.
    #[error("BPF filter: {0}")]
    Bpf(#[from] crate::config::BuildError),

    /// `Monitor` builder rejected the configuration (0.20+).
    #[error("monitor build: {0}")]
    Build(#[from] BuildError),

    /// A handler panicked and `MonitorBuilder::catch_handler_panics(true)` was
    /// set (0.25 W1e) — the panic was caught and converted to this error so the
    /// configured [`HandlerErrorPolicy`](crate::monitor::HandlerErrorPolicy)
    /// (e.g. `Isolate`) decides whether to continue or tear down.
    #[error("handler panicked: {0}")]
    HandlerPanic(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Build-time errors for the 0.20 `Monitor` API. Surfaced from
/// [`crate::monitor::MonitorBuilder::build`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// `.interface(...)` / `.interfaces(...)` was not called.
    #[error(
        "at least one interface required (call .interface(...) or .interfaces([...]) on the builder)"
    )]
    NoInterface,

    /// Multi-interface monitors land in Phase E; today the builder
    /// rejects more than one interface.
    ///
    /// More than the dispatcher's per-monitor handler-type cap.
    #[error("too many event types registered: limit {limit}, found {actual}")]
    TooManyEventTypes {
        /// Maximum number of distinct event types supported.
        limit: usize,
        /// Actual count from the builder.
        actual: usize,
    },

    /// A `Protocol` impl's `dispatch()` shape and `register()` outcome
    /// disagree (e.g. `Dispatch::Tcp(_)` but `register()` returned
    /// `Err` outside the lifecycle-only fast path).
    #[error("dispatch shape mismatch in Protocol impl: {0}")]
    ProtocolDispatchMismatch(String),

    /// 0.21 A.6: A detector declared (via `detector! { counters: [K] }`)
    /// that it needs a counter for key type `type_name`, but no
    /// `.counter::<K>(window, bucket)` call registered it on the
    /// builder. Without this check, the miss would surface as a
    /// `ctx.counter_mut::<K>()` panic at the first dispatched
    /// event — moving it to build-time turns a runtime explosion
    /// into a clear configuration error.
    #[error(
        "detector `{detector}` references counter type `{type_name}` but no `.counter::<{type_name}>(window, bucket)` was registered on the builder"
    )]
    CounterNotRegistered {
        /// The `detector!` macro's `name:` slug (or `"unnamed"`
        /// for raw `Detector::new(...)`).
        detector: &'static str,
        /// `std::any::type_name::<K>()` of the missing counter type.
        type_name: &'static str,
    },

    /// 0.21 D.1: A handler is registered against a typed message
    /// event (e.g. `on::<Http>(|msg|…)`) for an L7 protocol `P`,
    /// but `.protocol::<P>()` was never called on the builder.
    /// Without the slot the parser never runs, so the handler
    /// would silently never fire — moving it to build time
    /// surfaces the misconfiguration. Lifecycle-only typed
    /// events (`FlowStarted<Tcp>`, `Tick`, etc.) are exempt;
    /// they're driven by the central tracker regardless.
    #[error(
        "handler for typed message event of protocol `{protocol_name}` requires `.protocol::<{protocol_name}>()` to be called on the builder"
    )]
    HandlerForUnregisteredProtocol {
        /// `Protocol::NAME` of the missing protocol marker.
        protocol_name: &'static str,
    },

    /// 0.21 F: [`crate::monitor::Monitor::subscribe`] called for a
    /// protocol that wasn't opted into broadcast delivery via
    /// [`crate::monitor::MonitorBuilder::with_broadcast`]. Without
    /// the broadcast slot there's no per-subscriber queue to drain.
    #[error(
        "protocol `{protocol_name}` was not registered for broadcast; call `.with_broadcast::<{protocol_name}>()` instead of `.protocol::<{protocol_name}>()` to subscribe to its messages"
    )]
    ProtocolNotBroadcast {
        /// `Protocol::NAME` of the missing broadcast registration.
        protocol_name: &'static str,
    },

    /// 0.21 E.1: [`crate::monitor::Monitor::replay`] or
    /// [`crate::monitor::Monitor::replay_with_config`] called on a
    /// monitor whose builder didn't have a
    /// [`crate::monitor::MonitorBuilder::pcap_source`] declared.
    #[error("Monitor::replay requires `MonitorBuilder::pcap_source(path)` to be set")]
    PcapSourceRequired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::other("test");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn display_variants() {
        let e = Error::Config("bad block_size".into());
        assert_eq!(e.to_string(), "invalid configuration: bad block_size");

        let e = Error::InterfaceNotFound("eth99".into());
        assert_eq!(e.to_string(), "interface not found: eth99");

        let e = Error::PermissionDenied;
        assert!(e.to_string().contains("CAP_NET_RAW"));

        let io_err = std::io::Error::other("fail");
        let e = Error::SockOpt {
            option: "PACKET_VERSION",
            source: io_err,
        };
        assert!(e.to_string().contains("PACKET_VERSION"));
    }
}
