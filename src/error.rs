//! Error types for netring.

/// All errors returned by netring.
#[derive(Debug, thiserror::Error)]
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
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

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
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
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

        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "fail");
        let e = Error::SockOpt {
            option: "PACKET_VERSION",
            source: io_err,
        };
        assert!(e.to_string().contains("PACKET_VERSION"));
    }
}
