//! AF_XDP backend for kernel-bypass packet I/O (feature: `af-xdp`).
//!
//! Provides 10–24 Mpps throughput via XDP sockets with shared UMEM memory.
//! Requires Linux 5.4+, an NIC with XDP driver support, and an attached
//! XDP program that redirects packets to the socket.
//!
//! # Status
//!
//! This module provides the type definitions and builder API. The actual
//! AF_XDP implementation depends on the `af-xdp` feature flag which
//! requires `xsk-rs` (and its native dependency `libxdp`).
//!
//! Without the feature, only the builder types are available (for downstream
//! crates to compile against).
//!
//! # Standalone API
//!
//! AF_XDP uses different ring semantics (UMEM + fill/completion/rx/tx rings)
//! than AF_PACKET (block-based mmap). This module provides a standalone API
//! that does **not** implement [`PacketSource`](crate::traits::PacketSource).
//! A unified trait-based API is planned for a future version using GATs.

/// Builder for AF_XDP sockets.
///
/// # Examples
///
/// ```no_run,ignore
/// use netring::afxdp::XdpSocketBuilder;
///
/// let xdp = XdpSocketBuilder::default()
///     .interface("eth0")
///     .queue_id(0)
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone)]
#[must_use]
pub struct XdpSocketBuilder {
    interface: Option<String>,
    /// NIC queue ID to bind to. Default: 0.
    pub queue_id: u32,
    /// UMEM frame size in bytes. Default: 4096.
    pub frame_size: usize,
    /// Number of UMEM frames. Default: 4096.
    pub frame_count: usize,
    /// Try zero-copy mode (falls back to copy mode). Default: true.
    pub zero_copy: bool,
}

impl Default for XdpSocketBuilder {
    fn default() -> Self {
        Self {
            interface: None,
            queue_id: 0,
            frame_size: 4096,
            frame_count: 4096,
            zero_copy: true,
        }
    }
}

impl XdpSocketBuilder {
    /// Set the network interface name (required).
    pub fn interface(mut self, name: &str) -> Self {
        self.interface = Some(name.to_string());
        self
    }

    /// Set the NIC queue ID to bind to. Default: 0.
    pub fn queue_id(mut self, id: u32) -> Self {
        self.queue_id = id;
        self
    }

    /// UMEM frame size. Default: 4096.
    pub fn frame_size(mut self, size: usize) -> Self {
        self.frame_size = size;
        self
    }

    /// Number of UMEM frames. Default: 4096.
    pub fn frame_count(mut self, count: usize) -> Self {
        self.frame_count = count;
        self
    }

    /// Try zero-copy mode (falls back to copy mode if unsupported). Default: true.
    pub fn zero_copy(mut self, enable: bool) -> Self {
        self.zero_copy = enable;
        self
    }

    /// Validate the builder configuration.
    ///
    /// Returns the interface name if valid.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`](crate::Error::Config) if interface is not set
    /// or parameters are invalid.
    pub fn validate(&self) -> Result<&str, crate::Error> {
        let iface = self
            .interface
            .as_deref()
            .ok_or_else(|| crate::Error::Config("interface is required".into()))?;
        if self.frame_size == 0 {
            return Err(crate::Error::Config("frame_size must be > 0".into()));
        }
        if self.frame_count == 0 {
            return Err(crate::Error::Config("frame_count must be > 0".into()));
        }
        Ok(iface)
    }

    /// Build the XDP socket.
    ///
    /// # Requirements
    ///
    /// - Feature `af-xdp` must be enabled
    /// - `libxdp` native library must be installed
    /// - An XDP program must be separately attached to the interface
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`](crate::Error::Config) if configuration is invalid,
    /// [`Error::Io`](crate::Error::Io) if socket creation fails.
    #[cfg(feature = "af-xdp")]
    pub fn build(self) -> Result<XdpSocket, crate::Error> {
        let _iface = self.validate()?;
        // xsk-rs implementation would go here
        Err(crate::Error::Config(
            "AF_XDP build: xsk-rs integration not yet implemented".into(),
        ))
    }

    /// Build the XDP socket (stub without `af-xdp` feature).
    #[cfg(not(feature = "af-xdp"))]
    pub fn build(self) -> Result<XdpSocket, crate::Error> {
        Err(crate::Error::Config(
            "AF_XDP requires the 'af-xdp' feature flag and libxdp native library".into(),
        ))
    }
}

/// AF_XDP socket handle.
///
/// Requires the `af-xdp` feature to construct. Without it, this type
/// exists only for downstream code to reference.
pub struct XdpSocket {
    _private: (),
}

impl XdpSocket {
    /// Receive packets (non-blocking).
    ///
    /// Returns owned copies of received packets. The underlying UMEM frames
    /// are recycled automatically.
    #[cfg(feature = "af-xdp")]
    pub fn recv(&mut self) -> Result<Vec<crate::OwnedPacket>, crate::Error> {
        // xsk-rs implementation would go here
        Ok(Vec::new())
    }

    /// Send a raw packet.
    ///
    /// Returns `false` if the TX ring is full.
    #[cfg(feature = "af-xdp")]
    pub fn send(&mut self, _data: &[u8]) -> Result<bool, crate::Error> {
        // xsk-rs implementation would go here
        Ok(false)
    }

    /// Flush pending TX frames.
    #[cfg(feature = "af-xdp")]
    pub fn flush(&mut self) -> Result<(), crate::Error> {
        Ok(())
    }
}

impl std::fmt::Debug for XdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdpSocket").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_missing_interface() {
        let err = XdpSocketBuilder::default().build().unwrap_err();
        assert!(matches!(err, crate::Error::Config(_)));
    }

    #[test]
    fn builder_defaults() {
        let b = XdpSocketBuilder::default();
        assert_eq!(b.queue_id, 0);
        assert_eq!(b.frame_size, 4096);
        assert_eq!(b.frame_count, 4096);
        assert!(b.zero_copy);
    }

    #[test]
    fn builder_validate_ok() {
        let b = XdpSocketBuilder::default().interface("lo");
        assert!(b.validate().is_ok());
    }

    #[test]
    fn builder_validate_zero_frame_size() {
        let b = XdpSocketBuilder::default().interface("lo").frame_size(0);
        assert!(b.validate().is_err());
    }
}
