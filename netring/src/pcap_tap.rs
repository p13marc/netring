//! Pcap tap — record each captured packet to a [`CaptureWriter`]
//! **before** the flow tracker processes it.
//!
//! Available under the `pcap + tokio` features. Used via the
//! `with_pcap_tap` / `with_pcap_tap_policy` builder methods on
//! [`FlowStream`](crate::FlowStream), [`SessionStream`],
//! [`DatagramStream`], and [`DedupStream`](crate::DedupStream).
//!
//! ```no_run
//! # use std::fs::File;
//! # async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
//! use netring::{AsyncCapture, TapErrorPolicy};
//! use netring::flow::extract::FiveTuple;
//! use netring::pcap::CaptureWriter;
//!
//! let writer = CaptureWriter::create(File::create("capture.pcap")?)?;
//! let cap = AsyncCapture::open("eth0")?;
//! let _stream = cap
//!     .flow_stream(FiveTuple::bidirectional())
//!     .with_pcap_tap(writer);
//! # Ok(()) }
//! ```
//!
//! The tap survives [`session_stream`](crate::FlowStream::session_stream),
//! [`datagram_stream`](crate::FlowStream::datagram_stream), and
//! [`with_async_reassembler`](crate::FlowStream::with_async_reassembler)
//! conversions — same plumbing as
//! [`with_dedup`](crate::FlowStream::with_dedup).
//!
//! [`SessionStream`]: crate::async_adapters::session_stream::SessionStream
//! [`DatagramStream`]: crate::async_adapters::datagram_stream::DatagramStream

use crate::error::Error;
use crate::packet::Packet;
use crate::pcap::CaptureWriter;

/// What to do when a pcap tap encounters a write error mid-capture.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TapErrorPolicy {
    /// Log the error via `tracing::warn!` and continue capturing.
    /// Subsequent packets are still tapped (until the next error).
    /// Default — appropriate for opportunistic recording.
    #[default]
    Continue,
    /// Drop the tap on first error (no further packets written),
    /// but keep the flow stream running. Subsequent packets pass
    /// through to the tracker unmodified.
    DropTap,
    /// Fail the next stream poll with [`Error::Io`]. The flow stream
    /// terminates. Recommended for evidence-recording pipelines
    /// where partial captures are a defect.
    FailStream,
}

/// Sealed trait erasing the `W` type parameter of [`CaptureWriter<W>`]
/// so the four stream types can hold an `Option<PcapTap>` without
/// proliferating generics. One virtual call per packet; overhead is
/// dwarfed by syscall cost on the disk write.
pub(crate) trait TapWriter: Send {
    fn write(&mut self, pkt: &Packet<'_>) -> Result<(), pcap_file::PcapError>;
}

impl<W: std::io::Write + Send + 'static> TapWriter for CaptureWriter<W> {
    fn write(&mut self, pkt: &Packet<'_>) -> Result<(), pcap_file::PcapError> {
        self.write_packet(pkt)
    }
}

/// Owned pcap tap — a writer plus its error policy.
///
/// Constructed by `with_pcap_tap` / `with_pcap_tap_policy` on each
/// stream type; users never name this type directly.
pub struct PcapTap {
    inner: Box<dyn TapWriter>,
    policy: TapErrorPolicy,
    /// Set when the tap was dropped under [`TapErrorPolicy::DropTap`].
    dropped: bool,
}

impl PcapTap {
    /// Wrap a `CaptureWriter` with the given error policy.
    pub(crate) fn new<W>(writer: CaptureWriter<W>, policy: TapErrorPolicy) -> Self
    where
        W: std::io::Write + Send + 'static,
    {
        Self::from_writer(Box::new(writer), policy)
    }

    /// Internal constructor from any [`TapWriter`] — used by tests
    /// to inject a mock without going through the pcap-file layer.
    pub(crate) fn from_writer(writer: Box<dyn TapWriter>, policy: TapErrorPolicy) -> Self {
        Self {
            inner: writer,
            policy,
            dropped: false,
        }
    }

    /// Write `pkt`, honouring the policy. Returns `Some(Error)`
    /// **only** when the policy is [`TapErrorPolicy::FailStream`]
    /// and the write fails; in all other cases returns `None` and
    /// silently records / logs / drops as configured.
    pub(crate) fn write_or_handle(&mut self, pkt: &Packet<'_>) -> Option<Error> {
        if self.dropped {
            return None;
        }
        let result = self.inner.write(pkt);
        self.handle_result(result)
    }

    /// Policy-handling logic split out from [`write_or_handle`] so
    /// it can be unit-tested without constructing a real
    /// `Packet<'_>` (which requires a kernel `tpacket3_hdr`).
    fn handle_result(&mut self, result: Result<(), pcap_file::PcapError>) -> Option<Error> {
        match result {
            Ok(()) => None,
            Err(err) => match self.policy {
                TapErrorPolicy::Continue => {
                    tracing::warn!(
                        target: "netring::pcap_tap",
                        ?err,
                        "pcap tap write failed; continuing (policy = Continue)"
                    );
                    None
                }
                TapErrorPolicy::DropTap => {
                    tracing::warn!(
                        target: "netring::pcap_tap",
                        ?err,
                        "pcap tap write failed; dropping tap (policy = DropTap)"
                    );
                    self.dropped = true;
                    None
                }
                TapErrorPolicy::FailStream => Some(Error::Io(std::io::Error::other(format!(
                    "pcap tap write failed: {err}"
                )))),
            },
        }
    }

    /// True if a prior write error under [`TapErrorPolicy::DropTap`]
    /// has retired this tap.
    pub fn is_dropped(&self) -> bool {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub TapWriter used only to construct a [`PcapTap`]; we
    /// drive policy behaviour through [`PcapTap::handle_result`]
    /// directly to avoid needing a real `Packet<'_>`.
    struct NoopWriter;
    impl TapWriter for NoopWriter {
        fn write(&mut self, _pkt: &Packet<'_>) -> Result<(), pcap_file::PcapError> {
            Ok(())
        }
    }

    fn tap_with(policy: TapErrorPolicy) -> PcapTap {
        PcapTap::from_writer(Box::new(NoopWriter), policy)
    }

    fn simulated_failure() -> Result<(), pcap_file::PcapError> {
        Err(pcap_file::PcapError::IoError(std::io::Error::other(
            "simulated",
        )))
    }

    #[test]
    fn continue_policy_swallows_errors() {
        let mut tap = tap_with(TapErrorPolicy::Continue);
        for _ in 0..3 {
            assert!(tap.handle_result(simulated_failure()).is_none());
        }
        assert!(!tap.is_dropped(), "Continue keeps the tap alive");
    }

    #[test]
    fn drop_policy_retires_tap_after_first_failure() {
        let mut tap = tap_with(TapErrorPolicy::DropTap);
        assert!(tap.handle_result(simulated_failure()).is_none());
        assert!(tap.is_dropped());
    }

    #[test]
    fn fail_stream_policy_surfaces_error() {
        let mut tap = tap_with(TapErrorPolicy::FailStream);
        let err = tap
            .handle_result(simulated_failure())
            .expect("FailStream propagates");
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn ok_path_no_error_no_drop() {
        let mut tap = tap_with(TapErrorPolicy::FailStream);
        for _ in 0..5 {
            assert!(tap.handle_result(Ok(())).is_none());
        }
        assert!(!tap.is_dropped());
    }

    #[test]
    fn default_policy_is_continue() {
        assert_eq!(TapErrorPolicy::default(), TapErrorPolicy::Continue);
    }
}
