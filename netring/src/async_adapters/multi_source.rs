//! [`MultiSource`] — what every source of a `Multi*Stream` fan-in can
//! tell you about itself, whatever kind of source it is.
//!
//! The tagged fan-ins ([`MultiFlowStream`](super::multi_streams::MultiFlowStream),
//! [`MultiSessionStream`](super::multi_streams::MultiSessionStream),
//! [`MultiDatagramStream`](super::multi_streams::MultiDatagramStream) and
//! their AF_XDP twins) hold one stream per source. Before 0.31.1 that
//! stream had to be the live AF_PACKET (or, on the `XdpMulti*` types,
//! AF_XDP) stream the constructor built, and the fan-in exposed only
//! capture stats and tracker counters per source. Now any netring
//! source stream with the same event type can be a source —
//! [`SessionStream`](crate::SessionStream) over either kernel backend,
//! [`PcapSessionStream`](crate::PcapSessionStream) replaying a file,
//! and the flow / datagram equivalents — through
//! `push_source` / `with_source`, and each source hands back its
//! tracker, its live flow snapshots and its dedup through this trait
//! (`source(idx)` / `source_mut(idx)`). One
//! `MultiSessionStream<E, F>` therefore serves a live multi-interface
//! run and a `--read capture.pcap` run alike (issues #176, #177).
//!
//! Sealed: implemented by netring's own stream types only.

use flowscope::{FlowExtractor, FlowStats, FlowTracker, FlowTrackerStats};

use crate::dedup::Dedup;
use crate::error::Error;
use crate::stats::CaptureStats;

mod sealed {
    pub trait Sealed {}
}
pub(crate) use sealed::Sealed;

/// Per-source introspection every fan-in source offers. See the
/// [module docs](self).
///
/// Implemented by [`FlowStream`](crate::FlowStream) (with no user
/// state), [`SessionStream`](crate::SessionStream),
/// [`DatagramStream`](crate::DatagramStream) — over AF_PACKET or
/// AF_XDP — and by [`PcapFlowStream`](crate::PcapFlowStream),
/// [`PcapSessionStream`](crate::PcapSessionStream),
/// [`PcapDatagramStream`](crate::PcapDatagramStream). Each of those
/// also has the same methods inherently (often with a richer return
/// type); the trait is what the fan-ins hand out for a source of any
/// kind. New in 0.31.1.
pub trait MultiSource<E: FlowExtractor>: Sealed {
    /// The source's flow table.
    fn tracker(&self) -> &FlowTracker<E, ()>;

    /// Cumulative tracker counters: `flows_created`, `flows_ended`,
    /// `flows_evicted`, `packets_unmatched`.
    fn tracker_stats(&self) -> &FlowTrackerStats {
        self.tracker().stats()
    }

    /// Count of live flow entries.
    fn active_flows(&self) -> usize {
        self.tracker().flow_count()
    }

    /// Owned `(key, stats)` for every live flow — reassembly
    /// diagnostics included where the source reassembles (session
    /// streams). Boxed so the trait stays object-safe; the concrete
    /// streams' inherent `snapshot_flow_stats` is unboxed.
    fn snapshot_flow_stats(&self) -> Box<dyn Iterator<Item = (E::Key, FlowStats)> + '_>;

    /// The source's [`Dedup`], if one was configured (`with_dedup`), for
    /// its `dropped()` / `seen()` counters.
    fn dedup(&self) -> Option<&Dedup>;

    /// Mutable access to the source's [`Dedup`] (e.g. `reset()`).
    fn dedup_mut(&mut self) -> Option<&mut Dedup>;

    /// Kernel-ring statistics: `Some` for an AF_PACKET / AF_XDP source
    /// (reading resets the kernel's counters, like
    /// [`StreamCapture::capture_stats`](crate::StreamCapture::capture_stats)),
    /// `None` for a replay source, which has no ring.
    fn capture_stats(&self) -> Option<Result<CaptureStats, Error>>;

    /// Frames a replay source has read from its file so far: `Some`
    /// for the `Pcap*Stream`s (their `packets_read()`), `None` for a
    /// kernel source (use [`Self::capture_stats`]).
    fn packets_read(&self) -> Option<u64>;
}
