use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use netring_flow::tracker::FlowEvents;
use netring_flow::{FlowEvent, FlowExtractor, FlowTracker, PacketView, Timestamp};

use pcap_file::pcap::PcapReader;

/// Errors from this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pcap: {0}")]
    Pcap(#[from] pcap_file::PcapError),
}

/// A pcap-backed source of [`PacketView`]s.
///
/// Wraps [`PcapReader`] from `pcap-file` and exposes ergonomic
/// iterators that hand off to `netring-flow`.
pub struct PcapFlowSource<R: Read> {
    reader: PcapReader<R>,
}

impl PcapFlowSource<BufReader<File>> {
    /// Open a pcap file from disk.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = PcapReader::new(BufReader::new(file))?;
        Ok(Self { reader })
    }
}

impl<R: Read> PcapFlowSource<R> {
    /// Wrap any `Read` (e.g., `Cursor<&[u8]>` for tests).
    pub fn from_reader(reader: R) -> Result<Self, Error> {
        Ok(Self {
            reader: PcapReader::new(reader)?,
        })
    }

    /// Iterate raw [`PacketView`]s. Each call yields the next packet
    /// or `Err` on a malformed record.
    ///
    /// Note: each [`OwnedPacketView`] owns its data (we copy from
    /// the pcap reader because the underlying buffer is reused
    /// across `next_packet` calls). One alloc per packet — fine for
    /// offline analysis; not appropriate for sustained 1+ Gbps live
    /// replay.
    pub fn views(self) -> ViewIter<R> {
        ViewIter {
            reader: self.reader,
        }
    }

    /// One-step pipeline: feed every view through `extractor` and
    /// emit [`FlowEvent`]s.
    ///
    /// Constructs an internal [`FlowTracker`] with default config
    /// and `()` for per-flow user state. For non-default config or
    /// custom user state, drop down to the manual pattern:
    ///
    /// ```no_run
    /// use netring_flow_pcap::PcapFlowSource;
    /// use netring_flow::{FlowTracker, FlowTrackerConfig};
    /// use netring_flow::extract::FiveTuple;
    /// use std::time::Duration;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut tracker = FlowTracker::<FiveTuple>::with_config(
    ///     FiveTuple::bidirectional(),
    ///     FlowTrackerConfig {
    ///         idle_timeout_tcp: Duration::from_secs(60),
    ///         ..Default::default()
    ///     },
    /// );
    /// for view in PcapFlowSource::open("trace.pcap")?.views() {
    ///     for _evt in tracker.track(view?.as_view()) {
    ///         // process
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    pub fn with_extractor<E: FlowExtractor>(self, extractor: E) -> EventIter<R, E>
    where
        E::Key: Clone,
    {
        EventIter {
            views: self.views(),
            tracker: FlowTracker::new(extractor),
            pending: std::collections::VecDeque::new(),
            sweep_done: false,
        }
    }
}

/// An owned [`PacketView`] — frame bytes in a `Vec<u8>` plus
/// timestamp. Use [`as_view`](Self::as_view) to get a borrowed
/// `PacketView<'_>`.
#[derive(Debug, Clone)]
pub struct OwnedPacketView {
    pub frame: Vec<u8>,
    pub timestamp: Timestamp,
}

impl OwnedPacketView {
    /// Borrow as a [`PacketView`].
    pub fn as_view(&self) -> PacketView<'_> {
        PacketView::new(&self.frame, self.timestamp)
    }
}

/// Iterator yielding `Result<OwnedPacketView, Error>`.
pub struct ViewIter<R: Read> {
    reader: PcapReader<R>,
}

impl<R: Read> Iterator for ViewIter<R> {
    type Item = Result<OwnedPacketView, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let pkt = self.reader.next_packet()?;
        match pkt {
            Ok(p) => {
                let ts = Timestamp::new(p.timestamp.as_secs() as u32, p.timestamp.subsec_nanos());
                Some(Ok(OwnedPacketView {
                    frame: p.data.into_owned(),
                    timestamp: ts,
                }))
            }
            Err(e) => Some(Err(e.into())),
        }
    }
}

/// Iterator yielding `Result<FlowEvent<E::Key>, Error>`.
///
/// Drives an internal [`FlowTracker`] over the pcap stream. After
/// the underlying pcap is exhausted, runs one final sweep with a
/// far-future timestamp to flush remaining flows as
/// [`FlowEvent::Ended { reason: IdleTimeout, .. }`](FlowEvent::Ended).
pub struct EventIter<R: Read, E: FlowExtractor>
where
    E::Key: Clone,
{
    views: ViewIter<R>,
    tracker: FlowTracker<E, ()>,
    pending: std::collections::VecDeque<FlowEvent<E::Key>>,
    sweep_done: bool,
}

impl<R: Read, E: FlowExtractor> Iterator for EventIter<R, E>
where
    E::Key: Clone,
{
    type Item = Result<FlowEvent<E::Key>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ev) = self.pending.pop_front() {
                return Some(Ok(ev));
            }

            // Pull the next packet view, push events.
            match self.views.next() {
                Some(Ok(view)) => {
                    let evts: FlowEvents<E::Key> = self.tracker.track(view.as_view());
                    for ev in evts {
                        self.pending.push_back(ev);
                    }
                    // Loop to drain
                }
                Some(Err(e)) => return Some(Err(e)),
                None => {
                    // Pcap exhausted. Run one final sweep.
                    if !self.sweep_done {
                        self.sweep_done = true;
                        // Far-future sweep: 1 day past whatever the
                        // tracker last saw.
                        let last_seen_sec = self
                            .tracker
                            .flows()
                            .map(|(_, e)| e.stats.last_seen.sec)
                            .max()
                            .unwrap_or(0);
                        let far = Timestamp::new(last_seen_sec.saturating_add(86_400), 0);
                        for ev in self.tracker.sweep(far) {
                            self.pending.push_back(ev);
                        }
                        // Loop to drain
                    } else {
                        return None;
                    }
                }
            }
        }
    }
}
