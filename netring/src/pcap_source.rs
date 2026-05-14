//! Async pcap source for offline replay — feeds the same downstream
//! tooling (flow trackers, decoders) as a live AF_PACKET capture.
//!
//! Available under the `pcap + tokio` features.
//!
//! ```no_run
//! # async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
//! use futures::StreamExt;
//! use netring::pcap_source::AsyncPcapSource;
//!
//! let mut source = AsyncPcapSource::open("capture.pcap").await?;
//! while let Some(pkt) = source.next().await {
//!     let pkt = pkt?;
//!     // hand off to your decoder
//!     # let _ = pkt;
//!     # break;
//! }
//! # Ok(()) }
//! ```
//!
//! Format is auto-detected at open: legacy PCAP and PCAPNG are both
//! supported. Optional pacing (`replay_speed > 0.0`) replays at
//! recorded wire rate (or a scaled multiple).
//!
//! Implemented as a tokio `mpsc` channel fed from a `spawn_blocking`
//! task running the sync `pcap_file` reader — keeps the runtime
//! healthy on slow disks without polluting the public API surface.
//!
//! ## Composing with flow tracking
//!
//! [`AsyncPcapSource::flow_events`] returns a stream of
//! [`flowscope::FlowEvent`]s ready for the same downstream processing
//! as `AsyncCapture::flow_stream`. Available under the `flow` feature.
//! For session-level processing on offline pcaps, drive flowscope's
//! sync [`FlowSessionDriver`] inside a `spawn_blocking` task with
//! `AsyncPcapSource`'s yielded packets as input.
//!
//! [`FlowSessionDriver`]: flowscope::FlowSessionDriver

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_core::Stream;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;
use tokio::sync::mpsc;

use crate::error::Error;
use crate::packet::{OwnedPacket, PacketDirection, PacketStatus, Timestamp};

/// Detected pcap file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapFormat {
    /// Legacy PCAP (DLT_EN10MB by default).
    LegacyPcap,
    /// PCAPNG with one or more Interface Description Blocks.
    Pcapng,
}

/// Configuration for [`AsyncPcapSource`].
#[derive(Debug, Clone)]
pub struct AsyncPcapConfig {
    /// Pacing factor.
    ///
    /// - `0.0` (default) — yield as fast as possible.
    /// - `1.0` — replay at packet-recorded wire rate.
    /// - `0.5` / `2.0` — half / double speed.
    ///
    /// Sub-millisecond pacing is best-effort; `std::thread::sleep`
    /// granularity on Linux is typically 1-10 ms.
    pub replay_speed: f32,

    /// Maximum packets buffered ahead of the consumer. Default 64.
    pub queue_depth: usize,

    /// At EOF, restart the reader from the beginning instead of
    /// closing the stream. Default `false`.
    pub loop_at_eof: bool,
}

impl Default for AsyncPcapConfig {
    fn default() -> Self {
        Self {
            replay_speed: 0.0,
            queue_depth: 64,
            loop_at_eof: false,
        }
    }
}

/// Async reader over a pcap or pcapng file.
///
/// Implements [`Stream<Item = Result<OwnedPacket, Error>>`]. See
/// module-level docs.
pub struct AsyncPcapSource {
    receiver: mpsc::Receiver<Result<OwnedPacket, Error>>,
    _task: tokio::task::JoinHandle<()>,
    format: PcapFormat,
    packets_yielded: Arc<AtomicU64>,
}

impl AsyncPcapSource {
    /// Open a pcap or pcapng file for async streaming with default config.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open_with_config(path, AsyncPcapConfig::default()).await
    }

    /// Open with custom replay config.
    pub async fn open_with_config(
        path: impl AsRef<Path>,
        config: AsyncPcapConfig,
    ) -> Result<Self, Error> {
        let path: PathBuf = path.as_ref().to_owned();
        let format = sniff_format(&path)?;
        let (tx, rx) = mpsc::channel(config.queue_depth.max(1));
        let packets_yielded = Arc::new(AtomicU64::new(0));
        let task_yielded = packets_yielded.clone();

        let task = tokio::task::spawn_blocking(move || {
            if let Err(e) = run_reader(&path, format, config, tx, task_yielded) {
                tracing::warn!(
                    target: "netring::pcap_source",
                    error = ?e,
                    "pcap reader task ended with error"
                );
            }
        });

        Ok(Self {
            receiver: rx,
            _task: task,
            format,
            packets_yielded,
        })
    }

    /// Format detected at open.
    pub fn format(&self) -> PcapFormat {
        self.format
    }

    /// Number of packets yielded so far (analog to
    /// [`CaptureStats::packets`](crate::stats::CaptureStats) for live
    /// captures).
    pub fn packets_yielded(&self) -> u64 {
        self.packets_yielded.load(Ordering::Relaxed)
    }
}

impl Stream for AsyncPcapSource {
    type Item = Result<OwnedPacket, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}

// ── format detection ─────────────────────────────────────────────

/// PCAP magic numbers (any endian, microsecond or nanosecond).
const PCAP_MAGICS: &[u32] = &[0xa1b2_c3d4, 0xd4c3_b2a1, 0xa1b2_3c4d, 0x4d3c_b2a1];

/// PCAPNG Section Header Block type.
const PCAPNG_SHB: u32 = 0x0a0d_0d0a;

fn sniff_format(path: &Path) -> Result<PcapFormat, Error> {
    let mut file = File::open(path).map_err(Error::Io)?;
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf).map_err(Error::Io)?;
    let magic_le = u32::from_le_bytes(buf);
    let magic_be = u32::from_be_bytes(buf);

    if PCAP_MAGICS.contains(&magic_le) || PCAP_MAGICS.contains(&magic_be) {
        Ok(PcapFormat::LegacyPcap)
    } else if magic_le == PCAPNG_SHB || magic_be == PCAPNG_SHB {
        Ok(PcapFormat::Pcapng)
    } else {
        Err(Error::Config(format!(
            "{path:?}: not a pcap or pcapng file (magic = 0x{magic_le:08x})"
        )))
    }
}

// ── background reader ────────────────────────────────────────────

fn run_reader(
    path: &Path,
    format: PcapFormat,
    config: AsyncPcapConfig,
    tx: mpsc::Sender<Result<OwnedPacket, Error>>,
    packets_yielded: Arc<AtomicU64>,
) -> Result<(), Error> {
    loop {
        match format {
            PcapFormat::LegacyPcap => read_legacy(path, &config, &tx, &packets_yielded)?,
            PcapFormat::Pcapng => read_pcapng(path, &config, &tx, &packets_yielded)?,
        }
        if !config.loop_at_eof {
            break;
        }
    }
    Ok(())
}

fn read_legacy(
    path: &Path,
    config: &AsyncPcapConfig,
    tx: &mpsc::Sender<Result<OwnedPacket, Error>>,
    packets_yielded: &Arc<AtomicU64>,
) -> Result<(), Error> {
    let file = File::open(path).map_err(Error::Io)?;
    let mut reader = PcapReader::new(BufReader::new(file))
        .map_err(|e| Error::Config(format!("PcapReader::new failed: {e}")))?;

    let mut start_wall: Option<Instant> = None;
    let mut first_ts: Option<Timestamp> = None;

    while let Some(pkt) = reader.next_packet() {
        let pkt = match pkt {
            Ok(p) => p,
            Err(e) => {
                let _ = tx.blocking_send(Err(Error::Config(format!("pcap read: {e}"))));
                return Ok(());
            }
        };

        let ts = duration_to_timestamp(pkt.timestamp);
        if config.replay_speed > 0.0 {
            pace(ts, &mut start_wall, &mut first_ts, config.replay_speed);
        }

        let owned = pcap_packet_to_owned(&pkt.data, pkt.orig_len, ts);
        if tx.blocking_send(Ok(owned)).is_err() {
            // Receiver dropped.
            return Ok(());
        }
        packets_yielded.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

fn read_pcapng(
    path: &Path,
    config: &AsyncPcapConfig,
    tx: &mpsc::Sender<Result<OwnedPacket, Error>>,
    packets_yielded: &Arc<AtomicU64>,
) -> Result<(), Error> {
    use pcap_file::pcapng::Block;

    let file = File::open(path).map_err(Error::Io)?;
    let mut reader = PcapNgReader::new(BufReader::new(file))
        .map_err(|e| Error::Config(format!("PcapNgReader::new failed: {e}")))?;

    let mut start_wall: Option<Instant> = None;
    let mut first_ts: Option<Timestamp> = None;

    while let Some(block) = reader.next_block() {
        let block = match block {
            Ok(b) => b,
            Err(e) => {
                let _ = tx.blocking_send(Err(Error::Config(format!("pcapng read: {e}"))));
                return Ok(());
            }
        };

        // Extract (timestamp, data, orig_len) from EPB or SimplePacket.
        let (ts, data, orig_len) = match block {
            Block::EnhancedPacket(epb) => {
                let ts = duration_to_timestamp(epb.timestamp);
                (ts, epb.data.into_owned(), epb.original_len)
            }
            Block::SimplePacket(sp) => {
                // SimplePacket has no timestamp — use zero.
                (Timestamp::new(0, 0), sp.data.into_owned(), sp.original_len)
            }
            // IDB, SHB, NRB, ISB, etc.: skip silently.
            _ => continue,
        };

        if config.replay_speed > 0.0 {
            pace(ts, &mut start_wall, &mut first_ts, config.replay_speed);
        }

        let owned = pcap_packet_to_owned(&data, orig_len, ts);
        if tx.blocking_send(Ok(owned)).is_err() {
            return Ok(());
        }
        packets_yielded.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

/// Wall-clock pacing: sleep so the wall delta matches the pcap
/// delta scaled by `1/speed`.
fn pace(
    ts: Timestamp,
    start_wall: &mut Option<Instant>,
    first_ts: &mut Option<Timestamp>,
    speed: f32,
) {
    let first = *first_ts.get_or_insert(ts);
    let started = *start_wall.get_or_insert_with(Instant::now);
    let dt_pcap = timestamp_delta(ts, first);
    let dt_wall = dt_pcap.div_f32(speed);
    let target = started + dt_wall;
    let now = Instant::now();
    if target > now {
        std::thread::sleep(target - now);
    }
}

fn timestamp_delta(later: Timestamp, earlier: Timestamp) -> Duration {
    let later_ns = (later.sec as u64) * 1_000_000_000 + later.nsec as u64;
    let earlier_ns = (earlier.sec as u64) * 1_000_000_000 + earlier.nsec as u64;
    let delta_ns = later_ns.saturating_sub(earlier_ns);
    Duration::from_nanos(delta_ns)
}

fn duration_to_timestamp(d: Duration) -> Timestamp {
    Timestamp::new(d.as_secs() as u32, d.subsec_nanos())
}

fn pcap_packet_to_owned(data: &[u8], orig_len: u32, timestamp: Timestamp) -> OwnedPacket {
    OwnedPacket {
        data: data.to_vec(),
        timestamp,
        original_len: orig_len as usize,
        status: PacketStatus::default(),
        // Pcap files don't record direction — use Host as the
        // benign default (extractor doesn't care).
        direction: PacketDirection::Host,
        rxhash: 0,
        vlan_tci: 0,
        vlan_tpid: 0,
        // EtherType is encoded in the frame itself; the wrapper
        // doesn't need a separate ll_protocol for parsing.
        ll_protocol: 0x0800,
        source_ll_addr: [0; 8],
        source_ll_addr_len: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_legacy_pcap(packets: &[(Timestamp, Vec<u8>)]) -> NamedTempFile {
        use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
        let file = NamedTempFile::new().expect("tempfile");
        let header = PcapHeader {
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: u32::MAX,
            datalink: pcap_file::DataLink::from(1),
            ts_resolution: pcap_file::TsResolution::NanoSecond,
            endianness: pcap_file::Endianness::native(),
        };
        let mut writer =
            PcapWriter::with_header(file.reopen().unwrap(), header).expect("PcapWriter");
        for (ts, data) in packets {
            let pkt = PcapPacket::new_owned(
                Duration::new(ts.sec as u64, ts.nsec),
                data.len() as u32,
                data.clone(),
            );
            writer.write_packet(&pkt).expect("write");
        }
        drop(writer);
        file
    }

    #[test]
    fn sniff_legacy_pcap() {
        let f = write_legacy_pcap(&[(Timestamp::new(1, 0), vec![0xaa; 4])]);
        let fmt = sniff_format(f.path()).expect("sniff");
        assert_eq!(fmt, PcapFormat::LegacyPcap);
    }

    #[test]
    fn sniff_unknown_errors() {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(&[0u8; 16]).expect("write zero bytes");
        let r = sniff_format(f.path());
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn read_legacy_pcap_yields_owned_packets() {
        use futures::StreamExt;
        let f = write_legacy_pcap(&[
            (Timestamp::new(100, 0), vec![1, 2, 3]),
            (Timestamp::new(101, 0), vec![4, 5, 6, 7]),
        ]);
        let mut source = AsyncPcapSource::open(f.path()).await.expect("open");
        assert_eq!(source.format(), PcapFormat::LegacyPcap);
        let p1 = source.next().await.unwrap().expect("p1");
        assert_eq!(p1.data, vec![1, 2, 3]);
        assert_eq!(p1.timestamp, Timestamp::new(100, 0));
        let p2 = source.next().await.unwrap().expect("p2");
        assert_eq!(p2.data, vec![4, 5, 6, 7]);
        // EOF
        assert!(source.next().await.is_none());
        assert_eq!(source.packets_yielded(), 2);
    }

    #[tokio::test]
    async fn loop_at_eof_keeps_yielding() {
        use futures::StreamExt;
        let f = write_legacy_pcap(&[(Timestamp::new(1, 0), vec![0xff])]);
        let cfg = AsyncPcapConfig {
            loop_at_eof: true,
            queue_depth: 4,
            ..AsyncPcapConfig::default()
        };
        let mut source = AsyncPcapSource::open_with_config(f.path(), cfg)
            .await
            .expect("open");
        for _ in 0..5 {
            let pkt = source.next().await.unwrap().expect("loop yield");
            assert_eq!(pkt.data, vec![0xff]);
        }
    }

    /// Don't need PCAPNG-write to test PCAPNG read here — the format
    /// detection branch and the `Block::*` matching are smoke-tested
    /// by the integration test against committed fixtures (if any).
    /// Format-only sanity:
    #[test]
    fn pcapng_magic_recognized() {
        // PCAPNG Section Header Block magic in little-endian.
        let bytes = 0x0a0d_0d0au32.to_le_bytes();
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(&bytes).expect("write");
        let fmt = sniff_format(f.path()).expect("sniff");
        assert_eq!(fmt, PcapFormat::Pcapng);
    }
}
