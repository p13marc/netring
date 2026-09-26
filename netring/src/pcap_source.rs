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
//! For session-level processing on offline pcaps, use
//! [`AsyncPcapSource::sessions`] / [`AsyncPcapSource::datagrams`] (or
//! [`PcapFlowStream::session_stream`](crate::PcapFlowStream)), which
//! drive a flowscope [`FlowTracker`](flowscope::FlowTracker) directly.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_core::Stream;
use tokio::sync::mpsc;

use crate::error::Error;
use crate::packet::{OwnedPacket, PacketDirection, PacketStatus, Timestamp};

/// Detected pcap file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
            if let Err(e) = run_reader(&path, config, tx, task_yielded) {
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

/// Read the capture through flowscope's [`CaptureReader`]: pcap and
/// pcapng (per-interface timestamp resolution), every link type
/// flowscope can turn into Ethernet (Linux cooked `tcpdump -i any`
/// captures, raw IP, BSD loopback), and the recorded direction.
///
/// Stops for good when the receiver is gone or the file is corrupt —
/// it never reopens after either. With `loop_at_eof`, each pass is
/// shifted by the capture's span (plus a microsecond) so packet time
/// keeps advancing: idle timeouts and sweeps keep working on a looping
/// replay. An empty file is not looped.
///
/// [`CaptureReader`]: flowscope::pcap::CaptureReader
fn run_reader(
    path: &Path,
    config: AsyncPcapConfig,
    tx: mpsc::Sender<Result<OwnedPacket, Error>>,
    packets_yielded: Arc<AtomicU64>,
) -> Result<(), Error> {
    let mut shift = Duration::ZERO;
    let mut unsupported = 0u64;
    loop {
        let reader = flowscope::pcap::CaptureReader::open(path)
            .map_err(|e| Error::Config(format!("{path:?}: {e}")))?;
        let mut span: Option<(Duration, Duration)> = None;
        let mut start_wall: Option<Instant> = None;
        let mut first_ts: Option<Timestamp> = None;
        for packet in reader {
            let p = match packet {
                Ok(p) => p,
                Err(e) => {
                    let _ = tx.blocking_send(Err(Error::Config(format!("{path:?}: {e}"))));
                    return Ok(());
                }
            };
            let raw = p.timestamp;
            span = Some(match span {
                None => (raw, raw),
                Some((lo, hi)) => (lo.min(raw), hi.max(raw)),
            });
            let ts = duration_to_timestamp(raw + shift);
            let orig_len = p.original_len;
            let direction = match p.direction {
                Some(flowscope::pcap::CaptureDirection::Outbound) => PacketDirection::Outgoing,
                // Inbound, or not recorded: the benign default.
                _ => PacketDirection::Host,
            };
            let frame = match p.into_ethernet() {
                Ok(frame) => frame,
                Err(datalink) => {
                    if unsupported == 0 {
                        tracing::warn!(
                            target: "netring::pcap_source",
                            ?datalink,
                            "skipping packets of an unsupported link type"
                        );
                    }
                    unsupported += 1;
                    continue;
                }
            };
            if config.replay_speed > 0.0 {
                pace(ts, &mut start_wall, &mut first_ts, config.replay_speed);
            }
            let owned = owned_packet(frame, orig_len, ts, direction);
            if tx.blocking_send(Ok(owned)).is_err() {
                // Receiver dropped: nobody is reading any more.
                return Ok(());
            }
            packets_yielded.fetch_add(1, Ordering::Relaxed);
        }
        let Some((lo, hi)) = span else {
            // Nothing read: looping would spin on an empty file.
            return Ok(());
        };
        if !config.loop_at_eof || tx.is_closed() {
            return Ok(());
        }
        shift += hi - lo + Duration::from_micros(1);
    }
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

fn owned_packet(
    data: Vec<u8>,
    orig_len: u32,
    timestamp: Timestamp,
    direction: PacketDirection,
) -> OwnedPacket {
    OwnedPacket {
        data,
        timestamp,
        // Pcap files carry a timestamp but not its clock source.
        timestamp_clock: crate::packet::TimestampClock::None,
        original_len: orig_len as usize,
        status: PacketStatus::default(),
        // From the pcapng EPB flags or a cooked header; `Host` when
        // the capture did not record it.
        direction,
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
    /// pcapng timestamps are ticks of the interface's `if_tsresol`
    /// (default µs); pcap-file hands them back as nanoseconds, so a
    /// µs capture used to replay 1000× too early.
    #[tokio::test]
    async fn pcapng_timestamps_honour_the_interface_resolution() {
        use futures::StreamExt;
        use pcap_file::DataLink;
        use pcap_file::pcapng::PcapNgWriter;
        use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
        use pcap_file::pcapng::blocks::interface_description::{
            InterfaceDescriptionBlock, InterfaceDescriptionOption,
        };

        let mut f = NamedTempFile::new().expect("tempfile");
        {
            let mut w = PcapNgWriter::new(&mut f).expect("writer");
            for options in [vec![], vec![InterfaceDescriptionOption::IfTsResol(9)]] {
                w.write_pcapng_block(InterfaceDescriptionBlock {
                    linktype: DataLink::ETHERNET,
                    snaplen: 65535,
                    options,
                })
                .expect("idb");
            }
            // Interface 0 (µs): 1_700_000_000.25 s.
            w.write_pcapng_block(EnhancedPacketBlock {
                interface_id: 0,
                timestamp: Duration::from_nanos(1_700_000_000_250_000),
                original_len: 1,
                data: std::borrow::Cow::Borrowed(&[1u8]),
                options: vec![],
            })
            .expect("epb");
            // Interface 1 (ns): 1_700_000_000 s + 7 ns.
            w.write_pcapng_block(EnhancedPacketBlock {
                interface_id: 1,
                timestamp: Duration::from_nanos(1_700_000_000_000_000_007),
                original_len: 1,
                data: std::borrow::Cow::Borrowed(&[2u8]),
                options: vec![],
            })
            .expect("epb");
        }
        let mut source = AsyncPcapSource::open(f.path()).await.expect("open");
        assert_eq!(source.format(), PcapFormat::Pcapng);
        let p1 = source.next().await.unwrap().expect("p1");
        assert_eq!(p1.timestamp, Timestamp::new(1_700_000_000, 250_000_000));
        let p2 = source.next().await.unwrap().expect("p2");
        assert_eq!(p2.timestamp, Timestamp::new(1_700_000_000, 7));
    }

    #[test]
    fn pcapng_magic_recognized() {
        // PCAPNG Section Header Block magic in little-endian.
        let bytes = 0x0a0d_0d0au32.to_le_bytes();
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(&bytes).expect("write");
        let fmt = sniff_format(f.path()).expect("sniff");
        assert_eq!(fmt, PcapFormat::Pcapng);
    }

    /// #159: a looping reader stops once nobody reads (it used to
    /// reopen the file in a tight loop forever).
    #[tokio::test]
    async fn loop_at_eof_stops_when_the_receiver_is_dropped() {
        let f = write_legacy_pcap(&[(Timestamp::new(1, 0), vec![0xaa; 60])]);
        let cfg = AsyncPcapConfig {
            loop_at_eof: true,
            queue_depth: 1,
            ..Default::default()
        };
        let AsyncPcapSource {
            receiver, _task, ..
        } = AsyncPcapSource::open_with_config(f.path(), cfg)
            .await
            .unwrap();
        drop(receiver);
        tokio::time::timeout(Duration::from_secs(5), _task)
            .await
            .expect("the reader task ends")
            .unwrap();
    }

    /// #159: an empty file is not looped.
    #[tokio::test]
    async fn loop_at_eof_on_an_empty_file_terminates() {
        use futures::StreamExt;
        let f = write_legacy_pcap(&[]);
        let cfg = AsyncPcapConfig {
            loop_at_eof: true,
            ..Default::default()
        };
        let mut src = AsyncPcapSource::open_with_config(f.path(), cfg)
            .await
            .unwrap();
        let next = tokio::time::timeout(Duration::from_secs(5), src.next())
            .await
            .expect("stream ends");
        assert!(next.is_none());
    }

    /// #168: each pass of a looping replay continues the clock.
    #[tokio::test]
    async fn looped_packet_time_keeps_advancing() {
        use futures::StreamExt;
        let f = write_legacy_pcap(&[
            (Timestamp::new(10, 0), vec![0xaa; 60]),
            (Timestamp::new(11, 0), vec![0xbb; 60]),
        ]);
        let cfg = AsyncPcapConfig {
            loop_at_eof: true,
            ..Default::default()
        };
        let mut src = AsyncPcapSource::open_with_config(f.path(), cfg)
            .await
            .unwrap();
        let mut ts = Vec::new();
        for _ in 0..6 {
            ts.push(src.next().await.unwrap().unwrap().timestamp);
        }
        assert!(ts.windows(2).all(|w| w[0] < w[1]), "{ts:?}");
        // The second pass starts a microsecond after the first ended.
        assert_eq!(ts[2], Timestamp::new(11, 1_000));
    }

    /// #167: a Linux cooked capture (`tcpdump -i any`) arrives as
    /// Ethernet, with the recorded direction.
    #[tokio::test]
    async fn linux_cooked_capture_is_normalised() {
        use futures::StreamExt;
        use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
        let ip = [
            0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let mut sll = vec![0, 4, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0, 0x08, 0x00];
        sll.extend_from_slice(&ip);
        let file = NamedTempFile::new().unwrap();
        let header = PcapHeader {
            datalink: pcap_file::DataLink::LINUX_SLL,
            ..Default::default()
        };
        let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).unwrap();
        w.write_packet(&PcapPacket::new(
            Duration::from_secs(1),
            sll.len() as u32,
            &sll,
        ))
        .unwrap();
        drop(w);
        let mut src = AsyncPcapSource::open(file.path()).await.unwrap();
        let p = src.next().await.unwrap().unwrap();
        assert_eq!(&p.data[12..14], &[0x08, 0x00]);
        assert_eq!(&p.data[14..], &ip);
        assert_eq!(p.direction, PacketDirection::Outgoing);
    }
}
