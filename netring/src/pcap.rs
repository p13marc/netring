//! PCAP/PCAPNG export helpers (feature: `pcap`).
//!
//! Streams captured packets to a PCAP or PCAPNG file via the pure-Rust
//! [`pcap-file`] crate (no native libpcap dependency).
//!
//! # Examples
//!
//! ```no_run
//! # #[cfg(feature = "pcap")]
//! # fn _ex() -> Result<(), Box<dyn std::error::Error>> {
//! use netring::Capture;
//! use netring::pcap::CaptureWriter;
//! use std::fs::File;
//!
//! let mut cap = Capture::open("eth0")?;
//! let mut writer = CaptureWriter::create(File::create("out.pcap")?)?;
//!
//! let mut pkts = cap.packets();
//! let mut n = 0;
//! while n < 1000 {
//!     let Some(pkt) = pkts.next_packet() else { break };
//!     writer.write_packet(&pkt)?;
//!     n += 1;
//! }
//! # Ok(()) }
//! ```
//!
//! [`pcap-file`]: https://crates.io/crates/pcap-file

use std::borrow::Cow;
use std::io::Write;
use std::time::Duration;

use pcap_file::DataLink;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};

use crate::packet::{OwnedPacket, Packet};

/// Linktype for raw Ethernet frames (DLT_EN10MB / 1).
const LINKTYPE_ETHERNET: u32 = 1;

/// `if_tsresol` value selecting **nanosecond** timestamp resolution
/// (10⁻⁹ s): a single byte whose low 7 bits are the negative power of ten
/// (MSB 0 = base-10). pcapng's default when the option is absent is `6`
/// (microseconds), so writing nanosecond values without setting this makes
/// every external reader (Wireshark, tcpdump) misread them 1000× off.
const IF_TSRESOL_NANOS: u8 = 9;

/// Streams [`Packet`] / [`OwnedPacket`] values to a PCAP file.
///
/// Wraps [`pcap_file::pcap::PcapWriter`] with a netring-friendly surface.
/// The output file uses `DLT_EN10MB` (Ethernet) link-type by default — set
/// a different one via [`new_with_linktype`](Self::new_with_linktype) if
/// you're capturing a non-Ethernet medium.
pub struct CaptureWriter<W: Write> {
    inner: PcapWriter<W>,
}

impl<W: Write> CaptureWriter<W> {
    /// Open a PCAP writer over `out`, using `DLT_EN10MB` (Ethernet) link-type.
    ///
    /// Writes the file header immediately. The writer takes ownership of
    /// `out`; flush behavior is the underlying writer's.
    pub fn create(out: W) -> Result<Self, pcap_file::PcapError> {
        Self::new_with_linktype(out, LINKTYPE_ETHERNET)
    }

    /// Open a PCAP writer with a custom link-type code.
    ///
    /// See [PCAP linktype list](https://www.tcpdump.org/linktypes.html) for
    /// values (e.g. 1 = Ethernet, 113 = Linux SLL, 12 = raw IP).
    pub fn new_with_linktype(out: W, linktype: u32) -> Result<Self, pcap_file::PcapError> {
        let header = PcapHeader {
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: u32::MAX,
            datalink: pcap_file::DataLink::from(linktype),
            ts_resolution: pcap_file::TsResolution::NanoSecond,
            endianness: pcap_file::Endianness::native(),
        };
        Ok(Self {
            inner: PcapWriter::with_header(out, header)?,
        })
    }

    /// Write one zero-copy packet.
    ///
    /// Uses the kernel timestamp (nanosecond precision) and the original
    /// wire length for the PCAP record header.
    pub fn write_packet(&mut self, pkt: &Packet<'_>) -> Result<(), pcap_file::PcapError> {
        let ts = pkt.timestamp();
        let record = PcapPacket::new_owned(
            Duration::new(ts.sec as u64, ts.nsec),
            pkt.original_len() as u32,
            pkt.data().to_vec(),
        );
        self.inner.write_packet(&record).map(|_| ())
    }

    /// Write a snaplen-truncated copy of one zero-copy packet.
    ///
    /// `caplen` bytes from the head of the packet are recorded; the
    /// PCAP record's `orig_len` keeps the full wire length, matching
    /// standard `tcpdump -s <snaplen>` semantics. If `caplen` is
    /// greater than or equal to the packet length, this is equivalent
    /// to [`write_packet`](Self::write_packet).
    pub fn write_packet_truncated(
        &mut self,
        pkt: &Packet<'_>,
        caplen: usize,
    ) -> Result<(), pcap_file::PcapError> {
        let ts = pkt.timestamp();
        let data = pkt.data();
        let truncated = if caplen < data.len() {
            data[..caplen].to_vec()
        } else {
            data.to_vec()
        };
        let record = PcapPacket::new_owned(
            Duration::new(ts.sec as u64, ts.nsec),
            pkt.original_len() as u32,
            truncated,
        );
        self.inner.write_packet(&record).map(|_| ())
    }

    /// Write one owned packet.
    pub fn write_owned(&mut self, pkt: &OwnedPacket) -> Result<(), pcap_file::PcapError> {
        let record = PcapPacket::new(
            Duration::new(pkt.timestamp.sec as u64, pkt.timestamp.nsec),
            pkt.original_len as u32,
            &pkt.data,
        );
        self.inner.write_packet(&record).map(|_| ())
    }

    /// Write a record from raw parts (no [`Packet`] needed) — the
    /// source-agnostic tap path. `original_len` is kept in the record's
    /// `orig_len`; `snaplen`, when `Some`, caps the recorded `caplen`.
    pub fn write_raw(
        &mut self,
        data: &[u8],
        ts: crate::packet::Timestamp,
        original_len: usize,
        snaplen: Option<u32>,
    ) -> Result<(), pcap_file::PcapError> {
        let captured = match snaplen {
            Some(cap) if (cap as usize) < data.len() => &data[..cap as usize],
            _ => data,
        };
        let record = PcapPacket::new(
            Duration::new(ts.sec as u64, ts.nsec),
            original_len as u32,
            captured,
        );
        self.inner.write_packet(&record).map(|_| ())
    }

    /// Unwrap into the inner writer.
    pub fn into_inner(self) -> W {
        self.inner.into_writer()
    }
}

/// Streams [`Packet`] / [`OwnedPacket`] values to a **pcapng** file
/// (issue #41).
///
/// pcapng is the IETF successor to classic pcap: it carries explicit
/// per-interface nanosecond resolution, multiple interfaces per file, and
/// per-packet metadata. This writer emits the minimal well-formed stream —
/// a Section Header Block, one Interface Description Block (Ethernet link
/// type, **nanosecond** `if_tsresol`), then one Enhanced Packet Block per
/// frame.
///
/// Mirrors [`CaptureWriter`]'s surface, and like it implements the internal
/// `TapWriter` trait so it drops straight into the stream types'
/// `with_pcap_tap(writer)` mid-pipeline recording.
///
/// ```no_run
/// # #[cfg(feature = "pcap")]
/// # fn _ex() -> Result<(), Box<dyn std::error::Error>> {
/// use netring::Capture;
/// use netring::pcap::CaptureWriterNg;
/// use std::fs::File;
///
/// let mut cap = Capture::open("eth0")?;
/// let mut writer = CaptureWriterNg::create(File::create("out.pcapng")?)?;
/// let mut pkts = cap.packets();
/// while let Some(pkt) = pkts.next_packet() {
///     writer.write_packet(&pkt)?;
/// }
/// # Ok(()) }
/// ```
///
/// The nanosecond timestamps are only as precise as the capturing clock —
/// see [`Packet::timestamp_clock`](crate::Packet::timestamp_clock) (issue
/// #40); with the default software stamp the low-order nanoseconds reflect
/// kernel software resolution, not wire arrival.
pub struct CaptureWriterNg<W: Write> {
    inner: PcapNgWriter<W>,
}

impl<W: Write> CaptureWriterNg<W> {
    /// Open a pcapng writer over `out` using `DLT_EN10MB` (Ethernet).
    ///
    /// Writes the Section Header Block and a single Interface Description
    /// Block (nanosecond `if_tsresol`) immediately.
    pub fn create(out: W) -> Result<Self, pcap_file::PcapError> {
        Self::new_with_linktype(out, LINKTYPE_ETHERNET)
    }

    /// Open a pcapng writer with a custom link-type code (see the
    /// [PCAP linktype list](https://www.tcpdump.org/linktypes.html)).
    pub fn new_with_linktype(out: W, linktype: u32) -> Result<Self, pcap_file::PcapError> {
        // `PcapNgWriter::new` emits the Section Header Block.
        let mut inner = PcapNgWriter::new(out)?;
        // One interface, `interface_id` 0, snaplen 0 (= unlimited), with
        // explicit nanosecond timestamp resolution.
        let mut idb = InterfaceDescriptionBlock::new(DataLink::from(linktype), 0);
        idb.options
            .push(InterfaceDescriptionOption::IfTsResol(IF_TSRESOL_NANOS));
        inner.write_pcapng_block(idb)?;
        Ok(Self { inner })
    }

    /// Write one zero-copy packet as an Enhanced Packet Block.
    pub fn write_packet(&mut self, pkt: &Packet<'_>) -> Result<(), pcap_file::PcapError> {
        self.write_epb(
            pkt.timestamp(),
            pkt.original_len(),
            Cow::Borrowed(pkt.data()),
        )
    }

    /// Write a snaplen-truncated copy of one zero-copy packet. `orig_len`
    /// keeps the full wire length (standard `tcpdump -s` semantics).
    pub fn write_packet_truncated(
        &mut self,
        pkt: &Packet<'_>,
        caplen: usize,
    ) -> Result<(), pcap_file::PcapError> {
        let data = pkt.data();
        let captured = if caplen < data.len() {
            &data[..caplen]
        } else {
            data
        };
        self.write_epb(pkt.timestamp(), pkt.original_len(), Cow::Borrowed(captured))
    }

    /// Write one owned packet as an Enhanced Packet Block.
    pub fn write_owned(&mut self, pkt: &OwnedPacket) -> Result<(), pcap_file::PcapError> {
        self.write_epb(pkt.timestamp, pkt.original_len, Cow::Borrowed(&pkt.data))
    }

    /// Write a record from raw parts (no [`Packet`] needed) — the
    /// source-agnostic tap path. See [`CaptureWriter::write_raw`].
    pub fn write_raw(
        &mut self,
        data: &[u8],
        ts: crate::packet::Timestamp,
        original_len: usize,
        snaplen: Option<u32>,
    ) -> Result<(), pcap_file::PcapError> {
        let captured = match snaplen {
            Some(cap) if (cap as usize) < data.len() => &data[..cap as usize],
            _ => data,
        };
        self.write_epb(ts, original_len, Cow::Borrowed(captured))
    }

    fn write_epb(
        &mut self,
        ts: crate::packet::Timestamp,
        original_len: usize,
        data: Cow<'_, [u8]>,
    ) -> Result<(), pcap_file::PcapError> {
        let block = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::new(ts.sec as u64, ts.nsec),
            original_len: original_len as u32,
            data,
            options: vec![],
        };
        self.inner.write_pcapng_block(block).map(|_| ())
    }

    /// Unwrap into the inner writer.
    pub fn into_inner(self) -> W {
        self.inner.into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PacketDirection, PacketStatus, Timestamp};
    use std::io::Cursor;

    fn make_owned(data: Vec<u8>) -> OwnedPacket {
        OwnedPacket {
            data,
            timestamp: Timestamp::new(1234, 567_890_000),
            timestamp_clock: crate::packet::TimestampClock::None,
            original_len: 100,
            status: PacketStatus::default(),
            direction: PacketDirection::Host,
            rxhash: 0,
            vlan_tci: 0,
            vlan_tpid: 0,
            ll_protocol: 0x0800,
            source_ll_addr: [0; 8],
            source_ll_addr_len: 0,
        }
    }

    #[test]
    fn writes_pcap_header() {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let _w = CaptureWriter::create(cursor).expect("create");
        }
        // PCAP magic for nanosecond resolution (any-endian variants begin
        // with 0xa1b23c4d / 0x4d3cb2a1) or microsecond (0xa1b2c3d4 / ...).
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let valid = matches!(magic, 0xa1b2_c3d4 | 0xd4c3_b2a1 | 0xa1b2_3c4d | 0x4d3c_b2a1);
        assert!(valid, "PCAP magic missing: 0x{magic:08x}");
    }

    #[test]
    fn round_trip_owned_packet() {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut w = CaptureWriter::create(cursor).expect("create");
            let pkt = make_owned(vec![1, 2, 3, 4, 5]);
            w.write_owned(&pkt).expect("write");
        }
        // Read it back.
        let cursor = Cursor::new(&buf);
        let mut reader = pcap_file::pcap::PcapReader::new(cursor).expect("reader");
        let record = reader.next_packet().expect("first").expect("record");
        assert_eq!(record.data.as_ref(), &[1, 2, 3, 4, 5]);
        assert_eq!(record.orig_len, 100);
    }

    /// Issue #104: the `Packet`-free `write_raw` path (used by the
    /// source-agnostic / AF_XDP flow-stream tap) records the same bytes,
    /// timestamp, and `orig_len`, and honours the snaplen cap.
    #[test]
    fn write_raw_round_trips_and_snaplen_truncates() {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut w = CaptureWriter::create(cursor).expect("create");
            // Full record: orig_len kept, all bytes recorded.
            w.write_raw(&[10, 20, 30, 40], Timestamp::new(7, 8), 64, None)
                .expect("write full");
            // Snaplen 2: caplen truncated to 2, orig_len still the full 64.
            w.write_raw(&[1, 2, 3, 4, 5], Timestamp::new(9, 0), 64, Some(2))
                .expect("write truncated");
        }
        let cursor = Cursor::new(&buf);
        let mut reader = pcap_file::pcap::PcapReader::new(cursor).expect("reader");

        let r0 = reader.next_packet().expect("rec0").expect("ok");
        assert_eq!(r0.data.as_ref(), &[10, 20, 30, 40]);
        assert_eq!(r0.orig_len, 64);
        assert_eq!(r0.timestamp, std::time::Duration::new(7, 8));
        drop(r0);

        let r1 = reader.next_packet().expect("rec1").expect("ok");
        assert_eq!(r1.data.as_ref(), &[1, 2], "snaplen truncates caplen");
        assert_eq!(r1.orig_len, 64, "orig_len keeps full wire length");
    }

    /// Closes feedback item F5 from des-rs: confirm that nanosecond
    /// timestamps survive a write → read cycle byte-for-byte. Cross-
    /// site forensic ordering depends on full nanosecond precision,
    /// so a microsecond-truncating regression must trip a test.
    #[test]
    fn round_trip_preserves_nanosecond_timestamp() {
        let ts_in = Timestamp::new(1_700_000_000, 123_456_789);
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut w = CaptureWriter::create(cursor).expect("create");
            let mut pkt = make_owned(vec![1, 2, 3, 4, 5]);
            pkt.timestamp = ts_in;
            w.write_owned(&pkt).expect("write");
        }
        let cursor = Cursor::new(&buf);
        let mut reader = pcap_file::pcap::PcapReader::new(cursor).expect("reader");
        let record = reader.next_packet().expect("first").expect("record");
        let expected = Duration::new(ts_in.sec as u64, ts_in.nsec);
        assert_eq!(
            record.timestamp, expected,
            "nanosecond precision lost across pcap round-trip"
        );
    }

    // ── pcapng (issue #41) ──────────────────────────────────────────

    #[test]
    fn pcapng_writes_shb_then_idb_with_nanosecond_resolution() {
        use pcap_file::pcapng::{Block, PcapNgReader};

        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let _w = CaptureWriterNg::create(cursor).expect("create");
        }
        // pcapng magic: Section Header Block type 0x0A0D0D0A.
        let block_type = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(block_type, 0x0A0D_0D0A, "pcapng SHB magic missing");

        // The IDB must declare Ethernet + nanosecond resolution, else
        // external tools (Wireshark) read the ns timestamps 1000x off.
        let cursor = Cursor::new(&buf);
        let mut reader = PcapNgReader::new(cursor).expect("reader");
        let mut saw_idb = false;
        while let Some(block) = reader.next_block() {
            if let Block::InterfaceDescription(idb) = block.expect("block") {
                assert_eq!(idb.linktype, DataLink::ETHERNET);
                assert!(
                    idb.options
                        .iter()
                        .any(|o| matches!(o, InterfaceDescriptionOption::IfTsResol(9))),
                    "IDB missing nanosecond if_tsresol (=9)"
                );
                saw_idb = true;
                break;
            }
        }
        assert!(saw_idb, "no Interface Description Block written");
    }

    #[test]
    fn pcapng_round_trip_owned_packet_preserves_data_ts_and_len() {
        use pcap_file::pcapng::{Block, PcapNgReader};

        let ts_in = Timestamp::new(1_700_000_000, 123_456_789);
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut w = CaptureWriterNg::create(cursor).expect("create");
            let mut pkt = make_owned(vec![9, 8, 7, 6, 5]);
            pkt.timestamp = ts_in;
            w.write_owned(&pkt).expect("write");
        }

        let cursor = Cursor::new(&buf);
        let mut reader = PcapNgReader::new(cursor).expect("reader");
        let mut epb_seen = 0;
        while let Some(block) = reader.next_block() {
            if let Block::EnhancedPacket(epb) = block.expect("block") {
                assert_eq!(epb.interface_id, 0);
                assert_eq!(epb.data.as_ref(), &[9, 8, 7, 6, 5]);
                assert_eq!(epb.original_len, 100);
                assert_eq!(
                    epb.timestamp,
                    Duration::new(ts_in.sec as u64, ts_in.nsec),
                    "nanosecond timestamp lost across pcapng round-trip"
                );
                epb_seen += 1;
            }
        }
        assert_eq!(epb_seen, 1, "expected exactly one Enhanced Packet Block");
    }
}
