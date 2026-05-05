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
//! for pkt in cap.packets().take(1000) {
//!     writer.write_packet(&pkt)?;
//! }
//! # Ok(()) }
//! ```
//!
//! [`pcap-file`]: https://crates.io/crates/pcap-file

use std::io::Write;
use std::time::Duration;

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

use crate::packet::{OwnedPacket, Packet};

/// Linktype for raw Ethernet frames (DLT_EN10MB / 1).
const LINKTYPE_ETHERNET: u32 = 1;

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

    /// Write one owned packet.
    pub fn write_owned(&mut self, pkt: &OwnedPacket) -> Result<(), pcap_file::PcapError> {
        let record = PcapPacket::new(
            Duration::new(pkt.timestamp.sec as u64, pkt.timestamp.nsec),
            pkt.original_len as u32,
            &pkt.data,
        );
        self.inner.write_packet(&record).map(|_| ())
    }

    /// Unwrap into the inner writer.
    pub fn into_inner(self) -> W {
        self.inner.into_writer()
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
        let valid = matches!(
            magic,
            0xa1b2_c3d4 | 0xd4c3_b2a1 | 0xa1b2_3c4d | 0x4d3c_b2a1
        );
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
}
