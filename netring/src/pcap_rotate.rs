//! Rotating + triggered pcap writers (issue #125).
//!
//! Two DFIR building blocks on top of [`CaptureWriter`]:
//!
//! - [`RotatingPcapWriter`] — a self-rotating capture sink. It owns its files
//!   under a directory, opens a fresh pcap (with its own header) whenever the
//!   current one crosses a **size** or **wall-clock duration** trigger, and
//!   prunes the oldest files to honour a **file-count** / **total-bytes**
//!   retention bound. This is the "capture forever without filling the disk"
//!   primitive.
//! - [`TriggeredPcapWriter`] + [`PreTriggerRing`] + [`TriggerHandle`] — a
//!   pre-trigger ring buffer. Packets are held in a bytes-bounded ring until a
//!   [`TriggerHandle`] is fired (from any anomaly handler / control task), at
//!   which point the ring is flushed and subsequent packets stream to a
//!   [`RotatingPcapWriter`]. This captures the *lead-up* to an event, not just
//!   what happened after you noticed it.
//!
//! Both expose `write` / `write_raw` directly, so they're usable outside the
//! Monitor's tap plumbing. Wiring them into the stream `with_pcap_tap` points
//! and a Monitor-level `pcap_tap` is a documented follow-up.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::packet::{Packet, Timestamp};
use crate::pcap::{CaptureWriter, LINKTYPE_ETHERNET};

/// pcap global header size + per-record header size, for the byte estimate that
/// drives the size trigger (the exact on-disk size is read back at rotation).
const PCAP_HEADER_BYTES: u64 = 24;
const PCAP_RECORD_HEADER_BYTES: u64 = 16;

/// How rotated files are named within the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileNaming {
    /// `<base>-000001.pcap`, `<base>-000002.pcap`, … — deterministic, ordered.
    Sequence,
    /// `<base>-<unix_seconds>.pcap` — wall-clock stamped (collisions within the
    /// same second fall back to a `-N` suffix).
    EpochSeconds,
}

/// Rotation + retention policy for a [`RotatingPcapWriter`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RotatingConfig {
    /// Rotate once the current file reaches this many bytes. `None` disables the
    /// size trigger.
    pub max_bytes: Option<u64>,
    /// Rotate once the current file has been open this long (wall clock). `None`
    /// disables the duration trigger.
    pub max_duration: Option<Duration>,
    /// Keep at most this many files; older ones are deleted. `None` = unbounded.
    pub max_files: Option<usize>,
    /// Keep at most this many bytes across all files; oldest deleted first.
    /// `None` = unbounded.
    pub max_total_bytes: Option<u64>,
    /// File naming scheme.
    pub naming: FileNaming,
    /// pcap link-type (default Ethernet).
    pub linktype: u32,
}

impl Default for RotatingConfig {
    fn default() -> Self {
        Self {
            max_bytes: Some(128 * 1024 * 1024),
            max_duration: None,
            max_files: Some(16),
            max_total_bytes: None,
            naming: FileNaming::Sequence,
            linktype: LINKTYPE_ETHERNET,
        }
    }
}

/// A metadata record for one rotated file.
#[derive(Debug, Clone)]
struct FileRecord {
    path: PathBuf,
    bytes: u64,
}

/// A self-rotating pcap writer (issue #125).
pub struct RotatingPcapWriter {
    dir: PathBuf,
    base: String,
    config: RotatingConfig,
    seq: u64,
    /// The current open file's writer, or `None` before the first write.
    current: Option<CaptureWriter<BufWriter<File>>>,
    current_path: Option<PathBuf>,
    opened_at: Option<Instant>,
    /// Estimated bytes written to the current file (drives the size trigger).
    current_bytes: u64,
    /// Closed + current files, oldest first, for retention accounting.
    files: VecDeque<FileRecord>,
}

impl RotatingPcapWriter {
    /// Create a rotating writer under `dir` with file basename `base`. Files are
    /// opened lazily on the first packet. The directory must exist.
    pub fn create(
        dir: impl AsRef<Path>,
        base: impl Into<String>,
        config: RotatingConfig,
    ) -> std::io::Result<Self> {
        Ok(Self {
            dir: dir.as_ref().to_path_buf(),
            base: base.into(),
            config,
            seq: 0,
            current: None,
            current_path: None,
            opened_at: None,
            current_bytes: 0,
            files: VecDeque::new(),
        })
    }

    fn next_path(&mut self) -> PathBuf {
        self.seq += 1;
        let name = match self.config.naming {
            FileNaming::Sequence => format!("{}-{:06}.pcap", self.base, self.seq),
            FileNaming::EpochSeconds => {
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let candidate = self.dir.join(format!("{}-{}.pcap", self.base, secs));
                if candidate.exists() {
                    format!("{}-{}-{}.pcap", self.base, secs, self.seq)
                } else {
                    format!("{}-{}.pcap", self.base, secs)
                }
            }
        };
        self.dir.join(name)
    }

    /// Open a fresh file, recording the previous one's final size.
    fn open_new(&mut self) -> std::io::Result<()> {
        self.finish_current()?;
        let path = self.next_path();
        let file = BufWriter::new(File::create(&path)?);
        let writer = CaptureWriter::new_with_linktype(file, self.config.linktype)
            .map_err(std::io::Error::other)?;
        self.current = Some(writer);
        self.current_path = Some(path.clone());
        self.opened_at = Some(Instant::now());
        self.current_bytes = PCAP_HEADER_BYTES;
        self.files.push_back(FileRecord { path, bytes: 0 });
        self.enforce_retention()?;
        Ok(())
    }

    /// Flush + record the current file's final (on-disk) byte count.
    fn finish_current(&mut self) -> std::io::Result<()> {
        if let Some(w) = self.current.take() {
            let mut inner = w.into_inner();
            inner.flush()?;
            drop(inner);
            if let Some(rec) = self.files.back_mut() {
                rec.bytes = std::fs::metadata(&rec.path).map(|m| m.len()).unwrap_or(0);
            }
        }
        self.current_path = None;
        self.opened_at = None;
        self.current_bytes = 0;
        Ok(())
    }

    /// Delete oldest files until the count / total-bytes bounds hold.
    fn enforce_retention(&mut self) -> std::io::Result<()> {
        if let Some(max) = self.config.max_files {
            while self.files.len() > max.max(1) {
                if let Some(rec) = self.files.pop_front() {
                    // Warn-and-continue on delete errors (a locked/held file
                    // must not stall the capture).
                    if let Err(e) = std::fs::remove_file(&rec.path) {
                        tracing::warn!(path = %rec.path.display(), error = %e, "pcap rotate: failed to delete old file");
                    }
                }
            }
        }
        if let Some(max) = self.config.max_total_bytes {
            let total: u64 = self.files.iter().map(|r| r.bytes).sum();
            let mut total = total;
            while total > max && self.files.len() > 1 {
                if let Some(rec) = self.files.pop_front() {
                    total = total.saturating_sub(rec.bytes);
                    if let Err(e) = std::fs::remove_file(&rec.path) {
                        tracing::warn!(path = %rec.path.display(), error = %e, "pcap rotate: failed to delete old file");
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether the current file has crossed a rotation trigger.
    fn should_rotate(&self) -> bool {
        if self.current.is_none() {
            return false;
        }
        if let Some(max) = self.config.max_bytes
            && self.current_bytes >= max
        {
            return true;
        }
        if let Some(max) = self.config.max_duration
            && let Some(opened) = self.opened_at
            && opened.elapsed() >= max
        {
            return true;
        }
        false
    }

    /// Ensure a current file is open and hasn't crossed a trigger.
    fn ensure_writable(&mut self) -> std::io::Result<()> {
        if self.current.is_none() || self.should_rotate() {
            self.open_new()?;
        }
        Ok(())
    }

    /// Force a rotation now (open a fresh file on the next write).
    pub fn rotate_now(&mut self) -> std::io::Result<()> {
        self.finish_current()
    }

    /// The path of the current file (`None` before the first write).
    pub fn current_path(&self) -> Option<&Path> {
        self.current_path.as_deref()
    }

    /// Paths of all retained files, oldest first.
    pub fn file_paths(&self) -> Vec<PathBuf> {
        self.files.iter().map(|r| r.path.clone()).collect()
    }

    /// Record one owned/borrowed packet (checking triggers first).
    pub fn write(&mut self, pkt: &Packet<'_>, snaplen: Option<u32>) -> std::io::Result<()> {
        self.ensure_writable()?;
        let caplen = match snaplen {
            Some(cap) => (cap as usize).min(pkt.data().len()),
            None => pkt.data().len(),
        };
        let w = self
            .current
            .as_mut()
            .expect("ensure_writable opened a file");
        match snaplen {
            Some(cap) => w.write_packet_truncated(pkt, cap as usize),
            None => w.write_packet(pkt),
        }
        .map_err(std::io::Error::other)?;
        self.current_bytes += PCAP_RECORD_HEADER_BYTES + caplen as u64;
        Ok(())
    }

    /// Record one packet from raw parts (the source-agnostic tap path).
    pub fn write_raw(
        &mut self,
        data: &[u8],
        ts: Timestamp,
        original_len: usize,
        snaplen: Option<u32>,
    ) -> std::io::Result<()> {
        self.ensure_writable()?;
        let caplen = match snaplen {
            Some(cap) => (cap as usize).min(data.len()),
            None => data.len(),
        };
        self.current
            .as_mut()
            .expect("ensure_writable opened a file")
            .write_raw(data, ts, original_len, snaplen)
            .map_err(std::io::Error::other)?;
        self.current_bytes += PCAP_RECORD_HEADER_BYTES + caplen as u64;
        Ok(())
    }

    /// Flush and close the current file.
    pub fn sync_and_close(&mut self) -> std::io::Result<()> {
        self.finish_current()
    }
}

/// A bytes-bounded ring of buffered packets — the pre-trigger window (issue
/// #125). Oldest packets are evicted once the total buffered payload exceeds the
/// cap.
pub struct PreTriggerRing {
    max_bytes: usize,
    buffered: usize,
    ring: VecDeque<(Vec<u8>, Timestamp, usize)>,
}

impl PreTriggerRing {
    /// New ring holding at most `max_bytes` of packet payload.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            buffered: 0,
            ring: VecDeque::new(),
        }
    }

    /// Buffer one packet, evicting oldest to stay within the byte cap.
    pub fn push(&mut self, data: &[u8], ts: Timestamp, original_len: usize) {
        self.buffered += data.len();
        self.ring.push_back((data.to_vec(), ts, original_len));
        while self.buffered > self.max_bytes && self.ring.len() > 1 {
            if let Some((d, _, _)) = self.ring.pop_front() {
                self.buffered -= d.len();
            }
        }
    }

    /// Drain the ring into `w`, oldest first.
    pub fn drain_into(&mut self, w: &mut RotatingPcapWriter) -> std::io::Result<()> {
        for (data, ts, orig) in self.ring.drain(..) {
            w.write_raw(&data, ts, orig, None)?;
        }
        self.buffered = 0;
        Ok(())
    }

    /// Number of buffered packets.
    pub fn len(&self) -> usize {
        self.ring.len()
    }

    /// Whether the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }
}

/// A shared trip-wire — fire it from any anomaly handler / control task to start
/// a [`TriggeredPcapWriter`] recording (issue #125).
#[derive(Debug, Clone, Default)]
pub struct TriggerHandle(Arc<AtomicBool>);

impl TriggerHandle {
    /// A fresh, un-fired handle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fire the trigger.
    pub fn fire(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Whether the trigger has fired.
    pub fn is_fired(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// A pre-trigger capture: buffer into a [`PreTriggerRing`] until a
/// [`TriggerHandle`] fires, then flush the ring and stream live to a
/// [`RotatingPcapWriter`] (issue #125).
pub struct TriggeredPcapWriter {
    ring: PreTriggerRing,
    writer: RotatingPcapWriter,
    trigger: TriggerHandle,
    fired: bool,
}

impl TriggeredPcapWriter {
    /// New triggered writer with a pre-trigger ring of `ring_bytes`, streaming
    /// to `writer` once fired. Share the returned [`TriggerHandle`] with the
    /// code that decides when to fire.
    pub fn new(ring_bytes: usize, writer: RotatingPcapWriter) -> (Self, TriggerHandle) {
        let trigger = TriggerHandle::new();
        (
            Self {
                ring: PreTriggerRing::new(ring_bytes),
                writer,
                trigger: trigger.clone(),
                fired: false,
            },
            trigger,
        )
    }

    /// Feed one packet. Before the trigger it lands in the ring; on the first
    /// fired call the ring is flushed; after, it streams straight through.
    pub fn write_raw(
        &mut self,
        data: &[u8],
        ts: Timestamp,
        original_len: usize,
    ) -> std::io::Result<()> {
        if !self.fired && self.trigger.is_fired() {
            self.fired = true;
            self.ring.drain_into(&mut self.writer)?;
        }
        if self.fired {
            self.writer.write_raw(data, ts, original_len, None)
        } else {
            self.ring.push(data, ts, original_len);
            Ok(())
        }
    }

    /// Whether the writer has started recording (the trigger fired).
    pub fn is_recording(&self) -> bool {
        self.fired
    }

    /// Flush + close the underlying rotating writer.
    pub fn sync_and_close(&mut self) -> std::io::Result<()> {
        self.writer.sync_and_close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Timestamp;

    fn raw(n: usize) -> Vec<u8> {
        vec![0xAB; n]
    }
    fn ts(s: u32) -> Timestamp {
        Timestamp::new(s, 0)
    }

    #[test]
    fn size_trigger_rotates_and_retention_prunes() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RotatingConfig {
            max_bytes: Some(200),
            max_duration: None,
            max_files: Some(2),
            max_total_bytes: None,
            naming: FileNaming::Sequence,
            linktype: LINKTYPE_ETHERNET,
        };
        let mut w = RotatingPcapWriter::create(dir.path(), "cap", cfg).unwrap();
        // Each 150-byte packet + record header (16B) crosses the 200B cap after
        // one packet, forcing a rotation per packet.
        for i in 0..5 {
            w.write_raw(&raw(150), ts(i), 150, None).unwrap();
        }
        w.sync_and_close().unwrap();
        // max_files = 2 → at most 2 files retained on disk.
        let on_disk = std::fs::read_dir(dir.path()).unwrap().count();
        assert!(
            on_disk <= 2,
            "retention should cap files at 2, got {on_disk}"
        );
    }

    #[test]
    fn pre_trigger_ring_buffers_then_flushes_on_fire() {
        let dir = tempfile::tempdir().unwrap();
        let w = RotatingPcapWriter::create(dir.path(), "trig", RotatingConfig::default()).unwrap();
        let (mut tw, handle) = TriggeredPcapWriter::new(4096, w);

        // Pre-trigger: buffered, nothing on disk yet.
        for i in 0..3 {
            tw.write_raw(&raw(64), ts(i), 64).unwrap();
        }
        assert!(!tw.is_recording());
        assert!(tw.writer.current_path().is_none());

        // Fire → next write flushes the ring + records live.
        handle.fire();
        tw.write_raw(&raw(64), ts(10), 64).unwrap();
        assert!(tw.is_recording());
        tw.sync_and_close().unwrap();

        // The file exists and is non-trivial (header + ≥4 packets).
        let path = std::fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(len > 24, "expected a populated pcap, got {len} bytes");
    }

    #[test]
    fn ring_evicts_oldest_past_cap() {
        let mut ring = PreTriggerRing::new(100);
        for i in 0..10 {
            ring.push(&raw(40), ts(i), 40);
        }
        // 100-byte cap / 40-byte packets → at most 3 retained.
        assert!(
            ring.len() <= 3,
            "ring should evict past cap, got {}",
            ring.len()
        );
    }
}
