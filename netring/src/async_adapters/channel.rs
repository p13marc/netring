//! Thread + channel adapter for runtime-agnostic async capture.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::{Receiver, SendTimeoutError, Sender, TryRecvError};

use crate::afpacket::rx::CaptureBuilder;
use crate::error::Error;
use crate::packet::OwnedPacket;

/// Spawns a capture thread, sends owned packets over a bounded channel.
///
/// Not zero-copy across the channel boundary (packets are copied out of ring).
/// Useful for runtime-agnostic async or multi-consumer patterns.
///
/// # Drop semantics
///
/// On drop, the capture thread is signaled to stop and joined; **any
/// packets still buffered in the channel are discarded**. Use
/// [`stop_and_drain()`](Self::stop_and_drain) instead if you need to
/// process trailing packets.
///
/// # Examples
///
/// ```no_run
/// use netring::async_adapters::channel::ChannelCapture;
///
/// let rx = ChannelCapture::spawn("lo", 4096).unwrap();
/// for packet in &rx {
///     println!("{} bytes", packet.data.len());
/// }
/// ```
pub struct ChannelCapture {
    receiver: Receiver<OwnedPacket>,
    handle: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl ChannelCapture {
    /// Spawn a capture thread on the given interface.
    ///
    /// Creates an `Capture` in the current thread (so errors propagate),
    /// then spawns a background thread that captures packets and sends
    /// [`OwnedPacket`]s over a bounded channel of the given `capacity`.
    ///
    /// # Errors
    ///
    /// - [`Error::InterfaceNotFound`] if the interface doesn't exist
    /// - [`Error::PermissionDenied`] without `CAP_NET_RAW`
    /// - [`Error::Mmap`] if ring buffer allocation fails
    pub fn spawn(interface: &str, capacity: usize) -> Result<Self, Error> {
        // Create the RX handle in the current thread so errors propagate.
        let rx = CaptureBuilder::default().interface(interface).build()?;

        let (sender, receiver) = crossbeam_channel::bounded(capacity);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            let mut rx = rx;
            pump(
                |out| {
                    // Short poll timeout so the worker checks the stop
                    // flag often.
                    if let Some(batch) = rx.next_batch_blocking(Duration::from_millis(10))? {
                        out.extend(batch.iter().map(|pkt| pkt.to_owned()));
                    }
                    Ok(())
                },
                &sender,
                &stop_clone,
            );
        });

        Ok(Self {
            receiver,
            handle: Some(handle),
            stop,
        })
    }

    /// Blocking receive of the next packet.
    ///
    /// Blocks until a packet is available or the capture thread stops
    /// (returns `Err(RecvError)` when the channel disconnects).
    pub fn recv(&self) -> Result<OwnedPacket, crossbeam_channel::RecvError> {
        self.receiver.recv()
    }

    /// Non-blocking receive attempt.
    ///
    /// Returns `Err(TryRecvError::Empty)` immediately if no packet is
    /// available, or `Err(TryRecvError::Disconnected)` if the capture
    /// thread has stopped.
    pub fn try_recv(&self) -> Result<OwnedPacket, TryRecvError> {
        self.receiver.try_recv()
    }

    /// Stop the capture thread, join it, and drain any packets still
    /// buffered in the channel.
    ///
    /// Use this instead of relying on [`Drop`](Self::drop) when trailing
    /// packets matter — `Drop` discards them.
    ///
    /// Returns the drained packets in FIFO order.
    pub fn stop_and_drain(mut self) -> Vec<OwnedPacket> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let mut drained = Vec::new();
        while let Ok(pkt) = self.receiver.try_recv() {
            drained.push(pkt);
        }
        drained
    }
}

/// Forward packets from `next_batch` to `sender` until `stop` is set,
/// the receiver is gone, or `next_batch` fails. Sends time out and
/// re-check `stop`, so a full channel whose receiver is not reading
/// cannot keep the worker — and a `drop` / `stop_and_drain` joining
/// it — blocked forever.
fn pump<F>(mut next_batch: F, sender: &Sender<OwnedPacket>, stop: &AtomicBool)
where
    F: FnMut(&mut Vec<OwnedPacket>) -> Result<(), Error>,
{
    let mut batch = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        batch.clear();
        if next_batch(&mut batch).is_err() {
            return;
        }
        for mut pkt in batch.drain(..) {
            loop {
                match sender.send_timeout(pkt, Duration::from_millis(10)) {
                    Ok(()) => break,
                    Err(SendTimeoutError::Timeout(back)) => {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        pkt = back;
                    }
                    Err(SendTimeoutError::Disconnected(_)) => return,
                }
            }
        }
    }
}

impl<'a> IntoIterator for &'a ChannelCapture {
    type Item = OwnedPacket;
    type IntoIter = ChannelIter<'a>;

    fn into_iter(self) -> ChannelIter<'a> {
        ChannelIter { cap: self }
    }
}

/// Iterator over packets from a [`ChannelCapture`].
pub struct ChannelIter<'a> {
    cap: &'a ChannelCapture,
}

impl Iterator for ChannelIter<'_> {
    type Item = OwnedPacket;

    fn next(&mut self) -> Option<OwnedPacket> {
        self.cap.receiver.recv().ok()
    }
}

impl Drop for ChannelCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PacketDirection, PacketStatus, Timestamp, TimestampClock};

    fn packet() -> OwnedPacket {
        OwnedPacket {
            data: vec![0; 60],
            timestamp: Timestamp::new(1, 0),
            timestamp_clock: TimestampClock::None,
            original_len: 60,
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

    /// #160: the worker stops when asked even though the channel is
    /// full and its receiver (still alive) is not reading — the
    /// situation in which `Drop` / `stop_and_drain` used to hang.
    #[test]
    fn a_full_channel_does_not_block_stopping() {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            pump(
                |out| {
                    out.extend((0..8).map(|_| packet()));
                    Ok(())
                },
                &sender,
                &worker_stop,
            )
        });
        thread::sleep(Duration::from_millis(50)); // channel full by now
        stop.store(true, Ordering::Relaxed);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = worker.join();
            let _ = done_tx.send(());
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "the worker stopped"
        );
        drop(receiver);
    }

    #[test]
    fn the_worker_stops_when_the_receiver_is_gone() {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        drop(receiver);
        let stop = AtomicBool::new(false);
        pump(
            |out| {
                out.push(packet());
                Ok(())
            },
            &sender,
            &stop,
        );
    }
}
