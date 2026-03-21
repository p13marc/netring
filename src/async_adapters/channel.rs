//! Thread + channel adapter for runtime-agnostic async capture.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::{Receiver, TryRecvError};

use crate::afpacket::rx::AfPacketRxBuilder;
use crate::error::Error;
use crate::packet::OwnedPacket;
use crate::traits::PacketSource;

/// Spawns a capture thread, sends owned packets over a bounded channel.
///
/// Not zero-copy across the channel boundary (packets are copied out of ring).
/// Useful for runtime-agnostic async or multi-consumer patterns.
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
    /// `capacity` is the bounded channel size. The thread copies packets via
    /// `to_owned()` and sends them over the channel.
    pub fn spawn(interface: &str, capacity: usize) -> Result<Self, Error> {
        // Create the RX handle in the current thread so errors propagate.
        let rx = AfPacketRxBuilder::default().interface(interface).build()?;

        let (sender, receiver) = crossbeam_channel::bounded(capacity);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            let mut rx = rx;
            while !stop_clone.load(Ordering::Relaxed) {
                match rx.next_batch_blocking(Duration::from_millis(100)) {
                    Ok(Some(batch)) => {
                        for pkt in &batch {
                            let owned = pkt.to_owned();
                            if sender.send(owned).is_err() {
                                return; // receiver dropped
                            }
                        }
                    }
                    Ok(None) => continue,
                    Err(_) => return,
                }
            }
        });

        Ok(Self {
            receiver,
            handle: Some(handle),
            stop,
        })
    }

    /// Blocking receive of the next packet.
    pub fn recv(&self) -> Result<OwnedPacket, crossbeam_channel::RecvError> {
        self.receiver.recv()
    }

    /// Non-blocking receive attempt.
    pub fn try_recv(&self) -> Result<OwnedPacket, TryRecvError> {
        self.receiver.try_recv()
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
