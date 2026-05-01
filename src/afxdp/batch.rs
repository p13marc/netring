//! Zero-copy AF_XDP RX batch.
//!
//! Mirrors the AF_PACKET [`PacketBatch`](crate::PacketBatch) lifecycle but for
//! AF_XDP descriptors:
//!
//! 1. [`XdpSocket::recv_batch`](crate::XdpSocket::recv_batch) peeks the RX ring,
//!    yielding an [`XdpBatch`] that holds `&mut self`.
//! 2. Iterating yields [`XdpPacket<'_>`] views borrowed directly from UMEM —
//!    no copies.
//! 3. Dropping the batch recycles the underlying UMEM frames and releases
//!    the RX descriptors back to the kernel, then refills the fill ring.
//!
//! Only one batch can be live per socket because the batch holds `&mut self`.

use std::marker::PhantomData;

use super::XdpSocket;

/// Zero-copy view of one AF_XDP RX packet.
///
/// `data()` borrows directly from the UMEM region — valid until the parent
/// [`XdpBatch`] is dropped.
pub struct XdpPacket<'a> {
    data: &'a [u8],
    len: u32,
    options: u32,
    addr: u64,
}

impl<'a> XdpPacket<'a> {
    /// Raw packet bytes.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Captured length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the packet is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Kernel-supplied options bitfield from `xdp_desc.options`.
    #[inline]
    pub fn options(&self) -> u32 {
        self.options
    }

    /// UMEM byte offset where the packet was placed.
    ///
    /// Opaque for most callers; useful for advanced layouts like shared UMEM.
    #[inline]
    pub fn umem_addr(&self) -> u64 {
        self.addr
    }

    /// Kernel timestamp, if available.
    ///
    /// Always returns `None` today: AF_XDP RX metadata extensions (timestamps
    /// via `BPF_PROG_TYPE_XDP` cooperation) are not yet integrated. Reserved
    /// for future expansion without an API break.
    #[inline]
    pub fn timestamp(&self) -> Option<crate::Timestamp> {
        None
    }

    /// Copy packet data out for long-lived storage.
    pub fn to_owned(&self) -> crate::OwnedPacket {
        crate::OwnedPacket {
            data: self.data.to_vec(),
            timestamp: crate::Timestamp::default(),
            original_len: self.len(),
        }
    }
}

/// Zero-copy view over a peeked range of the AF_XDP RX ring.
///
/// Construct via [`XdpSocket::recv_batch`](crate::XdpSocket::recv_batch).
///
/// # RAII
///
/// Dropping the batch:
///
/// 1. Returns each underlying UMEM frame to the free list.
/// 2. Releases the RX descriptors back to the kernel (advances the consumer
///    index).
/// 3. Refills the fill ring with as many free frames as fit.
///
/// Only one batch can be live at a time per [`XdpSocket`] — enforced by the
/// `&mut self` borrow this batch carries.
pub struct XdpBatch<'a> {
    socket: &'a mut XdpSocket,
    tok: super::ring::PeekToken,
    /// `*const ()` makes the type `!Send` and `!Sync` — same property the
    /// AF_PACKET PacketBatch enjoys (it carries the mmap-backed buffer's
    /// thread-affinity through the borrow on the source).
    _no_send_marker: PhantomData<*const ()>,
}

impl<'a> XdpBatch<'a> {
    /// Construct from a socket borrow + a fresh peek token. Internal use only.
    #[inline]
    pub(super) fn new(socket: &'a mut XdpSocket, tok: super::ring::PeekToken) -> Self {
        Self {
            socket,
            tok,
            _no_send_marker: PhantomData,
        }
    }

    /// Number of packets in the batch.
    #[inline]
    pub fn len(&self) -> usize {
        self.tok.n as usize
    }

    /// Whether the batch is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tok.n == 0
    }

    /// Iterate over packets in the batch.
    pub fn iter(&self) -> XdpBatchIter<'_> {
        XdpBatchIter { batch: self, i: 0 }
    }
}

impl<'a, 'b> IntoIterator for &'b XdpBatch<'a> {
    type Item = XdpPacket<'b>;
    type IntoIter = XdpBatchIter<'b>;

    fn into_iter(self) -> XdpBatchIter<'b> {
        self.iter()
    }
}

impl std::fmt::Debug for XdpBatch<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdpBatch")
            .field("n", &self.tok.n)
            .field("start", &self.tok.start)
            .finish()
    }
}

impl Drop for XdpBatch<'_> {
    fn drop(&mut self) {
        // Recycle UMEM frames before releasing RX descriptors. Recycling
        // first makes the addresses available for refill() at the end.
        for i in 0..self.tok.n {
            let desc: libc::xdp_desc = self.socket.rx.read_at(self.tok, i);
            self.socket.umem.free_frame(desc.addr);
        }
        self.socket.rx.consumer_release(self.tok);
        self.socket.refill();
    }
}

/// Iterator over packets in an [`XdpBatch`].
pub struct XdpBatchIter<'a> {
    batch: &'a XdpBatch<'a>,
    i: u32,
}

impl<'a> Iterator for XdpBatchIter<'a> {
    type Item = XdpPacket<'a>;

    fn next(&mut self) -> Option<XdpPacket<'a>> {
        loop {
            if self.i >= self.batch.tok.n {
                return None;
            }
            let desc: libc::xdp_desc = self.batch.socket.rx.read_at(self.batch.tok, self.i);
            self.i += 1;
            // Skip malformed descs without halting the iterator.
            match self
                .batch
                .socket
                .umem
                .data_checked(desc.addr, desc.len as usize)
            {
                Some(data) => {
                    return Some(XdpPacket {
                        data,
                        len: desc.len,
                        options: desc.options,
                        addr: desc.addr,
                    });
                }
                None => {
                    tracing::warn!(
                        addr = desc.addr,
                        len = desc.len,
                        "AF_XDP recv_batch: malformed descriptor; skipping"
                    );
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some((self.batch.tok.n - self.i) as usize))
    }
}

impl std::fmt::Debug for XdpBatchIter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdpBatchIter")
            .field("i", &self.i)
            .field("n", &self.batch.tok.n)
            .finish()
    }
}
