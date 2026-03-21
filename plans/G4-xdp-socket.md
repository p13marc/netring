# Phase G.4: XdpSocket API (recv/send/flush)

## Goal

Implement the public `XdpSocket` type that wires together socket, UMEM,
and the 4 rings into a usable recv/send/flush API.

## Replace the current stub

Remove the stub `XdpSocket` and `XdpSocketBuilder` from `afxdp/mod.rs`
and replace with the real implementation.

## File: `src/afxdp/mod.rs` (rewrite)

### XdpSocket struct

```rust
pub struct XdpSocket {
    fd: OwnedFd,
    umem: Umem,
    fill: FillRing,
    rx: RxRing,
    tx: TxRing,
    comp: CompletionRing,
    frame_size: usize,
}
```

### recv() — RX path

```rust
impl XdpSocket {
    pub fn recv(&mut self) -> Result<Vec<OwnedPacket>, Error> {
        // 1. Recycle completed TX frames back to UMEM free list
        self.recycle_completed();

        // 2. Peek RX ring for available descriptors
        let n = self.rx.consumer_peek(64);
        if n == 0 {
            return Ok(Vec::new());
        }

        let mut packets = Vec::with_capacity(n as usize);
        let base_idx = self.rx.cached_cons; // before release

        for i in 0..n {
            let desc = unsafe { self.rx.read_desc(base_idx + i) };
            let data = unsafe { self.umem.data(desc.addr, desc.len as usize) };
            packets.push(OwnedPacket {
                data: data.to_vec(),
                timestamp: Timestamp::default(),
                original_len: desc.len as usize,
            });
            // Return frame to UMEM free list
            self.umem.free_frame(desc.addr);
        }

        // 3. Release consumed RX descriptors
        self.rx.consumer_release(n);

        // 4. Refill the fill ring with recycled frames
        self.refill();

        Ok(packets)
    }
}
```

### send() — TX path

```rust
impl XdpSocket {
    pub fn send(&mut self, data: &[u8]) -> Result<bool, Error> {
        if data.len() > self.frame_size {
            return Err(Error::Config(...));
        }

        // 1. Recycle completed TX frames
        self.recycle_completed();

        // 2. Allocate a UMEM frame
        let addr = match self.umem.alloc_frame() {
            Some(a) => a,
            None => return Ok(false), // no frames available
        };

        // 3. Copy data into UMEM frame
        unsafe {
            let buf = self.umem.data_mut(addr, data.len());
            buf.copy_from_slice(data);
        }

        // 4. Submit TX descriptor
        let idx = match self.tx.producer_reserve(1) {
            Some(i) => i,
            None => {
                self.umem.free_frame(addr);
                return Ok(false); // TX ring full
            }
        };
        unsafe { self.tx.write_desc(idx, xdp_desc { addr, len: data.len() as u32, options: 0 }) };
        self.tx.producer_submit(1);

        Ok(true)
    }
}
```

### flush() + wakeup

```rust
impl XdpSocket {
    pub fn flush(&mut self) -> Result<(), Error> {
        // sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0) to kick the kernel
        // OR check NEED_WAKEUP flag and only wake if set
        if self.tx.needs_wakeup() {
            let ret = unsafe {
                libc::sendto(self.fd.as_raw_fd(), std::ptr::null(), 0,
                             libc::MSG_DONTWAIT, std::ptr::null(), 0)
            };
            if ret == -1 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EAGAIN) {
                    return Err(Error::Io(err));
                }
            }
        }
        Ok(())
    }
}
```

### Internal helpers

```rust
impl XdpSocket {
    /// Recycle completed TX frames back to UMEM free list.
    fn recycle_completed(&mut self) {
        let n = self.comp.consumer_peek(64);
        for i in 0..n {
            let addr = unsafe { self.comp.read_desc(self.comp.cached_cons + i) };
            self.umem.free_frame(addr);
        }
        if n > 0 {
            self.comp.consumer_release(n);
        }
    }

    /// Refill the fill ring with available frames from UMEM free list.
    fn refill(&mut self) {
        let available = self.umem.available().min(64) as u32;
        if available == 0 { return; }

        if let Some(idx) = self.fill.producer_reserve(available) {
            for i in 0..available {
                if let Some(addr) = self.umem.alloc_frame() {
                    unsafe { self.fill.write_desc(idx + i, addr) };
                }
            }
            self.fill.producer_submit(available);
        }
    }

    /// Wait for RX readiness using poll(2).
    pub fn poll(&self, timeout: Duration) -> Result<bool, Error> {
        let pfd = nix::poll::PollFd::new(self.fd.as_fd(), nix::poll::PollFlags::POLLIN);
        let timeout = nix::poll::PollTimeout::try_from(timeout)
            .unwrap_or(nix::poll::PollTimeout::MAX);
        let n = nix::poll::poll(&mut [pfd], timeout)?;
        Ok(n > 0)
    }
}
```

### XdpSocketBuilder::build()

```rust
pub fn build(self) -> Result<XdpSocket, Error> {
    let iface = self.validate()?;
    let ifindex = crate::afpacket::socket::resolve_interface(iface)? as u32;

    // 1. Allocate UMEM
    let mut umem = Umem::new(self.frame_size, self.frame_count)?;

    // 2. Create socket
    let fd = socket::create_xdp_socket()?;

    // 3. Register UMEM
    let reg = umem.as_reg();
    socket::register_umem(fd.as_fd(), &reg)?;

    // 4. Configure ring sizes (all same as frame_count, power of 2)
    let ring_size = self.frame_count.next_power_of_two() as u32;
    socket::set_fill_ring_size(fd.as_fd(), ring_size)?;
    socket::set_completion_ring_size(fd.as_fd(), ring_size)?;
    socket::set_rx_ring_size(fd.as_fd(), ring_size)?;
    socket::set_tx_ring_size(fd.as_fd(), ring_size)?;

    // 5. Get mmap offsets
    let offsets = socket::get_mmap_offsets(fd.as_fd())?;

    // 6. mmap all 4 rings
    let fill = unsafe { FillRing::mmap(fd.as_fd(), ring_size, &offsets.fr, XDP_UMEM_PGOFF_FILL_RING)? };
    let comp = unsafe { CompletionRing::mmap(fd.as_fd(), ring_size, &offsets.cr, XDP_UMEM_PGOFF_COMPLETION_RING)? };
    let rx = unsafe { RxRing::mmap(fd.as_fd(), ring_size, &offsets.rx, XDP_PGOFF_RX_RING)? };
    let tx = unsafe { TxRing::mmap(fd.as_fd(), ring_size, &offsets.tx, XDP_PGOFF_TX_RING)? };

    // 7. Pre-fill the fill ring
    // (allocate frames from UMEM and submit to fill ring)

    // 8. Bind to interface + queue
    let flags = if self.zero_copy { XDP_ZEROCOPY } else { XDP_COPY };
    socket::bind_xdp(fd.as_fd(), ifindex, self.queue_id, flags as u16)?;
    // Note: XDP_ZEROCOPY may fail → retry with XDP_COPY

    Ok(XdpSocket { fd, umem, fill, rx, tx, comp, frame_size: self.frame_size })
}
```

### AsFd + Debug

```rust
impl AsFd for XdpSocket { /* delegate to fd */ }
impl AsRawFd for XdpSocket { /* delegate to fd */ }
impl Debug for XdpSocket { /* frame_size, available frames */ }
```

## Tests

- Builder validation (missing interface, zero frame_size/count)
- Integration (needs CAP_NET_RAW + CAP_BPF + XDP-capable NIC): manual only
