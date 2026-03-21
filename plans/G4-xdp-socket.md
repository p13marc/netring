# Phase G.4: XdpSocket API (recv/send/flush)

## Replace current stub

Remove the stub from `afxdp/mod.rs`. Wire socket + UMEM + 4 rings into
a usable public API.

## XdpSocket struct

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

## XdpSocketBuilder::build()

```rust
pub fn build(self) -> Result<XdpSocket, Error> {
    let iface = self.validate()?;
    let ifindex = crate::afpacket::socket::resolve_interface(iface)? as u32;

    // 1. Allocate UMEM (MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE)
    let mut umem = Umem::new(self.frame_size, self.frame_count)?;

    // 2. Create socket
    let fd = socket::create_xdp_socket()?;

    // 3. Register UMEM with kernel
    socket::register_umem(fd.as_fd(), &umem.as_reg())?;

    // 4. Configure ring sizes (each power of 2, independent)
    let ring_size = (self.frame_count as u32).next_power_of_two();
    socket::set_ring_size(fd.as_fd(), ffi::XDP_UMEM_FILL_RING, ring_size)?;
    socket::set_ring_size(fd.as_fd(), ffi::XDP_UMEM_COMPLETION_RING, ring_size)?;
    socket::set_ring_size(fd.as_fd(), ffi::XDP_RX_RING, ring_size)?;
    socket::set_ring_size(fd.as_fd(), ffi::XDP_TX_RING, ring_size)?;

    // 5. Get mmap offsets from kernel
    let offsets = socket::get_mmap_offsets(fd.as_fd())?;

    // 6. mmap all 4 rings
    // NOTE: offsets.fr = fill ring, offsets.cr = completion ring (NOT .fill/.completion)
    // NOTE: pgoff values are u64, cast to off_t (i64) — safe on 64-bit
    let fill = unsafe { FillRing::mmap(fd.as_fd(), ring_size, &offsets.fr, ffi::XDP_UMEM_PGOFF_FILL_RING as u64)? };
    let comp = unsafe { CompletionRing::mmap(fd.as_fd(), ring_size, &offsets.cr, ffi::XDP_UMEM_PGOFF_COMPLETION_RING as u64)? };
    let rx = unsafe { RxRing::mmap(fd.as_fd(), ring_size, &offsets.rx, ffi::XDP_PGOFF_RX_RING as u64)? };
    let tx = unsafe { TxRing::mmap(fd.as_fd(), ring_size, &offsets.tx, ffi::XDP_PGOFF_TX_RING as u64)? };

    // 7. Pre-fill the fill ring
    // Allocate all frames and submit to fill ring for kernel to use
    let prefill = umem.available().min(ring_size as usize) as u32;
    if let Some(idx) = fill.producer_reserve(prefill) {
        for i in 0..prefill {
            if let Some(addr) = umem.alloc_frame() {
                unsafe { fill.write_desc(idx + i, addr) };
            }
        }
        fill.producer_submit(prefill);
    }

    // 8. Bind to interface + queue
    // flags=0: auto-negotiate (kernel tries zero-copy, falls back to copy)
    // XDP_USE_NEED_WAKEUP can be OR'd for wakeup optimization
    let bind_flags = if self.need_wakeup { ffi::XDP_USE_NEED_WAKEUP as u16 } else { 0 };
    socket::bind_xdp(fd.as_fd(), ifindex, self.queue_id, bind_flags)?;

    Ok(XdpSocket { fd, umem, fill, rx, tx, comp, frame_size: self.frame_size })
}
```

## recv() — RX path

```rust
pub fn recv(&mut self) -> Result<Vec<OwnedPacket>, Error> {
    // 1. Recycle completed TX frames
    self.recycle_completed();

    // 2. Peek RX ring
    let n = self.rx.consumer_peek(64);
    if n == 0 { return Ok(Vec::new()); }

    let mut packets = Vec::with_capacity(n as usize);
    let base_idx = self.rx.cached_cons;

    for i in 0..n {
        let desc: xdp_desc = unsafe { self.rx.read_desc(base_idx + i) };
        let data = unsafe { self.umem.data(desc.addr, desc.len as usize) };
        packets.push(OwnedPacket {
            data: data.to_vec(),
            timestamp: Timestamp::default(),
            original_len: desc.len as usize,
        });
        // Return frame to free list (will be refilled to fill ring below)
        self.umem.free_frame(desc.addr);
    }

    // 3. Release consumed RX descriptors
    self.rx.consumer_release(n);

    // 4. Refill fill ring with recycled frames
    self.refill();

    Ok(packets)
}
```

## send() — TX path

```rust
pub fn send(&mut self, data: &[u8]) -> Result<bool, Error> {
    if data.len() > self.frame_size {
        return Err(Error::Config(format!(
            "packet {} bytes exceeds frame size {}", data.len(), self.frame_size
        )));
    }

    self.recycle_completed();

    let addr = match self.umem.alloc_frame() {
        Some(a) => a,
        None => return Ok(false),
    };

    // Copy data into UMEM
    unsafe {
        let buf = self.umem.data_mut(addr, data.len());
        buf.copy_from_slice(data);
    }

    // Submit TX descriptor
    let idx = match self.tx.producer_reserve(1) {
        Some(i) => i,
        None => {
            self.umem.free_frame(addr);
            return Ok(false);
        }
    };
    unsafe {
        self.tx.write_desc(idx, xdp_desc { addr, len: data.len() as u32, options: 0 });
    }
    self.tx.producer_submit(1);

    Ok(true)
}
```

## flush() — TX wakeup

```rust
pub fn flush(&mut self) -> Result<(), Error> {
    // MSG_DONTWAIT is MANDATORY — kernel returns EOPNOTSUPP without it
    if self.tx.needs_wakeup() || true {  // always kick for simplicity
        let ret = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,  // MANDATORY
                std::ptr::null(),
                0,
            )
        };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EAGAIN)
               && err.raw_os_error() != Some(libc::ENOBUFS) {
                return Err(Error::Io(err));
            }
        }
    }
    Ok(())
}
```

## Internal helpers

```rust
fn recycle_completed(&mut self) {
    let n = self.comp.consumer_peek(64);
    let base = self.comp.cached_cons;
    for i in 0..n {
        let addr: u64 = unsafe { self.comp.read_desc(base + i) };
        self.umem.free_frame(addr);
    }
    if n > 0 { self.comp.consumer_release(n); }
}

fn refill(&mut self) {
    let want = self.umem.available().min(64) as u32;
    if want == 0 { return; }
    if let Some(idx) = self.fill.producer_reserve(want) {
        let mut filled = 0u32;
        for i in 0..want {
            if let Some(addr) = self.umem.alloc_frame() {
                unsafe { self.fill.write_desc(idx + i, addr) };
                filled += 1;
            }
        }
        if filled > 0 { self.fill.producer_submit(filled); }
    }
}

pub fn poll(&self, timeout: Duration) -> Result<bool, Error> {
    let pfd = nix::poll::PollFd::new(self.fd.as_fd(), nix::poll::PollFlags::POLLIN);
    let t = nix::poll::PollTimeout::try_from(timeout).unwrap_or(nix::poll::PollTimeout::MAX);
    let n = nix::poll::poll(&mut [pfd], t).map_err(|e| Error::Io(e.into()))?;
    Ok(n > 0)
}
```

## Trait impls

```rust
impl AsFd for XdpSocket { /* delegate to fd */ }
impl AsRawFd for XdpSocket { /* delegate to fd */ }
impl Debug for XdpSocket { /* frame_size, umem.available() */ }
```
