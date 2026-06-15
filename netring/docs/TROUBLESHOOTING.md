# Troubleshooting

## Common Errors

### `Error::PermissionDenied` — "insufficient privileges (need CAP_NET_RAW)"

AF_PACKET sockets require `CAP_NET_RAW`.

**Fix (option 1): Run as root**
```bash
sudo cargo run --example capture
```

**Fix (option 2): Set capability on binary**
```bash
cargo build --example capture --release
sudo setcap cap_net_raw+ep target/release/examples/capture
./target/release/examples/capture eth0
```

**Fix (option 3): Add to group (distro-dependent)**
```bash
sudo usermod -aG netdev $USER  # then re-login
```

### `Error::InterfaceNotFound` — "interface not found: eth0"

The interface name doesn't exist on this system.

```bash
# List available interfaces
ip link show
# Common names: lo, eth0, ens33, enp0s3, wlan0
```

### `Error::Mmap` with ENOMEM

The ring buffer is too large for available memory.

- `CaptureBuilder` automatically retries with smaller rings (down to 25%)
- Reduce `block_count` or `block_size` manually
- Increase locked memory limit: `ulimit -l unlimited`

### `Error::SockOpt("PACKET_IGNORE_OUTGOING")` on older kernels

`PACKET_IGNORE_OUTGOING` was added in Linux 4.20. On older kernels:
```rust
// Don't use .ignore_outgoing(true) on kernels < 4.20
let cap = Capture::builder()
    .interface("eth0")
    // .ignore_outgoing(true)  // skip this
    .build()?;
```

### `Error::SockOpt("SO_BUSY_POLL")`

Requires `CONFIG_NET_RX_BUSY_POLL` in kernel config. Not all kernels have it.

## Performance Issues

### High drop count in stats

```rust
let stats = cap.stats()?;
if stats.drops > 0 {
    // Ring is filling faster than you process
}
```

**Solutions:**
1. Increase `block_count` (more buffer)
2. Use `fanout()` to distribute across threads
3. Attach a BPF filter to drop unwanted packets in kernel
4. Do less work in the capture loop — copy and process elsewhere
5. Use `ignore_outgoing(true)` if you don't need TX packets

### Sequence gaps in batch processing

```
WARNING: block sequence gap: expected 5, got 8 (dropped 3 blocks)
```

Means the kernel ran out of blocks to fill — your processing was too slow
and the kernel had to recycle blocks you hadn't returned yet.

Same solutions as high drop count above.

### Block timeout not working (batch never arrives on sparse traffic)

If `block_timeout_ms(0)` is set, blocks only retire when full. On low-traffic
interfaces, this means you may never see a batch.

**Fix:** Use a non-zero timeout (default is 60ms).

### `mmap with MAP_LOCKED failed, retrying without`

This warning means `MAP_LOCKED` failed (missing `CAP_IPC_LOCK`). The ring
still works but pages may be swapped to disk under memory pressure.

**Fix:**
```bash
ulimit -l unlimited
# Or: sudo setcap cap_ipc_lock+ep /path/to/binary
```

## Fanout Issues

### All packets going to one socket

- Verify all sockets use the **same** `group_id`
- Verify all sockets are bound to the **same** interface
- Try `FanoutFlags::DEFRAG` to reassemble IP fragments before hashing
- Check that traffic has varied flows (same src/dst → same socket with Hash mode)

### Fanout `setsockopt` fails

Fanout must be called **after** `bind()`. The builder handles this automatically,
but if using the low-level socket API directly, ensure ordering.

## AF_XDP Issues

### AF_XDP only sees traffic addressed to my own MAC (issue #4)

AF_XDP runs in the driver RX path **after** the NIC's MAC filter. On a
non-promiscuous interface the driver only delivers frames addressed to the
NIC's MAC (plus broadcast and subscribed multicast), so passive capture (a
SPAN/mirror port, sniffing another host's traffic) sees nothing.

Enable promiscuous mode:

```rust,ignore
let sock = XdpSocket::builder().interface("eth0").promiscuous(true).build()?;
// or, on the Monitor:
Monitor::builder().xdp_interface_loaded("eth0").xdp_promiscuous(true) /* … */;
```

netring holds promiscuity via a self-cleaning AF_PACKET `PACKET_MR_PROMISC`
guard tied to the socket's lifetime, so it is released automatically on drop
(or crash). Note: `PACKET_MR_PROMISC` does **not** set the user-visible
`IFF_PROMISC` flag, so `ip link` / `ifconfig` will not display `PROMISC` even
though the interface is promiscuous (check `dev->promiscuity` is raised by
confirming capture works).

### AF_XDP in promiscuous mode still misses traffic on a multi-queue NIC

An AF_XDP socket binds to a **single** queue, and RSS spreads received traffic
across all the NIC's RX queues — so one socket only sees the share hashed to
its queue, even in promiscuous mode. Either reduce the NIC to a single queue:

```sh
ethtool -L <iface> combined 1
```

or open one AF_XDP socket per queue (shared-UMEM / fanout). On some Mellanox
NICs you must create twice as many AF_XDP queues as `ethtool -L combined` sets.

## Testing Without a Network

Use the loopback interface (`lo`) — it always exists:

```rust
let cap = Capture::open("lo")?;
```

Generate test traffic:
```bash
# In another terminal
ping 127.0.0.1
# Or
nc -u 127.0.0.1 12345 <<< "test packet"
```
