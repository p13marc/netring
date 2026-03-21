# Phase F: Bridge / IPS Mode

## Goal

Provide a `Bridge` abstraction that pairs RX+TX handles on two interfaces for
transparent inline packet forwarding with optional filtering/modification.
This is the "IPS mode" that Suricata and network taps need.

## Depends on

- Phase A (code quality) — TX block_size fix
- Phase B (ring presets) — BridgeBuilder uses RingProfile

## Limitations

- Bridge uses `AfPacketRx` / `AfPacketTx` directly (requires `PacketSource` trait)
- **Not compatible with AF_XDP backend** (Phase G) until a future GAT-based
  `PacketSource` trait redesign. AF_XDP uses a different batch/buffer model.

## Architecture

```
        Interface A                    Interface B
            │                              │
  ┌─────────▼──────────┐        ┌─────────▼──────────┐
  │ AfPacketRx (A)      │        │ AfPacketRx (B)      │
  │ captures packets    │        │ captures packets    │
  └─────────┬──────────┘        └─────────┬──────────┘
            │                              │
            ▼                              ▼
  ┌─────────────────────────────────────────────────┐
  │              Bridge                              │
  │  A→B: rx_a.next_batch() → filter → tx_b.send()  │
  │  B→A: rx_b.next_batch() → filter → tx_a.send()  │
  └─────────────────────────────────────────────────┘
            │                              │
  ┌─────────▼──────────┐        ┌─────────▼──────────┐
  │ AfPacketTx (B)      │        │ AfPacketTx (A)      │
  │ injects packets     │        │ injects packets     │
  └────────────────────┘        └────────────────────┘
```

## 1. BridgeAction enum

```rust
/// Action returned by a bridge filter callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeAction {
    /// Forward the packet to the other interface.
    Forward,
    /// Drop the packet (do not forward).
    Drop,
}
```

## 2. Bridge struct

Location: `src/bridge.rs`

```rust
/// Bidirectional packet bridge between two interfaces.
///
/// Forwards packets from A→B and B→A through an optional filter callback.
/// Designed for IPS (Intrusion Prevention System) and transparent tap use cases.
///
/// # Examples
///
/// ```no_run
/// use netring::bridge::{Bridge, BridgeAction};
///
/// let mut bridge = Bridge::builder()
///     .interface_a("eth0")
///     .interface_b("eth1")
///     .build()?;
///
/// // Forward all packets (transparent bridge)
/// bridge.run(|_pkt, _direction| BridgeAction::Forward)?;
/// # Ok::<(), netring::Error>(())
/// ```
pub struct Bridge {
    rx_a: AfPacketRx,
    tx_b: AfPacketTx,
    rx_b: AfPacketRx,
    tx_a: AfPacketTx,
}
```

## 3. BridgeBuilder

```rust
pub struct BridgeBuilder {
    interface_a: Option<String>,
    interface_b: Option<String>,
    profile: RingProfile,       // uses Phase B RingProfile
    promiscuous: bool,          // default: true (bridges should see all traffic)
    qdisc_bypass: bool,         // default: true (low latency forwarding)
}

impl BridgeBuilder {
    pub fn interface_a(mut self, name: &str) -> Self;
    pub fn interface_b(mut self, name: &str) -> Self;
    pub fn profile(mut self, profile: RingProfile) -> Self;
    pub fn promiscuous(mut self, enable: bool) -> Self;
    pub fn qdisc_bypass(mut self, enable: bool) -> Self;
    pub fn build(self) -> Result<Bridge, Error>;
}
```

`build()` creates 4 handles: `rx_a`, `tx_b` on interface A; `rx_b`, `tx_a` on
interface B. All with matching ring profiles. Promiscuous on by default.

## 4. Bridge::run()

```rust
/// Direction of packet flow through the bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeDirection {
    /// Packet from interface A heading to interface B.
    AtoB,
    /// Packet from interface B heading to interface A.
    BtoA,
}

impl Bridge {
    /// Run the bridge loop, forwarding packets through the filter.
    ///
    /// Blocks forever (until error or the filter callback returns an error).
    /// The callback receives each packet and its direction, and returns
    /// whether to forward or drop it.
    ///
    /// For maximum throughput, the callback should be fast — avoid allocations
    /// or heavy processing. Copy interesting packets via `to_owned()` and
    /// process them elsewhere.
    pub fn run<F>(&mut self, mut filter: F) -> Result<(), Error>
    where
        F: FnMut(&Packet<'_>, BridgeDirection) -> BridgeAction,
    {
        loop {
            // Poll both directions with short timeout
            self.forward_direction(&mut filter, BridgeDirection::AtoB)?;
            self.forward_direction(&mut filter, BridgeDirection::BtoA)?;
        }
    }
}
```

### Internal forwarding logic

```rust
fn forward_direction<F>(
    &mut self,
    filter: &mut F,
    direction: BridgeDirection,
) -> Result<(), Error>
where
    F: FnMut(&Packet<'_>, BridgeDirection) -> BridgeAction,
{
    let (rx, tx) = match direction {
        BridgeDirection::AtoB => (&mut self.rx_a, &mut self.tx_b),
        BridgeDirection::BtoA => (&mut self.rx_b, &mut self.tx_a),
    };

    if let Some(batch) = rx.next_batch() {
        for pkt in &batch {
            if filter(&pkt, direction) == BridgeAction::Forward {
                if let Some(mut slot) = tx.allocate(pkt.len()) {
                    slot.data_mut()[..pkt.len()].copy_from_slice(pkt.data());
                    slot.set_len(pkt.len());
                    slot.send();
                }
                // If TX ring full, drop silently (log at debug level)
            }
        }
        tx.flush()?;
    }
    Ok(())
}
```

## 5. Bridge stats

```rust
impl Bridge {
    /// Get forwarding statistics.
    pub fn stats(&self) -> Result<BridgeStats, Error>;
}

pub struct BridgeStats {
    pub a_to_b: CaptureStats,
    pub b_to_a: CaptureStats,
}
```

## 6. Module structure

```
src/bridge.rs   — Bridge, BridgeBuilder, BridgeAction, BridgeDirection, BridgeStats
```

Feature-gated? No — it's core functionality using existing types.

## Tests

- Unit: BridgeBuilder validation (missing interface names)
- Integration: create bridge on lo↔lo (loopback to itself), send packet, verify it loops
- Integration: bridge with drop filter, verify packets not forwarded

## Examples

```
examples/bridge.rs — transparent bridge between two interfaces
```

## Exports

- `bridge::{Bridge, BridgeBuilder, BridgeAction, BridgeDirection, BridgeStats}`
- Update README, docs
