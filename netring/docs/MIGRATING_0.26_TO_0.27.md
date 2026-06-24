# Migrating netring 0.26 → 0.27

0.27 ("1.0 API sweep, threat-intel, ML features & Tier-2 protocols") is the
pre-1.0 stabilization release. It is **mostly additive** — a large stack of new
NSM capabilities (YARA, Sigma, IOC threat-intel, OCSF, p0f, QUIC, asset
inventory, nPrint/ml-features, RITA, Tier-2 protocols, hot-reload, overload
detection) lands as opt-in features that don't touch existing code.

There are **three breaking changes**, all from the 1.0 API-stability sweep
([#37](https://github.com/p13marc/netring/issues/37)) plus a soundness fix
([#35](https://github.com/p13marc/netring/issues/35)). Each has a one-line fix.
There is also one **dependency bump** (flowscope 0.19), pulled transitively.

If your code doesn't exhaustively `match` a netring enum, doesn't iterate
`Capture::packets()`, and doesn't `impl` an L7 capability marker, it compiles
unchanged.

---

## 1. Breaking: `Capture::packets()` is now a *lending* iterator (soundness)

`Packets` used to be `Iterator<Item = Packet<'cap>>`, which let safe code
`.collect()` (or otherwise retain) packets that borrow into mmap ring blocks the
kernel recycles on the next pull — a real dangling read. The `Iterator` impl is
**removed** in favor of a lending shape that binds each packet to the per-call
`&mut self` borrow, so holding two packets or collecting them is now a compile
error.

```rust
// 0.26
for pkt in cap.packets() {
    handle(pkt.data());
}

// 0.27 — pick one:
let mut pkts = cap.packets();
while let Some(pkt) = pkts.next_packet() {
    handle(pkt.data());
}
// or the closure form for the common loop:
cap.packets().for_each(|pkt| handle(pkt.data()));
```

To **retain** packets past the loop body, copy out: `pkt.to_owned()` into a
`Vec<OwnedPacket>`. `packets_for(..)` / `packets_until(..)` change the same way.
The zero-copy batch path (`Capture::next_batch`) is **unaffected**.

## 2. Breaking: `#[non_exhaustive]` on public enums and output structs

Adding a variant/field to a public type is a breaking change unless it is
`#[non_exhaustive]` — and the attribute itself can't be added after 1.0 without a
major bump. So ahead of 1.0 the enums expected to grow, and the structs the
library *returns for you to read*, are now `#[non_exhaustive]`.

**Enums** (`Error`, `BuildError`, `LoaderError`, `SigmaError`, `ParseIpNetError`,
`BroadcastRecvError`, `HandlerErrorPolicy`, `BackendErrorPolicy`, `FanoutMode`,
`TimestampSource`, `RingProfile`, `XdpMode`, `Queues`, `PcapFormat`,
`TapErrorPolicy`, `BridgeAction`, `TrafficClass`, `Severity`, `TimestampClock`,
`DropBreakdown`) and the `ConversationChunk` enum: an **exhaustive `match` now
needs a wildcard `_` arm**.

```rust
// 0.26
match severity {
    Severity::Info => …,
    Severity::Warning => …,
    Severity::Error => …,
    Severity::Critical => …,
}

// 0.27 — add a catch-all
match severity {
    Severity::Info => …,
    Severity::Warning => …,
    Severity::Error => …,
    Severity::Critical => …,
    _ => …, // future variants
}
```

**Output structs** (`CaptureStats`, `XdpStats`, `BridgeStats`, `PacketStatus`,
`OwnedPacket`, `AnomalyContext`): you can still read every field; you just can't
build them by struct literal cross-crate (you weren't meant to). **Construction**
of existing variants/fields is otherwise unaffected.

> Config structs you *construct* by literal (`AsyncPcapConfig`, `BusyPollConfig`,
> the `Ring*`/builder configs) were deliberately **left exhaustive** — so your
> `SomeConfig { .. }` literals keep working.

## 3. Breaking: the L7 capability markers `HasSni` / `HasHttpHost` / `HasQname` are sealed

These gate the session-tier `.sni_glob()` / `.http_host_glob()` /
`.dns_qname_glob()` combinators. They are now **sealed**, so only netring's
builtin protocol markers can implement them. This stops a downstream
`impl HasSni for MyProto {}` from emitting an SNI filter against a message that
carries no SNI, and lets the bounds evolve post-1.0 without a major bump.

**Impact:** none on normal code — they were only ever implemented in-crate. If
you wrote a custom `Protocol` and `impl HasSni`/`HasHttpHost`/`HasQname` for it,
that impl no longer compiles; the combinators are reserved for builtin L7 markers
(`Tls`, `Http`, `Dns`, …).

## Dependency: flowscope 0.16 → 0.19

Pulled transitively — **no change on your side**. 0.17/0.18/0.19 are additive
over 0.16 (the `arp`/`asset` modules, ~25 new protocol parsers, `ml_features` +
`nprint`, the RITA detector, p0f/HASSH/JA4H/JA4X fingerprints). If you name
flowscope directly in your own `Cargo.toml`, require `>= 0.19`.

---

## What's worth adopting (all opt-in)

None of these are required — enable the feature and add the builder call.

| Capability | Feature | Entry point |
|---|---|---|
| Threat-intel IOC matching | `ioc` | `MonitorBuilder::ioc(IocSet)` |
| Live hot-reload of IOC / Sigma sets | — | `Monitor::reload_handle()` → `set_ioc` / `set_sigma` |
| YARA-X payload scanning | `yara` | `MonitorBuilder::yara(YaraRules)` + `on_yara_match` |
| Sigma rule evaluation | `sigma` | `MonitorBuilder::sigma(SigmaRuleSet)` |
| nDPI-style flow-risk scoring | `flow` + L7 | `MonitorBuilder::flow_risk()` |
| RITA beacon detection | `flow` | `pattern_detector!` over `RitaBeaconDetector` |
| Passive asset inventory | `asset` (+ protocols) | `MonitorBuilder::on_asset` |
| p0f TCP/OS fingerprinting | `p0f` | `MonitorBuilder::on_p0f()` |
| QUIC Initial SNI/ALPN | `quic` | `.protocol::<Quic>()` + `.on::<Quic>()` |
| Tier-2 protocol markers | `ssh`, `infra-protocols`, `ot-protocols`, … | `.protocol::<P>()` + `.on::<P>()` |
| AD / lateral-movement | `ad-protocols` | `.protocol::<Smb\|Kerberos\|Ldap\|Rdp>()` |
| nPrint / CICFlowMeter ML export | `nprint` / `ml-features` | `MonitorBuilder::nprint` / `on_ml_features` |
| OCSF Detection-Finding sink | `ocsf-sink` | `.sink(OcsfSink::stdout())` |
| Overload / backpressure signal | — | `OverloadDetector` driven from `on_capture_stats` |
| Symmetric RSS (fanout coherence) | `af-xdp` | `netring::xdp::rss::RssConfig::set_symmetric()` |

See [examples/README.md](../examples/README.md) for a runnable demo of each, and
the [CHANGELOG](../../CHANGELOG.md) `## 0.27.0` section for the full list.
