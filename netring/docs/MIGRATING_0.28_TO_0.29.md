# Migrating netring 0.28 → 0.29

0.29 adopts **flowscope 0.22** and uses the new threat-intel + analysis
primitives to redesign netring's detection surface. Most of the release is
**additive** — new builder methods for aggregation, RED metrics, DNS, owner
bandwidth, fingerprints, detectors, and capture tooling. The breaking surface is
concentrated in the **IOC / flow-risk** area.

> **Version note.** This ships as **`0.29.0`** — a pre-1.0 minor, so the breaking
> changes below are expected. The `1.0` API-freeze is deferred and tracked in
> [#37](https://github.com/p13marc/netring/issues/37).

If you only consume the `Monitor` via typed handlers and don't touch the IOC or
`flow_risk` APIs, you can likely bump the version and rebuild unchanged (the new
surfaces are opt-in and the event structs stay `#[non_exhaustive]`).

---

## 1. Breaking: `IocSet` is now flowscope's threat-intel type

`netring::monitor::ioc::IocSet` is now a re-export of
`flowscope::detect::ioc::IocSet` (issue
[#124](https://github.com/p13marc/netring/issues/124)). The netring-local risk
scaffolding (`monitor::risk`) was removed.

The path `netring::monitor::ioc::IocSet` is unchanged, and the `IocSetExt` trait
(re-exported in the prelude) keeps the ergonomic `check_*` helpers. What changed:

- Entries are typed by `IocKind` (`Ip` / `Domain` / `Ja3` / `Ja4` / …) — insert
  with `set.insert(IocKind::Domain, "evil.example", reputation, source)`.
- Matches return `IocMatch` (with `kind` / `value` / `reputation` / `source`),
  not a bare bool.
- `set.contains_ip(addr)` / `contains_domain(name)` return `Option<IocMatch>`.

`ReloadHandle::set_ioc` now takes the flowscope `IocSet`.

## 2. Breaking: `flow_risk()` is deprecated → `flow_analysis()`

Flow-risk scoring moved onto flowscope's `FlowAnalyzer` (issue
[#124](https://github.com/p13marc/netring/issues/124)):

```rust
// 0.28
let m = Monitor::builder().interface("eth0").flow_risk().build()?;

// 0.29
let m = Monitor::builder().interface("eth0").flow_analysis().build()?;
// or, with tuning + a per-flow callback:
let m = Monitor::builder()
    .interface("eth0")
    .on_analyzed_flow(|flow, _ctx| {
        // flow.risk.as_slugs(), flow.risk.max_severity(), flow.risk.score()
        Ok(())
    })
    .build()?;
```

`flow_risk()` still compiles as `#[deprecated]` sugar for `flow_analysis()`.
Each analyzed flow emits one `flow_risk` anomaly at its max severity
(Low→Info, Medium→Warning, High→Error, Severe→Critical).

## 3. MITRE ATT&CK is an observation label, not a sink change

Detectors (issue [#127](https://github.com/p13marc/netring/issues/127)) tag
findings with ATT&CK technique IDs via an `attack_technique` **observation
label** (auto-appended from `DetectorKind::attack_technique()`). This keeps
`AnomalySink::write` stable — custom sinks and `netring-exporters` need no
change. The OCSF and EVE sinks lift the label into their native ATT&CK fields.

## 4. New additive surfaces (no migration needed)

All opt-in; nothing to change unless you want them:

| Area | Entry points | Issue |
|------|--------------|-------|
| Detectors | `.detector(..)`, `.detectors(..)` | [#127](https://github.com/p13marc/netring/issues/127) |
| SSH/QUIC fingerprints | `on_ssh_fingerprint`, `on_quic_fingerprint`, `TlsFingerprint.pq_key_share` | [#128](https://github.com/p13marc/netring/issues/128) |
| YARA hot-reload | `ReloadHandle::set_yara` / `has_yara` | [#53](https://github.com/p13marc/netring/issues/53) |
| Community ID | `Ctx::community_id()`, event `community_id()` | [#123](https://github.com/p13marc/netring/issues/123) |
| App-proto + encrypted DNS | `TlsFingerprint.app_protocol`, `on_encrypted_dns` | [#133](https://github.com/p13marc/netring/issues/133) |
| DNS handler + name map | `on_dns`, `name_map`, `on_name`, `Ctx::names` | [#120](https://github.com/p13marc/netring/issues/120) |
| Owner bandwidth | `with_flow_attribution`, `owner_bandwidth`, `on_owner_bandwidth` | [#130](https://github.com/p13marc/netring/issues/130) |
| Aggregation | `aggregate`, `on_aggregate` | [#121](https://github.com/p13marc/netring/issues/121) |
| RED metrics | `red`, `on_red` | [#122](https://github.com/p13marc/netring/issues/122) |
| Rotating/triggered pcap | `RotatingPcapWriter`, `TriggeredPcapWriter` | [#125](https://github.com/p13marc/netring/issues/125) |
| Netns capture | `NetNs`, `CaptureBuilder::netns` | [#126](https://github.com/p13marc/netring/issues/126) |

## 5. Note: `owner_bandwidth()` requires an attribution hook

`owner_bandwidth()` / `owner_bandwidth_windowed()` without a prior
`with_flow_attribution(..)` is a build error
(`BuildError::AttributionHookRequired`) rather than a silent no-op — wire the
hook that maps a `FlowKey` to an owner `Attribution` first.
