# Metrics catalog

Every `netring_*` metric netring can emit through the
[`metrics`](https://crates.io/crates/metrics) facade (feature `metrics`),
with its type, labels, and cardinality notes. netring only *records*
values — the host application installs the recorder/exporter (e.g.
[`metrics-exporter-prometheus`](https://crates.io/crates/metrics-exporter-prometheus)).
Without a recorder installed, every record call is a cheap no-op.

## Capture telemetry (Phase C)

Emitted by
[`CaptureTelemetry::record_metrics`](https://docs.rs/netring/latest/netring/monitor/struct.CaptureTelemetry.html#method.record_metrics),
typically via the `MonitorBuilder::capture_metrics(period)` sugar or a
hand-written `on_capture_stats` handler. **Gauges**, not counters: the
totals are read as absolute cumulative values and `drop_rate` is a rate,
so a scrape always sees the latest sample rather than an increment.

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `netring_capture_packets`   | gauge | `source` | Cumulative packets delivered to userspace (passed the kernel filter). |
| `netring_capture_drops`     | gauge | `source` | Cumulative packets the kernel dropped (ring full). |
| `netring_capture_freezes`   | gauge | `source` | Cumulative TPACKET_V3 ring-freeze events. |
| `netring_capture_drop_rate` | gauge | `source` | Windowed drop rate `[0.0, 1.0]` over the last sample period. |

`source` is the capture source's index (`.interfaces([...])`
registration order), rendered as a string. **Cardinality:** one series
per source per metric — bounded by your interface count. Safe.

> The windowed `netring_capture_drop_rate` is the alerting signal: it
> reflects *current* loss, where a `…_drops / …_packets` ratio computed
> from the cumulative gauges would be smeared across the whole run.

## Capture counters (low-level)

Emitted by
[`metrics::record_capture_delta`](https://docs.rs/netring/latest/netring/metrics/fn.record_capture_delta.html)
for callers driving a raw `Capture` (no `Monitor`). These are
**counters** fed *deltas* from `Capture::stats()` (which resets the
kernel counters on read).

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `netring_capture_packets_total` | counter | `iface` | Total packets received past the kernel filter. |
| `netring_capture_drops_total`   | counter | `iface` | Total packets dropped (ring exhaustion). |
| `netring_capture_freezes_total` | counter | `iface` | Total ring-freeze events. |

**Cardinality:** one series per interface. Safe. Don't mix these with
the Phase C gauges for the same capture — pick the `Monitor` gauges
(absolute) *or* the raw-`Capture` counters (deltas), not both.

## Monitor resilience & health (Phase B/C)

Emitted by
[`MonitorHealth::record_metrics`](https://docs.rs/netring/latest/netring/monitor/struct.MonitorHealth.html#method.record_metrics)
(call it from a `.tick(..)` handler or your own poll loop — the health
handle has no built-in cadence). **Gauges.**

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `netring_monitor_handler_errors` | gauge | — | Cumulative handler errors swallowed under `HandlerErrorPolicy::Isolate`. |
| `netring_monitor_backend_errors` | gauge | — | Cumulative capture-backend errors swallowed under `BackendErrorPolicy::SkipSource`. |
| `netring_monitor_active_flows`   | gauge | — | Active flows in the tracker as of the last event. |

> These are the "silent failure" signals: `Isolate` / `SkipSource` keep the
> pipeline alive by swallowing errors, so a **rising** handler/backend error
> count is what you alert on. Unlabeled — one series each. Safe.

## Anomalies

Emitted by [`MetricsSink`](https://docs.rs/netring/latest/netring/anomaly/struct.MetricsSink.html)
when wired as a `Monitor` anomaly sink.

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `netring_anomaly_total`  | counter   | `kind` | One increment per anomaly emission. |
| `netring_anomaly_metric` | histogram | `metric` | One observation per numeric anomaly metric. |

Names are overridable via `MetricsSink::with_counter_name` /
`with_histogram_name` for namespacing.

> **Cardinality warning.** The `kind` label is bounded by your detector
> set (safe). Do **not** add per-flow / per-IP / per-port labels to these
> series in a custom sink — that is unbounded cardinality and will blow
> up a Prometheus TSDB. Keep high-cardinality identifiers in the anomaly
> *payload* (logs / EVE JSON), not in metric labels.
