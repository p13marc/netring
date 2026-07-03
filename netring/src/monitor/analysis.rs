//! Flow analysis — nDPI-style flow-risk scoring (issue #124).
//!
//! Wraps flowscope's [`FlowAnalyzer`] behind the Monitor's
//! [`flow_analysis`](crate::monitor::MonitorBuilder::flow_analysis) surface.
//! The analyzer folds each flow's observed L7 facts (TLS handshake, HTTP
//! request, DNS query/response) into a per-flow [`L7Summary`], then at flow end
//! computes a [`FlowRisk`] — the 14-flag nDPI-style risk bitset (obsolete TLS,
//! weak cipher, cleartext credentials, DGA domain, port/proto mismatch, …) —
//! and emits **one** `flow_risk` anomaly carrying the joined risk slugs and the
//! aggregate score.
//!
//! This supersedes the two-flag `flow_risk()` checks of 0.28. Threat-intel
//! matching stays in the live, hot-reloadable
//! [`ioc()`](crate::monitor::MonitorBuilder::ioc) path (which owns the
//! `ioc_match` anomalies and reloads sub-second); `flow_analysis` is pure risk
//! scoring, so the two compose without double-emitting.
//!
//! ## Finalize timing
//!
//! Risk is finalized in the `FlowEnded` handler. The flow's L7 messages are
//! observed as they parse over the flow's lifetime — for essentially every
//! flow the TLS handshake / HTTP request / DNS exchange that drives the risk
//! flags completes well before the flow ends. An L7 message that parses in the
//! *same packet batch* as the flow's final packet is drained after the
//! lifecycle event and so would miss that one flow's finalize; this is a
//! documented edge (deferred-finalize is a possible future refinement).
//!
//! [`L7Summary`]: flowscope::analysis::L7Summary
//! [`FlowRisk`]: flowscope::detect::FlowRisk

use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowscope::analysis::{AnalyzedFlow, FlowAnalyzer};
use flowscope::detect::RiskSeverity;

use crate::anomaly::Severity;
use crate::ctx::Ctx;
use crate::protocol::FlowKey;

/// Default idle TTL for per-flow analyzer state.
pub const DEFAULT_FLOW_ANALYSIS_TTL: Duration = Duration::from_secs(300);
/// Default bound on concurrently-tracked flows (LRU past the cap).
pub const DEFAULT_FLOW_ANALYSIS_MAX_FLOWS: usize = 65_536;

/// A handler invoked with each finalized [`AnalyzedFlow`] (issue #124). Shared
/// (`Arc`) so it can be cloned into the per-protocol `FlowEnded` closures.
pub type AnalyzedFlowHandler =
    Arc<dyn Fn(&AnalyzedFlow<FlowKey>, &mut Ctx<'_>) + Send + Sync + 'static>;

/// Shared, append-only registry of [`AnalyzedFlowHandler`]s. One list is shared
/// between the builder (which pushes via
/// [`on_analyzed_flow`](crate::monitor::MonitorBuilder::on_analyzed_flow)) and
/// the `FlowEnded` closures (which read it), so registration order relative to
/// `flow_analysis()` doesn't matter.
pub(crate) type AnalyzedFlowHandlers = Arc<Mutex<Vec<AnalyzedFlowHandler>>>;

/// Tuning for [`flow_analysis`](crate::monitor::MonitorBuilder::flow_analysis).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct FlowAnalysisConfig {
    /// Idle TTL before a flow's accumulated analyzer state is reclaimed.
    pub ttl: Duration,
    /// Bound on concurrently-tracked flows (LRU eviction past the cap) — the
    /// bounded-memory contract.
    pub max_flows: usize,
    /// Emit a `flow_risk` anomaly per risky flow. `false` keeps the analyzer
    /// running (so [`on_analyzed_flow`](crate::monitor::MonitorBuilder::on_analyzed_flow)
    /// handlers still fire) without anomaly output.
    pub emit_risk_anomalies: bool,
    /// Suppress `flow_risk` anomalies below this severity. Defaults to
    /// [`RiskSeverity::Low`] (emit everything).
    pub min_risk_severity: RiskSeverity,
}

impl Default for FlowAnalysisConfig {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_FLOW_ANALYSIS_TTL,
            max_flows: DEFAULT_FLOW_ANALYSIS_MAX_FLOWS,
            emit_risk_anomalies: true,
            min_risk_severity: RiskSeverity::Low,
        }
    }
}

/// StateMap cell holding the flow analyzer. Seeded via `state_init` at
/// `flow_analysis()` time; the `Default` impl is only a never-hit fallback for
/// the `state_mut::<T>` lazy-create bound.
pub(crate) struct AnalyzerCell {
    pub(crate) analyzer: FlowAnalyzer<FlowKey>,
}

impl AnalyzerCell {
    pub(crate) fn new(cfg: &FlowAnalysisConfig) -> Self {
        Self {
            analyzer: FlowAnalyzer::with_capacity(cfg.ttl, cfg.max_flows),
        }
    }
}

impl Default for AnalyzerCell {
    fn default() -> Self {
        Self::new(&FlowAnalysisConfig::default())
    }
}

/// Map flowscope's nDPI risk ladder onto netring's anomaly [`Severity`].
pub(crate) fn risk_severity_to_netring(sev: RiskSeverity) -> Severity {
    match sev {
        RiskSeverity::Low => Severity::Info,
        RiskSeverity::Medium => Severity::Warning,
        RiskSeverity::High => Severity::Error,
        RiskSeverity::Severe => Severity::Critical,
        // `RiskSeverity` is #[non_exhaustive]; treat anything new as high-ish.
        _ => Severity::Error,
    }
}

/// Emit the `flow_risk` anomaly for a finalized flow (when it tripped a flag at
/// or above `min`), then run every registered [`AnalyzedFlowHandler`]. The
/// analyzer borrow must already be released — `af` is owned.
pub(crate) fn emit_analyzed_flow(
    af: AnalyzedFlow<FlowKey>,
    emit_risk: bool,
    min: RiskSeverity,
    ctx: &mut Ctx<'_>,
    handlers: &[AnalyzedFlowHandler],
) {
    if emit_risk
        && let Some(sev) = af.severity()
        && sev >= min
    {
        let slugs = af.risk.as_slugs().collect::<Vec<_>>().join(",");
        ctx.emit("flow_risk", risk_severity_to_netring(sev))
            .with_key(&af.key)
            .with("risk", slugs)
            .with_metric("risk_score", af.score() as f64)
            .emit();
    }
    for h in handlers {
        h(&af, ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ladder_maps_to_netring() {
        assert_eq!(risk_severity_to_netring(RiskSeverity::Low), Severity::Info);
        assert_eq!(
            risk_severity_to_netring(RiskSeverity::Medium),
            Severity::Warning
        );
        assert_eq!(
            risk_severity_to_netring(RiskSeverity::High),
            Severity::Error
        );
        assert_eq!(
            risk_severity_to_netring(RiskSeverity::Severe),
            Severity::Critical
        );
    }

    #[test]
    fn default_config_is_sane() {
        let c = FlowAnalysisConfig::default();
        assert_eq!(c.ttl, DEFAULT_FLOW_ANALYSIS_TTL);
        assert_eq!(c.max_flows, DEFAULT_FLOW_ANALYSIS_MAX_FLOWS);
        assert!(c.emit_risk_anomalies);
        assert_eq!(c.min_risk_severity, RiskSeverity::Low);
    }

    /// The netring feed→finalize glue: an obsolete-TLS handshake observed onto a
    /// flow trips `TLS_OBSOLETE_VERSION` on finalize, and the analyzed flow's
    /// max severity maps to a netring anomaly severity. Exercises the exact
    /// analyzer methods the `flow_analysis()` on_ctx handlers call, without a
    /// capture or a crafted pcap.
    #[cfg(feature = "tls")]
    #[test]
    fn obsolete_tls_handshake_finalizes_to_a_risk_flag() {
        use flowscope::Timestamp;
        use flowscope::extract::FiveTupleKey;
        use flowscope::tls::{TlsHandshake, TlsVersion};
        use flowscope::{FlowStats, L4Proto};

        let mut cell = AnalyzerCell::new(&FlowAnalysisConfig::default());
        let key = FiveTupleKey::new(
            L4Proto::Tcp,
            "10.0.0.1:44321".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
        );
        // `TlsHandshake` is #[non_exhaustive]: default-then-mutate.
        let mut hs = TlsHandshake::default();
        hs.version = Some(TlsVersion::Tls1_0);

        let ts = Timestamp::new(1, 0);
        cell.analyzer.observe_tls(&key, &hs, ts);
        let af = cell.analyzer.finalize(&key, FlowStats::default());

        assert!(
            af.risk.as_slugs().any(|s| s == "tls_obsolete_version"),
            "expected tls_obsolete_version, got {:?}",
            af.risk.as_slugs().collect::<Vec<_>>()
        );
        // Medium-tier flag → Warning.
        assert_eq!(
            af.severity().map(risk_severity_to_netring),
            Some(Severity::Warning)
        );
    }
}
