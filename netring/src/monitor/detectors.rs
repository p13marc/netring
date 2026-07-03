//! Detector registry integration (issue #127).
//!
//! Lets a Monitor drive flowscope's heterogeneous [`Detector`] set — the
//! beacon / port-scan / RITA / connection-flood / data-exfil / DGA family —
//! from its own tracked event stream. Register detectors with
//! [`detector`](crate::monitor::MonitorBuilder::detector) /
//! [`detectors`](crate::monitor::MonitorBuilder::detectors); the run loop feeds
//! every tracked flow event through [`DetectorRegistry::observe_event`] and, when
//! the `dns` feature is on, DNS query names through
//! [`DetectorRegistry::observe_dns`], publishing each emitted
//! [`flowscope::OwnedAnomaly`] through the Monitor's sink chain.
//!
//! ## ATT&CK tagging
//!
//! Every anomaly a detector emits carries a typed
//! [`DetectorKind`](flowscope::DetectorKind). When that kind maps to a MITRE
//! ATT&CK technique (via [`DetectorKind::attack_technique`]), the publish path
//! appends an `attack_technique` observation (e.g. `T1071` for beaconing,
//! `T1046` for port scans), so it surfaces in every sink — JSON, EVE, OCSF.
//! (Lifting it into a sink's *native* ATT&CK field — OCSF `finding_info.attacks`
//! — is a documented follow-up; the technique is present as an observation
//! regardless.)
//!
//! [`Detector`]: flowscope::detect::Detector
//! [`DetectorRegistry`]: flowscope::detect::DetectorRegistry
//! [`DetectorKind::attack_technique`]: flowscope::DetectorKind::attack_technique

use flowscope::OwnedAnomaly;
use flowscope::detect::DetectorRegistry;

use crate::protocol::FlowKey;

/// StateMap cell holding the detector registry plus a reusable emission buffer.
///
/// Present in the Monitor's `StateMap` only when at least one detector is
/// registered — its presence is the "detectors armed" signal the run loop
/// checks (an unarmed monitor never allocates this).
pub(crate) struct DetectorCell {
    pub(crate) registry: DetectorRegistry<FlowKey>,
    /// Reused `observe_*` output buffer — cleared each drain.
    pub(crate) out: Vec<OwnedAnomaly>,
}

impl DetectorCell {
    pub(crate) fn new(registry: DetectorRegistry<FlowKey>) -> Self {
        Self {
            registry,
            out: Vec::new(),
        }
    }
}

impl Default for DetectorCell {
    /// Empty registry — only the `state_mut` lazy-create fallback; the real cell
    /// is seeded at `build()` with the user's registered detectors.
    fn default() -> Self {
        Self::new(DetectorRegistry::new())
    }
}
