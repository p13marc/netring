//! Integration tests for `netring-flow-pcap` against the fixtures
//! that live in `netring-flow/tests/data/`.

use std::io::Cursor;

use netring_flow::extract::FiveTuple;
use netring_flow::{EndReason, FlowEvent};
use netring_flow_pcap::PcapFlowSource;

const HTTP_SESSION: &[u8] = include_bytes!("../../netring-flow/tests/data/http_session.pcap");
const DNS_QUERIES: &[u8] = include_bytes!("../../netring-flow/tests/data/dns_queries.pcap");

#[test]
fn views_iterates_in_order() {
    let src = PcapFlowSource::from_reader(Cursor::new(HTTP_SESSION)).unwrap();
    let views: Vec<_> = src.views().collect::<Result<_, _>>().unwrap();
    assert!(!views.is_empty(), "fixture should have packets");
    // Timestamps should be monotonic non-decreasing.
    for w in views.windows(2) {
        assert!(
            w[0].timestamp <= w[1].timestamp,
            "timestamps must be ordered"
        );
    }
}

#[test]
fn event_iter_emits_full_lifecycle_for_http() {
    let src = PcapFlowSource::from_reader(Cursor::new(HTTP_SESSION)).unwrap();
    let evts: Vec<_> = src
        .with_extractor(FiveTuple::bidirectional())
        .collect::<Result<_, _>>()
        .unwrap();

    let started = evts
        .iter()
        .filter(|e| matches!(e, FlowEvent::Started { .. }))
        .count();
    let est = evts
        .iter()
        .filter(|e| matches!(e, FlowEvent::Established { .. }))
        .count();
    let ended_fin = evts
        .iter()
        .filter(|e| {
            matches!(
                e,
                FlowEvent::Ended {
                    reason: EndReason::Fin,
                    ..
                }
            )
        })
        .count();

    assert_eq!(started, 1);
    assert_eq!(est, 1);
    assert_eq!(ended_fin, 1, "HTTP fixture closes with FIN");
}

#[test]
fn event_iter_runs_final_sweep_on_pcap_exhaustion() {
    // DNS fixture has unfinished UDP flows (no close protocol).
    // The companion crate's `EventIter` runs a final sweep so we
    // see Ended { IdleTimeout } for them.
    let src = PcapFlowSource::from_reader(Cursor::new(DNS_QUERIES)).unwrap();
    let evts: Vec<_> = src
        .with_extractor(FiveTuple::bidirectional())
        .collect::<Result<_, _>>()
        .unwrap();

    let started = evts
        .iter()
        .filter(|e| matches!(e, FlowEvent::Started { .. }))
        .count();
    let ended_idle = evts
        .iter()
        .filter(|e| {
            matches!(
                e,
                FlowEvent::Ended {
                    reason: EndReason::IdleTimeout,
                    ..
                }
            )
        })
        .count();

    assert!(started >= 1);
    assert_eq!(
        started, ended_idle,
        "every Started should reach Ended via the final sweep"
    );
}
