//! Issue #54 (action half): deliberate, counted load shedding under overload.
//!
//! The companion to `monitor_overload` (the detection *signal*). A
//! [`LoadShedder`] couples the hysteresis detector with a [`ShedPolicy`]: under
//! `Emergency` it admits only a deterministic fraction of *new* flows (here
//! 25%), shedding the rest at the dispatch boundary and **counting** every
//! decision — never a silent drop. Already-admitted flows keep flowing (the
//! elephant-friendly choice), and a bidirectional key hash means both legs of a
//! flow share one verdict.
//!
//! netring owns the *mechanism + policy + honest counters*; the *heuristic*
//! (the keep rate, what counts as sheddable) is the app's. The kernel-ring and
//! XDP elephant-shunt levers are the hardware-gated follow-up (#44).
//!
//! ```sh
//! cargo run --example monitor_load_shedding --features "tokio,flow" -- eth0
//! ```

use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netring::monitor::Monitor;
use netring::monitor::overload::{LoadShedder, OverloadConfig, ShedPolicy};
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    // Detect at 5% drops; under load, admit ~25% of new flows.
    let shedder = Arc::new(Mutex::new(LoadShedder::new(
        OverloadConfig::default().enter_at(0.05).recover_at(0.01, 3),
        ShedPolicy::SampleFlows { keep: 0.25 },
    )));

    eprintln!("monitor_load_shedding: watching {iface} (Ctrl-C to stop)");

    let shed_stats = shedder.clone();
    let shed_admit = shedder.clone();

    Monitor::builder()
        .interface(&iface)
        .name("load_shedding")
        .protocol::<Tcp>()
        .on_capture_stats(Duration::from_secs(1), move |t, _ctx| {
            let mut s = shed_stats.lock().unwrap();
            if let Some(state) = s.observe(t.drop_rate) {
                let st = s.stats();
                eprintln!(
                    "{state:?}: drop {:.1}% — admitted {} / shed {} new flows",
                    t.drop_rate * 100.0,
                    st.admitted,
                    st.shed,
                );
            }
            Ok(())
        })
        .on_ctx::<FlowStarted<Tcp>>(move |evt: &FlowStarted<Tcp>, _ctx: &mut Ctx<'_>| {
            // Direction-invariant key hash: both legs share an admission verdict.
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            evt.key.hash(&mut hasher);
            if shed_admit
                .lock()
                .unwrap()
                .admit_new_flow(hasher.finish())
                .is_shed()
            {
                // Under overload this flow is shed — skip its expensive
                // processing (L7 parsing, enrichment, …). Here we just note it.
            }
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_until_signal()
        .await?;

    Ok(())
}
