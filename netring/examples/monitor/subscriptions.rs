//! The 0.25 **subscription engine** — the headline API. Three strongly-typed
//! tiers, each with per-subscription filters that split into a kernel
//! conjunction (BPF-pushable) + a userspace remainder:
//!
//! - `packet()`        — every frame, pre-tracking (`&PacketView`).
//! - `flow::<P>()`     — once per flow, at its end (`&FlowEnded<P>`).
//! - `session::<P>()`  — each parsed L7 message (`&P::Message`).
//!
//! plus `.expr("…")` — the same `Predicate` AST from a runtime filter string.
//!
//! ```sh
//! cargo run --example monitor_subscriptions --features monitor -- eth0
//! ```

use netring::PacketView;
use netring::ctx::Ctx;
use netring::monitor::Monitor;
use netring::monitor::subscription::{flow, packet, session};
use netring::protocol::builtin::{Tcp, Tls};
use netring::protocol::event_typed::FlowEnded;

#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".to_string());

    let monitor =
        Monitor::builder()
            .interface(&iface)
            // The session tier needs the relevant L7 parser registered.
            .protocol::<Tcp>()
            .protocol::<Tls>()
            // 1. PACKET tier — every frame matching the filter. `tcp().dst_port(443)`
            //    is kernel-pushable, so non-443 traffic is shed before userspace.
            .subscribe(
                packet()
                    .tcp()
                    .dst_port(443)
                    .to(|view: &PacketView, _ctx: &mut Ctx<'_>| {
                        println!("packet → :443  ({} bytes)", view.frame.len());
                        Ok(())
                    }),
            )
            // 2. FLOW tier — once per flow at its end, only for flows over 1 MiB.
            .subscribe(flow::<Tcp>().bytes_over(1 << 20).to(
                |evt: &FlowEnded<Tcp>, _ctx: &mut Ctx<'_>| {
                    println!("big flow ended: {} ↔ {}", evt.key.a, evt.key.b);
                    Ok(())
                },
            ))
            // 3. SESSION tier — each parsed TLS handshake whose SNI matches a glob.
            //    `sni_glob` is only available on `session::<Tls>()` (typed gating).
            .subscribe(session::<Tls>().sni_glob("*.bank.example").to(
                |_msg, _ctx: &mut Ctx<'_>| {
                    println!("TLS handshake → *.bank.example");
                    Ok(())
                },
            ))
            // 4. RUNTIME string filter — `.expr(..)` parses to the *same* AST as the
            //    typed combinators, so `packet().expr("udp and dst port 53")` and
            //    `packet().udp().dst_port(53)` are identical.
            .subscribe(
                packet()
                    .expr("udp and dst port 53")
                    .expect("valid filter string")
                    .to(|_view: &PacketView, _ctx: &mut Ctx<'_>| {
                        println!("dns packet");
                        Ok(())
                    }),
            )
            .build()?;

    println!("# subscription tiers active on {iface} (Ctrl-C to stop)");
    monitor.run_until_signal().await
}
