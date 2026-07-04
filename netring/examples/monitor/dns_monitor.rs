//! DNS monitoring (issue #120): a structured DNS exchange handler plus a passive
//! IP→name map.
//!
//! `.on_dns(|view, ctx| …)` hands you each DNS query/response as a [`DnsView`]
//! (client/server split, qname, rcode, community id). `.name_map()` folds DNS
//! responses (and TLS SNI) into a rolling IP→name index; `.on_name(…)` fires as
//! new names are learned, and `ctx.names(ip)` resolves an IP inside any handler.
//!
//! ```sh
//! cargo run --example monitor_dns_monitor --features "tokio,flow,dns" -- eth0
//! ```

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_dns_monitor: DNS exchanges + IP→name map on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .on_dns(|v, _ctx| {
            if let Some(qname) = v.qname() {
                let kind = if v.is_query() { "query" } else { "response" };
                println!("dns {kind:<8} {} → {qname}", v.client);
            }
            Ok(())
        })
        .name_map()
        .on_name(|ip, claim, _ctx| {
            println!("learned {ip} = {}", claim.name);
        })
        .sink(StdoutSink::default())
        .build()?
        .run_until_signal()
        .await?;

    Ok(())
}
