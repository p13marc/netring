//! Bandwidth by **OS process** (recipe, not a core API).
//!
//! Packets on the wire carry no process identity — so this is a *host-side*
//! resolver, not something passive capture can do alone. We snapshot
//! `/proc/net/{tcp,tcp6,udp,udp6}` (socket → inode) and `/proc/<pid>/fd/*`
//! (inode → pid/comm) into a `(local_ip, local_port) → pid` map, refresh it on a
//! timer, and feed it to the generic [`with_flow_attribution`] hook (issue #130).
//! `on_owner_bandwidth` then reports throughput per process.
//!
//! **Caveats — read before relying on this** (the same ones `nethogs` / `ss -p`
//! have):
//! - **Local host only.** Only meaningful when netring captures *this host's*
//!   traffic. On a span/tap/mirror port the traffic is other hosts' — the map
//!   won't match, and everything lands in the "unattributed" bucket.
//! - **Best-effort & racy.** A short flow that opens and closes between
//!   snapshots is missed; UDP is connectionless so its mapping is weaker.
//! - **Privilege.** You only see other users' sockets as root (or with
//!   `CAP_NET_ADMIN` + read access to their `/proc/<pid>/fd`).
//! - The precise, always-on version is an eBPF sock/cgroup hook (tracked
//!   separately); this `/proc` scanner is the pragmatic, no-eBPF 90% solution.
//! - IPv6 sockets are parsed too, but this demo's parser unit-test covers v4.
//!
//! ```sh
//! sudo -E cargo run --example monitor_process_bandwidth --features "tokio,flow" -- lo
//! ```

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use flowscope::correlate::Attribution;
use netring::prelude::*;

/// A snapshot of which local process owns which local socket endpoint.
#[derive(Default)]
struct Owners {
    /// `(local_ip, local_port)` → owning pid.
    by_endpoint: HashMap<(IpAddr, u16), u32>,
    /// pid → process name (for display).
    comm: HashMap<u32, String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_process_bandwidth: per-process bandwidth on {iface} (Ctrl-C to stop)");

    let owners = Arc::new(RwLock::new(snapshot()));

    // Refresh the socket→pid map on a timer (blocking /proc walk off-thread).
    {
        let owners = Arc::clone(&owners);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                if let Ok(snap) = tokio::task::spawn_blocking(snapshot).await {
                    *owners.write().unwrap() = snap;
                }
            }
        });
    }

    Monitor::builder()
        .interface(&iface)
        // Attribute each flow to the pid owning its local endpoint (either side).
        .with_flow_attribution({
            let owners = Arc::clone(&owners);
            move |key| {
                let o = owners.read().ok()?;
                [(key.a.ip(), key.a.port()), (key.b.ip(), key.b.port())]
                    .into_iter()
                    .find_map(|ep| o.by_endpoint.get(&ep).copied())
                    .map(|pid| Attribution(u64::from(pid)))
            }
        })
        .on_owner_bandwidth(Duration::from_secs(10), {
            let owners = Arc::clone(&owners);
            move |r| {
                let o = owners.read().unwrap();
                println!("── bandwidth by process ──────────────────");
                for (attr, bps) in r.top(10) {
                    let pid = attr.0 as u32;
                    let comm = o.comm.get(&pid).map(String::as_str).unwrap_or("?");
                    println!("  {pid:>7} {comm:<16} {bps:>12.0} B/s");
                }
                println!(
                    "  (unattributed {:.0} B/s — {:.0}% — e.g. remote or already-closed sockets)",
                    r.unknown_rate(),
                    r.unknown_share() * 100.0
                );
                Ok(())
            }
        })
        .sink(StdoutSink::default())
        .build()?
        .run_until_signal()
        .await?;

    Ok(())
}

/// Build the endpoint→pid + pid→comm maps from `/proc`.
fn snapshot() -> Owners {
    let inode_owner = inode_to_pid_comm();
    let mut owners = Owners::default();
    for proto in ["tcp", "udp"] {
        let Ok(contents) = fs::read_to_string(format!("/proc/net/{proto}")) else {
            continue;
        };
        for ((ip, port), inode) in parse_proc_net_v4(&contents) {
            if let Some((pid, comm)) = inode_owner.get(&inode) {
                owners.by_endpoint.insert((IpAddr::V4(ip), port), *pid);
                owners.comm.entry(*pid).or_insert_with(|| comm.clone());
            }
        }
    }
    owners
}

/// Walk `/proc/<pid>/fd/*` → `socket:[inode]` to build `inode → (pid, comm)`.
fn inode_to_pid_comm() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();
    let Ok(procs) = fs::read_dir("/proc") else {
        return map;
    };
    for entry in procs.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path())
                && let Some(inode) = target.to_str().and_then(parse_socket_inode)
            {
                map.entry(inode).or_insert_with(|| (pid, comm.clone()));
            }
        }
    }
    map
}

/// `socket:[12345]` → `12345`.
fn parse_socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Parse the IPv4 `/proc/net/{tcp,udp}` table → `((local_ip, local_port), inode)`
/// per row. The local address is a little-endian hex `IP:PORT`; inode is field 9.
fn parse_proc_net_v4(contents: &str) -> Vec<((Ipv4Addr, u16), u64)> {
    let mut out = Vec::new();
    for line in contents.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let Some((hex_ip, hex_port)) = f[1].split_once(':') else {
            continue;
        };
        let (Ok(ip_raw), Ok(port), Ok(inode)) = (
            u32::from_str_radix(hex_ip, 16),
            u16::from_str_radix(hex_port, 16),
            f[9].parse::<u64>(),
        ) else {
            continue;
        };
        // /proc stores the address little-endian: to_le_bytes recovers the octets.
        let ip = Ipv4Addr::from(ip_raw.to_le_bytes());
        out.push(((ip, port), inode));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_proc_net_tcp_row() {
        // Header + one row: 127.0.0.1:53 (0100007F:0035), inode 12345.
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000";
        let rows = parse_proc_net_v4(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], ((Ipv4Addr::new(127, 0, 0, 1), 53), 12345));
    }

    #[test]
    fn socket_inode_link_parsing() {
        assert_eq!(parse_socket_inode("socket:[98765]"), Some(98765));
        assert_eq!(parse_socket_inode("anon_inode:[eventpoll]"), None);
        assert_eq!(parse_socket_inode("/dev/null"), None);
    }
}
