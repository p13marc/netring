# Plan 60 — CLI tooling (`netring-cli`)

## Summary

Ship two ready-to-use CLI binaries that exercise the flow stack
end-to-end and double as user-facing demonstrations:

1. **`flow-summary`** — live or pcap input, prints flow lifecycle
   events; production-quality replacement for `tcpdump | grep` for
   flow-level visibility.
2. **`flow-replay`** — reads a pcap, re-emits flows in real time
   (or fast-forwarded), useful for testing IDS rules / collector
   integrations.

Both ship as a `netring-cli` workspace member.

## Status

Not started.

## Prerequisites

- Plans 00–04 published.
- Plan 20 (`netring-flow-pcap`) — used by both tools.
- (Soft) Plans 22/23/24 — for richer protocol-aware output, but the
  v1 of these tools ship without L7 parsing.

## Out of scope

- Replacing tcpdump or Wireshark. Different domain.
- Live packet capture on non-Linux. `flow-summary` is Linux-only
  for live capture (uses netring); pcap mode works everywhere.
- Web UI. CLI only.

---

## `flow-summary`

### Usage

```
flow-summary live <interface>            # live capture
flow-summary pcap <path>                 # pcap input
flow-summary live -i lo --format json    # JSON line per event
flow-summary pcap trace.pcap --extractor mac  # use MacPair
flow-summary live -i eth0 --filter "tcp,port=443"  # simple filter
```

### Output formats

- **default**: one line per Started/Ended event, colorized
- **json**: one JSON object per line (machine-friendly)
- **conn-log**: Zeek-style conn.log columns (matches `async_flow_history` example)
- **summary**: aggregated table at exit (top-N flows by bytes / packets)

### Filter language

Tiny subset of BPF-like syntax:

```
proto=tcp
proto=udp
port=443
ip=10.0.0.1
host=example.com  # resolves once at start
```

Combined with commas for AND. No OR / parentheses (that's tcpdump's
domain).

### Built-in subcommands

```
flow-summary live IFACE [--format FMT] [--filter EXPR] [--output PATH]
flow-summary pcap FILE [--format FMT] [--filter EXPR] [--output PATH]
flow-summary stats          # show internal tracker stats while running
```

---

## `flow-replay`

Reads a pcap, re-emits flow events in (configurable) real time.
Useful for:

- Testing IDS rules without re-running real attacks.
- Validating IPFIX collector setup.
- Demoing flow tracking without needing a live network.

### Usage

```
flow-replay trace.pcap                          # real-time (preserve original gaps)
flow-replay trace.pcap --speed 10               # 10x speedup
flow-replay trace.pcap --output ipfix --target 127.0.0.1:9995
flow-replay trace.pcap --format csv > flows.csv # write CSV summary
flow-replay trace.pcap --output udp --target 127.0.0.1:8125 --metric netflow
```

### Speed control

- `--speed 1.0` (default): preserve inter-packet gaps from pcap.
- `--speed 10.0`: 10× faster.
- `--speed inf`: as fast as possible (no sleeps).
- `--speed 0`: pause on each packet, advance with key press
  (interactive).

---

## Files

### NEW

```
netring-cli/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs
│   ├── flow_summary.rs       # subcommand: live/pcap → events
│   ├── flow_replay.rs        # subcommand: pcap → re-emit
│   ├── filter.rs             # tiny filter expression parser
│   ├── format.rs             # output format trait + impls
│   └── exporter.rs           # IPFIX / CSV / JSON sinks
└── tests/
    ├── flow_summary_pcap.rs  # integration: feed pcap, check output
    └── flow_replay_speed.rs  # speed control timing test
```

---

## Cargo.toml

```toml
[package]
name = "netring-cli"
version = "0.1.0"
description = "CLI tools for netring flow tracking"
keywords = ["netring", "flow", "cli", "pcap", "ipfix"]
categories = ["command-line-utilities", "network-programming"]

[[bin]]
name = "flow-summary"
path = "src/bin/flow_summary.rs"

[[bin]]
name = "flow-replay"
path = "src/bin/flow_replay.rs"

[dependencies]
netring = { version = "0.7", path = "../netring", features = ["tokio", "flow"] }
netring-flow = { version = "0.1", path = "../netring-flow" }
netring-flow-pcap = { version = "0.1", path = "../netring-flow-pcap" }
netring-flow-export = { version = "0.1", path = "../netring-flow-export", optional = true }
clap = { version = "4", features = ["derive"] }
tokio = { workspace = true }
futures = "0.3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
anyhow = "1"
colored = "2"

[features]
default = ["ipfix"]
ipfix = ["dep:netring-flow-export"]
```

---

## Implementation steps

### Phase A — `flow-summary` first

1. Skeleton + `clap` arg parsing.
2. `live` mode:
   - Open `AsyncCapture`.
   - `flow_stream(...)` with selected extractor.
   - For each event, dispatch to selected formatter.
3. `pcap` mode:
   - Use `netring-flow-pcap::PcapFlowSource`.
   - For each event, dispatch to formatter.
4. Formatters:
   - **default**: pretty colorized line.
   - **json**: `serde_json::to_writer` per event.
   - **conn-log**: tab-separated.
   - **summary**: HashMap<Key, Stats> aggregator, print on Ctrl-C.
5. Filter parser — tiny hand-rolled, ~50 LOC.
6. Output redirection (`--output PATH` writes to file or stdout).
7. Tests + README with examples.

### Phase B — `flow-replay`

1. Skeleton + `clap` arg parsing.
2. Read pcap, advance through it with original timestamps.
3. Speed control: maintain a `replay_clock` that advances at
   `wall_clock_elapsed * speed`.
   - For each packet, sleep until `replay_clock >= pkt.ts`, then
     emit.
4. Output sinks:
   - IPFIX (via `netring-flow-export`)
   - CSV / JSON line per Ended flow
   - UDP datagram (raw flow record format, configurable)
5. Interactive mode (`--speed 0`).
6. Tests + README.

---

## Tests

### Integration

- `flow_summary live --format json` against a synthetic pcap (run
  via `flow-summary pcap` instead — same code path) + JSON parse
  the output, assert ≥1 event has `type=ended`.
- `flow_replay --speed inf` finishes in <100ms for a small pcap.
- `flow_summary --filter "proto=tcp"` excludes UDP frames in the
  output.
- `--output PATH` writes to file correctly.

---

## Acceptance criteria

- [ ] Both binaries build.
- [ ] `flow-summary --help` shows usage.
- [ ] `flow-replay --help` shows usage.
- [ ] ≥3 integration tests for each.
- [ ] README has copy-paste examples.
- [ ] `cargo install --path netring-cli` works (so users can
      install with one command).

---

## Risks

1. **Subcommand UX bikeshedding.** Lock in `flow-summary live`
   vs `flow-summary --live` early; document.
2. **Color output on non-tty.** Use `colored::control::should_colorize()`.
3. **Speed control jitter.** `tokio::time::sleep` granularity is
   typically <1ms; for sub-ms inter-packet gaps we'd need busy-wait.
   Document the limitation.
4. **Output redirect SIGPIPE.** When piping into `head` etc., handle
   broken pipe gracefully (exit 0, not panic).
5. **`netring-cli` shouldn't be a runtime dep of the libraries.**
   Workspace member only; users can `cargo install` from path or
   crates.io.

---

## Effort

- LOC: ~700 across the 2 binaries + helpers.
- Time: 1.5 days.

---

## What this unlocks

- "Try it without writing code" — install one binary, point at
  an interface, get flow visibility. Ten-second value
  demonstration that text doesn't match.
- Real-world stress test of the API: if writing a CLI exposes
  awkwardness in the API surface, that's a signal to fix the API.
- A reference for users building their own tooling on top of
  netring-flow.
