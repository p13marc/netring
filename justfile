# netring justfile (workspace-aware: netring + netring-flow)
# Requires: just (https://github.com/casey/just)
#
# Integration tests and examples need AF_PACKET (CAP_NET_RAW).
# `just setcap` grants capabilities on compiled binaries via sudo,
# then tests/examples run as the current user (no sudo).

set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# ── Build ───────────────────────────────────────────────────────────────────

# Build the whole workspace
build:
    cargo build --workspace

# Build in release mode
build-release:
    cargo build --workspace --release --all-targets

# Build all examples
build-examples:
    cargo build -p netring --examples --features tokio,channel

# ── Capabilities ────────────────────────────────────────────────────────────

# Grant CAP_NET_RAW+CAP_NET_ADMIN on all test and example binaries (requires sudo)
setcap:
    #!/usr/bin/env bash
    set -euo pipefail
    # Build everything first
    cargo test -p netring --features "integration-tests,tokio,channel" --no-run 2>&1 | tail -1
    cargo build -p netring --examples --features tokio,channel 2>&1 | tail -1
    # Collect all binary paths
    bins=()
    while IFS= read -r bin; do
        [ -f "$bin" ] && bins+=("$bin")
    done < <(
        cargo test -p netring --features "integration-tests,tokio,channel" --no-run --message-format=json 2>/dev/null \
            | jq -r 'select(.executable != null) | .executable'
        cargo build -p netring --examples --features tokio,channel --message-format=json 2>/dev/null \
            | jq -r 'select(.executable != null) | .executable'
    )
    if [ ${#bins[@]} -eq 0 ]; then
        echo "No binaries found to setcap"
        exit 1
    fi
    echo "Setting CAP_NET_RAW,CAP_NET_ADMIN on ${#bins[@]} binaries..."
    for bin in "${bins[@]}"; do
        sudo setcap cap_net_raw,cap_net_admin+ep "$bin" && \
            echo "  ✓ $(basename "$bin")" || \
            echo "  ✗ $(basename "$bin") (failed)"
    done
    echo "✓ Done. Run tests/examples without sudo."

# Check if AF_PACKET is available (useful in containers)
check-afpacket:
    #!/usr/bin/env bash
    python3 -c "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)).close()" 2>/dev/null \
        && echo "✓ AF_PACKET available" \
        || { echo "✗ AF_PACKET not available"; \
             echo "  Run: just setcap  (bare metal, needs sudo once)"; \
             echo "  Or:  podman run --cap-add=NET_RAW --cap-add=NET_ADMIN ..."; \
             exit 1; }

# ── Test ────────────────────────────────────────────────────────────────────

# Run unit tests across the workspace (no privileges needed)
test-unit:
    cargo test --workspace

# Run ALL tests including integration (run `just setcap` first)
test:
    cargo test -p netring --features "integration-tests,tokio,channel" -- --test-threads=1
    cargo test -p netring-flow

# Run netring-flow tests only (cross-platform, no privileges)
test-flow:
    cargo test -p netring-flow

# Run property-based invariant tests with extended case count
proptest-flow:
    PROPTEST_CASES=10000 cargo test -p netring-flow --test proptest_invariants --features test-helpers

# Regenerate the committed pcap fixtures (deterministic; only re-run
# when you want to change synthetic traffic shape).
fixtures:
    cargo run -p netring-flow --example generate_fixtures --features test-helpers

# ── Fuzz (requires nightly) ─────────────────────────────────────────

# Build all fuzz targets (verifies they compile).
fuzz-build:
    cd netring-flow && cargo +nightly fuzz build

# Run a single fuzz target until interrupted; pass --time SECONDS to bound.
fuzz target *args:
    cd netring-flow && cargo +nightly fuzz run "{{target}}" {{args}}

# Run all fuzz targets for 30s each — used by the CI smoke job.
fuzz-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    cd netring-flow
    for t in extract_five_tuple extract_strip_vlan extract_strip_mpls extract_inner_vxlan extract_inner_gtpu extract_ip_pair; do
        echo "▶ fuzz $t for 30s"
        cargo +nightly fuzz run "$t" -- -max_total_time=30
    done

# Run a specific test by name
test-one name:
    cargo test -p netring --features "integration-tests,tokio,channel" -- --test-threads=1 "{{name}}"

# Run integration tests only
test-integration:
    cargo test -p netring --features "integration-tests,tokio,channel" --test '*' -- --test-threads=1

# Verify netring-flow has zero default deps (proves runtime-free claim)
verify-flow-no-deps:
    @cargo tree -p netring-flow --no-default-features
    @echo "✓ netring-flow has no default deps"

# ── Examples ────────────────────────────────────────────────────────────────

# Run an example (run `just setcap` first for AF_PACKET access)
example name *args:
    cargo run -p netring --example "{{name}}" --features tokio,channel -- {{args}}

# Shorthand recipes
capture *args:      (example "capture" args)
batch *args:        (example "batch_processing" args)
inject *args:       (example "inject" args)
fanout *args:       (example "fanout" args)
stats *args:        (example "stats_monitor" args)
low-latency *args:  (example "low_latency" args)
async *args:           (example "async_capture" args)
async-stream *args:    (example "async_stream" args)
async-inject *args:    (example "async_inject" args)
async-signal *args:    (example "async_signal" args)
async-pipeline *args:  (example "async_pipeline" args)
async-bridge *args:    (example "async_bridge" args)
async-streamext *args: (example "async_streamext" args)
async-xdp *args:       cargo run -p netring --example async_xdp --features tokio,af-xdp -- {{args}}
async-metrics *args:   cargo run -p netring --example async_metrics --features tokio,metrics -- {{args}}
channel *args:      (example "channel_consumer" args)
ebpf *args:         (example "ebpf_filter" args)
dpi *args:          (example "dpi" args)
bridge *args:       (example "bridge" args)

# Flow tracking examples (require `flow` feature → netring-flow)
flow-keys *args:     cargo run -p netring --example async_flow_keys --features tokio,parse -- {{args}}
flow-summary *args:  cargo run -p netring --example async_flow_summary --features tokio,flow -- {{args}}
flow-filter *args:   cargo run -p netring --example async_flow_filter --features tokio,flow -- {{args}}
flow-history *args:  cargo run -p netring --example async_flow_history --features tokio,flow -- {{args}}
flow-channel *args:  cargo run -p netring --example async_flow_channel --features tokio,flow -- {{args}}

# Loopback dedup demo (no privileges-by-default; needs setcap for live capture)
lo-dedup *args:      cargo run -p netring --example async_lo_dedup --features tokio -- {{args}}

# Sync flow tracking examples (in netring-flow, no Linux privileges needed)
flow-pcap-keys *args:        cargo run -p netring-flow --example pcap_flow_keys -- {{args}}
flow-pcap-summary *args:     cargo run -p netring-flow --example pcap_flow_summary -- {{args}}
flow-pcap-reassembly *args:  cargo run -p netring-flow --example pcap_buffered_reassembly -- {{args}}

# ── Lint & Format ───────────────────────────────────────────────────────────

# Run clippy on the workspace with all features
clippy:
    cargo clippy --workspace --all-targets --all-features -- --deny warnings

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Format code
fmt:
    cargo fmt --all

# ── Docs ────────────────────────────────────────────────────────────────────

# Build documentation for the whole workspace
doc:
    cargo doc --workspace --all-features --no-deps

# Build and open documentation in browser
doc-open:
    cargo doc --workspace --all-features --no-deps --open

# ── Bench ───────────────────────────────────────────────────────────────────

# Run benchmarks
bench:
    cargo bench -p netring

# Verify benchmarks compile
bench-check:
    cargo bench -p netring --no-run

# ── CI ──────────────────────────────────────────────────────────────────────

# Quick CI (no privileges): lint + unit tests + docs + bench compile + flow no-deps check
ci: clippy test-unit verify-flow-no-deps doc bench-check
    @echo "✓ CI checks passed"

# Full CI: setcap + lint + ALL tests + docs + bench
ci-full: setcap clippy test doc bench-check
    @echo "✓ Full CI checks passed"

# ── Utility ─────────────────────────────────────────────────────────────────

# Clean build artifacts
clean:
    cargo clean

# Show project stats
project-stats:
    @echo "Source:    $(find netring/src netring-flow/src -name '*.rs' | wc -l) files"
    @echo "Tests:     $(find netring/tests -name '*.rs' 2>/dev/null | wc -l) files"
    @echo "Examples:  $(find netring/examples -name '*.rs' 2>/dev/null | wc -l) files"
    @echo "Docs:      $(find docs -name '*.md' 2>/dev/null | wc -l) files"
    @echo "Lines:     $(find netring/src netring-flow/src netring/tests netring/examples netring/benches -name '*.rs' -exec cat {} + 2>/dev/null | wc -l) Rust"
    @cargo test --workspace --features tokio,channel 2>&1 | grep "test result" \
        | awk '{sum += $$4} END {print "Tests:     " sum " passing"}'
