# netring justfile (single-crate workspace)
# Requires: just (https://github.com/casey/just)
#
# Integration tests and examples need AF_PACKET (CAP_NET_RAW).
# `just setcap` grants capabilities on compiled binaries via sudo,
# then tests/examples run as the current user (no sudo).
#
# Flow & session tracking lives in the separate `flowscope` crate
# (https://github.com/p13marc/flowscope). Pulled in via netring's
# `flow` feature; tests for it live in that repo.

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

# Run unit tests (no privileges needed)
test-unit:
    cargo test --workspace

# Run ALL tests including integration (run `just setcap` first)
test:
    cargo test -p netring --features "integration-tests,tokio,channel" -- --test-threads=1

# Run a specific test by name
test-one name:
    cargo test -p netring --features "integration-tests,tokio,channel" -- --test-threads=1 "{{name}}"

# Run integration tests only
test-integration:
    cargo test -p netring --features "integration-tests,tokio,channel" --test '*' -- --test-threads=1

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
async-xdp-busy *args:  cargo run -p netring --example async_xdp_busy_poll --features tokio,af-xdp -- {{args}}
async-metrics *args:   cargo run -p netring --example async_metrics --features tokio,metrics -- {{args}}
channel *args:      (example "channel_consumer" args)
ebpf *args:         (example "ebpf_filter" args)
dpi *args:          (example "dpi" args)
bridge *args:       (example "bridge" args)

# Flow tracking examples (require `flow` feature → flowscope)
flow-keys *args:     cargo run -p netring --example async_flow_keys --features tokio,parse -- {{args}}
flow-summary *args:  cargo run -p netring --example async_flow_summary --features tokio,flow -- {{args}}
flow-filter *args:   cargo run -p netring --example async_flow_filter --features tokio,flow -- {{args}}
flow-history *args:  cargo run -p netring --example async_flow_history --features tokio,flow -- {{args}}
flow-channel *args:  cargo run -p netring --example async_flow_channel --features tokio,flow -- {{args}}

# Loopback dedup demo (no privileges-by-default; needs setcap for live capture)
lo-dedup *args:      cargo run -p netring --example async_lo_dedup --features tokio -- {{args}}

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

# Build documentation
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

# Quick CI (no privileges): lint + unit tests + docs + bench compile
ci: clippy test-unit doc bench-check
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
    @echo "Source:    $(find netring/src -name '*.rs' | wc -l) files"
    @echo "Tests:     $(find netring/tests -name '*.rs' 2>/dev/null | wc -l) files"
    @echo "Examples:  $(find netring/examples -name '*.rs' 2>/dev/null | wc -l) files"
    @echo "Docs:      $(find docs -name '*.md' 2>/dev/null | wc -l) files"
    @echo "Lines:     $(find netring/src netring/tests netring/examples netring/benches -name '*.rs' -exec cat {} + 2>/dev/null | wc -l) Rust"
    @cargo test --workspace --features tokio,channel 2>&1 | grep "test result" \
        | awk '{sum += $$4} END {print "Tests:     " sum " passing"}'
