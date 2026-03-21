# netring justfile
# Requires: just (https://github.com/casey/just)
#
# Integration tests and examples need AF_PACKET (CAP_NET_RAW).
# On bare metal: `just test` uses sudo setcap.
# In containers: AF_PACKET may be blocked — use `just test-unit` instead,
# or run the container with `--cap-add=NET_RAW --cap-add=NET_ADMIN`.

set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# ── Build ───────────────────────────────────────────────────────────────────

# Build the library
build:
    cargo build

# Build in release mode
build-release:
    cargo build --release --all-targets

# Build all examples
build-examples:
    cargo build --examples --features tokio,channel

# ── Test ────────────────────────────────────────────────────────────────────

# Run unit tests only (no privileges needed)
test-unit:
    cargo test

# Run ALL tests including integration tests
# On bare metal: uses sudo for CAP_NET_RAW
# In containers: needs --cap-add=NET_RAW,NET_ADMIN
test:
    sudo -E cargo test --features "integration-tests,tokio,channel" -- --test-threads=1

# Run a specific test by name
test-one name:
    sudo -E cargo test --features "integration-tests,tokio,channel" -- --test-threads=1 "{{name}}"

# Run integration tests only
test-integration:
    sudo -E cargo test --features "integration-tests,tokio,channel" --test '*' -- --test-threads=1

# Check if AF_PACKET is available (useful in containers)
check-afpacket:
    #!/usr/bin/env bash
    if sudo python3 -c "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)).close()" 2>/dev/null; then
        echo "✓ AF_PACKET available"
    else
        echo "✗ AF_PACKET not available"
        echo "  If in a container, run with: --cap-add=NET_RAW --cap-add=NET_ADMIN"
        echo "  If on bare metal, check: sudo capsh --print | grep net_raw"
        exit 1
    fi

# ── Examples ────────────────────────────────────────────────────────────────

# Run an example with sudo (needs CAP_NET_RAW)
example name *args:
    sudo -E cargo run --example "{{name}}" --features tokio,channel -- {{args}}

# Shorthand recipes for each example
capture *args:      (example "capture" args)
batch *args:        (example "batch_processing" args)
inject *args:       (example "inject" args)
fanout *args:       (example "fanout" args)
stats *args:        (example "stats_monitor" args)
low-latency *args:  (example "low_latency" args)
async *args:        (example "async_capture" args)
channel *args:      (example "channel_consumer" args)

# ── Lint & Format ───────────────────────────────────────────────────────────

# Run clippy with all features
clippy:
    cargo clippy --all-targets --all-features -- --deny warnings

# Check formatting
fmt-check:
    cargo fmt -- --check

# Format code
fmt:
    cargo fmt

# ── Docs ────────────────────────────────────────────────────────────────────

# Build documentation
doc:
    cargo doc --all-features --no-deps

# Build and open documentation in browser
doc-open:
    cargo doc --all-features --no-deps --open

# ── Bench ───────────────────────────────────────────────────────────────────

# Run benchmarks
bench:
    cargo bench

# Verify benchmarks compile
bench-check:
    cargo bench --no-run

# ── CI ──────────────────────────────────────────────────────────────────────

# Quick CI (no privileges): lint + unit tests + docs + bench compile
ci: clippy test-unit doc bench-check
    @echo "✓ CI checks passed"

# Full CI (needs sudo/CAP_NET_RAW): lint + ALL tests + docs + bench
ci-full: clippy test doc bench-check
    @echo "✓ Full CI checks passed"

# ── Utility ─────────────────────────────────────────────────────────────────

# Clean build artifacts
clean:
    cargo clean

# Show project stats
project-stats:
    @echo "Source:    $(find src -name '*.rs' | wc -l) files"
    @echo "Tests:     $(find tests -name '*.rs' | wc -l) files"
    @echo "Examples:  $(find examples -name '*.rs' | wc -l) files"
    @echo "Docs:      $(find docs -name '*.md' | wc -l) files"
    @echo "Lines:     $(find src tests examples benches -name '*.rs' -exec cat {} + | wc -l) Rust"
    @cargo test --features tokio,channel 2>&1 | grep "test result" \
        | awk '{sum += $$4} END {print "Tests:     " sum " passing"}'
