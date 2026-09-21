#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Synapse 2.0 Regression Suites
# Part of Phase 6: Assurance & Parity
# Runs the in-process Synapse-to-Synapse integration suites. This is NOT an
# interoperability test against other BitTorrent clients (libtorrent, Transmission, ...).
# ==============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TEST_DIR="$(mktemp -d /tmp/synapse-interop-XXXXXX)"
cleanup() {
    echo ">>> Cleaning up background processes and test artifacts in ${TEST_DIR}..."
    kill $(jobs -p) 2>/dev/null || true
    rm -rf "${TEST_DIR}"
}
trap cleanup EXIT

echo "========================================================"
echo " Synapse in-process regression suites"
echo " Test Dir: ${TEST_DIR}"
echo "========================================================"

# 1. Compile synapse binaries and harness
echo ">>> Building Synapse test harnesses..."
cargo test -p synapse-engine --test hostile_peer_e2e --no-run
cargo test -p synapse-engine --test swarm_simulation_harness_test --no-run

# 2. Run in-process end-to-end wire integration suites
echo ""
echo ">>> Running in-process loopback wire transfer tests (TCP, MSE, BEP40, BEP10)..."
cargo test -p synapse-engine --test hostile_peer_e2e -- --nocapture

echo ""
echo ">>> Running multi-peer swarm simulation harness (choking, endgame, snubbing, smart-ban)..."
cargo test -p synapse-engine --test swarm_simulation_harness_test -- --nocapture

echo ""
echo ">>> Running uTP packet and selective-ack loopback verification..."
cargo test -p synapse-wire utp::tests -- --nocapture

echo ""
echo ">>> Running Message Stream Encryption (MSE RC4) handshake verification..."
cargo test -p synapse-wire crypto::tests -- --nocapture

echo ""
echo "========================================================"
echo " [SUCCESS] In-process regression suites passed (no third-party client was involved)"
echo "========================================================"
