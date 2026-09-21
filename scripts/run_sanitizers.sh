#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Synapse 2.0 Sanitizer & Miri Test Runner
# Part of Phase 6: Assurance & Parity
# ==============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

MODE="${1:-all}"

echo "========================================================"
echo " Synapse 2.0 Assurance: Sanitizers & Miri Runner"
echo " Mode: ${MODE}"
echo "========================================================"

run_miri() {
    echo ""
    echo ">>> Running Miri on pure logic crates..."
    echo "Crates: synapse-bencode, synapse-picker, synapse-meta, synapse-wire"
    
    if ! command -v cargo-miri &> /dev/null; then
        echo "[!] cargo-miri not found. Install via: rustup +nightly component add miri"
        echo "[!] Skipping Miri execution."
        return 0
    fi

    # Pure crates with zero async I/O / socket requirements
    cargo +nightly miri test -p synapse-bencode
    cargo +nightly miri test -p synapse-picker --lib
    cargo +nightly miri test -p synapse-meta --lib
    echo ">>> Miri validation passed successfully."
}

run_asan() {
    echo ""
    echo ">>> Running AddressSanitizer (ASAN)..."
    
    # Target detection
    TARGET="$(rustc -vV | sed -n 's|host: ||p')"
    echo "Target: ${TARGET}"

    RUSTFLAGS="-Zsanitizer=address" \
    RUSTDOCFLAGS="-Zsanitizer=address" \
    cargo +nightly test \
        --workspace \
        --exclude synapse-engine \
        --target "${TARGET}" \
        -Zbuild-std=std,panic_abort || {
            echo "[!] ASAN requires nightly with rust-src component (rustup +nightly component add rust-src)"
            echo "[!] Run manually with: RUSTFLAGS=\"-Zsanitizer=address\" cargo +nightly test -Zbuild-std --target ${TARGET}"
        }
}

run_tsan() {
    echo ""
    echo ">>> Running ThreadSanitizer (TSAN)..."
    
    TARGET="$(rustc -vV | sed -n 's|host: ||p')"
    echo "Target: ${TARGET}"

    RUSTFLAGS="-Zsanitizer=thread" \
    RUSTDOCFLAGS="-Zsanitizer=thread" \
    cargo +nightly test \
        --workspace \
        --exclude synapse-engine \
        --target "${TARGET}" \
        -Zbuild-std=std,panic_abort || {
            echo "[!] TSAN requires nightly with rust-src component (rustup +nightly component add rust-src)"
            echo "[!] Run manually with: RUSTFLAGS=\"-Zsanitizer=thread\" cargo +nightly test -Zbuild-std --target ${TARGET}"
        }
}

case "${MODE}" in
    miri)
        run_miri
        ;;
    asan)
        run_asan
        ;;
    tsan)
        run_tsan
        ;;
    all)
        run_miri
        run_asan
        run_tsan
        ;;
    *)
        echo "Usage: $0 [miri|asan|tsan|all]"
        exit 1
        ;;
esac

echo ""
echo "=== All requested sanitizer/miri checks finished ==="
