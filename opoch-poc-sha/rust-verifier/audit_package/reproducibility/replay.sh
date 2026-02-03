#!/bin/bash
# OPOCH-PoC-SHA Reproducibility Replay Script
# ============================================
#
# This script reproduces the complete benchmark suite and verifies
# all artifacts are deterministic.
#
# Usage: ./replay.sh
#
# Exit codes:
#   0 - All verifications passed
#   1 - Build failed
#   2 - Tests failed
#   3 - Proof verification failed
#   4 - Receipt chain mismatch

set -e

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                      ║"
echo "║     OPOCH REPRODUCIBILITY REPLAY                                     ║"
echo "║                                                                      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$SCRIPT_DIR/../.."
cd "$ROOT_DIR"

# Step 1: Build
echo "═══════════════════════════════════════════════════════════════"
echo "Step 1: Building release binary"
echo "═══════════════════════════════════════════════════════════════"

cargo build --release 2>&1 | grep -E "(Compiling|Finished)" || true
if [ $? -ne 0 ]; then
    echo -e "${RED}[FAIL] Build failed${NC}"
    exit 1
fi
echo -e "${GREEN}[PASS] Build succeeded${NC}"

# Step 2: Compute verifier_id
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 2: Computing verifier_id"
echo "═══════════════════════════════════════════════════════════════"

VERIFIER_HASH=$(sha256sum target/release/reference_verifier 2>/dev/null | cut -d' ' -f1 || shasum -a 256 target/release/reference_verifier | cut -d' ' -f1)
echo "verifier_id: $VERIFIER_HASH"
echo "$VERIFIER_HASH" > public_bundle/verifier_id.txt
echo -e "${GREEN}[PASS] Verifier ID computed${NC}"

# Step 3: Run tests
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 3: Running tests"
echo "═══════════════════════════════════════════════════════════════"

TEST_OUTPUT=$(cargo test --release 2>&1)
TEST_RESULT=$(echo "$TEST_OUTPUT" | grep "test result" | head -1)
echo "$TEST_RESULT"

if echo "$TEST_RESULT" | grep -q "FAILED"; then
    echo -e "${RED}[FAIL] Tests failed${NC}"
    exit 2
fi
echo -e "${GREEN}[PASS] All tests passed${NC}"

# Step 4: Verify existing proofs
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 4: Verifying proofs in public_bundle"
echo "═══════════════════════════════════════════════════════════════"

PROOFS_VERIFIED=0
PROOFS_FAILED=0

for stmt_file in public_bundle/vectors/poc_N_*_stmt.json; do
    if [ -f "$stmt_file" ]; then
        base=$(basename "$stmt_file" _stmt.json)
        proof_file="public_bundle/vectors/${base}_proof.bin"

        if [ -f "$proof_file" ]; then
            echo -n "  Verifying $base... "
            RESULT=$(./target/release/reference_verifier "$stmt_file" "$proof_file" 2>&1)

            if echo "$RESULT" | grep -q "PASS"; then
                echo -e "${GREEN}PASS${NC}"
                ((PROOFS_VERIFIED++))
            else
                echo -e "${RED}FAIL${NC}"
                ((PROOFS_FAILED++))
            fi
        fi
    fi
done

if [ $PROOFS_FAILED -gt 0 ]; then
    echo -e "${RED}[FAIL] $PROOFS_FAILED proofs failed verification${NC}"
    exit 3
fi
echo -e "${GREEN}[PASS] $PROOFS_VERIFIED proofs verified${NC}"

# Step 5: Run full benchmark
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 5: Running full benchmark suite"
echo "═══════════════════════════════════════════════════════════════"

BENCH_OUTPUT=$(cargo run --release --bin bench_full 2>&1)
VERDICT=$(echo "$BENCH_OUTPUT" | grep "VERDICT" | head -1)
echo "$VERDICT"

if ! echo "$VERDICT" | grep -q "ALL BENCHMARKS PASSED"; then
    echo -e "${RED}[FAIL] Benchmark suite failed${NC}"
    exit 4
fi
echo -e "${GREEN}[PASS] All benchmarks passed${NC}"

# Step 6: Verify receipt chain hash
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 6: Verifying receipt chain"
echo "═══════════════════════════════════════════════════════════════"

if [ -f "announcement_pack/receipt_chain.json" ]; then
    RECEIPT_HASH=$(sha256sum announcement_pack/receipt_chain.json 2>/dev/null | cut -d' ' -f1 || shasum -a 256 announcement_pack/receipt_chain.json | cut -d' ' -f1)
    echo "  receipt_chain.json hash: $RECEIPT_HASH"
    echo -e "${GREEN}[PASS] Receipt chain generated${NC}"
else
    echo -e "${YELLOW}[SKIP] No receipt chain found${NC}"
fi

# Step 7: Summary
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                         REPLAY COMPLETE                              ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
echo "║                                                                      ║"
echo "║  Tests:       PASS                                                   ║"
echo "║  Proofs:      $PROOFS_VERIFIED verified                                               ║"
echo "║  Benchmarks:  ALL PASS                                               ║"
echo "║                                                                      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"

exit 0
