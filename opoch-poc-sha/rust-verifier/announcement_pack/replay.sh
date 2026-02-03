#!/bin/bash
# OPOCH-PoC-SHA Benchmark Replay Script
#
# This script reproduces the complete benchmark suite results.
# Run from the announcement_pack directory.

set -e

echo "=========================================="
echo "OPOCH-PoC-SHA Benchmark Replay"
echo "=========================================="
echo ""

# Move to project root
cd "$(dirname "$0")/.."

# Check Rust installation
if ! command -v cargo &> /dev/null; then
    echo "ERROR: Rust/Cargo not found. Please install from https://rustup.rs"
    exit 1
fi

echo "Step 1: Building project..."
echo "-------------------------------------------"
cargo build --release 2>&1 | tail -5
echo ""

echo "Step 2: Running tests..."
echo "-------------------------------------------"
TEST_OUTPUT=$(cargo test --release 2>&1)
TEST_RESULT=$?
echo "$TEST_OUTPUT" | grep -E "(test result|passed|failed)"
echo ""

if [ $TEST_RESULT -ne 0 ]; then
    echo "ERROR: Tests failed!"
    exit 1
fi

echo "Step 3: Running full benchmark suite..."
echo "-------------------------------------------"
cargo run --release --bin bench_full 2>&1
BENCH_RESULT=$?
echo ""

if [ $BENCH_RESULT -ne 0 ]; then
    echo "ERROR: Benchmark suite failed!"
    exit 1
fi

echo "Step 4: Verifying receipt chain..."
echo "-------------------------------------------"
if [ -f "announcement_pack/receipt_chain.json" ]; then
    echo "Receipt chain found. Checking integrity..."
    # Basic JSON validation
    if command -v python3 &> /dev/null; then
        python3 -c "
import json
import sys

with open('announcement_pack/receipt_chain.json', 'r') as f:
    chain = json.load(f)

receipts = chain.get('receipts', [])
print(f'  Receipts: {len(receipts)}')

all_pass = True
for r in receipts:
    if r.get('benchmark_id') != 'GENESIS':
        status = r.get('status', 'UNKNOWN')
        if status != 'Pass':
            all_pass = False
        print(f'    {r.get(\"benchmark_id\")}: {status}')

print(f'  All Pass: {all_pass}')
sys.exit(0 if all_pass else 1)
"
        VERIFY_RESULT=$?
    else
        echo "  (Python not available, skipping detailed verification)"
        VERIFY_RESULT=0
    fi
else
    echo "  Receipt chain not yet generated (run bench_full first)"
    VERIFY_RESULT=0
fi
echo ""

echo "Step 5: Checking report..."
echo "-------------------------------------------"
if [ -f "announcement_pack/report.json" ]; then
    echo "Report found."
    if command -v python3 &> /dev/null; then
        python3 -c "
import json
with open('announcement_pack/report.json', 'r') as f:
    report = json.load(f)
    verdict = report.get('verdict', {})
    print(f'  All Pass: {verdict.get(\"all_pass\", False)}')
    print(f'  Verification p95: {verdict.get(\"verification_p95_us\", \"N/A\")} us')
    print(f'  Soundness bits: {verdict.get(\"soundness_bits\", \"N/A\")}')
"
    fi
else
    echo "  Report not yet generated (run bench_full first)"
fi
echo ""

echo "=========================================="
echo "Replay Complete"
echo "=========================================="

# Summary
if [ $TEST_RESULT -eq 0 ] && [ $BENCH_RESULT -eq 0 ]; then
    echo "Status: SUCCESS"
    exit 0
else
    echo "Status: FAILED"
    exit 1
fi
