# OPOCH-PoC-SHA: Complete Benchmark Championship Plan

## Executive Summary

This plan establishes OPOCH-PoC-SHA as the definitive benchmark leader for verifiable computation. No shortcuts. Complete implementation.

---

## Phase 1: Standardized Computation Benchmarks

### 1.1 SHA-256 Hash Chain (CURRENT - EXTEND)

**Status:** ✅ Implemented (1B iterations, ~78µs verification on Apple M4)

**Extensions needed:**
```
Benchmark points:
- 1K iterations (baseline)
- 1M iterations (standard comparison point)
- 1B iterations (current showcase)
- 10B iterations (extreme scale)

Metrics to capture:
- Prover time (total, per-hash)
- Verifier time (total, per-verification)
- Proof size (bytes, bytes/iteration)
- Memory usage (peak, average)
- Throughput (hashes/second proved)
```

### 1.2 Merkle Tree Verification

**Implementation plan:**

```rust
// merkle_bench.rs

/// Prove Merkle path verification for depths 20, 24, 28, 32
/// Each proof shows: "I verified a Merkle path correctly"

struct MerkleBenchmark {
    tree_depth: usize,      // 20, 24, 28, 32
    num_verifications: usize, // 1, 100, 10000
}

// AIR constraints for Merkle verification:
// 1. Hash consistency: H(left || right) = parent
// 2. Path consistency: sibling selection matches index bits
// 3. Root matches claimed root

// Trace structure:
// | level | node_hash | sibling | is_right | parent |
```

**Benchmark matrix:**
| Depth | Leaves | Use Case |
|-------|--------|----------|
| 20 | 1M | Small blockchain state |
| 24 | 16M | Medium state |
| 28 | 256M | Large state |
| 32 | 4B | Ethereum-scale |

### 1.3 ECDSA/EdDSA Signature Verification

**This is the "hard" benchmark - must nail it.**

```rust
// ecdsa_bench.rs

/// Prove ECDSA signature verification
/// Curve: secp256k1 (Bitcoin/Ethereum standard)

// AIR constraints needed:
// 1. Field arithmetic (256-bit) in Goldilocks
// 2. Point addition/doubling
// 3. Scalar multiplication
// 4. Final comparison

// Estimated trace width: 64+ columns
// Estimated rows per verification: ~10,000

// Also implement EdDSA (Ed25519) for comparison
// EdDSA is cleaner in circuits (no modular inverse)
```

**Benchmark targets:**
| Operation | Target Prove Time | Target Verify Time |
|-----------|-------------------|-------------------|
| 1 ECDSA verify | < 1 second | < 1 ms |
| 100 ECDSA verify | < 30 seconds | < 1 ms |
| 1 EdDSA verify | < 500 ms | < 1 ms |
| 100 EdDSA verify | < 15 seconds | < 1 ms |

### 1.4 Keccak-256 (Ethereum Compatibility)

**Critical for Ethereum ecosystem credibility.**

```rust
// keccak_bench.rs

/// Prove Keccak-256 hash computation
/// This is NOT SHA-3, it's the Ethereum variant

// Keccak-f[1600] permutation:
// - 24 rounds
// - 5 step mappings per round (θ, ρ, π, χ, ι)
// - 1600-bit state (5×5×64)

// AIR constraints:
// - State transition per round
// - XOR, rotation, AND operations
// - Padding verification

// Estimated trace: 200+ columns, 24 rows per hash
```

**Benchmark targets:**
| Operation | Target Prove Time | Target Verify Time |
|-----------|-------------------|-------------------|
| 1 Keccak-256 | < 100 ms | < 1 ms |
| 1K Keccak chain | < 60 seconds | < 1 ms |
| 1M Keccak chain | < 2 hours | < 1 ms |

### 1.5 Fibonacci Sequence

**Simple baseline - easy to verify correctness.**

```rust
// fibonacci_bench.rs

/// Prove Fibonacci computation: F(n) for large n
/// F(0) = 0, F(1) = 1, F(n) = F(n-1) + F(n-2)

// AIR is trivial:
// Trace: | step | F_prev | F_curr |
// Constraint: next.F_prev = curr.F_curr
//            next.F_curr = curr.F_prev + curr.F_curr

// Field: Goldilocks (results mod p)
```

**Benchmark points:**
| n | Steps | Expected Prove | Expected Verify |
|---|-------|----------------|-----------------|
| 2^20 | 1M | ~10 seconds | < 1 ms |
| 2^24 | 16M | ~2 minutes | < 1 ms |
| 2^28 | 256M | ~30 minutes | < 1 ms |

---

## Phase 2: Scaling Curves

### 2.1 Comprehensive Scaling Analysis

**Generate data for N = 2^10, 2^14, 2^18, 2^22, 2^26, 2^30**

```rust
// scaling_bench.rs

struct ScalingPoint {
    n: u64,
    prover_time_ms: f64,
    verifier_time_us: f64,
    proof_size_bytes: usize,
    memory_peak_mb: f64,
}

fn run_scaling_suite() -> Vec<ScalingPoint> {
    let ns = [
        1 << 10,   // 1K
        1 << 14,   // 16K
        1 << 18,   // 256K
        1 << 22,   // 4M
        1 << 26,   // 64M
        1 << 30,   // 1B
    ];

    ns.iter().map(|&n| benchmark_at_scale(n)).collect()
}
```

**Expected asymptotic behavior:**
```
Prover:   O(N log N) - FFT-dominated
Verifier: O(log² N)  - FRI query-dominated
Proof:    O(log² N)  - Merkle paths + FRI layers
```

**Visualization outputs:**
1. Log-log plot of prover time vs N
2. Verifier time vs N (should be nearly flat)
3. Proof size vs N (should be logarithmic)
4. Memory usage vs N

### 2.2 Asymptotic Verification

```python
# verify_asymptotics.py

import numpy as np
from scipy.optimize import curve_fit

def n_log_n(x, a, b):
    return a * x * np.log2(x) + b

def log_squared(x, a, b):
    return a * (np.log2(x) ** 2) + b

# Fit prover times to O(N log N)
# Fit verifier times to O(log² N)
# Report R² values to prove claims
```

---

## Phase 3: Apples-to-Apples Comparisons

### 3.1 Comparison Framework

**Same machine. Same computation. Same security level.**

```rust
// comparison_harness.rs

trait ProvingSystem {
    fn name(&self) -> &str;
    fn prove_sha256_chain(&self, n: usize) -> (Duration, Vec<u8>);
    fn verify(&self, proof: &[u8]) -> (Duration, bool);
    fn security_bits(&self) -> usize;
}

// Implementations for each system:
// - OPOCH-PoC-SHA (ours)
// - Plonky2 (via FFI or subprocess)
// - Plonky3 (via FFI or subprocess)
// - RISC Zero (via SDK)
// - SP1 (via SDK)
// - Stone (via subprocess)
```

### 3.2 Competitor Integration

**Plonky2:**
```toml
# Cargo.toml additions
[dependencies]
plonky2 = "0.2"
plonky2_field = "0.2"
```

**RISC Zero:**
```toml
[dependencies]
risc0-zkvm = "0.21"
```

**SP1:**
```toml
[dependencies]
sp1-sdk = "1.0"
```

**Stone (StarkWare):**
```bash
# Build Stone prover
git clone https://github.com/starkware-libs/stone-prover
cd stone-prover && bazel build //...
```

### 3.3 Standardized Test Circuit

**Every system proves the same computation:**

```
CIRCUIT: SHA-256 chain of length 10,000

Input: seed = SHA-256("benchmark_seed_v1")
Output: h_10000 = SHA-256^10000(seed)

Security: 128 bits minimum
```

**Comparison metrics:**
| Metric | How to Compare |
|--------|----------------|
| Prover time | Wall clock, same machine |
| Verifier time | Wall clock, same machine |
| Proof size | Bytes |
| Memory usage | Peak RSS |
| Setup time | If applicable |
| Trusted setup | Yes/No |

### 3.4 Fair Comparison Protocol

1. **Same hardware** - Run all on identical AWS instance
2. **Same security** - Normalize to 128-bit security
3. **Same computation** - Identical circuit/program
4. **Same conditions** - Cold start, no caching
5. **Multiple runs** - Report median of 10 runs
6. **Open methodology** - Publish all scripts

---

## Phase 4: Hardware Matrix

### 4.1 Target Platforms

| Platform | Instance/Device | Why |
|----------|-----------------|-----|
| Apple M1 | MacBook Air M1 | Developer standard |
| Apple M2 | MacBook Pro M2 | Developer premium |
| AWS ARM | c7g.xlarge | Cloud ARM |
| AWS x86 | c7i.xlarge | Cloud Intel |
| Consumer x86 | i7-12700H laptop | Accessibility |
| Consumer AMD | Ryzen 7 5800X | AMD coverage |

### 4.2 Benchmark Script

```bash
#!/bin/bash
# run_hardware_matrix.sh

PLATFORMS=(
    "m1_mac"
    "m2_mac"
    "aws_c7g"
    "aws_c7i"
    "consumer_intel"
    "consumer_amd"
)

BENCHMARKS=(
    "sha256_1m"
    "sha256_1b"
    "merkle_d28"
    "ecdsa_100"
    "keccak_1k"
    "fibonacci_2_24"
)

for platform in "${PLATFORMS[@]}"; do
    for bench in "${BENCHMARKS[@]}"; do
        echo "Running $bench on $platform..."
        ./run_benchmark.sh $platform $bench >> results/$platform/$bench.json
    done
done
```

### 4.3 Output Format

```json
{
  "platform": "aws_c7g.xlarge",
  "cpu": "AWS Graviton3",
  "cores": 4,
  "memory_gb": 8,
  "benchmark": "sha256_chain_1b",
  "runs": [
    {
      "run_id": 1,
      "prover_time_ms": 163000,
      "verifier_time_us": 5.2,
      "proof_size_bytes": 150000,
      "peak_memory_mb": 2400
    }
  ],
  "median_prover_ms": 163500,
  "median_verifier_us": 5.1,
  "timestamp": "2026-02-02T12:00:00Z"
}
```

---

## Phase 5: Security Validation

### 5.1 Third-Party Audit

**Target firms (in order of preference):**
1. Trail of Bits - Gold standard for ZK audits
2. Zellic - Strong cryptography team
3. OtterSec - Blockchain focused
4. Veridise - Formal verification expertise

**Audit scope:**
```
1. Cryptographic primitives
   - SHA-256 implementation correctness
   - Field arithmetic correctness
   - FRI protocol implementation

2. AIR constraint soundness
   - Transition constraints complete
   - Boundary constraints binding
   - No constraint gaps

3. Security parameter validation
   - 136-bit soundness claim
   - No weak randomness
   - Proper domain separation

4. Implementation security
   - No timing side channels
   - Memory safety (Rust helps)
   - Input validation
```

**Budget estimate:** $50K - $150K depending on scope

### 5.2 Published Test Vectors

```json
// test_vectors_v1.json
{
  "version": "1.0.0",
  "sha256_fips": [...],      // Already have
  "chain_vectors": [...],    // Already have
  "field_vectors": [
    {
      "op": "mul",
      "a": "0x123...",
      "b": "0x456...",
      "result": "0x789..."
    }
  ],
  "fri_vectors": [
    {
      "polynomial_degree": 1024,
      "evaluations": [...],
      "commitments": [...],
      "queries": [...],
      "expected_valid": true
    }
  ],
  "proof_vectors": [
    {
      "input": "test",
      "n": 1000,
      "d0": "0x...",
      "y": "0x...",
      "proof_hex": "0x...",
      "expected_valid": true
    }
  ]
}
```

### 5.3 Formal Verification

**Scope:**
1. Field arithmetic in Goldilocks
2. SHA-256 round function
3. Merkle path verification

**Tools:**
- Lean 4 / Mathlib for mathematical proofs
- Kani for Rust verification
- Coq for critical lemmas

**Deliverables:**
```lean
-- field_arithmetic.lean

theorem goldilocks_mul_correct :
  ∀ (a b : Fp), (a * b).val = (a.val * b.val) % p := by
  ...

theorem fri_soundness :
  ∀ (poly : Polynomial Fp) (proof : FriProof),
    verify_fri proof → degree poly < max_degree ∨
    prob_accept < 2^(-136) := by
  ...
```

---

## Phase 6: Implementation Timeline

### Week 1-2: Foundation
- [ ] Set up benchmark harness infrastructure
- [ ] Implement Fibonacci AIR (simplest, validates framework)
- [ ] Run initial scaling tests on SHA-256

### Week 3-4: Merkle & Keccak
- [ ] Implement Merkle tree verification AIR
- [ ] Implement Keccak-256 AIR
- [ ] Initial benchmarks for both

### Week 5-6: ECDSA (Hard Part)
- [ ] Implement 256-bit field emulation in Goldilocks
- [ ] Implement secp256k1 point operations
- [ ] Implement ECDSA verification AIR
- [ ] Optimize for performance

### Week 7-8: Competitor Integration
- [ ] Integrate Plonky2
- [ ] Integrate RISC Zero
- [ ] Integrate SP1
- [ ] Run comparison suite

### Week 9-10: Hardware Matrix
- [ ] Set up all target platforms
- [ ] Run full benchmark suite on each
- [ ] Generate comparison reports

### Week 11-12: Security & Polish
- [ ] Generate comprehensive test vectors
- [ ] Begin formal verification
- [ ] Prepare audit documentation
- [ ] Write final benchmark report

---

## Phase 7: Deliverables

### 7.1 Code
```
opoch-poc-sha/
├── benches/
│   ├── sha256_scaling.rs
│   ├── merkle_bench.rs
│   ├── keccak_bench.rs
│   ├── ecdsa_bench.rs
│   ├── fibonacci_bench.rs
│   └── comparison_harness.rs
├── competitors/
│   ├── plonky2_wrapper/
│   ├── risc0_wrapper/
│   ├── sp1_wrapper/
│   └── stone_wrapper/
└── results/
    ├── scaling/
    ├── hardware/
    └── comparisons/
```

### 7.2 Reports
1. **Scaling Analysis Report** (PDF)
   - Asymptotic verification
   - Log-log plots
   - Statistical analysis

2. **Competitor Comparison Report** (PDF)
   - Fair comparison methodology
   - Head-to-head results
   - Analysis of trade-offs

3. **Hardware Performance Report** (PDF)
   - Platform-specific results
   - Optimization recommendations
   - Cloud cost analysis

### 7.3 Interactive Dashboard
```
https://benchmarks.opoch.io/

Features:
- Real-time benchmark results
- Interactive scaling plots
- Hardware comparison tool
- Reproducibility instructions
```

---

## Success Criteria

### Must Achieve
- [ ] SHA-256 chain: Fastest verification for N > 10^6
- [ ] All benchmarks reproducible by third parties
- [ ] Clear asymptotic advantages demonstrated
- [ ] At least one third-party audit initiated

### Should Achieve
- [ ] ECDSA verification competitive with specialized systems
- [ ] Keccak performance within 2x of SHA-256
- [ ] Formal verification of core primitives

### Nice to Have
- [ ] Full audit completed
- [ ] Interactive benchmark dashboard live
- [ ] Integration with major frameworks (Foundry, Hardhat)

---

## Zero Budget Approach

### ALL FREE - No Money Required

| Need | Free Solution |
|------|---------------|
| **Cloud Compute** | GitHub Actions (2000+ free minutes/month), GitLab CI, or local machine |
| **Hardware Matrix** | Community contributions + free tier cloud (Oracle Free Tier, GCP Free) |
| **Security Audit** | Self-audit + community review + bug bounty via reputation |
| **Formal Verification** | Open source tools (Lean 4, Kani, Coq) - all free |
| **Competitor Comparison** | All open source (Plonky2, RISC Zero, SP1) |
| **Dashboard** | GitHub Pages (free) + static site |

### Free Resources to Use

**Compute:**
```
1. GitHub Actions - 2000 min/month free (Linux)
2. GitLab CI - 400 min/month free
3. Oracle Cloud Free Tier - 4 ARM cores FOREVER FREE
4. Google Cloud Free Tier - $300 credits for 90 days
5. Local machine - Your own hardware
```

**Hardware Matrix (Community-Sourced):**
```
1. Post benchmarks script
2. Ask community to run on their hardware
3. Collect results via GitHub Issues/Discussions
4. Aggregate into report

Platforms covered for FREE:
- M1/M2 Macs (community devs have these)
- Linux x86 (everyone has access)
- ARM (Oracle free tier, Raspberry Pi)
- Windows (community)
```

**Security Validation (Free):**
```
1. Self-audit with detailed documentation
2. Public code review (open source)
3. Crypto Twitter review (tag researchers)
4. Academic review (post to ePrint/arXiv)
5. Bug bounty via reputation (Hall of Fame)
6. Formal verification with free tools:
   - Lean 4 (free, open source)
   - Kani (free, Rust verifier by AWS)
   - Coq (free, open source)
```

**Competitor Benchmarks (All Open Source):**
```
Plonky2 - MIT License, free
Plonky3 - MIT License, free
RISC Zero - Apache 2.0, free
SP1 - MIT License, free
Stone - Apache 2.0, free
```

### Revised Timeline (Self-Funded)

| Week | Task | Resources |
|------|------|-----------|
| 1-2 | Fibonacci + Scaling benchmarks | Local machine |
| 3-4 | Merkle tree AIR | Local machine |
| 5-6 | Keccak-256 AIR | Local machine |
| 7-8 | ECDSA AIR (hardest) | Local machine |
| 9-10 | Competitor integration | GitHub Actions |
| 11-12 | Community hardware matrix | Community contributions |

### Community-Powered Validation

**Instead of paid audit, do:**

1. **Publish Everything**
   - Full source code (done ✅)
   - Complete math spec (done ✅)
   - Test vectors (done ✅)

2. **Invite Review**
   - Post on r/crypto, r/rust
   - Tag ZK researchers on Twitter
   - Submit to academic cryptography mailing lists
   - Post on Ethereum Research forum

3. **Bug Bounty (Reputation-Based)**
   ```
   OPOCH-PoC-SHA Security Hall of Fame

   Found a bug? Get credited:
   - Critical: Named in README + paper acknowledgment
   - High: Named in CONTRIBUTORS.md
   - Medium: Named in release notes
   ```

4. **Formal Verification (DIY)**
   ```lean
   -- We write the proofs ourselves using free tools
   -- Lean 4 + Mathlib for field arithmetic
   -- Kani for Rust code verification
   -- All open source, all free
   ```

### GitHub Actions Benchmark Workflow

```yaml
# .github/workflows/benchmarks.yml
name: Benchmark Suite

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Run benchmarks
        run: |
          cargo bench --release
          cargo run --release --bin e2e

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: results/

      - name: Update benchmark page
        run: |
          # Generate markdown report
          ./scripts/generate_report.sh > docs/BENCHMARKS.md

  competitor-comparison:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup competitors
        run: |
          # All free, open source
          cargo install plonky2
          # RISC Zero
          curl -L https://risczero.com/install | bash

      - name: Run comparisons
        run: ./scripts/compare_all.sh
```

### Free Dashboard (GitHub Pages)

```
https://[username].github.io/opoch-poc-sha/benchmarks/

Built with:
- GitHub Pages (free)
- Chart.js (free)
- Static HTML/CSS/JS
- Auto-updated via GitHub Actions
```

---

## Total Cost: $0

| Item | Solution | Cost |
|------|----------|------|
| Compute | GitHub Actions + Oracle Free | $0 |
| Hardware testing | Community sourced | $0 |
| Security audit | Community review + self-audit | $0 |
| Formal verification | Lean 4 / Kani (open source) | $0 |
| Competitors | All open source | $0 |
| Dashboard | GitHub Pages | $0 |
| **TOTAL** | | **$0** |

---

*This plan establishes OPOCH-PoC-SHA as the benchmark champion through rigorous, reproducible methodology - completely free.*
