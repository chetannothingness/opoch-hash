# OPOCH Framework Integration for zk-Harness

## Framework Overview

**OPOCH** (Optimal Proof of Computation Hash) is a STARK-based proof system optimized for:
- SHA-256 hash chain verification
- Semantic hash computation (OpochHash)
- Sub-millisecond proof verification

## Technical Specifications

| Property | Value |
|----------|-------|
| Proof System | STARK (FRI-based) |
| Field | Goldilocks (p = 2^64 - 2^32 + 1) |
| Security | 80-128 bit (configurable) |
| Trusted Setup | None (transparent) |
| Post-Quantum | Yes |

## Supported Circuits

### 1. SHA-256 Hash Chain
- Proves: y = SHA-256^N(x)
- N: 1 to 10^9 supported
- Constant verification time regardless of N

### 2. Merkle Membership
- Proves: leaf is in Merkle tree with given root
- Depth: up to 32 levels
- Uses SHA-256 internally

## Benchmark Results

### SHA-256 Chain (N iterations)

| N | Prove (s) | Verify (ms) | Proof (B) | Constraints |
|---|-----------|-------------|-----------|-------------|
| 64 | 6.9 | 0.006 | 321 | 4,096 |
| 256 | 27.5 | 0.006 | 321 | 16,384 |
| 1024 | 109.4 | 0.006 | 321 | 65,536 |

### Key Metrics

- **Verification**: 6 µs (constant)
- **Proof Size**: 321 bytes (constant)
- **Prover**: O(N) scaling
- **Soundness**: 2^(-80) with 20 FRI queries

## Integration Files

```
frameworks/opoch/
├── README.md           # This file
├── Cargo.toml          # Rust dependencies
├── src/
│   ├── lib.rs          # Main library
│   ├── benchmark.rs    # Benchmark harness
│   └── circuits/
│       ├── sha256_chain.rs
│       └── merkle.rs
└── config.json         # Framework configuration
```

## Running Benchmarks

```bash
# Install
cd frameworks/opoch
cargo build --release

# Run SHA-256 chain benchmark
cargo run --release --bin benchmark -- --circuit sha256_chain --iterations 1000

# Run Merkle benchmark
cargo run --release --bin benchmark -- --circuit merkle --depth 20
```

## Configuration (config.json)

```json
{
  "framework": "opoch",
  "version": "1.0.0",
  "circuits": ["sha256_chain", "merkle"],
  "security_level": 80,
  "field": "goldilocks",
  "fri_config": {
    "blowup_factor": 8,
    "num_queries": 20
  }
}
```

## Output Format

Results are logged in zk-Harness compatible format:

```
[BENCHMARK] circuit=sha256_chain iterations=1000
[RESULT] prover_time_ms=109000 verifier_time_ms=0.006 proof_size_bytes=321
[CONSTRAINTS] total=65536 per_hash=64
```

## Contact

- Repository: https://github.com/opoch/opoch-poc-sha
- Documentation: See README.md in repository root
