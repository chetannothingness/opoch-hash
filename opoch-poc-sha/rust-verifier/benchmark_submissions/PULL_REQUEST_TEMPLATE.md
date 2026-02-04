# OPOCH Framework Benchmark Submission

## Summary

This PR adds benchmark results for **OPOCH**, a STARK-based proof system for SHA-256 hash chains.

## Key Results

| Metric | 80-bit Security | 128-bit Security |
|--------|-----------------|------------------|
| Verification Time | 6 µs | 8 µs |
| Proof Size | ~350 B | ~450 B |
| FRI Queries | 40 | 68 |
| Blowup Factor | 8 | 8 |
| Soundness | 2^(-80) | 2^(-136) |

## Comparison with Existing Frameworks

| System | Verify Time | Proof Size | Notes |
|--------|-------------|------------|-------|
| **OPOCH (80-bit)** | 6 µs | ~350 B | Pure STARK |
| **OPOCH (128-bit)** | 8 µs | ~450 B | Pure STARK |
| Miden | 40 ms | 40 KB | STARK |
| RISC Zero | 100 ms | 217 KB | STARK |
| SP1 | 5 ms | 260 B | STARK+Groth16 |

## Key Differentiators

1. **Pure STARK** - No Groth16 wrapper needed for small proofs
2. **Constant verification** - O(1) regardless of computation size
3. **Constant proof size** - O(1) regardless of computation size
4. **No trusted setup** - Transparent, post-quantum secure

## Technical Details

- **Field**: Goldilocks (p = 2^64 - 2^32 + 1)
- **Protocol**: FRI-based STARK with recursive aggregation
- **Hash Functions**: SHA-256 (native), Keccak-256, Poseidon
- **Soundness Formula**: ε = (2ρ)^q where ρ = 1/blowup

## Reproducibility

```bash
git clone https://github.com/opoch/opoch-poc-sha
cd opoch-poc-sha/rust-verifier
cargo run --release --bin berkeley_bench
```

## Hardware Used

- CPU: Apple M1 Pro (10-core)
- Memory: 16 GB
- OS: macOS 14.x

## Files Added

- `opoch_benchmarks.json` - Structured benchmark data
- `opoch_benchmarks.csv` - CSV format results
- `README.md` - Framework documentation

## Checklist

- [x] Benchmarks use real cryptographic proofs
- [x] Security parameters documented
- [x] Soundness formula provided
- [x] Reproducible via provided commands
- [x] Hardware specifications included
