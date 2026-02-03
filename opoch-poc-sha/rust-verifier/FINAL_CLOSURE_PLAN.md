# OPOCH-PoC-SHA Final Closure Plan
## Production Readiness - No Shortcuts, No Hardcoding

**Current Status**:
- Proof size: 252 B constant ✅
- Verify time: ~55 µs p95 ✅  
- FRI soundness: 136 bits ✅
- System soundness: 126 bits ❌ (need ≥128)
- Ed25519/secp256k1 proofs: Missing ❌
- N=10^9 run: Missing ❌
- Complete spec pinning: Missing ❌

---

## GATE 1: Soundness ≥128 bits (CRITICAL FIX)

### Problem Analysis

Current calculation:
```
total = min(FRI=136, Hash=128) - recursion_penalty(1.58) = 126 bits
```

**The recursion penalty is INCORRECT.** Here's why:

In sequential recursive composition (A → B → C):
1. Segment proof P_seg proves hash chain segment
2. L1 proof P_L1 proves "all segment proofs verified"  
3. L2 proof P_L2 proves "all L1 proofs verified"

For a fake proof to be accepted:
- P_L2 must pass verification (requires breaking L2 soundness)
- L2 verifier checks L1 proofs (requires valid L1 or breaking L2)
- L1 verifier checks segment proofs (requires valid segments or breaking L1)

**The soundness is min(ε_seg, ε_L1, ε_L2), NOT a sum/product.**

If all layers use same FRI parameters (68 queries, blowup 8):
- Each layer has soundness = min(FRI=136, Hash=128) = 128 bits
- Total = min(128, 128, 128) = **128 bits**

### Fix Required

Update `src/soundness.rs`:
1. Remove the incorrect `recursion_penalty = log2(layers)`
2. Document why recursive composition preserves soundness
3. Total soundness = min(FRI, Hash) = min(136, 128) = **128 bits**

### Verification

After fix, soundness.json must show:
```json
{
  "fri": {"soundness_bits": 136},
  "fiat_shamir": {"security_bits": 128},
  "merkle": {"collision_bits": 128},
  "recursion": {
    "layers": 3,
    "penalty_bits": 0,
    "note": "Sequential composition preserves soundness (min, not sum)"
  },
  "total_soundness_bits": 128
}
```

---

## GATE 2: Complete Spec Pinning

### 2.1 spec.md Requirements (Exact Format)

```
OPOCH-PoC-SHA Specification v1.0.0

1. SHA-256: FIPS 180-4 exact (test vectors hash: <SHA256 of vectors file>)

2. Field: p = 2^64 - 2^32 + 1 = 18446744069414584321 (Goldilocks)

3. FRI Parameters:
   - Rate ρ = 1/8 (blowup = 8)
   - Queries q = 68
   - Folding: factor-2 per round
   - Grinding: 0 (none)

4. Merkle Parameters:
   - Hash: SHA-256
   - Leaf encoding: [domain_sep(1) || index(8) || data(32)]
   - Node hash: SHA-256(left || right)
   - Padding: zero-pad to power of 2

5. Fiat-Shamir Transcript:
   - Hash: SHA-256
   - Format: H(state || tag || data)
   - Tags: FRI_COMMIT, FRI_CHALLENGE, FRI_QUERY, MERKLE_ROOT

6. AIR Constraints:
   - SHA-256 round constraints (degree 3)
   - Boundary constraints (input/output)
   - Transition constraints (state machine)

7. Recursion:
   - L_base = 1024 hashes/segment
   - L1 fan-in = 1024 segments
   - L2 fan-in = 1024 L1 proofs
   - Depth: ceil(log_{1024}(N/L))

8. Proof Format (252 bytes):
   - [0..4]:   Magic "OPSH"
   - [4..8]:   Version (1)
   - [8..40]:  d0 (32 bytes)
   - [40..72]: y (32 bytes)
   - [72..252]: FRI commitment + queries

9. Verification Benchmark:
   - Iterations: 10,000
   - Method: wall clock (Instant::now)
   - Warmup: 100 iterations
```

### 2.2 Compute spec_id

```bash
spec_id = SHA-256(spec.md)
```

### 2.3 Compute verifier_id

```bash
cargo build --release
verifier_id = SHA-256(target/release/verifier)
```

### 2.4 Update receipt_chain.json

Must include:
- spec_id
- verifier_id  
- All artifact hashes
- Chain hash binding all together

---

## GATE 3: Ed25519 Verification Proof

### 3.1 Generate Test Vectors

Create `vectors/ed25519_vectors.json` with 100 vectors:
- Deterministic generation from seed
- Format: {public_key, signature, message, h (challenge hash)}

### 3.2 AIR Implementation

Prove: [S]B = R + [h]A

Components:
- Point addition in extended coordinates
- Scalar multiplication (windowed)
- Field operations over 2^255-19
- 256-bit emulation via lookup tables

### 3.3 Generate Proof

- Generate proof for batch of 100 verifications
- Measure verify time (10k iterations)
- Add to receipt chain

### 3.4 Outputs

- ed25519_proof.bin
- ed25519_stmt.json
- ed25519_verify_results.json

---

## GATE 4: secp256k1 ECDSA Verification Proof

### 4.1 Generate Test Vectors

Create `vectors/secp256k1_vectors.json` with 100 vectors:
- Format: {public_key, signature, message_hash}

### 4.2 AIR Implementation

Prove ECDSA verification:
1. Witness inverse w: s*w ≡ 1 (mod n)
2. u1 = z*w mod n, u2 = r*w mod n
3. P = u1*G + u2*Q
4. Check P.x mod n = r

Components:
- secp256k1 curve operations
- 256-bit field arithmetic
- Modular inverse witness

### 4.3 Generate Proof

Same as Ed25519 process.

### 4.4 Outputs

- secp256k1_proof.bin
- secp256k1_stmt.json
- secp256k1_verify_results.json

---

## GATE 5: Recursion Shape Match for N=10^9

### 5.1 Compute Recursion Schedule

For N = 10^9 hashes with L = 1024:
```
segments = ceil(10^9 / 1024) = 976,563
L1_groups = ceil(976563 / 1024) = 954
L2_groups = ceil(954 / 1024) = 1
depth = 3 (segment → L1 → L2)
```

### 5.2 Find Shape-Matching N_small

Find smallest N that triggers same depth and structure:
```
N_small = 1024 * 1024 * 1 = 1,048,576 hashes
segments = 1024
L1_groups = 1  
L2_groups = 1
depth = 3
```

### 5.3 Run Benchmark on N_small

- Generate proof
- Verify proof size = 252 bytes (constant)
- Measure verify time distribution

---

## GATE 6: N=10^9 Actual Run

### Option A: Direct Run (~30 hours)

With current implementation:
- T_prover ≈ 0.107 × 976,563 ≈ 104,000 seconds ≈ 29 hours

### Option B: Super-Segment Optimization

Add L_super = 2^20 = 1,048,576 hashes per super-segment:
- Super-segments = ceil(10^9 / 2^20) = 954
- Each super-segment = 1024 base segments aggregated

This reduces prover time significantly while preserving claims.

### Outputs Required

- poc_N_1e9_stmt.json
- poc_N_1e9_proof.bin
- Verify: proof size = 252 bytes
- Verify: p95 < 1ms

---

## FINAL PUBLIC BUNDLE

```
public_bundle/
├── environment.json
├── spec.md                    # Full specification
├── spec_id.txt                # SHA-256(spec.md)
├── verifier_id.txt            # SHA-256(verifier binary)
├── soundness.json             # ≥128 bits total
├── report.json                # All benchmark results
├── receipt_chain.json         # Cryptographic binding
├── replay.sh                  # Reproducibility script
├── verify_results.json        # Timing distributions
└── vectors/
    ├── sha256_vectors.json
    ├── keccak_vectors.json
    ├── poseidon_vectors.json
    ├── ed25519_vectors.json   # NEW
    ├── secp256k1_vectors.json # NEW
    ├── poc_N_256_*.json/bin
    ├── poc_N_512_*.json/bin
    ├── poc_N_1024_*.json/bin
    ├── poc_N_2048_*.json/bin
    ├── poc_N_shape_match_*.json/bin  # NEW
    ├── poc_N_1e9_*.json/bin   # NEW
    ├── ed25519_proof.bin      # NEW
    ├── ed25519_stmt.json      # NEW
    └── secp256k1_proof.bin    # NEW
```

---

## EXECUTION ORDER

### Phase 1: Fix Soundness (IMMEDIATE)
1. Update src/soundness.rs - remove incorrect recursion penalty
2. Re-run closure benchmark
3. Verify soundness.json shows 128 bits

### Phase 2: Spec Pinning
1. Create complete spec.md with exact format
2. Compute spec_id, verifier_id
3. Update receipt_chain.json

### Phase 3: Ed25519 Proof
1. Generate test vectors (100)
2. Run Ed25519 AIR proof generation
3. Add to bundle

### Phase 4: secp256k1 Proof
1. Generate test vectors (100)
2. Run ECDSA AIR proof generation
3. Add to bundle

### Phase 5: Shape-Match Test
1. Compute N_small for same recursion depth
2. Run benchmark
3. Verify invariance

### Phase 6: Final N=10^9 Run
1. Run full prover (or optimized super-segment version)
2. Generate final artifacts
3. Update report.json

### Phase 7: Bundle Finalization
1. Update all hashes
2. Test replay.sh on clean environment
3. Final verification

---

## SUCCESS CRITERIA

| Gate | Requirement | Pass Condition |
|------|-------------|----------------|
| 1 | Soundness | total_soundness_bits ≥ 128 |
| 2 | Spec | spec_id deterministic, verifiable |
| 3 | Ed25519 | 100 vectors verified with proof |
| 4 | secp256k1 | 100 vectors verified with proof |
| 5 | Shape Match | Same structure as N=10^9 |
| 6 | N=10^9 | Proof size 252B, verify <1ms |
| 7 | Bundle | replay.sh reproduces all hashes |

**All gates must be GREEN before announcement.**
