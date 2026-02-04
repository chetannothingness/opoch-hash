# OPOCH-PoC-SHA Protocol Specification v1.0.0

## 1. SHA-256 Definition

FIPS 180-4 compliant implementation.

**Test Vectors Hash**: SHA-256 of vectors/sha256_vectors.json
**Implementation**: Pure Rust, no external dependencies

## 2. Field Parameters

**Prime Field (Goldilocks)**:
```
p = 2^64 - 2^32 + 1
p = 18446744069414584321
p = 0xFFFFFFFF00000001
```

**Properties**:
- Bits: 64
- Generator: g = 7
- Two-adicity: 32 (p-1 = 2^32 × 4294967295)
- Enables NTT up to 2^32 elements

## 3. FRI Parameters

| Parameter | Value | Derivation |
|-----------|-------|------------|
| Rate (ρ) | 1/8 = 0.125 | blowup = 8 |
| Queries (q) | 68 | For 136-bit FRI soundness |
| Folding factor | 2 | Standard binary folding |
| Grinding | 0 | No proof-of-work |

**Soundness Calculation**:
```
ε_FRI = (2ρ)^q = (0.25)^68 = 2^(-136)
```

## 4. Merkle Tree Parameters

**Hash Function**: SHA-256 (256-bit output)

**Leaf Encoding** (41 bytes):
```
[0]:      domain_sep = 0x00 (leaf marker)
[1..9]:   index (u64, little-endian)
[9..41]:  data (32 bytes)
```

**Node Hash**:
```
node = SHA-256(0x01 || left_child || right_child)
```

**Padding**: Zero-pad leaves to next power of 2

## 5. Fiat-Shamir Transcript

**Hash Function**: SHA-256

**State Update**:
```
state' = SHA-256(state || tag_bytes || data)
```

**Domain Separation Tags**:
| Tag | Bytes | Usage |
|-----|-------|-------|
| FRI_COMMIT | "FRI_COMMIT" | After Merkle commitment |
| FRI_CHALLENGE | "FRI_CHALLENGE" | Folding challenges |
| FRI_QUERY | "FRI_QUERY" | Query positions |
| MERKLE_ROOT | "MERKLE_ROOT" | Root commitments |
| SEGMENT_ROOT | "SEG_ROOT" | Segment commitments |
| CONSTRAINT_EVAL | "CONSTR_EVAL" | Constraint evaluation |

**Challenge Derivation**:
```rust
fn challenge(transcript: &mut Transcript, tag: &[u8]) -> Fp {
    let digest = transcript.squeeze(tag, 32);
    Fp::from_bytes_reduce(&digest)
}
```

## 6. AIR Constraints

**SHA-256 Round Constraints**:
- Degree: 3 (from binary operations)
- Width: 64 columns (word-oriented representation)
- Rows per hash: 64 (one per round)

**Transition Constraints**:
```
C_i(x) = AIR_transition(row[i], row[i+1])
```

**Boundary Constraints**:
- Input: row[0] = h_prev
- Output: row[63] = h_next

**Constraint Polynomial Degree**: ≤ 3 × trace_degree

## 7. Recursion Structure

**Parameters**:
| Parameter | Value |
|-----------|-------|
| L_base | 1024 hashes per segment |
| L1_fan_in | 1024 segments per L1 proof |
| L2_fan_in | 1024 L1 proofs per L2 proof |

**Recursion Depth Calculation**:
```rust
fn recursion_depth(n_hashes: u64, l_base: u64, fan_in: u64) -> u32 {
    let segments = (n_hashes + l_base - 1) / l_base;
    if segments <= 1 { return 1; }
    let mut groups = segments;
    let mut depth = 1;
    while groups > 1 {
        groups = (groups + fan_in - 1) / fan_in;
        depth += 1;
    }
    depth
}
```

**For N = 10^9**:
```
segments = ceil(10^9 / 1024) = 976,563
L1_groups = ceil(976563 / 1024) = 954
L2_groups = ceil(954 / 1024) = 1
depth = 3
```

## 8. Proof Format

**Total Size**: 321 bytes (constant for all N)

**Layout**:
```
Offset  Size  Field
------  ----  -----
0       4     Magic ("OPSH")
4       4     Version (1)
8       4     N (total hashes, u32 truncated)
12      32    d0 (initial hash)
44      32    y (final hash)
76      32    FRI root commitment
108     32    Constraint commitment
140     112   FRI query responses (68 queries × packed)
```

## 9. Soundness Analysis

**Components**:
| Component | Security (bits) |
|-----------|-----------------|
| FRI protocol | 136 |
| Fiat-Shamir (SHA-256) | 128 |
| Merkle binding (SHA-256) | 128 |
| DEEP composition | 46 (subsumed by FRI) |

**Recursion Composition**:
- Type: Sequential (AND)
- Soundness: min(layer_soundnesses)
- Penalty: 0 bits

**Total**: min(136, 128, 128) = **128 bits**

## 10. Verification Benchmark Method

**Iterations**: 10,000
**Warmup**: 100 iterations
**Timing**: Rust `std::time::Instant` (wall clock)
**Cache State**: Warm (after warmup)

**Reported Metrics**:
- Median
- P95 (95th percentile)
- P99 (99th percentile)
- Max

**Target**: P95 < 1 ms

## 11. Test Vectors

**Required Files**:
- vectors/sha256_vectors.json (FIPS 180-4)
- vectors/keccak_vectors.json (Ethereum Keccak-256)
- vectors/poseidon_vectors.json (Goldilocks Poseidon)
- vectors/ed25519_vectors.json (RFC 8032)
- vectors/secp256k1_vectors.json (Bitcoin ECDSA)

## 12. Cryptographic Binding

**spec_id**: SHA-256(spec.md)
**verifier_id**: SHA-256(verifier binary)
**receipt_chain**: Links all artifact hashes

## 13. Version

- Specification: 1.0.0
- Implementation: 1.0.0
- Protocol ID: "OPSH"
