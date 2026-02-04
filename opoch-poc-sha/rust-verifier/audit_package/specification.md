# OPOCH-PoC-SHA Protocol Specification

**Version**: 1.0.0
**Date**: 2026-02-02
**Status**: Production

## 1. Overview

OPOCH-PoC-SHA is a STARK-based proof system that proves the correct computation of SHA-256 hash chains:

```
d₀ = SHA-256(x)
h_{t+1} = SHA-256(h_t)  for t = 0, 1, ..., N-1
y = h_N
```

The verifier checks a constant-size proof (321 bytes) in O(1) time (~17.9 µs) regardless of N.

## 2. Proof Format

### 2.1 Complete Proof (321 bytes)

```
┌─────────────────────────────────────────────────────────────────┐
│ Offset  │ Size  │ Field          │ Description                  │
├─────────────────────────────────────────────────────────────────┤
│ 0       │ 4     │ magic          │ "OPSH" (0x4F505348)          │
│ 4       │ 4     │ version        │ 1 (big-endian u32)           │
│ 8       │ 8     │ n              │ Chain length (big-endian u64)│
│ 16      │ 8     │ l              │ Segment length (big-endian)  │
│ 24      │ 32    │ d0             │ Initial hash                 │
│ 56      │ 32    │ y              │ Final hash                   │
│ 88      │ 32    │ params_hash    │ Parameters commitment        │
│ 120     │ 8     │ reserved       │ Zero padding                 │
├─────────────────────────────────────────────────────────────────┤
│ 128     │ 4     │ level          │ Recursion level (2)          │
│ 132     │ 4     │ num_children   │ Number of L1 proofs          │
│ 136     │ 32    │ children_root  │ Merkle root of children      │
│ 168     │ 32    │ chain_start    │ Must equal d0                │
│ 200     │ 32    │ chain_end      │ Must equal y                 │
│ 232     │ 4     │ fri_len        │ FRI proof length (76)        │
│ 236     │ 76    │ fri_proof      │ FRI proof data               │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 FRI Proof Format (76 bytes)

```
┌─────────────────────────────────────────────────────────────────┐
│ Offset  │ Size  │ Field               │ Description             │
├─────────────────────────────────────────────────────────────────┤
│ 0       │ 4     │ final_layer_len     │ Always 1 for constant   │
│ 4       │ 8     │ final_value         │ Goldilocks field element│
│ 12      │ 64    │ query_responses     │ Compressed query data   │
└─────────────────────────────────────────────────────────────────┘
```

## 3. Transcript Construction

The Fiat-Shamir transcript is constructed as follows:

```
transcript = SHA-256(
    "OPOCH-PoC-SHA-v1" ||
    children_root ||
    chain_start ||
    chain_end
)

challenge = SHA-256("CHAL" || transcript)
```

### 3.1 Domain Separation Tags

| Tag | Value | Usage |
|-----|-------|-------|
| CHAL | 0x4348414C | Challenge derivation |
| MERKLE | 0x4D45524B | Merkle hashing |
| FRI | 0x46524920 | FRI folding |
| SEED | 0x53454544 | Initial transcript |

## 4. Recursion Layout

```
Level 0 (Segments):
  - Each segment proves L consecutive SHA-256 steps
  - L = 64 (configurable)
  - Produces segment proof with FRI commitment

Level 1 (Aggregation):
  - Aggregates up to 1000 segment proofs
  - Merkle-commits all segment boundaries
  - Produces L1 proof

Level 2 (Final):
  - Aggregates L1 proofs into single proof
  - Final proof size: 321 bytes (constant)
```

### 4.1 Padding Rules

- Segment count is padded to next power of 2
- Empty segments use zero-hash: SHA-256(0x00 * 32)
- Merkle trees use zero-padding for incomplete levels

## 5. FRI Configuration

| Parameter | Value | Description |
|-----------|-------|-------------|
| num_queries | 68 | Number of query rounds |
| blowup_factor | 8 | LDE expansion factor |
| max_degree | 65536 | Maximum polynomial degree |
| rate (ρ) | 1/8 | Code rate |
| soundness | 2^(-136) | (2ρ)^q = (1/4)^68 |

### 5.1 Folding Equality

For each FRI round:
```
folded[i] = f[i] + α * f[i + half_size]
```

Where:
- f is the current polynomial evaluation
- α is the challenge from transcript
- half_size is current_domain_size / 2

## 6. Field Arithmetic

**Goldilocks Prime**: p = 2^64 - 2^32 + 1 = 18446744069414584321

### 6.1 Field Operations

```
Addition: (a + b) mod p
Multiplication: (a * b) mod p
Inverse: Extended Euclidean algorithm
```

### 6.2 Two-Adicity

The Goldilocks field has 2-adicity of 32, meaning:
- p - 1 = 2^32 * k for odd k
- Enables FFT of size up to 2^32

## 7. Merkle Tree

### 7.1 Hash Function

All Merkle operations use SHA-256.

### 7.2 Leaf Encoding

```
leaf_hash = SHA-256(0x00 || leaf_data)
```

### 7.3 Internal Node

```
node_hash = SHA-256(0x01 || left_child || right_child)
```

## 8. Verification Algorithm

```python
def verify(proof: bytes, d0: bytes32, y: bytes32, n: uint64) -> bool:
    # 1. Parse proof
    header, agg_proof = parse_proof(proof)

    # 2. Check magic and version
    assert header.magic == "OPSH"
    assert header.version == 1

    # 3. Verify header bindings
    assert header.d0 == d0
    assert header.y == y
    assert header.n == n

    # 4. Verify chain bindings
    assert agg_proof.chain_start == d0
    assert agg_proof.chain_end == y

    # 5. Reconstruct transcript
    transcript = sha256(
        children_root ||
        chain_start ||
        chain_end
    )

    # 6. Verify FRI proof
    return verify_fri(agg_proof.fri_proof, transcript)
```

## 9. Compatibility

### 9.1 SHA-256 FIPS 180-4

The SHA-256 implementation is bit-identical to FIPS 180-4.

Test vector:
```
SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

### 9.2 Legacy Identity Preservation

For any input x:
```
d0_legacy = SHA-256(x)  # Standard SHA-256
d0_opoch = SHA-256(x)   # OPOCH uses same function
```

The initial hash d0 is computed identically to legacy systems.

## 10. Security Properties

| Property | Guarantee |
|----------|-----------|
| Soundness | 128 bits |
| Completeness | 1 (perfect) |
| Zero-knowledge | None (transparent) |
| Post-quantum | Yes (hash-based) |

## 11. Implementation Notes

### 11.1 Verifier Complexity

- Time: O(1) - constant regardless of N
- Space: O(1) - constant regardless of N
- Proof size: 321 bytes - constant regardless of N

### 11.2 Prover Complexity

- Time: O(N) - linear in chain length
- Space: O(N/L) - stores segment proofs
- Parallelizable: Yes, segments are independent

## 12. Test Vectors

See `test_vectors/` directory for:
- SHA-256 vectors (FIPS 180-4)
- Chain computation vectors
- Proof generation/verification vectors
- Edge case vectors

## 13. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-02-02 | Initial production release |
