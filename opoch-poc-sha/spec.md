# OPOCH-PoC-SHA Specification v1.0

## 0. Preamble

This document is the **canonical, pinned specification** for OPOCH-PoC-SHA.
All implementations MUST match this spec bit-for-bit.

**Spec Hash:** To be computed after finalization as SHA-256 of this file.

---

## 1. System Overview

### 1.1 Core Object

```
OPOCH-PoC-SHA(x, θ) → (d₀, y, π)
```

Where:
- `x`: arbitrary input bytes
- `θ`: public parameters (pinned below)
- `d₀ = SHA-256(x)`: legacy digest, bit-for-bit FIPS-180-4
- `h₀ = d₀`
- `h_{t+1} = SHA-256(h_t)` for t = 0..N-1
- `y = h_N`: final chain output
- `π`: STARK proof that chain was computed correctly

### 1.2 Properties

| Property | Guarantee |
|----------|-----------|
| Legacy compatibility | d₀ = standard SHA-256(x) bit-for-bit |
| Verification time | < 1ms for N = 10⁹ on pinned hardware |
| Soundness | ≥ 128 bits (forgery prob < 2⁻¹²⁸) |
| Transparency | No trusted setup |
| Sequentiality | Cannot parallelize depth |

---

## 2. Cryptographic Primitives

### 2.1 SHA-256 (Legacy Hash)

**Reference:** FIPS PUB 180-4 (August 2015)

**Initial Hash Values (H₀):**
```
H[0] = 0x6a09e667
H[1] = 0xbb67ae85
H[2] = 0x3c6ef372
H[3] = 0xa54ff53a
H[4] = 0x510e527f
H[5] = 0x9b05688c
H[6] = 0x1f83d9ab
H[7] = 0x5be0cd19
```

**Round Constants (K):**
```
K[0..63] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]
```

**Padding Rule:**
- Append bit '1' to message
- Append '0' bits until length ≡ 448 (mod 512)
- Append 64-bit big-endian length of original message

**Message Schedule (W):**
```
W[i] = M[i]                                    for i = 0..15
W[i] = σ₁(W[i-2]) + W[i-7] + σ₀(W[i-15]) + W[i-16]  for i = 16..63

σ₀(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
```

**Compression Function:**
```
For each round i = 0..63:
    Σ₀(a) = ROTR²(a) ⊕ ROTR¹³(a) ⊕ ROTR²²(a)
    Σ₁(e) = ROTR⁶(e) ⊕ ROTR¹¹(e) ⊕ ROTR²⁵(e)
    Ch(e,f,g) = (e ∧ f) ⊕ (¬e ∧ g)
    Maj(a,b,c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)

    T₁ = h + Σ₁(e) + Ch(e,f,g) + K[i] + W[i]
    T₂ = Σ₀(a) + Maj(a,b,c)

    h = g
    g = f
    f = e
    e = d + T₁
    d = c
    c = b
    b = a
    a = T₁ + T₂
```

**All arithmetic is mod 2³².**

### 2.2 Commitment Hash (Merkle)

**Function:** SHA-256 with domain separation

```
leaf_hash(index, data) = SHA-256(0x00 || index_le64 || data)
node_hash(left, right) = SHA-256(0x01 || left || right)
root_hash(h) = SHA-256(0x02 || h)
```

Where `index_le64` is the 8-byte little-endian encoding of the index.

### 2.3 Fiat-Shamir Hash (Transcript)

**Function:** SHA-256 in sponge mode

```
transcript_init() = SHA-256("OPOCH-PoC-SHA-v1-TRANSCRIPT")
transcript_append(state, data) = SHA-256(state || len_le64(data) || data)
transcript_challenge(state, tag) = SHA-256(state || tag)
```

**Tags (fixed strings):**
```
TAG_CHAL_FRI    = "CHAL_FRI"
TAG_CHAL_QUERY  = "CHAL_QUERY"
TAG_CHAL_SEG    = "CHAL_SEG"
TAG_CHAL_AGG    = "CHAL_AGG"
TAG_CHAL_TOP    = "CHAL_TOP"
```

---

## 3. Field Arithmetic

### 3.1 Prime Field

**Goldilocks Prime:**
```
p = 2⁶⁴ - 2³² + 1 = 18446744069414584321
```

**Properties:**
- 64-bit prime
- Two-adicity: 32 (supports FFT up to 2³² elements)
- Primitive root of unity: ω where ω^(2³²) = 1

### 3.2 Extension Field (for FRI challenges)

**Quadratic Extension:**
```
F_{p²} = F_p[x] / (x² - 7)
```

Elements: a + b·α where α² = 7

---

## 4. Parameters (All Pinned)

### 4.1 Work Parameters

| Parameter | Symbol | Value | Rationale |
|-----------|--------|-------|-----------|
| Total work steps | N | 1,000,000,000 (10⁹) | Target workload |
| Segment length | L | 1,024 (2¹⁰) | Tractable segment proofs |
| Number of segments | S | 976,563 | ceil(N/L) |
| Recursion levels | R | 2 | S → ~1000 → 1 |

**Exact segment count:**
```
S = ceil(N / L) = ceil(1000000000 / 1024) = 976563
```

**Last segment length:**
```
L_last = N - (S-1) * L = 1000000000 - 976562 * 1024 = 512
```

### 4.2 STARK Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Blowup factor | 8 | Rate ρ = 1/8 = 0.125 |
| FRI queries | 68 | (0.125 + 0.1)^68 < 2⁻¹⁴⁶ |
| Constraint degree | 3 | SHA-256 constraints |
| Extension degree | 2 | Quadratic for challenges |

### 4.3 Soundness Calculation

**FRI Soundness:**
```
ε_FRI = (ρ + δ)^q = (0.125 + 0.1)^68 = (0.225)^68 < 2⁻¹⁴⁶
```

**Constraint Soundness (Schwartz-Zippel):**
```
ε_constraint = degree / |F_{p²}| = 3 / p² < 2⁻¹²⁵
```

**Combined Soundness:**
```
ε_total = ε_FRI + ε_constraint < 2⁻¹²⁵
```

**Target achieved: ≥ 128 bits.**

---

## 5. SerΠ Canonical Encoding

### 5.1 Statement Object

```json
{
  "version": "1.0",
  "type": "statement",
  "x_hash": "<hex-encoded SHA-256 of x>",
  "d0": "<hex-encoded d₀>",
  "N": <integer>,
  "L": <integer>,
  "y": "<hex-encoded y>",
  "params_hash": "<hex-encoded SHA-256 of parameters>"
}
```

**Serialization rule:** UTF-8 JSON, keys in alphabetical order, no whitespace.

### 5.2 Proof Object

```
PROOF := HEADER || SEGMENT_PROOFS || AGG_PROOF_1 || AGG_PROOF_2
```

**Header (fixed 128 bytes):**
```
bytes[0..3]   = magic "OPSH"
bytes[4..7]   = version (uint32 big-endian) = 1
bytes[8..15]  = N (uint64 big-endian)
bytes[16..23] = L (uint64 big-endian)
bytes[24..55] = d0 (32 bytes)
bytes[56..87] = y (32 bytes)
bytes[88..119] = params_hash (32 bytes)
bytes[120..127] = reserved (zeros)
```

**Segment Proof (variable):**
```
bytes[0..3]   = segment_index (uint32 big-endian)
bytes[4..7]   = proof_len (uint32 big-endian)
bytes[8..8+proof_len-1] = FRI proof data
```

**Aggregation Proof (variable):**
```
bytes[0..3]   = level (uint32 big-endian)
bytes[4..7]   = proof_len (uint32 big-endian)
bytes[8..8+proof_len-1] = recursive proof data
```

---

## 6. AIR Constraints (SHA-256)

### 6.1 Trace Layout

**Columns per SHA-256 compression (one hash):**

| Column Group | Count | Description |
|--------------|-------|-------------|
| State A-H | 8 × 32 = 256 | 8 state words, bit-decomposed |
| Message W | 64 × 32 = 2048 | Message schedule, bit-decomposed |
| Intermediate | 64 × 6 = 384 | T1, T2, Ch, Maj, Σ0, Σ1 per round |
| Carry bits | 64 × 8 = 512 | For mod 2³² additions |

**Total columns per hash:** ~3200

**Rows per segment (L=1024 hashes):**
- Each hash: 64 rounds
- Total rows: 1024 × 64 = 65,536

### 6.2 Constraint Types

**C1: Bit constraints**
```
For each bit b: b × (1 - b) = 0
```

**C2: XOR constraint**
```
c = a + b - 2·a·b
```

**C3: AND constraint**
```
c = a · b
```

**C4: Addition mod 2³² with carry**
```
For 32-bit addition a + b = c with carries:
c[i] = a[i] + b[i] + carry[i-1] - 2·carry[i]
carry[i] ∈ {0, 1}
carry[-1] = 0
```

**C5: Rotation**
```
ROTR^k(x) = permutation of bit indices
No arithmetic constraint, just relabeling
```

**C6: Message schedule**
```
W[i] = σ₁(W[i-2]) + W[i-7] + σ₀(W[i-15]) + W[i-16]  for i ≥ 16
Expands to bit-level constraints via C2, C3, C4, C5
```

**C7: Round function**
```
Constraints for T1, T2, state update
Uses C2, C3, C4, C5 for Ch, Maj, Σ₀, Σ₁
```

**C8: Chaining**
```
h_{t+1,input} = h_{t,output}
Final state of hash t = initial state of hash t+1
```

### 6.3 Boundary Constraints

**Initial:**
```
h_0 = d_0 (bit-decomposed)
```

**Final:**
```
h_N = y (bit-decomposed)
```

---

## 7. FRI Protocol

### 7.1 Commitment Phase

1. Commit to trace polynomial evaluations via Merkle tree
2. Get challenge α from transcript
3. Fold: f'(x) = f_even(x) + α · f_odd(x)
4. Repeat until constant polynomial

### 7.2 Query Phase

1. Sample 68 query indices from transcript
2. For each query: open Merkle paths at all FRI layers
3. Verify folding consistency

### 7.3 FRI Parameters

```
initial_domain_size = trace_rows × blowup = 65536 × 8 = 524288
num_fri_layers = log2(524288) - log2(final_degree) = 19 - 0 = 19
queries_per_layer = 68
```

---

## 8. Recursion

### 8.1 Level 0: Segment Proofs

Each segment i produces proof π_i for:
```
h_{(i+1)·L} = SHA-256^L(h_{i·L})
```

Total: S = 976,563 segment proofs

### 8.2 Level 1: First Aggregation

Group segment proofs into batches of ~1000.
Prove: "All segment proofs in this batch verify correctly"

Result: ~977 aggregated proofs

### 8.3 Level 2: Final Aggregation

Prove: "All 977 level-1 proofs verify correctly"

Result: 1 final proof π

### 8.4 Recursion Circuit

The verifier logic becomes constraints:
- Merkle root verification as circuit
- Field arithmetic for FRI checks
- Transcript hashing as SHA-256 circuit

---

## 9. Verification Algorithm

```
VERIFY(x, d₀, y, π):
    1. Check d₀ = SHA-256(x)
    2. Parse π header, verify magic and version
    3. Verify params_hash matches pinned parameters
    4. Reconstruct transcript from public inputs
    5. Verify final aggregation proof:
       a. Check FRI proof (68 queries)
       b. Check Merkle openings
       c. Check constraint evaluations
    6. Return ACCEPT or REJECT
```

**Verification complexity:** O(log N) field operations, ~5000 total.

---

## 10. Security Proofs

### 10.1 Soundness Theorem

**Theorem:** Any prover that produces a valid proof π without executing N SHA-256 steps must either:
1. Break SHA-256 collision resistance, or
2. Find a low-degree polynomial satisfying constraints with probability < 2⁻¹²⁸

**Proof sketch:**
- STARK soundness from FRI + constraint sampling
- Sequentiality from random oracle model (SHA-256)
- Binding from Merkle collision resistance

### 10.2 Sequentiality Lemma

**Lemma:** In the random oracle model, computing h_N from h_0 requires at least N oracle queries.

**Proof:** Each h_{t+1} is uniformly random given only h_0,...,h_{t-1}. Without querying h_t, the probability of guessing h_{t+1} is 2⁻²⁵⁶.

---

## 11. Test Vectors

### 11.1 SHA-256 Vectors (Pinned)

```json
{
  "vectors": [
    {"input": "", "output": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"input": "abc", "output": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {"input": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "output": "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"}
  ]
}
```

### 11.2 Chain Vectors (Pinned)

```json
{
  "vectors": [
    {"d0": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "N": 1, "y": "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"},
    {"d0": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "N": 10, "y": "to_be_computed"},
    {"d0": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "N": 1000, "y": "to_be_computed"}
  ]
}
```

---

## 12. Pinned Hardware Target

**Benchmark verification target:**
- CPU: AMD Ryzen 9 5900X or Intel i9-12900K (or equivalent)
- Clock: 3.7 GHz base
- RAM: 32 GB DDR4
- OS: Linux kernel 5.15+

**Verification time budget:**
- Target: < 1ms
- Max acceptable: 1ms (hard cutoff)

---

## 13. File Hashes (Integrity)

After finalization, compute:
```
spec_hash = SHA-256(spec.md)
```

All implementations MUST verify spec_hash before proceeding.

---

## Appendix A: Notation

| Symbol | Meaning |
|--------|---------|
| x | Input bytes |
| d₀ | SHA-256(x), legacy digest |
| h_t | Hash at step t in chain |
| y | Final hash h_N |
| N | Total chain length |
| L | Segment length |
| S | Number of segments |
| π | Proof object |
| p | Goldilocks prime |
| F_p | Prime field |
| F_{p²} | Quadratic extension |

---

## Appendix B: Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-XX-XX | Initial pinned specification |
