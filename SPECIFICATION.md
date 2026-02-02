# OpochHash Formal Specification

## Version 1.0

---

## 0. Foundational Axiom

**A0 (Witnessability)**: A distinction is admissible if and only if a finite procedure separates it.

A hash used as a truth fingerprint is an admissible distinction only if:
1. It is computed deterministically from the object's meaning
2. Any collision has an accountable cause

**Definition**: Hashing is a compiler from meaning into a fixed tape, followed by a mixer.

```
OpochHash = Mix ∘ Ser_Π
```

---

## 1. Information-Theoretic Limits

These bounds are **irreducible**. No construction can exceed them.

### 1.1 Collision Bound (Birthday Paradox)

For an ideal hash function H: X → {0,1}^n, after q queries:

```
Pr[collision] ≲ q² / 2^(n+1)
```

For constant success probability: **q = Θ(2^(n/2))**

With n = 256 bits, collision requires ≈ 2^128 queries.

### 1.2 Preimage Bound

For fixed target y ∈ {0,1}^n:

```
Pr[∃x: H(x) = y] ≤ q / 2^n
```

For constant success probability: **q = Θ(2^n)**

### 1.3 Consequence

Any real-world break is either:
1. Deviation from ideal mixing (cryptographic weakness)
2. Application-layer slack (non-canonical meaning)

OpochHash addresses (2) completely and relies on proven primitives for (1).

---

## 2. Semantic Quotient Π

### 2.1 Definitions

Let **O** be the set of semantic objects.

Define semantic equivalence **o ~ o'** ("same meaning") as an equivalence relation that is:
- Reflexive: o ~ o
- Symmetric: o ~ o' ⟹ o' ~ o
- Transitive: o ~ o' ∧ o' ~ o'' ⟹ o ~ o''

### 2.2 Required Properties

A hash that fingerprints meaning must satisfy:

**P1 (No Minted Distinctions)**:
```
o ~ o' ⟹ Hash(o) = Hash(o')
```

**P2 (No Minted Collisions at Meaning Layer)**:
```
o ≁ o' ⟹ Ser_Π(o) ≠ Ser_Π(o')
```

---

## 3. Ser_Π: Canonical Serialization

### 3.1 Definition

```
Ser_Π: O → Σ^(<∞)
```

A deterministic function mapping semantic objects to finite bit strings.

### 3.2 Required Properties

**P3 (Quotient Respect)**:
```
o ~ o' ⟹ Ser_Π(o) = Ser_Π(o')
```

**P4 (Injectivity on Meaning Classes)**:
```
o ≁ o' ⟹ Ser_Π(o) ≠ Ser_Π(o')
```

**P5 (Domain Separation)**:
Type, version, schema, and context are part of the tape.

### 3.3 Canonical Tape Format

```
TAPE = MAGIC ‖ VERSION ‖ CONTEXT_TAG ‖ PAYLOAD

PAYLOAD = TLV(object)

TLV = TYPE_TAG (2 bytes) ‖ LENGTH (4 bytes) ‖ VALUE
```

#### Magic Number
```
MAGIC = 0x4F504348 ("OPCH")
```

#### Type Tags (2 bytes, big-endian)

| Tag    | Type      |
|--------|-----------|
| 0x0000 | NULL      |
| 0x0001 | BOOL      |
| 0x0002 | INT       |
| 0x0003 | FLOAT     |
| 0x0004 | BYTES     |
| 0x0005 | STRING    |
| 0x0100 | LIST      |
| 0x0101 | SET       |
| 0x0102 | MAP       |
| 0x0200 | STRUCT    |
| 0x0203 | OPTIONAL  |

### 3.4 Canonicalization Rules

#### 3.4.1 Integers
- Sign byte (0x00 = non-negative, 0x01 = negative)
- Big-endian magnitude
- Minimal representation (no leading zeros)

#### 3.4.2 Floats
- IEEE 754 double-precision, big-endian
- **NaN**: Canonical quiet NaN (0x7FF8000000000000)
- **Zero**: Positive zero (0x0000000000000000)
- **Infinity**: Preserved with sign

#### 3.4.3 Strings
- UTF-8 encoding
- NFC Unicode normalization
- No length-ambiguity (length-prefixed)

#### 3.4.4 Sets
- Elements sorted by serialized bytes (lexicographic)
- Guarantees order-independence

#### 3.4.5 Maps
- Key-value pairs sorted by serialized key (lexicographic)
- Guarantees order-independence

#### 3.4.6 Structs
- Schema ID included (namespace, name, version)
- Fields sorted by name (UTF-8 lexicographic)

#### 3.4.7 Optional
- 0x00 = absent (None)
- 0x01 = present (followed by serialized value)

---

## 4. Mix: Universal Two-Regime Mixer

### 4.1 Architecture

The mixer uses a Pareto-optimal two-regime design:

```
Mix(TAPE) = {
    SmallMsgMode(SMALL ‖ len ‖ TAPE)   if |TAPE| ≤ τ
    TreeMode(TREE ‖ TAPE)               if |TAPE| > τ
}
```

Where τ is pinned in the spec (default: 1024 bytes).

**Rationale**: No single mixer regime can minimize both:
- Fixed overhead (small messages)
- Per-byte cost (large messages)

The two-regime design is the unique Pareto-optimal decomposition.

### 4.1.1 Small Message Mode (|TAPE| ≤ τ)

```
digest = CoreHash(SMALL ‖ len(TAPE) ‖ TAPE)
XOF = CoreXOF(SMALL-XOF ‖ len(TAPE) ‖ TAPE)
```

No tree structure. Minimal overhead. Optimized for latency.

### 4.1.2 Tree Mode (|TAPE| > τ)

Using a sponge/compression construction with:
- **Capacity**: c bits (security = c/2 bits)
- **Rate**: r bits (throughput)
- **State**: c + r bits

### 4.2 Domain Tags

| Tag  | Mode      |
|------|-----------|
| 0x00 | LEAF      |
| 0x01 | PARENT    |
| 0x02 | ROOT      |
| 0x03 | ROOT_XOF  |
| 0x04 | KEYED     |
| 0x05 | MAC       |
| 0x06 | KDF       |
| 0x07 | PRF       |

### 4.3 Operations

#### 4.3.1 Leaf Hash
```
h_i = Sponge(LEAF ‖ i ‖ M_i)
```
Where i is the 64-bit chunk index.

#### 4.3.2 Parent Hash
```
h_p = Sponge(PARENT ‖ h_L ‖ h_R)
```

#### 4.3.3 Root Hash
```
digest = Sponge(ROOT ‖ h_root)
```

#### 4.3.4 XOF Mode
```
output = SpongeStream(ROOT_XOF ‖ h_root)
```

#### 4.3.5 Keyed Mode
```
digest = Sponge(KEYED ‖ len(K) ‖ K ‖ len(role) ‖ role ‖ data)
```

### 4.4 Tree Construction

1. Split input into chunks of size CHUNK_SIZE
2. Hash each chunk as a leaf
3. Build binary tree bottom-up
4. Odd nodes promote to next level
5. Apply root finalization

### 4.5 Parameters

| Parameter      | Default | Security Level |
|----------------|---------|----------------|
| Capacity       | 512 bits| 256-bit        |
| Hash Size      | 256 bits| Full           |
| Chunk Size     | 4096 B  | Performance    |

---

## 5. Collision Localization Theorem

**Definition**:
```
OpochHash(o) = Mix(Ser_Π(o))
```

**Theorem**: If OpochHash(o) = OpochHash(o'), exactly one of the following holds:

1. **Same Meaning**: o ~ o'
   - Expected behavior, not a bug

2. **Serialization Bug**: Ser_Π violated injectivity
   - Fix: correct the canonicalization rule

3. **Cryptographic Collision**: Mix collided on distinct tapes
   - Probability bounded by birthday limit
   - If within bound: acceptable
   - If exceeded: mixer is broken

4. **Truncation Collision**: Output was truncated
   - Governed by birthday at truncated length
   - Fix: use full output length

**Corollary**: Every collision has exactly one accountable cause with a specific fix.

---

## 6. Security Claims

### 6.1 What OpochHash Achieves

| Property | Claim |
|----------|-------|
| Collision Resistance | 2^128 queries (256-bit output) |
| Preimage Resistance | 2^256 queries |
| Second-Preimage Resistance | 2^256 queries |
| Semantic Canonicalization | Complete (by construction) |
| Domain Separation | Complete (by tagging) |
| Collision Attribution | Complete (by theorem) |

### 6.2 What OpochHash Does NOT Claim

- Faster than SHA-256 on raw bytes (use SHA-256 for that)
- Novel cryptographic primitives (uses proven Keccak)
- Breaking information-theoretic limits

### 6.3 Comparison to Byte-Only Hashes

| Issue | SHA-256 | OpochHash |
|-------|---------|-----------|
| Float NaN variants | Collide unpredictably | Canonical |
| Map ordering | User's problem | Handled |
| Schema evolution | User's problem | Versioned |
| Protocol confusion | Possible | Domain-separated |
| Length extension | Vulnerable | Immune (sponge) |

---

## 7. Implementation Requirements

### 7.1 Conformance

A conforming implementation MUST:

1. Implement Ser_Π exactly as specified
2. Implement Mix with correct domain separation
3. Pass all property tests for quotient respect
4. Pass all property tests for injectivity
5. Produce identical hashes for the test vectors

### 7.2 Test Vectors

```python
# Test Vector 1: Integer
OpochHash(SInt(42)) = <hex_value>

# Test Vector 2: String
OpochHash(SString("hello")) = <hex_value>

# Test Vector 3: Nested
OpochHash(SMap({SString("a"): SInt(1)})) = <hex_value>

# Test Vector 4: Canonical equivalence
OpochHash(SFloat(0.0)) == OpochHash(SFloat(-0.0))
OpochHash(SFloat(NaN)) == OpochHash(SFloat(NaN))
```

### 7.3 Security Requirements

1. Use audited Keccak/SHAKE implementation
2. Constant-time comparison for MACs
3. Secure memory handling for keys
4. No timing leaks in serialization

---

## 8. Rationale

### 8.1 Why Sponge?

- Single primitive for hash/XOF/MAC/KDF/PRF
- No length extension attacks
- Clean domain separation
- Proven security (Keccak)

### 8.2 Why Tree?

- Parallelism on large inputs
- Streaming capability
- Incremental updates (future)

### 8.3 Why Explicit Canonicalization?

- Most "hash breaks" are canonicalization failures
- Removes entire class of bugs by construction
- Enables cross-language compatibility

---

## 9. References

1. Keccak/SHA-3: FIPS 202
2. Sponge Construction: Bertoni et al.
3. Birthday Bound: standard probability theory
4. Domain Separation: NIST SP 800-185

---

## Appendix A: Canonical Equivalences

Objects that MUST produce identical hashes:

| Object A | Object B |
|----------|----------|
| SFloat(0.0) | SFloat(-0.0) |
| SFloat(NaN) | SFloat(NaN) (any payload) |
| SString("é") NFC | SString("e\u0301") NFD |
| SSet({1,2,3}) | SSet({3,1,2}) |
| SMap({a:1,b:2}) | SMap({b:2,a:1}) |

---

## Appendix B: Formal Properties (for verification)

```
∀o ∈ O: OpochHash(o) = OpochHash(canonical(o))
∀o,o' ∈ O: o ~ o' ⟺ canonical(o) = canonical(o')
∀o,o' ∈ O: Ser_Π(o) = Ser_Π(o') ⟺ o ~ o'
∀o ∈ O: deserialize(serialize(o)) ~ o
∀t₁,t₂ ∈ Tape: t₁ ≠ t₂ ⟹ Pr[Mix(t₁) = Mix(t₂)] ≤ 2^(-n)
```
