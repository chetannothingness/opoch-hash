# Hash-Based Proof of Computation

## Overview

A Π-clean (meaning first, then mixing), deterministic, and mechanically verifiable proof of computation stack built on OpochHash.

**Three Levels**:
- **Level 0 (Receipted Replay)**: Verifier replays computation; hash chain proves no tampering. O(T) verification.
- **Level 1 (Spot-Check Proof)**: Verifier checks randomly sampled transitions via Merkle openings. Probabilistic soundness.
- **Level 2 (Succinct STARK-style)**: Polylog verification via polynomial commitments. Hash-based via Merkle + Fiat–Shamir.

All three share the same kernel primitives.

---

## 0. Kernel Primitives

### Hash Function

```
H(x) = TreeSpongeMixer(Ser_Π(x))
```

With domain tags and receipts from OpochHash.

### Deterministic Program Semantics

A **total step function**:

```
Step : (P, s_t) → s_{t+1}
```

Where:
- **P** is the program (or circuit)
- **s_t** is the full machine state at tick t (PC, registers, memory root, I/O, etc.)
- **Totality** means Step always returns a next state (illegal ops map to explicit FAIL state)

### Computation Claim

```
y = F_P(x)
```

With execution length T, producing states:

```
s_0 = Init(P, x)
s_{t+1} = Step(P, s_t)
y = Out(s_T)
```

---

## 1. Level 0: Receipted Replay

**Proof that the prover ran exactly these steps.** Verification is replay.

### Prover Output

Emit:
- P, x, claimed y, T
- Receipt chain:

```
c_0 = H("STEP" ‖ 0 ‖ P ‖ x)
c_{t+1} = H("STEP" ‖ (t+1) ‖ c_t ‖ s_t ‖ s_{t+1})
```

Publish c_T.

### Verifier

1. Replay Step from (P, x) to T
2. Recompute c_T
3. Check:
   - Computed y matches claimed y
   - Computed c_T matches published c_T

**Properties**:
- Perfect integrity (UNIQUE)
- Verification cost: O(T)

---

## 2. Level 1: Hash-Based Spot-Check Proof

Proves computation **without replay**, with tunable soundness.

### 2.1 Commit to Trace with Merkle Tree

Define leaf hashes:

```
ℓ_t := H("LEAF" ‖ t ‖ s_t)
```

Build Merkle root:

```
R := MerkleRoot(ℓ_0, ..., ℓ_T)
```

Public statement:

```
Stmt := (H(P), H(x), H(y), T, R)
```

All Π-serialized.

### 2.2 Deterministic Challenges (No Interaction)

Generate challenge seed:

```
seed := H("CHAL" ‖ Stmt)
```

Use XOF expansion from H to derive k indices:

```
q_i ∈ {0, 1, ..., T-1}, i = 1..k
```

### 2.3 Proof Object

For each sampled index q, prover supplies:
1. Opened states (s_q, s_{q+1})
2. Merkle authentication paths π_q, π_{q+1} proving ℓ_q, ℓ_{q+1} are in root R
3. Auxiliary data for transition check (RAM proofs if needed)

```
Π := {(q_i, s_{q_i}, s_{q_{i+1}}, π_{q_i}, π_{q_{i+1}}, aux_{q_i})}_{i=1}^k
```

### 2.4 Verifier

Given Stmt and Π:

1. Recompute seed = H("CHAL" ‖ Stmt) and indices q_i
2. For each q_i:
   - Verify Merkle paths for ℓ_{q_i}, ℓ_{q_{i+1}} to root R
   - Check local transition: s_{q_{i+1}} = Step(P, s_{q_i})
3. Verify y = Out(s_T)

### Soundness Bound

If b bad transitions among T steps:

```
Pr[miss] ≤ (1 - b/T)^k
```

Choose k ≈ (T/b) · ln(1/ε) for negligible miss probability ε.

---

## 3. RAM Programs: Merkle Memory

State includes memory as Merkle commitment:

```
s_t := (pc_t, regs_t, M_t, io_t)
```

Where M_t is the Merkle root of memory at time t.

### Auxiliary Data for Transitions

For each transition at q:
- Merkle proof(s) for each memory **read** (address → value under M_q)
- Merkle proof(s) for each memory **write** showing update from M_q to M_{q+1}

### Verifier Checks

1. Read proofs valid under M_q
2. Write updates produce M_{q+1}
3. CPU/register/pc updates match instruction semantics

---

## 4. Level 2: Succinct Proof (STARK-style)

For huge traces (millions/billions of steps), compress to polylog verification.

### 4.1 Arithmetize Execution Trace

Represent trace as columns over finite field:
- pc(t), regs(t), etc.
- Memory access columns
- Constraint polynomials enforcing s_{t+1} = Step(s_t)

### 4.2 Commit Columns with Merkle Roots

Build Merkle commitments to each column (hash trees over evaluations).

### 4.3 Fiat–Shamir Challenges

Derive randomness from commitment roots using H to pick evaluation points.

### 4.4 Low-Degree Testing (FRI)

FRI-style proofs show committed columns are low-degree and satisfy constraints.

**Result**: Verification is polylog in T, fully hash-based.

---

## 5. Pinned Requirements (No Minted Differences)

For full determinism and universal replayability:

| Requirement | Specification |
|-------------|---------------|
| Ser_Π | Fixed for P, x, y, s_t |
| Merkle Format | Binary tree, fixed padding, fixed leaf encoding |
| Challenge Derivation | XOF expansion rule, modulus, rejection sampling |
| Instruction Semantics | Total (illegal ops → explicit FAIL state) |
| Domain Tags | "LEAF", "NODE", "CHAL", "STEP", "MEMREAD", "MEMWRITE", "ROOT" |

---

## 6. What This Proves

| Level | Property | Guarantee |
|-------|----------|-----------|
| 0 | UNIQUE | Correctness by replay + integrity by hash chain |
| 1 | UNIQUE | Probabilistic soundness with explicit (1-b/T)^k bound |
| 2 | UNIQUE | Succinct correctness with polynomial-commitment soundness |

### Failure Mode Localization

Every failure is attributable to exactly one cause:
1. **Ser_Π bug** - minted slack (fixable)
2. **Merkle commitment mismatch** - proof invalid
3. **Wrong Step semantics** - implementation bug
4. **Hash collision** - bounded by hash security (2^128)
5. **Missed bad steps** (Level 1 only) - explicit (1-b/T)^k bound

---

## Domain Tags

| Tag | Purpose |
|-----|---------|
| STEP | Receipt chain transitions |
| LEAF | Merkle leaf for state |
| NODE | Merkle internal node |
| ROOT | Merkle root finalization |
| CHAL | Challenge seed derivation |
| MEMREAD | Memory read proof |
| MEMWRITE | Memory write proof |
| POLY | Polynomial commitment |
| FRI | FRI layer commitment |

---

*Complete hash-based proof of computation stack in pure kernel math.*
