# OPOCH Complete Execution Plan: Beat All Benchmarks

## Zero Shortcuts. Complete Implementation. World-Class Performance.

---

## Executive Summary

This plan implements 6 components to achieve benchmark dominance:

| Component | Impact | Effort | Priority |
|-----------|--------|--------|----------|
| 1. Lookup Tables | 5-10x speedup everywhere | 2 weeks | HIGHEST |
| 2. Keccak-256 AIR | Ethereum compatibility | 2 weeks | HIGH |
| 3. Poseidon AIR | ZK-native hash, recursion | 1 week | HIGH |
| 4. 256-bit Field Emulation | Unlocks signatures | 2 weeks | HIGH |
| 5. Ed25519 + EdDSA AIR | Modern signatures | 2 weeks | MEDIUM |
| 6. secp256k1 + ECDSA AIR | Bitcoin/Ethereum sigs | 3 weeks | MEDIUM |

**Total: 12 weeks to beat everyone at everything.**

---

## Phase 1: Lookup Engine (Week 1-2)

### 1.1 Core Lookup Tables to Implement

```rust
// src/lookup/tables.rs

/// All lookup tables - PINNED SPECIFICATION
pub mod tables {
    /// U8 range table: {0, 1, ..., 255}
    pub const U8_TABLE_SIZE: usize = 256;

    /// U16 range table: {0, 1, ..., 65535}
    pub const U16_TABLE_SIZE: usize = 65536;

    /// XOR8 table: (a, b, a^b) for a,b in [0,255]
    /// Size: 256 * 256 = 65536 entries
    pub const XOR8_TABLE_SIZE: usize = 65536;

    /// AND8 table: (a, b, a&b) for a,b in [0,255]
    pub const AND8_TABLE_SIZE: usize = 65536;

    /// NOT8 table: (a, !a & 0xFF) for a in [0,255]
    pub const NOT8_TABLE_SIZE: usize = 256;

    /// ADD8C table: (a, b, cin, sum, cout)
    /// a + b + cin = sum + 256*cout
    /// Size: 256 * 256 * 2 = 131072 entries
    pub const ADD8C_TABLE_SIZE: usize = 131072;

    /// CARRY16 table: (x, carry, rem) where x = rem + 65536*carry
    /// For x in [0, 2^17-1], carry in {0,1}, rem in [0,65535]
    pub const CARRY16_TABLE_SIZE: usize = 131072;

    /// MUL8 table: (a, b, lo, hi) where a*b = lo + 256*hi
    pub const MUL8_TABLE_SIZE: usize = 65536;

    /// BIT table: {0, 1}
    pub const BIT_TABLE_SIZE: usize = 2;

    /// ROT1BYTE table: (byte, carry_in, byte_rot, carry_out)
    /// For 1-bit rotation across bytes
    pub const ROT1BYTE_TABLE_SIZE: usize = 512;

    /// SHIFTk tables for k in 1..7
    /// (byte, shifted_byte, overflow_bits)
    pub const SHIFT_TABLE_SIZE: usize = 256 * 7;
}
```

### 1.2 Lookup Argument Implementation

**Option A: Grand Product (Permutation) Lookup**

```rust
// src/lookup/grand_product.rs

/// Grand product lookup argument
///
/// Proves: all values in witness column W are in table T
///
/// Math:
/// Z_0 = 1
/// Z_{i+1} = Z_i * (W_i + β + γ*i) / (T_{π(i)} + β + γ*i)
/// Z_n = 1 (if valid)
///
/// Constraints:
/// 1. Z_0 = 1
/// 2. Z_{i+1} * (T_{π(i)} + β + γ*i) = Z_i * (W_i + β + γ*i)
/// 3. Z_n = 1

pub struct GrandProductLookup {
    /// Table values (committed once)
    table: Vec<Fp>,
    /// Running product column
    z: Vec<Fp>,
    /// Fiat-Shamir challenges
    beta: Fp,
    gamma: Fp,
}

impl GrandProductLookup {
    /// Generate lookup proof
    pub fn prove(&self, witness: &[Fp], transcript: &mut Transcript) -> LookupProof {
        // 1. Commit to witness
        let witness_commitment = self.commit_witness(witness);
        transcript.append_commitment(&witness_commitment);

        // 2. Get challenges
        self.beta = transcript.challenge();
        self.gamma = transcript.challenge();

        // 3. Compute running product
        let mut z = vec![Fp::ONE];
        for i in 0..witness.len() {
            let num = witness[i] + self.beta + self.gamma * Fp::new(i as u64);
            let den = self.table[self.find_in_table(witness[i])] + self.beta + self.gamma * Fp::new(i as u64);
            z.push(z[i] * num * den.inverse());
        }

        // 4. Assert z[n] = 1
        assert!(z[witness.len()].is_one(), "Lookup failed: value not in table");

        // 5. Commit to Z and generate FRI proof
        // ...
    }

    /// Verify lookup proof
    pub fn verify(&self, proof: &LookupProof, transcript: &mut Transcript) -> bool {
        // 1. Reconstruct challenges
        // 2. Verify FRI proof for Z column
        // 3. Check boundary constraints Z_0 = 1, Z_n = 1
        // 4. Verify transition constraints
    }
}
```

**Option B: Log-Derivative Lookup (Faster)**

```rust
// src/lookup/log_derivative.rs

/// Log-derivative lookup argument
///
/// Proves: sum_t 1/(W_t + β) = sum_t m_t/(T_t + β)
/// where m_t = multiplicity of T_t in W
///
/// This is typically faster than grand product

pub struct LogDerivativeLookup {
    table: Vec<Fp>,
    multiplicities: Vec<u64>,
    beta: Fp,
}

impl LogDerivativeLookup {
    pub fn prove(&self, witness: &[Fp], transcript: &mut Transcript) -> LookupProof {
        // 1. Count multiplicities
        let mut mult = vec![0u64; self.table.len()];
        for &w in witness {
            let idx = self.find_in_table(w);
            mult[idx] += 1;
        }

        // 2. Get challenge β
        self.beta = transcript.challenge();

        // 3. Compute helper columns for sum verification
        // Left side: sum_t 1/(W_t + β)
        // Right side: sum_t m_t/(T_t + β)

        // 4. Prove equality via running sum column
    }
}
```

### 1.3 Table Generation (Compile-Time)

```rust
// src/lookup/generate.rs

/// Generate all lookup tables at compile time
pub fn generate_xor8_table() -> Vec<(u8, u8, u8)> {
    let mut table = Vec::with_capacity(65536);
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            table.push((a, b, a ^ b));
        }
    }
    table
}

pub fn generate_and8_table() -> Vec<(u8, u8, u8)> {
    let mut table = Vec::with_capacity(65536);
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            table.push((a, b, a & b));
        }
    }
    table
}

pub fn generate_add8c_table() -> Vec<(u8, u8, u8, u8, u8)> {
    let mut table = Vec::with_capacity(131072);
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            for cin in 0..=1u8 {
                let sum = a as u16 + b as u16 + cin as u16;
                let cout = (sum >> 8) as u8;
                let s = (sum & 0xFF) as u8;
                table.push((a, b, cin, s, cout));
            }
        }
    }
    table
}

pub fn generate_carry16_table() -> Vec<(u32, u16, u16)> {
    let mut table = Vec::with_capacity(131072);
    for x in 0..131072u32 {
        let carry = (x >> 16) as u16;
        let rem = (x & 0xFFFF) as u16;
        table.push((x, carry, rem));
    }
    table
}

pub fn generate_rot1byte_table() -> Vec<(u8, u8, u8, u8)> {
    let mut table = Vec::with_capacity(512);
    for byte in 0..=255u8 {
        for carry_in in 0..=1u8 {
            let combined = ((carry_in as u16) << 8) | (byte as u16);
            let rotated = (combined >> 1) | ((combined & 1) << 8);
            let byte_rot = (rotated & 0xFF) as u8;
            let carry_out = ((rotated >> 8) & 1) as u8;
            table.push((byte, carry_in, byte_rot, carry_out));
        }
    }
    table
}
```

### 1.4 Files to Create

```
src/lookup/
├── mod.rs              # Module exports
├── tables.rs           # Table definitions
├── generate.rs         # Table generation
├── grand_product.rs    # Grand product lookup
├── log_derivative.rs   # Log derivative lookup
├── air.rs              # Lookup AIR constraints
└── tests.rs            # Comprehensive tests
```

### 1.5 Tests for Phase 1

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_xor8_lookup() {
        let table = generate_xor8_table();
        let witness = vec![
            (0x12, 0x34, 0x12 ^ 0x34),
            (0xFF, 0x00, 0xFF),
            (0xAB, 0xCD, 0xAB ^ 0xCD),
        ];
        assert!(verify_lookup(&witness, &table));
    }

    #[test]
    fn test_carry16_lookup() {
        let table = generate_carry16_table();
        // Test: 70000 = 4464 + 65536*1
        assert!(table.contains(&(70000, 1, 4464)));
    }

    #[test]
    fn test_lookup_soundness() {
        // Attempt to prove invalid lookup
        let table = generate_u8_table();
        let invalid_witness = vec![256]; // Out of range
        assert!(!can_prove_lookup(&invalid_witness, &table));
    }
}
```

---

## Phase 2: 256-bit Field Emulation (Week 3-4)

### 2.1 Limb Representation

```rust
// src/bigint/mod.rs

/// 256-bit integer represented as 16 × 16-bit limbs
///
/// X = Σ x_i × 2^(16i) for i = 0..15
///
/// Choice: 16-bit limbs with lookup-based carries
/// This is optimal for STARK with lookup tables

pub const LIMB_BITS: usize = 16;
pub const LIMB_COUNT: usize = 16;
pub const LIMB_MAX: u64 = (1 << LIMB_BITS) - 1;

#[derive(Clone, Debug)]
pub struct U256Limbs {
    /// Limbs in little-endian order
    /// limbs[0] is least significant
    pub limbs: [Fp; LIMB_COUNT],
}

impl U256Limbs {
    /// Create from bytes (big-endian, as in crypto standards)
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Self {
        let mut limbs = [Fp::ZERO; LIMB_COUNT];
        for i in 0..16 {
            let hi = bytes[30 - 2*i] as u64;
            let lo = bytes[31 - 2*i] as u64;
            limbs[i] = Fp::new((hi << 8) | lo);
        }
        U256Limbs { limbs }
    }

    /// Convert to bytes (big-endian)
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..16 {
            let limb = self.limbs[i].to_u64();
            bytes[30 - 2*i] = (limb >> 8) as u8;
            bytes[31 - 2*i] = (limb & 0xFF) as u8;
        }
        bytes
    }
}
```

### 2.2 Range Checks via Lookup

```rust
// src/bigint/range.rs

/// Range check all limbs are in [0, 2^16 - 1]
/// Uses U16 lookup table

pub struct LimbRangeCheck {
    lookup: LogDerivativeLookup,
}

impl LimbRangeCheck {
    pub fn check(&self, x: &U256Limbs, transcript: &mut Transcript) -> bool {
        // Each limb must be in U16 table
        for limb in &x.limbs {
            if limb.to_u64() > LIMB_MAX {
                return false;
            }
        }
        // Generate lookup proof
        self.lookup.prove(&x.limbs.to_vec(), transcript)
    }
}
```

### 2.3 Addition with Carries

```rust
// src/bigint/add.rs

/// Add two 256-bit integers with carry propagation
///
/// For each limb i:
///   s_i = a_i + b_i + c_i
///   s_i = r_i + 2^16 × c_{i+1}
///
/// Constrained via CARRY16 lookup

pub struct U256Add;

impl U256Add {
    /// Compute a + b, returning (sum, overflow)
    pub fn add(a: &U256Limbs, b: &U256Limbs) -> (U256Limbs, bool) {
        let mut result = [Fp::ZERO; LIMB_COUNT];
        let mut carry = Fp::ZERO;

        for i in 0..LIMB_COUNT {
            let sum = a.limbs[i] + b.limbs[i] + carry;
            let sum_val = sum.to_u64();
            result[i] = Fp::new(sum_val & LIMB_MAX);
            carry = Fp::new(sum_val >> LIMB_BITS);
        }

        (U256Limbs { limbs: result }, !carry.is_zero())
    }

    /// Generate AIR constraints for addition
    pub fn constrain_add(
        a: &[Column; LIMB_COUNT],
        b: &[Column; LIMB_COUNT],
        result: &[Column; LIMB_COUNT],
        carries: &[Column; LIMB_COUNT + 1],
    ) -> Vec<Constraint> {
        let mut constraints = Vec::new();

        // c_0 = 0 (no initial carry)
        constraints.push(carries[0].eq(Fp::ZERO));

        // For each limb: a_i + b_i + c_i = r_i + 2^16 × c_{i+1}
        for i in 0..LIMB_COUNT {
            let sum = a[i] + b[i] + carries[i];
            let expected = result[i] + carries[i + 1] * Fp::new(1 << LIMB_BITS);
            constraints.push(sum.eq(expected));

            // Carry is 0 or 1
            constraints.push(carries[i + 1] * (carries[i + 1] - Fp::ONE).eq(Fp::ZERO));
        }

        constraints
    }
}
```

### 2.4 Multiplication

```rust
// src/bigint/mul.rs

/// Multiply two 256-bit integers
///
/// Schoolbook multiplication:
/// t_k = Σ_{i+j=k} a_i × b_j
///
/// Then propagate carries

pub struct U256Mul;

impl U256Mul {
    /// Compute a × b mod 2^256 (truncated)
    pub fn mul_truncated(a: &U256Limbs, b: &U256Limbs) -> U256Limbs {
        // Compute full 512-bit product
        let mut product = [0u128; LIMB_COUNT * 2];

        for i in 0..LIMB_COUNT {
            for j in 0..LIMB_COUNT {
                let prod = a.limbs[i].to_u64() as u128 * b.limbs[j].to_u64() as u128;
                product[i + j] += prod;
            }
        }

        // Propagate carries and truncate to 256 bits
        let mut result = [Fp::ZERO; LIMB_COUNT];
        let mut carry = 0u128;

        for i in 0..LIMB_COUNT {
            let sum = product[i] + carry;
            result[i] = Fp::new((sum & LIMB_MAX as u128) as u64);
            carry = sum >> LIMB_BITS;
        }

        U256Limbs { limbs: result }
    }

    /// Compute full 512-bit product (needed for reduction)
    pub fn mul_full(a: &U256Limbs, b: &U256Limbs) -> [Fp; LIMB_COUNT * 2] {
        // ... similar but return all 32 limbs
    }
}
```

### 2.5 Modular Reduction

```rust
// src/bigint/reduce.rs

/// Modular reduction for specific primes
///
/// Ed25519 field: p = 2^255 - 19
/// secp256k1 field: p = 2^256 - 2^32 - 977
/// secp256k1 order: n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

/// Ed25519 field modulus
pub const ED25519_P: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED,
];

/// secp256k1 field modulus
pub const SECP256K1_P: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
];

/// secp256k1 group order
pub const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

pub struct ModularReduce;

impl ModularReduce {
    /// Reduce mod Ed25519 prime p = 2^255 - 19
    ///
    /// Strategy: fold high bits back with factor 19
    /// If x = x_lo + 2^255 × x_hi, then
    /// x ≡ x_lo + 19 × x_hi (mod p)
    pub fn reduce_ed25519(x: &[Fp; 32]) -> U256Limbs {
        // Split at bit 255 (limb 15, bit 15)
        let mut lo = [Fp::ZERO; LIMB_COUNT];
        lo.copy_from_slice(&x[0..16]);

        // Clear top bit of limb 15
        let top_bit = (lo[15].to_u64() >> 15) & 1;
        lo[15] = Fp::new(lo[15].to_u64() & 0x7FFF);

        // High part (bits 255..511)
        let mut hi = [Fp::ZERO; LIMB_COUNT];
        hi[0] = Fp::new(top_bit); // bit 255
        for i in 0..16 {
            if i + 16 < 32 {
                hi[i] = hi[i] + x[i + 16];
            }
        }

        // Multiply hi by 19 and add to lo
        let hi_times_19 = Self::mul_by_small(&hi, 19);
        let (result, overflow) = U256Add::add(
            &U256Limbs { limbs: lo },
            &U256Limbs { limbs: hi_times_19 },
        );

        // May need one more reduction
        if overflow || Self::gte_p_ed25519(&result) {
            Self::sub_p_ed25519(&result)
        } else {
            result
        }
    }

    /// Reduce mod secp256k1 prime p = 2^256 - 2^32 - 977
    pub fn reduce_secp256k1(x: &[Fp; 32]) -> U256Limbs {
        // Similar strategy: fold high bits
        // 2^256 ≡ 2^32 + 977 (mod p)
        // ... implementation
    }

    fn mul_by_small(x: &[Fp; LIMB_COUNT], k: u64) -> [Fp; LIMB_COUNT] {
        let mut result = [Fp::ZERO; LIMB_COUNT];
        let mut carry = 0u64;

        for i in 0..LIMB_COUNT {
            let prod = x[i].to_u64() * k + carry;
            result[i] = Fp::new(prod & LIMB_MAX);
            carry = prod >> LIMB_BITS;
        }

        result
    }
}
```

### 2.6 Witness Inverse (Critical Optimization)

```rust
// src/bigint/inverse.rs

/// Modular inverse via witness + multiplication check
///
/// Instead of computing x^(-1) in-circuit (expensive!),
/// we make x^(-1) a witness and verify:
///   x × x^(-1) ≡ 1 (mod n)
///
/// This is a single multiplication, not exponentiation!

pub struct WitnessInverse;

impl WitnessInverse {
    /// Given x and claimed inverse w, verify x*w ≡ 1 (mod n)
    pub fn verify_inverse(
        x: &U256Limbs,
        w: &U256Limbs, // witness inverse
        modulus: &U256Limbs,
    ) -> bool {
        // Compute x * w
        let product = U256Mul::mul_full(x, w);

        // Reduce mod n
        let reduced = ModularReduce::reduce_generic(&product, modulus);

        // Check result is 1
        reduced.is_one()
    }

    /// Generate AIR constraints for inverse verification
    pub fn constrain_inverse(
        x: &[Column; LIMB_COUNT],
        w: &[Column; LIMB_COUNT],
        modulus: &[Fp; LIMB_COUNT],
    ) -> Vec<Constraint> {
        // Product columns (intermediate)
        // Reduction columns (intermediate)
        // Final check: result = 1
    }
}
```

### 2.7 Files to Create

```
src/bigint/
├── mod.rs          # Module exports
├── limbs.rs        # U256Limbs type
├── range.rs        # Range checks
├── add.rs          # Addition
├── sub.rs          # Subtraction
├── mul.rs          # Multiplication
├── reduce.rs       # Modular reduction
├── inverse.rs      # Witness inverse
├── compare.rs      # Comparison
└── tests.rs        # Comprehensive tests
```

---

## Phase 3: Poseidon AIR (Week 5)

### 3.1 Poseidon Specification

```rust
// src/poseidon/mod.rs

/// Poseidon hash for Goldilocks field
///
/// Parameters (pinned):
/// - State width: t = 12
/// - Capacity: c = 4
/// - Rate: r = 8
/// - Full rounds: R_f = 8 (4 before, 4 after partial)
/// - Partial rounds: R_p = 22
/// - S-box: x^7 (optimal for Goldilocks)

pub const POSEIDON_T: usize = 12;      // State width
pub const POSEIDON_C: usize = 4;       // Capacity
pub const POSEIDON_R: usize = 8;       // Rate
pub const POSEIDON_RF: usize = 8;      // Full rounds total
pub const POSEIDON_RP: usize = 22;     // Partial rounds
pub const POSEIDON_SBOX_EXP: u64 = 7;  // x^7

/// MDS matrix (12x12 for t=12)
/// Cauchy matrix construction for security
pub const POSEIDON_MDS: [[Fp; POSEIDON_T]; POSEIDON_T] = [
    // ... 12x12 matrix values
];

/// Round constants (RF + RP rounds × t elements)
pub const POSEIDON_RC: [[Fp; POSEIDON_T]; POSEIDON_RF + POSEIDON_RP] = [
    // ... precomputed round constants
];
```

### 3.2 S-box Computation

```rust
// src/poseidon/sbox.rs

/// S-box: x^7 in Goldilocks field
///
/// Compute efficiently as:
/// x² = x × x
/// x³ = x² × x
/// x⁶ = x³ × x³
/// x⁷ = x⁶ × x
///
/// 4 multiplications total

pub fn sbox(x: Fp) -> Fp {
    let x2 = x * x;
    let x3 = x2 * x;
    let x6 = x3 * x3;
    x6 * x
}

/// AIR constraints for S-box
///
/// Columns: x, x2, x3, x6, x7
/// Constraints:
/// - x2 = x * x
/// - x3 = x2 * x
/// - x6 = x3 * x3
/// - x7 = x6 * x
pub fn sbox_constraints(
    x: Column,
    x2: Column,
    x3: Column,
    x6: Column,
    x7: Column,
) -> Vec<Constraint> {
    vec![
        x2.eq(x * x),
        x3.eq(x2 * x),
        x6.eq(x3 * x3),
        x7.eq(x6 * x),
    ]
}
```

### 3.3 Full Round AIR

```rust
// src/poseidon/round.rs

/// Full round: all S-boxes active
///
/// 1. Add round constants
/// 2. Apply S-box to ALL elements
/// 3. Multiply by MDS matrix

pub fn full_round_constraints(
    state_in: &[Column; POSEIDON_T],
    state_out: &[Column; POSEIDON_T],
    round_constants: &[Fp; POSEIDON_T],
    sbox_intermediates: &[[Column; 4]; POSEIDON_T], // x2, x3, x6, x7 for each
) -> Vec<Constraint> {
    let mut constraints = Vec::new();

    // Step 1+2: Add constants and apply S-box
    for i in 0..POSEIDON_T {
        let x = state_in[i] + Fp::from(round_constants[i]);
        let (x2, x3, x6, x7) = (
            sbox_intermediates[i][0],
            sbox_intermediates[i][1],
            sbox_intermediates[i][2],
            sbox_intermediates[i][3],
        );
        constraints.extend(sbox_constraints(x, x2, x3, x6, x7));
    }

    // Step 3: MDS matrix
    for i in 0..POSEIDON_T {
        let mut sum = Column::zero();
        for j in 0..POSEIDON_T {
            sum = sum + POSEIDON_MDS[i][j] * sbox_intermediates[j][3]; // x7
        }
        constraints.push(state_out[i].eq(sum));
    }

    constraints
}
```

### 3.4 Partial Round AIR

```rust
/// Partial round: only first element gets S-box
///
/// 1. Add round constants
/// 2. Apply S-box to state[0] ONLY
/// 3. Multiply by MDS matrix

pub fn partial_round_constraints(
    state_in: &[Column; POSEIDON_T],
    state_out: &[Column; POSEIDON_T],
    round_constants: &[Fp; POSEIDON_T],
    sbox_intermediate: &[Column; 4], // Only for state[0]
) -> Vec<Constraint> {
    let mut constraints = Vec::new();

    // S-box only on first element
    let x0 = state_in[0] + round_constants[0];
    constraints.extend(sbox_constraints(
        x0,
        sbox_intermediate[0],
        sbox_intermediate[1],
        sbox_intermediate[2],
        sbox_intermediate[3],
    ));

    // MDS: first element uses x7, others use state_in + rc
    for i in 0..POSEIDON_T {
        let mut sum = POSEIDON_MDS[i][0] * sbox_intermediate[3];
        for j in 1..POSEIDON_T {
            sum = sum + POSEIDON_MDS[i][j] * (state_in[j] + round_constants[j]);
        }
        constraints.push(state_out[i].eq(sum));
    }

    constraints
}
```

### 3.5 Files to Create

```
src/poseidon/
├── mod.rs          # Module exports, parameters
├── constants.rs    # MDS matrix, round constants
├── sbox.rs         # S-box computation
├── round.rs        # Round constraints
├── hash.rs         # Complete hash function
├── air.rs          # Full AIR for Poseidon
└── tests.rs        # Test vectors
```

---

## Phase 4: Keccak-256 AIR (Week 6-7)

### 4.1 State Representation

```rust
// src/keccak/state.rs

/// Keccak-256 state as 200 bytes (25 lanes × 8 bytes)
///
/// Bytewise representation is KEY for lookup-based operations
///
/// Lane[x][y] = bytes[8*(5*y + x) .. 8*(5*y + x) + 8]

pub const KECCAK_STATE_BYTES: usize = 200;
pub const KECCAK_LANES: usize = 25;
pub const KECCAK_LANE_BYTES: usize = 8;
pub const KECCAK_ROUNDS: usize = 24;

#[derive(Clone)]
pub struct KeccakState {
    /// State as 200 bytes (little-endian within lanes)
    pub bytes: [Fp; KECCAK_STATE_BYTES],
}

impl KeccakState {
    /// Get lane[x][y] as 8 bytes
    pub fn get_lane(&self, x: usize, y: usize) -> [Fp; 8] {
        let offset = 8 * (5 * y + x);
        let mut lane = [Fp::ZERO; 8];
        lane.copy_from_slice(&self.bytes[offset..offset + 8]);
        lane
    }

    /// Set lane[x][y]
    pub fn set_lane(&mut self, x: usize, y: usize, lane: &[Fp; 8]) {
        let offset = 8 * (5 * y + x);
        self.bytes[offset..offset + 8].copy_from_slice(lane);
    }
}
```

### 4.2 Round Constants

```rust
// src/keccak/constants.rs

/// Keccak round constants (RC)
pub const KECCAK_RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Rotation offsets for ρ step
pub const KECCAK_RHO_OFFSETS: [[usize; 5]; 5] = [
    [ 0, 36,  3, 41, 18],
    [ 1, 44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
];

/// π step permutation: (x,y) -> (y, 2x+3y mod 5)
pub fn pi_permute(x: usize, y: usize) -> (usize, usize) {
    (y, (2 * x + 3 * y) % 5)
}
```

### 4.3 Theta Step (Bytewise with Lookups)

```rust
// src/keccak/theta.rs

/// θ step: XOR each lane with parity of columns
///
/// C[x] = A[x,0] ⊕ A[x,1] ⊕ A[x,2] ⊕ A[x,3] ⊕ A[x,4]
/// D[x] = C[x-1] ⊕ ROT1(C[x+1])
/// A'[x,y] = A[x,y] ⊕ D[x]
///
/// Bytewise: use XOR8 lookup for all XORs
/// ROT1: use ROT1BYTE lookup

pub fn theta_constraints(
    state_in: &KeccakStateColumns,
    state_out: &KeccakStateColumns,
    c_columns: &[[Column; 8]; 5],      // Parity of each column
    d_columns: &[[Column; 8]; 5],      // D values
    rot1_carries: &[[Column; 8]; 5],   // Carry bits for ROT1
    lookup: &mut LookupAccumulator,
) -> Vec<Constraint> {
    let mut constraints = Vec::new();

    // Compute C[x] = XOR of column x (5-way XOR, bytewise)
    for x in 0..5 {
        for byte_idx in 0..8 {
            // C[x][byte] = A[x,0][byte] ⊕ A[x,1][byte] ⊕ ... ⊕ A[x,4][byte]
            // Chain of XOR8 lookups
            let mut acc = state_in.get_lane_byte(x, 0, byte_idx);
            for y in 1..5 {
                let next = state_in.get_lane_byte(x, y, byte_idx);
                let result = Column::new(); // intermediate
                lookup.add_xor8(acc, next, result);
                acc = result;
            }
            constraints.push(c_columns[x][byte_idx].eq(acc));
        }
    }

    // Compute D[x] = C[x-1] ⊕ ROT1(C[x+1])
    for x in 0..5 {
        let x_minus_1 = (x + 4) % 5;
        let x_plus_1 = (x + 1) % 5;

        // ROT1 on C[x+1]: rotate entire 64-bit lane by 1 bit
        // Bytewise: use ROT1BYTE table with carry propagation
        let mut carry = Column::zero();
        for byte_idx in 0..8 {
            let byte_in = c_columns[x_plus_1][byte_idx];
            let byte_out = Column::new();
            let carry_out = rot1_carries[x_plus_1][byte_idx];

            lookup.add_rot1byte(byte_in, carry, byte_out, carry_out);
            carry = carry_out;

            // XOR with C[x-1]
            let d_byte = Column::new();
            lookup.add_xor8(c_columns[x_minus_1][byte_idx], byte_out, d_byte);
            constraints.push(d_columns[x][byte_idx].eq(d_byte));
        }
        // Final carry wraps to first byte (handled in ROT1)
    }

    // Apply D[x] to all lanes in column x
    for x in 0..5 {
        for y in 0..5 {
            for byte_idx in 0..8 {
                let in_byte = state_in.get_lane_byte(x, y, byte_idx);
                let out_byte = state_out.get_lane_byte(x, y, byte_idx);
                lookup.add_xor8(in_byte, d_columns[x][byte_idx], out_byte);
            }
        }
    }

    constraints
}
```

### 4.4 Rho and Pi Steps

```rust
// src/keccak/rho_pi.rs

/// ρ step: rotate each lane by fixed offset
/// π step: permute lane positions
///
/// Combined because they're both permutations

pub fn rho_pi_constraints(
    state_in: &KeccakStateColumns,   // After θ
    state_out: &KeccakStateColumns,  // Before χ
    shift_tables: &ShiftTables,
    lookup: &mut LookupAccumulator,
) -> Vec<Constraint> {
    let mut constraints = Vec::new();

    for x in 0..5 {
        for y in 0..5 {
            let rot = KECCAK_RHO_OFFSETS[y][x];
            let (new_x, new_y) = pi_permute(x, y);

            if rot == 0 {
                // No rotation, just permute
                for byte_idx in 0..8 {
                    let in_byte = state_in.get_lane_byte(x, y, byte_idx);
                    let out_byte = state_out.get_lane_byte(new_x, new_y, byte_idx);
                    constraints.push(out_byte.eq(in_byte));
                }
            } else {
                // Rotation by 'rot' bits
                // Decompose into byte shift + bit shift
                let byte_shift = rot / 8;
                let bit_shift = rot % 8;

                for byte_idx in 0..8 {
                    let src_byte_idx = (byte_idx + 8 - byte_shift) % 8;
                    let in_byte = state_in.get_lane_byte(x, y, src_byte_idx);

                    if bit_shift == 0 {
                        let out_byte = state_out.get_lane_byte(new_x, new_y, byte_idx);
                        constraints.push(out_byte.eq(in_byte));
                    } else {
                        // Use SHIFTk lookup
                        let next_byte_idx = (src_byte_idx + 7) % 8;
                        let next_byte = state_in.get_lane_byte(x, y, next_byte_idx);
                        let out_byte = state_out.get_lane_byte(new_x, new_y, byte_idx);

                        lookup.add_shift(in_byte, next_byte, bit_shift, out_byte);
                    }
                }
            }
        }
    }

    constraints
}
```

### 4.5 Chi Step

```rust
// src/keccak/chi.rs

/// χ step: non-linear mixing
///
/// A'[x,y] = A[x,y] ⊕ ((¬A[x+1,y]) ∧ A[x+2,y])
///
/// Bytewise: use NOT8, AND8, XOR8 lookups

pub fn chi_constraints(
    state_in: &KeccakStateColumns,
    state_out: &KeccakStateColumns,
    not_columns: &KeccakStateColumns,  // Intermediate ¬A[x+1,y]
    and_columns: &KeccakStateColumns,  // Intermediate (¬A[x+1,y]) ∧ A[x+2,y]
    lookup: &mut LookupAccumulator,
) -> Vec<Constraint> {
    let mut constraints = Vec::new();

    for y in 0..5 {
        for x in 0..5 {
            let x_plus_1 = (x + 1) % 5;
            let x_plus_2 = (x + 2) % 5;

            for byte_idx in 0..8 {
                // NOT A[x+1,y]
                let a_x1 = state_in.get_lane_byte(x_plus_1, y, byte_idx);
                let not_a_x1 = not_columns.get_lane_byte(x, y, byte_idx);
                lookup.add_not8(a_x1, not_a_x1);

                // (NOT A[x+1,y]) AND A[x+2,y]
                let a_x2 = state_in.get_lane_byte(x_plus_2, y, byte_idx);
                let and_result = and_columns.get_lane_byte(x, y, byte_idx);
                lookup.add_and8(not_a_x1, a_x2, and_result);

                // A[x,y] XOR and_result
                let a_xy = state_in.get_lane_byte(x, y, byte_idx);
                let out = state_out.get_lane_byte(x, y, byte_idx);
                lookup.add_xor8(a_xy, and_result, out);
            }
        }
    }

    constraints
}
```

### 4.6 Iota Step

```rust
// src/keccak/iota.rs

/// ι step: XOR round constant into lane[0][0]

pub fn iota_constraints(
    state_in: &KeccakStateColumns,
    state_out: &KeccakStateColumns,
    round: usize,
    lookup: &mut LookupAccumulator,
) -> Vec<Constraint> {
    let rc = KECCAK_RC[round];
    let rc_bytes = rc.to_le_bytes();

    let mut constraints = Vec::new();

    // XOR RC into lane[0][0]
    for byte_idx in 0..8 {
        let in_byte = state_in.get_lane_byte(0, 0, byte_idx);
        let out_byte = state_out.get_lane_byte(0, 0, byte_idx);
        let rc_byte = Fp::new(rc_bytes[byte_idx] as u64);

        // out = in XOR rc_byte (constant)
        // Use XOR8 lookup with constant
        lookup.add_xor8_const(in_byte, rc_byte, out_byte);
    }

    // All other lanes unchanged
    for x in 0..5 {
        for y in 0..5 {
            if x == 0 && y == 0 { continue; }
            for byte_idx in 0..8 {
                let in_byte = state_in.get_lane_byte(x, y, byte_idx);
                let out_byte = state_out.get_lane_byte(x, y, byte_idx);
                constraints.push(out_byte.eq(in_byte));
            }
        }
    }

    constraints
}
```

### 4.7 Files to Create

```
src/keccak/
├── mod.rs          # Module exports
├── constants.rs    # Round constants, rotation offsets
├── state.rs        # State representation
├── theta.rs        # θ step
├── rho_pi.rs       # ρ and π steps
├── chi.rs          # χ step
├── iota.rs         # ι step
├── round.rs        # Complete round
├── hash.rs         # Keccak-256 hash function
├── air.rs          # Full AIR
└── tests.rs        # Test vectors (Ethereum compatible)
```

---

## Phase 5: Ed25519 + EdDSA AIR (Week 8-9)

### 5.1 Curve Parameters

```rust
// src/ed25519/params.rs

/// Ed25519 curve: -x² + y² = 1 + d·x²·y² (mod p)
///
/// p = 2^255 - 19
/// d = -121665/121666 mod p
/// Base point B = (Bx, By)
/// Order L = 2^252 + 27742317777372353535851937790883648493

pub const ED25519_D: [u8; 32] = [
    // d = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
    0x52, 0x03, 0x6c, 0xee, 0x2b, 0x6f, 0xfe, 0x73,
    0x8c, 0xc7, 0x40, 0x79, 0x77, 0x79, 0xe8, 0x98,
    0x00, 0x70, 0x0a, 0x4d, 0x41, 0x41, 0xd8, 0xab,
    0x75, 0xeb, 0x4d, 0xca, 0x13, 0x59, 0x78, 0xa3,
];

pub const ED25519_BX: [u8; 32] = [
    // Bx = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
    // ...
];

pub const ED25519_BY: [u8; 32] = [
    // By = 0x6666666666666666666666666666666666666666666666666666666666666658
    // ...
];

pub const ED25519_L: [u8; 32] = [
    // L = 2^252 + 27742317777372353535851937790883648493
    // ...
];
```

### 5.2 Point Operations

```rust
// src/ed25519/point.rs

/// Edwards curve point in extended coordinates (X, Y, Z, T)
/// where x = X/Z, y = Y/Z, x·y = T/Z

pub struct EdwardsPoint {
    pub x: U256Limbs,
    pub y: U256Limbs,
    pub z: U256Limbs,
    pub t: U256Limbs,
}

impl EdwardsPoint {
    /// Point addition (unified formula, works for all cases)
    ///
    /// A = X1 · X2
    /// B = Y1 · Y2
    /// C = T1 · d · T2
    /// D = Z1 · Z2
    /// E = (X1 + Y1) · (X2 + Y2) - A - B
    /// F = D - C
    /// G = D + C
    /// H = B - a·A  (a = -1 for Ed25519)
    /// X3 = E · F
    /// Y3 = G · H
    /// T3 = E · H
    /// Z3 = F · G
    pub fn add(&self, other: &EdwardsPoint, field: &Ed25519Field) -> EdwardsPoint {
        let a = field.mul(&self.x, &other.x);
        let b = field.mul(&self.y, &other.y);
        let c = field.mul(&field.mul(&self.t, &other.t), &field.d());
        let d = field.mul(&self.z, &other.z);

        let x1_plus_y1 = field.add(&self.x, &self.y);
        let x2_plus_y2 = field.add(&other.x, &other.y);
        let e = field.sub(&field.mul(&x1_plus_y1, &x2_plus_y2), &field.add(&a, &b));

        let f = field.sub(&d, &c);
        let g = field.add(&d, &c);
        let h = field.add(&b, &a); // B - (-1)·A = B + A

        EdwardsPoint {
            x: field.mul(&e, &f),
            y: field.mul(&g, &h),
            t: field.mul(&e, &h),
            z: field.mul(&f, &g),
        }
    }

    /// Point doubling (faster than generic add)
    pub fn double(&self, field: &Ed25519Field) -> EdwardsPoint {
        let a = field.square(&self.x);
        let b = field.square(&self.y);
        let c = field.mul_by_2(&field.square(&self.z));
        let h = field.add(&a, &b);
        let e = field.sub(&h, &field.square(&field.add(&self.x, &self.y)));
        let g = field.sub(&a, &b);
        let f = field.add(&c, &g);

        EdwardsPoint {
            x: field.mul(&e, &f),
            y: field.mul(&g, &h),
            t: field.mul(&e, &h),
            z: field.mul(&f, &g),
        }
    }
}
```

### 5.3 Scalar Multiplication with Precomputed Tables

```rust
// src/ed25519/scalar_mul.rs

/// Fixed-base scalar multiplication using precomputed table
///
/// For base point B, precompute:
/// TABLE[i] = 2^(4i) · B  for i = 0..63
///
/// Then for scalar k with 4-bit windows:
/// k·B = Σ k_i · TABLE[i]

pub const WINDOW_SIZE: usize = 4;
pub const NUM_WINDOWS: usize = 64; // 256 / 4

pub struct FixedBaseTable {
    /// TABLE[i][j] = j · 2^(4i) · B for j in 0..15
    pub points: [[EdwardsPoint; 16]; NUM_WINDOWS],
}

impl FixedBaseTable {
    /// Precompute table for base point B
    pub fn new(base: &EdwardsPoint, field: &Ed25519Field) -> Self {
        let mut table = [[EdwardsPoint::identity(); 16]; NUM_WINDOWS];

        let mut power = base.clone();
        for i in 0..NUM_WINDOWS {
            // TABLE[i][0] = identity
            // TABLE[i][j] = j · power for j = 1..15
            table[i][0] = EdwardsPoint::identity();
            table[i][1] = power.clone();
            for j in 2..16 {
                table[i][j] = table[i][j-1].add(&power, field);
            }

            // power *= 2^4
            for _ in 0..4 {
                power = power.double(field);
            }
        }

        FixedBaseTable { points: table }
    }

    /// Compute k·B using table lookup
    pub fn scalar_mul(&self, k: &U256Limbs, field: &Ed25519Field) -> EdwardsPoint {
        let mut result = EdwardsPoint::identity();
        let k_bytes = k.to_bytes_be();

        for i in 0..NUM_WINDOWS {
            // Extract 4-bit window
            let byte_idx = i / 2;
            let nibble_idx = i % 2;
            let nibble = if nibble_idx == 0 {
                k_bytes[31 - byte_idx] & 0x0F
            } else {
                (k_bytes[31 - byte_idx] >> 4) & 0x0F
            };

            // Add TABLE[i][nibble]
            result = result.add(&self.points[i][nibble as usize], field);
        }

        result
    }
}
```

### 5.4 EdDSA Verification AIR

```rust
// src/ed25519/eddsa_air.rs

/// EdDSA verification: [S]B = R + [h]A
///
/// Inputs (public):
/// - A: public key (point)
/// - R: signature point
/// - S: signature scalar
/// - h: hash of (R || A || message), reduced mod L
///
/// Verification:
/// 1. Compute [S]B using fixed-base table
/// 2. Compute [h]A using variable-base scalar mul
/// 3. Compute R + [h]A
/// 4. Check equality with [S]B

pub struct EdDSAVerificationAir {
    /// Columns for [S]B computation
    sb_columns: ScalarMulColumns,
    /// Columns for [h]A computation
    ha_columns: ScalarMulColumns,
    /// Columns for R + [h]A
    add_columns: PointAddColumns,
    /// Final comparison columns
    compare_columns: CompareColumns,
}

impl EdDSAVerificationAir {
    pub fn constraints(
        &self,
        public_key: &EdwardsPointWitness,
        signature_r: &EdwardsPointWitness,
        signature_s: &U256Witness,
        hash_h: &U256Witness,
    ) -> Vec<Constraint> {
        let mut constraints = Vec::new();

        // 1. [S]B - fixed base scalar multiplication
        constraints.extend(
            self.sb_columns.fixed_base_constraints(signature_s, &PRECOMPUTED_B_TABLE)
        );

        // 2. [h]A - variable base scalar multiplication
        constraints.extend(
            self.ha_columns.variable_base_constraints(hash_h, public_key)
        );

        // 3. R + [h]A
        constraints.extend(
            self.add_columns.point_add_constraints(signature_r, &self.ha_columns.result)
        );

        // 4. [S]B == R + [h]A
        constraints.extend(
            self.compare_columns.point_equality_constraints(
                &self.sb_columns.result,
                &self.add_columns.result,
            )
        );

        constraints
    }
}
```

### 5.5 Files to Create

```
src/ed25519/
├── mod.rs              # Module exports
├── params.rs           # Curve parameters
├── field.rs            # Field operations (uses bigint)
├── point.rs            # Point operations
├── scalar_mul.rs       # Scalar multiplication
├── precompute.rs       # Table precomputation
├── eddsa_verify.rs     # EdDSA verification logic
├── air.rs              # Complete AIR
└── tests.rs            # Test vectors (RFC 8032)
```

---

## Phase 6: secp256k1 + ECDSA AIR (Week 10-12)

### 6.1 Curve Parameters

```rust
// src/secp256k1/params.rs

/// secp256k1 curve: y² = x³ + 7 (mod p)
///
/// p = 2^256 - 2^32 - 977
/// n = order of generator G
/// G = (Gx, Gy)

pub const SECP256K1_A: u64 = 0;
pub const SECP256K1_B: u64 = 7;

pub const SECP256K1_GX: [u8; 32] = [
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
];

pub const SECP256K1_GY: [u8; 32] = [
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
    0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
    0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
];
```

### 6.2 Point Operations (Jacobian Coordinates)

```rust
// src/secp256k1/point.rs

/// Point in Jacobian coordinates (X, Y, Z)
/// where x = X/Z², y = Y/Z³
///
/// Avoids field inversions until final conversion

pub struct JacobianPoint {
    pub x: U256Limbs,
    pub y: U256Limbs,
    pub z: U256Limbs,
}

impl JacobianPoint {
    /// Point doubling in Jacobian coordinates
    ///
    /// For y² = x³ + 7:
    /// A = Y1²
    /// B = 4·X1·A
    /// C = 8·A²
    /// D = 3·X1²
    /// X3 = D² - 2·B
    /// Y3 = D·(B - X3) - C
    /// Z3 = 2·Y1·Z1
    pub fn double(&self, field: &Secp256k1Field) -> JacobianPoint {
        let a = field.square(&self.y);
        let b = field.mul_by_4(&field.mul(&self.x, &a));
        let c = field.mul_by_8(&field.square(&a));
        let d = field.mul_by_3(&field.square(&self.x));

        let x3 = field.sub(&field.square(&d), &field.mul_by_2(&b));
        let y3 = field.sub(&field.mul(&d, &field.sub(&b, &x3)), &c);
        let z3 = field.mul_by_2(&field.mul(&self.y, &self.z));

        JacobianPoint { x: x3, y: y3, z: z3 }
    }

    /// Point addition (mixed: Jacobian + Affine)
    pub fn add_affine(&self, other: &AffinePoint, field: &Secp256k1Field) -> JacobianPoint {
        // ... standard formulas
    }

    /// Convert to affine (requires inverse)
    pub fn to_affine(&self, field: &Secp256k1Field) -> AffinePoint {
        let z_inv = field.inverse(&self.z);
        let z_inv2 = field.square(&z_inv);
        let z_inv3 = field.mul(&z_inv2, &z_inv);

        AffinePoint {
            x: field.mul(&self.x, &z_inv2),
            y: field.mul(&self.y, &z_inv3),
        }
    }
}
```

### 6.3 ECDSA Verification AIR

```rust
// src/secp256k1/ecdsa_air.rs

/// ECDSA verification
///
/// Given: (r, s) signature, z = hash(message), Q = public key
///
/// 1. w = s⁻¹ mod n  (WITNESS, verified by s·w = 1 mod n)
/// 2. u1 = z·w mod n
/// 3. u2 = r·w mod n
/// 4. P = u1·G + u2·Q
/// 5. Accept iff P.x mod n = r

pub struct ECDSAVerificationAir {
    /// Witness for s⁻¹
    w_witness: U256Witness,
    /// u1 computation columns
    u1_columns: MulModColumns,
    /// u2 computation columns
    u2_columns: MulModColumns,
    /// u1·G computation
    u1g_columns: ScalarMulColumns,
    /// u2·Q computation
    u2q_columns: ScalarMulColumns,
    /// P = u1·G + u2·Q
    p_add_columns: PointAddColumns,
    /// Final check: P.x mod n = r
    final_check: CompareColumns,
}

impl ECDSAVerificationAir {
    pub fn constraints(
        &self,
        r: &U256Witness,
        s: &U256Witness,
        z: &U256Witness,
        public_key: &AffinePointWitness,
    ) -> Vec<Constraint> {
        let mut constraints = Vec::new();

        // 1. Verify w is inverse of s: s·w ≡ 1 (mod n)
        constraints.extend(
            verify_inverse_constraints(s, &self.w_witness, &SECP256K1_N)
        );

        // 2. u1 = z·w mod n
        constraints.extend(
            self.u1_columns.mul_mod_constraints(z, &self.w_witness, &SECP256K1_N)
        );

        // 3. u2 = r·w mod n
        constraints.extend(
            self.u2_columns.mul_mod_constraints(r, &self.w_witness, &SECP256K1_N)
        );

        // 4a. u1·G (fixed base)
        constraints.extend(
            self.u1g_columns.fixed_base_constraints(&self.u1_columns.result, &PRECOMPUTED_G_TABLE)
        );

        // 4b. u2·Q (variable base)
        constraints.extend(
            self.u2q_columns.variable_base_constraints(&self.u2_columns.result, public_key)
        );

        // 4c. P = u1·G + u2·Q
        constraints.extend(
            self.p_add_columns.point_add_constraints(
                &self.u1g_columns.result,
                &self.u2q_columns.result,
            )
        );

        // 5. P.x mod n = r
        let p_affine = self.p_add_columns.result.to_affine_columns();
        constraints.extend(
            self.final_check.mod_equality_constraints(&p_affine.x, r, &SECP256K1_N)
        );

        constraints
    }
}
```

### 6.4 Files to Create

```
src/secp256k1/
├── mod.rs              # Module exports
├── params.rs           # Curve parameters
├── field.rs            # Field operations
├── point.rs            # Point operations (Jacobian)
├── scalar_mul.rs       # Scalar multiplication
├── precompute.rs       # Table precomputation for G
├── ecdsa_verify.rs     # ECDSA verification logic
├── air.rs              # Complete AIR
└── tests.rs            # Test vectors
```

---

## Phase 7: Integration & Benchmarks (Week 13-14)

### 7.1 Unified Benchmark Harness

```rust
// src/bench/harness.rs

pub trait Benchmark {
    fn name(&self) -> &str;
    fn setup(&mut self);
    fn prove(&mut self) -> ProofResult;
    fn verify(&self, proof: &ProofResult) -> bool;
}

pub struct BenchmarkRunner {
    benchmarks: Vec<Box<dyn Benchmark>>,
}

impl BenchmarkRunner {
    pub fn run_all(&mut self) -> BenchmarkReport {
        let mut results = Vec::new();

        for bench in &mut self.benchmarks {
            bench.setup();

            // Prove
            let prove_start = Instant::now();
            let proof = bench.prove();
            let prove_time = prove_start.elapsed();

            // Verify
            let verify_start = Instant::now();
            let valid = bench.verify(&proof);
            let verify_time = verify_start.elapsed();

            results.push(BenchmarkResult {
                name: bench.name().to_string(),
                prove_time,
                verify_time,
                proof_size: proof.size(),
                valid,
            });
        }

        BenchmarkReport { results }
    }
}
```

### 7.2 Complete File Structure

```
src/
├── lib.rs
├── field.rs                 # Goldilocks field (existing)
├── sha256.rs                # SHA-256 (existing)
├── fri.rs                   # FRI protocol (existing)
├── merkle.rs                # Merkle trees (existing)
├── transcript.rs            # Fiat-Shamir (existing)
│
├── lookup/                  # Phase 1: Lookups
│   ├── mod.rs
│   ├── tables.rs
│   ├── generate.rs
│   ├── grand_product.rs
│   ├── log_derivative.rs
│   └── tests.rs
│
├── bigint/                  # Phase 2: 256-bit arithmetic
│   ├── mod.rs
│   ├── limbs.rs
│   ├── add.rs
│   ├── mul.rs
│   ├── reduce.rs
│   ├── inverse.rs
│   └── tests.rs
│
├── poseidon/                # Phase 3: Poseidon hash
│   ├── mod.rs
│   ├── constants.rs
│   ├── sbox.rs
│   ├── round.rs
│   ├── air.rs
│   └── tests.rs
│
├── keccak/                  # Phase 4: Keccak-256
│   ├── mod.rs
│   ├── constants.rs
│   ├── state.rs
│   ├── theta.rs
│   ├── rho_pi.rs
│   ├── chi.rs
│   ├── iota.rs
│   ├── air.rs
│   └── tests.rs
│
├── ed25519/                 # Phase 5: Ed25519 + EdDSA
│   ├── mod.rs
│   ├── params.rs
│   ├── field.rs
│   ├── point.rs
│   ├── scalar_mul.rs
│   ├── eddsa_verify.rs
│   ├── air.rs
│   └── tests.rs
│
├── secp256k1/               # Phase 6: secp256k1 + ECDSA
│   ├── mod.rs
│   ├── params.rs
│   ├── field.rs
│   ├── point.rs
│   ├── scalar_mul.rs
│   ├── ecdsa_verify.rs
│   ├── air.rs
│   └── tests.rs
│
└── bench/                   # Benchmarks
    ├── mod.rs
    ├── harness.rs
    ├── sha256_bench.rs
    ├── keccak_bench.rs
    ├── poseidon_bench.rs
    ├── ecdsa_bench.rs
    ├── eddsa_bench.rs
    └── scaling_bench.rs
```

---

## Success Metrics

### Must Achieve (Week 14)

| Benchmark | Target Prove | Target Verify | Target Size |
|-----------|--------------|---------------|-------------|
| SHA-256 1M chain | < 10s | < 100µs | < 50KB |
| SHA-256 1B chain | < 3min | < 10µs | < 200KB |
| Keccak 1K chain | < 60s | < 100µs | < 100KB |
| Poseidon 1M | < 5s | < 50µs | < 30KB |
| EdDSA 1 sig | < 500ms | < 1ms | < 50KB |
| EdDSA 100 sigs | < 15s | < 1ms | < 100KB |
| ECDSA 1 sig | < 1s | < 1ms | < 50KB |
| ECDSA 100 sigs | < 30s | < 1ms | < 100KB |

### Scaling Validation

```
For N = 2^k where k = 10, 14, 18, 22, 26, 30:

Prover time:  T_p(N) = O(N log N)
Verifier time: T_v(N) = O(log² N) ≈ constant for practical N
Proof size:   S(N) = O(log² N)

Must demonstrate:
- T_p(2N) / T_p(N) ≈ 2  (linear in N)
- T_v(2N) / T_v(N) ≈ 1  (constant)
- S(2N) / S(N) ≈ 1     (logarithmic)
```

---

## Timeline Summary

| Week | Phase | Deliverable |
|------|-------|-------------|
| 1-2 | Lookup Engine | All tables, grand product + log derivative |
| 3-4 | 256-bit Emulation | Limbs, add, mul, reduce, inverse |
| 5 | Poseidon | Complete AIR, tests passing |
| 6-7 | Keccak-256 | Complete AIR, Ethereum compatible |
| 8-9 | Ed25519 + EdDSA | Complete AIR, RFC 8032 compatible |
| 10-12 | secp256k1 + ECDSA | Complete AIR, Bitcoin/Ethereum compatible |
| 13-14 | Integration | Benchmarks, comparisons, documentation |

---

**Total: 14 weeks. Zero shortcuts. Beat everyone.**
