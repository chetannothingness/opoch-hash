//! Modular Reduction for Specific Primes
//!
//! Implements efficient reduction for:
//! - Ed25519 field: p = 2^255 - 19
//! - secp256k1 field: p = 2^256 - 2^32 - 977
//! - secp256k1 order: n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

use crate::field::Fp;
use super::{LIMB_COUNT, LIMB_BITS, LIMB_MAX, DOUBLE_LIMB_COUNT};
use super::limbs::U256Limbs;
use super::mul::U512Product;
use super::add::U256Add;
use super::sub::U256Sub;
use super::compare::U256Compare;

/// Ed25519 field modulus: p = 2^255 - 19
pub const ED25519_P: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED,
];

/// secp256k1 field modulus: p = 2^256 - 2^32 - 977
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

/// Modular reduction operations
pub struct ModularReduce;

impl ModularReduce {
    /// Get Ed25519 modulus as U256Limbs
    pub fn ed25519_p() -> U256Limbs {
        U256Limbs::from_bytes_be(&ED25519_P)
    }

    /// Get secp256k1 field modulus as U256Limbs
    pub fn secp256k1_p() -> U256Limbs {
        U256Limbs::from_bytes_be(&SECP256K1_P)
    }

    /// Get secp256k1 order as U256Limbs
    pub fn secp256k1_n() -> U256Limbs {
        U256Limbs::from_bytes_be(&SECP256K1_N)
    }

    /// Reduce mod Ed25519 prime p = 2^255 - 19
    ///
    /// For p = 2^255 - 19: 2^256 ≡ 38 (mod p)
    ///
    /// Strategy: For x = lo + hi × 2^256,
    /// x ≡ lo + 38 × hi (mod p)
    ///
    /// Since hi*38 may exceed 256 bits, we iterate until the high part is zero.
    pub fn reduce_ed25519(x: &U512Product) -> U256Limbs {
        let lo = x.low();
        let hi = x.high();

        // Base case: high part is zero
        if hi.is_zero() {
            let p = Self::ed25519_p();
            let mut result = lo;
            while U256Compare::gte(&result, &p) {
                result = U256Sub::sub(&result, &p).0;
            }
            return result;
        }

        // Compute hi * 38 (returns 512-bit result to handle overflow)
        let hi_times_38 = super::mul::U256Mul::mul_u64(&hi, 38);

        // Add lo (extended to 512 bits) to hi * 38
        let lo_extended = U512Product::from_low(lo);
        let sum = Self::add_512(&lo_extended, &hi_times_38);

        // Recursively reduce
        // This converges because hi*38 is at most 262 bits (256 + 6),
        // and after each iteration the high part shrinks by ~250 bits.
        Self::reduce_ed25519(&sum)
    }

    /// Reduce mod secp256k1 prime p = 2^256 - 2^32 - 977
    ///
    /// For p = 2^256 - 2^32 - 977: 2^256 ≡ 2^32 + 977 (mod p)
    ///
    /// Strategy: For x = lo + hi × 2^256,
    /// x ≡ lo + hi × (2^32 + 977) (mod p)
    ///
    /// Since hi * (2^32 + 977) may exceed 256 bits, we iterate until the high part is zero.
    pub fn reduce_secp256k1(x: &U512Product) -> U256Limbs {
        // Reduction factor: 2^32 + 977 = 4294968273
        const REDUCTION_FACTOR: u64 = (1u64 << 32) + 977;

        let lo = x.low();
        let hi = x.high();

        // Base case: high part is zero
        if hi.is_zero() {
            let p = Self::secp256k1_p();
            let mut result = lo;
            while U256Compare::gte(&result, &p) {
                result = U256Sub::sub(&result, &p).0;
            }
            return result;
        }

        // Compute hi * (2^32 + 977) as a 512-bit result to handle overflow
        let hi_times_factor = super::mul::U256Mul::mul_u64(&hi, REDUCTION_FACTOR);

        // Add lo (extended to 512 bits) to hi * factor
        let lo_extended = U512Product::from_low(lo);
        let sum = Self::add_512(&lo_extended, &hi_times_factor);

        // Recursively reduce
        // This converges because hi * factor is at most 289 bits (256 + 33),
        // and after each iteration the high part shrinks significantly.
        Self::reduce_secp256k1(&sum)
    }

    /// Reduce mod secp256k1 order n
    pub fn reduce_secp256k1_n(x: &U512Product) -> U256Limbs {
        // Similar to secp256k1_p but with different constant
        // For simplicity, use generic reduction
        Self::reduce_generic(x, &Self::secp256k1_n())
    }

    /// Generic reduction for any modulus
    ///
    /// Uses specialized reduction for known primes (Ed25519, secp256k1)
    /// Falls back to iterative reduction for arbitrary moduli
    pub fn reduce_generic(x: &U512Product, modulus: &U256Limbs) -> U256Limbs {
        // Check for specialized primes - these have efficient reduction
        let ed25519_p = Self::ed25519_p();
        if modulus == &ed25519_p {
            return Self::reduce_ed25519(x);
        }

        let secp256k1_p = Self::secp256k1_p();
        if modulus == &secp256k1_p {
            return Self::reduce_secp256k1(x);
        }

        // For arbitrary modulus, use iterative reduction
        // x = lo + hi * 2^256
        // x ≡ lo + hi * (2^256 mod m) (mod m)
        Self::reduce_generic_iterative(x, modulus)
    }

    /// Iterative reduction for arbitrary modulus
    ///
    /// Computes x mod m where x is 512 bits and m is 256 bits
    /// Uses: x = lo + hi * 2^256 ≡ lo + hi * r (mod m) where r = 2^256 mod m
    fn reduce_generic_iterative(x: &U512Product, modulus: &U256Limbs) -> U256Limbs {
        let lo = x.low();
        let hi = x.high();

        // If high part is zero, just reduce the low part
        if hi.is_zero() {
            let mut result = lo;
            while U256Compare::gte(&result, modulus) {
                result = U256Sub::sub(&result, modulus).0;
            }
            return result;
        }

        // Compute r = 2^256 mod modulus
        // 2^256 = q * m + r where q and r we need to find
        // Since 2^256 is just 1 followed by 256 zeros, we can compute this
        let r = Self::compute_2_256_mod(modulus);

        // Compute hi * r (this is a 512-bit product since both are 256-bit)
        let hi_times_r = super::mul::U256Mul::mul_full(&hi, &r);

        // Add lo to hi * r (both are effectively 512-bit values)
        // lo as 512-bit is just lo with zero high part
        let lo_512 = U512Product::from_low(lo);
        let sum_512 = Self::add_512(&lo_512, &hi_times_r);

        // The result might still need reduction
        // Since r < m and hi < 2^256, hi*r < m * 2^256 < 2^512
        // And lo < 2^256, so sum < 2^512 + 2^256
        // After first reduction, result < 2^257 approximately (if m is close to 2^256)
        // So we iterate until high part is zero
        let new_hi = sum_512.high();
        if new_hi.is_zero() {
            let mut result = sum_512.low();
            while U256Compare::gte(&result, modulus) {
                result = U256Sub::sub(&result, modulus).0;
            }
            result
        } else {
            // Need another round of reduction
            Self::reduce_generic_iterative(&sum_512, modulus)
        }
    }

    /// Compute 2^256 mod modulus
    ///
    /// Since 2^256 is larger than any 256-bit modulus, we compute it as:
    /// 2^256 = 2 * 2^255 = ... build up using doubling
    fn compute_2_256_mod(modulus: &U256Limbs) -> U256Limbs {
        // Start with 1, double 256 times, reducing each time
        let mut result = U256Limbs::one();

        for _ in 0..256 {
            // Double
            let (doubled, overflow) = U256Add::add(&result, &result);
            result = if overflow || U256Compare::gte(&doubled, modulus) {
                U256Sub::sub(&doubled, modulus).0
            } else {
                doubled
            };
        }

        result
    }

    /// Add two 512-bit numbers
    fn add_512(a: &U512Product, b: &U512Product) -> U512Product {
        let mut result = [Fp::ZERO; DOUBLE_LIMB_COUNT];
        let mut carry = 0u128;

        for i in 0..DOUBLE_LIMB_COUNT {
            let sum = a.limbs[i].to_u64() as u128
                    + b.limbs[i].to_u64() as u128
                    + carry;
            result[i] = Fp::new((sum & LIMB_MAX as u128) as u64);
            carry = sum >> LIMB_BITS;
        }

        // Ignore final carry (truncate at 512 bits)
        U512Product { limbs: result }
    }

    /// Reduce a 256-bit value mod p (single reduction)
    pub fn reduce_256(x: &U256Limbs, modulus: &U256Limbs) -> U256Limbs {
        if U256Compare::gte(x, modulus) {
            U256Sub::sub(x, modulus).0
        } else {
            x.clone()
        }
    }

    /// Multiply by small constant (helper)
    fn mul_by_small(x: &U256Limbs, k: u64) -> U256Limbs {
        let mut result = [Fp::ZERO; LIMB_COUNT];
        let mut carry = 0u128;

        for i in 0..LIMB_COUNT {
            let prod = x.limbs[i].to_u64() as u128 * k as u128 + carry;
            result[i] = Fp::new((prod & LIMB_MAX as u128) as u64);
            carry = prod >> LIMB_BITS;
        }

        // Truncate overflow (caller handles)
        U256Limbs { limbs: result }
    }
}

/// Field arithmetic over specific modulus
pub struct ModularArith {
    modulus: U256Limbs,
}

impl ModularArith {
    /// Create new modular arithmetic context
    pub fn new(modulus: U256Limbs) -> Self {
        ModularArith { modulus }
    }

    /// Ed25519 field
    pub fn ed25519() -> Self {
        Self::new(ModularReduce::ed25519_p())
    }

    /// secp256k1 field
    pub fn secp256k1() -> Self {
        Self::new(ModularReduce::secp256k1_p())
    }

    /// secp256k1 scalar field
    pub fn secp256k1_scalar() -> Self {
        Self::new(ModularReduce::secp256k1_n())
    }

    /// Modular addition
    pub fn add(&self, a: &U256Limbs, b: &U256Limbs) -> U256Limbs {
        let (sum, overflow) = U256Add::add(a, b);
        if overflow || U256Compare::gte(&sum, &self.modulus) {
            U256Sub::sub(&sum, &self.modulus).0
        } else {
            sum
        }
    }

    /// Modular subtraction
    pub fn sub(&self, a: &U256Limbs, b: &U256Limbs) -> U256Limbs {
        let (diff, underflow) = U256Sub::sub(a, b);
        if underflow {
            U256Add::add(&diff, &self.modulus).0
        } else {
            diff
        }
    }

    /// Modular negation
    pub fn neg(&self, a: &U256Limbs) -> U256Limbs {
        if a.is_zero() {
            a.clone()
        } else {
            U256Sub::sub(&self.modulus, a).0
        }
    }

    /// Modular multiplication
    pub fn mul(&self, a: &U256Limbs, b: &U256Limbs) -> U256Limbs {
        let product = super::mul::U256Mul::mul_full(a, b);
        ModularReduce::reduce_generic(&product, &self.modulus)
    }

    /// Modular squaring
    pub fn square(&self, a: &U256Limbs) -> U256Limbs {
        let product = super::mul::U256Mul::square(a);
        ModularReduce::reduce_generic(&product, &self.modulus)
    }

    /// Modular doubling
    pub fn double(&self, a: &U256Limbs) -> U256Limbs {
        self.add(a, a)
    }

    /// Get modulus
    pub fn modulus(&self) -> &U256Limbs {
        &self.modulus
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_p() {
        let p = ModularReduce::ed25519_p();
        // p = 2^255 - 19
        // In hex: 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED

        let bytes = p.to_bytes_be();
        assert_eq!(bytes[0], 0x7F);
        assert_eq!(bytes[31], 0xED);
    }

    #[test]
    fn test_secp256k1_p() {
        let p = ModularReduce::secp256k1_p();
        // p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

        let bytes = p.to_bytes_be();
        assert_eq!(bytes[0], 0xFF);
        assert_eq!(bytes[27], 0xFE);
        assert_eq!(bytes[31], 0x2F);
    }

    #[test]
    fn test_reduce_256() {
        let p = ModularReduce::ed25519_p();

        // Value smaller than p should stay same
        let small = U256Limbs::from_u64(12345);
        let reduced = ModularReduce::reduce_256(&small, &p);
        assert_eq!(small, reduced);

        // Value equal to p should become 0
        let reduced_p = ModularReduce::reduce_256(&p, &p);
        assert!(reduced_p.is_zero());
    }

    #[test]
    fn test_modular_add() {
        let arith = ModularArith::new(U256Limbs::from_u64(100));

        let a = U256Limbs::from_u64(60);
        let b = U256Limbs::from_u64(70);
        let sum = arith.add(&a, &b);

        // 60 + 70 = 130 ≡ 30 (mod 100)
        assert_eq!(sum.limbs[0].to_u64(), 30);
    }

    #[test]
    fn test_modular_sub() {
        let arith = ModularArith::new(U256Limbs::from_u64(100));

        let a = U256Limbs::from_u64(30);
        let b = U256Limbs::from_u64(70);
        let diff = arith.sub(&a, &b);

        // 30 - 70 ≡ -40 ≡ 60 (mod 100)
        assert_eq!(diff.limbs[0].to_u64(), 60);
    }

    #[test]
    fn test_modular_mul() {
        let arith = ModularArith::new(U256Limbs::from_u64(100));

        let a = U256Limbs::from_u64(7);
        let b = U256Limbs::from_u64(15);
        let product = arith.mul(&a, &b);

        // 7 * 15 = 105 ≡ 5 (mod 100)
        assert_eq!(product.limbs[0].to_u64(), 5);
    }

    #[test]
    fn test_modular_neg() {
        let arith = ModularArith::new(U256Limbs::from_u64(100));

        let a = U256Limbs::from_u64(30);
        let neg_a = arith.neg(&a);

        // -30 ≡ 70 (mod 100)
        assert_eq!(neg_a.limbs[0].to_u64(), 70);

        // a + (-a) should be 0
        let sum = arith.add(&a, &neg_a);
        assert!(sum.is_zero());
    }
}
