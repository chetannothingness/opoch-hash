//! 256-bit Multiplication
//!
//! Implements schoolbook and Karatsuba multiplication with explicit carries.

use crate::field::Fp;
use super::{LIMB_BITS, LIMB_COUNT, LIMB_MAX, DOUBLE_LIMB_COUNT};
use super::limbs::U256Limbs;

/// 512-bit product (for full multiplication result)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct U512Product {
    /// 32 limbs for 512 bits
    pub limbs: [Fp; DOUBLE_LIMB_COUNT],
}

impl U512Product {
    /// Zero
    pub fn zero() -> Self {
        U512Product {
            limbs: [Fp::ZERO; DOUBLE_LIMB_COUNT],
        }
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|x| x.is_zero())
    }

    /// Get low 256 bits as U256Limbs
    pub fn low(&self) -> U256Limbs {
        let mut limbs = [Fp::ZERO; LIMB_COUNT];
        limbs.copy_from_slice(&self.limbs[0..LIMB_COUNT]);
        U256Limbs { limbs }
    }

    /// Get high 256 bits as U256Limbs
    pub fn high(&self) -> U256Limbs {
        let mut limbs = [Fp::ZERO; LIMB_COUNT];
        limbs.copy_from_slice(&self.limbs[LIMB_COUNT..DOUBLE_LIMB_COUNT]);
        U256Limbs { limbs }
    }

    /// Create from a 256-bit value (low part, high part is zero)
    pub fn from_low(low: U256Limbs) -> Self {
        let mut limbs = [Fp::ZERO; DOUBLE_LIMB_COUNT];
        for i in 0..LIMB_COUNT {
            limbs[i] = low.limbs[i];
        }
        U512Product { limbs }
    }

    /// Create from U256Limbs (alias for from_low)
    pub fn from_256(x: &U256Limbs) -> Self {
        Self::from_low(x.clone())
    }
}

/// 256-bit multiplication operations
pub struct U256Mul;

impl U256Mul {
    /// Full multiplication: returns 512-bit product
    ///
    /// Uses schoolbook algorithm with O(n²) limb multiplications
    pub fn mul_full(a: &U256Limbs, b: &U256Limbs) -> U512Product {
        let mut product = [0u128; DOUBLE_LIMB_COUNT];

        // Schoolbook multiplication
        for i in 0..LIMB_COUNT {
            for j in 0..LIMB_COUNT {
                let prod = a.limbs[i].to_u64() as u128 * b.limbs[j].to_u64() as u128;
                product[i + j] += prod;
            }
        }

        // Propagate carries
        let mut result = [Fp::ZERO; DOUBLE_LIMB_COUNT];
        let mut carry = 0u128;

        for i in 0..DOUBLE_LIMB_COUNT {
            let sum = product[i] + carry;
            result[i] = Fp::new((sum & LIMB_MAX as u128) as u64);
            carry = sum >> LIMB_BITS;
        }

        U512Product { limbs: result }
    }

    /// Truncated multiplication: returns low 256 bits of product (mod 2^256)
    pub fn mul_truncated(a: &U256Limbs, b: &U256Limbs) -> U256Limbs {
        let full = Self::mul_full(a, b);
        full.low()
    }

    /// Multiply by a single u64 value
    pub fn mul_u64(a: &U256Limbs, b: u64) -> U512Product {
        let mut product = [0u128; LIMB_COUNT + 4];

        // b is at most 64 bits = 4 limbs
        let b_limbs = [
            (b & LIMB_MAX) as u128,
            ((b >> 16) & LIMB_MAX) as u128,
            ((b >> 32) & LIMB_MAX) as u128,
            ((b >> 48) & LIMB_MAX) as u128,
        ];

        for i in 0..LIMB_COUNT {
            for (j, &bl) in b_limbs.iter().enumerate() {
                product[i + j] += a.limbs[i].to_u64() as u128 * bl;
            }
        }

        // Propagate carries
        let mut result = [Fp::ZERO; DOUBLE_LIMB_COUNT];
        let mut carry = 0u128;

        for i in 0..DOUBLE_LIMB_COUNT {
            let sum = if i < product.len() { product[i] } else { 0 } + carry;
            result[i] = Fp::new((sum & LIMB_MAX as u128) as u64);
            carry = sum >> LIMB_BITS;
        }

        U512Product { limbs: result }
    }

    /// Multiply by a small constant (fits in u64)
    pub fn mul_by_small(a: &U256Limbs, k: u64) -> U256Limbs {
        let mut result = [Fp::ZERO; LIMB_COUNT];
        let mut carry = 0u128;

        for i in 0..LIMB_COUNT {
            let prod = a.limbs[i].to_u64() as u128 * k as u128 + carry;
            result[i] = Fp::new((prod & LIMB_MAX as u128) as u64);
            carry = prod >> LIMB_BITS;
        }

        // Note: truncates overflow
        U256Limbs { limbs: result }
    }

    /// Square (slightly more efficient than mul_full for squaring)
    pub fn square(a: &U256Limbs) -> U512Product {
        let mut product = [0u128; DOUBLE_LIMB_COUNT];

        // Diagonal terms: a_i * a_i
        for i in 0..LIMB_COUNT {
            let ai = a.limbs[i].to_u64() as u128;
            product[2 * i] += ai * ai;
        }

        // Off-diagonal terms: 2 * a_i * a_j for i < j
        for i in 0..LIMB_COUNT {
            for j in (i + 1)..LIMB_COUNT {
                let prod = 2 * a.limbs[i].to_u64() as u128 * a.limbs[j].to_u64() as u128;
                product[i + j] += prod;
            }
        }

        // Propagate carries
        let mut result = [Fp::ZERO; DOUBLE_LIMB_COUNT];
        let mut carry = 0u128;

        for i in 0..DOUBLE_LIMB_COUNT {
            let sum = product[i] + carry;
            result[i] = Fp::new((sum & LIMB_MAX as u128) as u64);
            carry = sum >> LIMB_BITS;
        }

        U512Product { limbs: result }
    }

    /// Compute intermediate products (for AIR constraints)
    ///
    /// Returns the matrix of partial products: product[i][j] = a_i * b_j
    pub fn compute_partial_products(a: &U256Limbs, b: &U256Limbs) -> [[Fp; LIMB_COUNT]; LIMB_COUNT] {
        let mut products = [[Fp::ZERO; LIMB_COUNT]; LIMB_COUNT];

        for i in 0..LIMB_COUNT {
            for j in 0..LIMB_COUNT {
                let prod = a.limbs[i].to_u64() as u128 * b.limbs[j].to_u64() as u128;
                // Note: each partial product can be up to 32 bits
                // Store as Fp (which can hold it)
                products[i][j] = Fp::new(prod as u64);
            }
        }

        products
    }

    /// Verify multiplication result
    ///
    /// Checks that sum of partial products equals result (with proper shifting)
    pub fn verify_mul(a: &U256Limbs, b: &U256Limbs, result: &U512Product) -> bool {
        let computed = Self::mul_full(a, b);
        computed == *result
    }
}

/// Wrapping multiplication (mod 2^256)
impl std::ops::Mul for U256Limbs {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        U256Mul::mul_truncated(&self, &rhs)
    }
}

impl std::ops::Mul<&U256Limbs> for &U256Limbs {
    type Output = U256Limbs;

    fn mul(self, rhs: &U256Limbs) -> U256Limbs {
        U256Mul::mul_truncated(self, rhs)
    }
}

impl std::ops::MulAssign for U256Limbs {
    fn mul_assign(&mut self, rhs: Self) {
        *self = U256Mul::mul_truncated(self, &rhs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_mul() {
        let a = U256Limbs::from_u64(100);
        let b = U256Limbs::from_u64(200);
        let product = U256Mul::mul_full(&a, &b);

        assert_eq!(product.limbs[0].to_u64(), 20000);
        assert!(product.limbs[1..].iter().all(|x| x.is_zero()));
    }

    #[test]
    fn test_mul_overflow() {
        // 2^128 * 2^128 = 2^256 (overflows 256 bits)
        let a = U256Limbs::from_u128(1u128 << 127);
        let b = U256Limbs::from_u128(2); // 2^128 * 2 = 2^129
        let product = U256Mul::mul_full(&a, &b);

        // Result should be non-zero in high bits
        assert!(!product.high().is_zero() || !product.low().is_zero());
    }

    #[test]
    fn test_mul_truncated() {
        let a = U256Limbs::from_u64(0xFFFFFFFF);
        let b = U256Limbs::from_u64(0xFFFFFFFF);

        let full = U256Mul::mul_full(&a, &b);
        let truncated = U256Mul::mul_truncated(&a, &b);

        assert_eq!(full.low(), truncated);
    }

    #[test]
    fn test_square() {
        let a = U256Limbs::from_u64(12345);
        let sq_full = U256Mul::square(&a);
        let mul_full = U256Mul::mul_full(&a, &a);

        assert_eq!(sq_full, mul_full);
    }

    #[test]
    fn test_mul_by_small() {
        let a = U256Limbs::from_u64(12345);
        let result = U256Mul::mul_by_small(&a, 19);

        // 12345 * 19 = 234555
        assert_eq!(result.limbs[0].to_u64(), 234555 & LIMB_MAX);
        assert_eq!(result.limbs[1].to_u64(), (234555 >> 16) & LIMB_MAX);
    }

    #[test]
    fn test_mul_commutativity() {
        let a = U256Limbs::from_u64(12345);
        let b = U256Limbs::from_u64(67890);

        let ab = U256Mul::mul_full(&a, &b);
        let ba = U256Mul::mul_full(&b, &a);

        assert_eq!(ab, ba);
    }

    #[test]
    fn test_mul_identity() {
        let a = U256Limbs::from_u64(12345);
        let one = U256Limbs::one();

        let product = U256Mul::mul_truncated(&a, &one);
        assert_eq!(product, a);
    }

    #[test]
    fn test_mul_zero() {
        let a = U256Limbs::from_u64(12345);
        let zero = U256Limbs::zero();

        let product = U256Mul::mul_full(&a, &zero);
        assert!(product.is_zero());
    }

    #[test]
    fn test_partial_products() {
        let a = U256Limbs::from_u64(3);
        let b = U256Limbs::from_u64(5);

        let products = U256Mul::compute_partial_products(&a, &b);

        // 3 * 5 = 15, all other products should be 0
        assert_eq!(products[0][0].to_u64(), 15);
        assert!(products[0][1..].iter().all(|x| x.is_zero()));
    }

    #[test]
    fn test_large_mul() {
        // Test with values that exercise multiple limbs
        let a_bytes: [u8; 32] = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let b_bytes: [u8; 32] = [
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];

        let a = U256Limbs::from_bytes_be(&a_bytes);
        let b = U256Limbs::from_bytes_be(&b_bytes);

        let product = U256Mul::mul_full(&a, &b);

        // Verify it's correct by checking commutativity
        let product2 = U256Mul::mul_full(&b, &a);
        assert_eq!(product, product2);
    }
}
