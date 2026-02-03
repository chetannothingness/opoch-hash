//! 256-bit Subtraction with Borrow Propagation
//!
//! Implements subtraction with explicit borrow columns for AIR constraints.

use crate::field::Fp;
use super::{LIMB_BITS, LIMB_COUNT, LIMB_MAX};
use super::limbs::U256Limbs;

/// 256-bit subtraction operations
pub struct U256Sub;

impl U256Sub {
    /// Subtract two 256-bit integers, returning (difference, underflow)
    pub fn sub(a: &U256Limbs, b: &U256Limbs) -> (U256Limbs, bool) {
        let mut result = [Fp::ZERO; LIMB_COUNT];
        let mut borrow = 0i64;

        for i in 0..LIMB_COUNT {
            let diff = a.limbs[i].to_u64() as i64 - b.limbs[i].to_u64() as i64 - borrow;
            if diff < 0 {
                result[i] = Fp::new((diff + (1 << LIMB_BITS)) as u64);
                borrow = 1;
            } else {
                result[i] = Fp::new(diff as u64);
                borrow = 0;
            }
        }

        (U256Limbs { limbs: result }, borrow != 0)
    }

    /// Subtract with explicit borrow output
    pub fn sub_with_borrows(a: &U256Limbs, b: &U256Limbs) -> (U256Limbs, [Fp; LIMB_COUNT + 1]) {
        let mut result = [Fp::ZERO; LIMB_COUNT];
        let mut borrows = [Fp::ZERO; LIMB_COUNT + 1];

        for i in 0..LIMB_COUNT {
            let a_val = a.limbs[i].to_u64() as i64;
            let b_val = b.limbs[i].to_u64() as i64;
            let borrow_val = borrows[i].to_u64() as i64;

            let diff = a_val - b_val - borrow_val;
            if diff < 0 {
                result[i] = Fp::new((diff + (1 << LIMB_BITS)) as u64);
                borrows[i + 1] = Fp::ONE;
            } else {
                result[i] = Fp::new(diff as u64);
                borrows[i + 1] = Fp::ZERO;
            }
        }

        (U256Limbs { limbs: result }, borrows)
    }

    /// Subtract u64 from U256
    pub fn sub_u64(a: &U256Limbs, b: u64) -> (U256Limbs, bool) {
        let b_limbs = U256Limbs::from_u64(b);
        Self::sub(a, &b_limbs)
    }

    /// Decrement by 1
    pub fn dec(a: &U256Limbs) -> (U256Limbs, bool) {
        Self::sub_u64(a, 1)
    }

    /// Negate (compute 2^256 - a)
    pub fn negate(a: &U256Limbs) -> U256Limbs {
        let mut max = [Fp::ZERO; LIMB_COUNT];
        for i in 0..LIMB_COUNT {
            max[i] = Fp::new(LIMB_MAX);
        }
        let max = U256Limbs { limbs: max };

        // 2^256 - a = (2^256 - 1) - a + 1 = ~a + 1
        let not_a = a.bitnot();
        let (result, _) = super::add::U256Add::add(&not_a, &U256Limbs::one());
        result
    }

    /// Verify subtraction constraint
    ///
    /// Constraint: a_i - b_i - borrow_i = r_i - 2^16 × borrow_{i+1}
    pub fn verify_sub(
        a: &U256Limbs,
        b: &U256Limbs,
        result: &U256Limbs,
        borrows: &[Fp; LIMB_COUNT + 1],
    ) -> bool {
        // Check initial borrow is zero
        if borrows[0] != Fp::ZERO {
            return false;
        }

        for i in 0..LIMB_COUNT {
            let a_val = a.limbs[i].to_u64() as i64;
            let b_val = b.limbs[i].to_u64() as i64;
            let borrow_in = borrows[i].to_u64() as i64;
            let r_val = result.limbs[i].to_u64() as i64;
            let borrow_out = borrows[i + 1].to_u64() as i64;

            let lhs = a_val - b_val - borrow_in;
            let rhs = r_val - (borrow_out << LIMB_BITS);

            if lhs != rhs {
                return false;
            }

            // Check borrow is 0 or 1
            if borrows[i + 1].to_u64() > 1 {
                return false;
            }
        }

        true
    }

    /// Compute constraint polynomial evaluations for subtraction
    pub fn constraint_evals(
        a: &U256Limbs,
        b: &U256Limbs,
        result: &U256Limbs,
        borrows: &[Fp; LIMB_COUNT + 1],
    ) -> [Fp; LIMB_COUNT] {
        let two_pow_16 = Fp::new(1 << LIMB_BITS);
        let mut evals = [Fp::ZERO; LIMB_COUNT];

        for i in 0..LIMB_COUNT {
            // a_i - b_i - borrow_i - r_i + 2^16 × borrow_{i+1} = 0
            let lhs = a.limbs[i] - b.limbs[i] - borrows[i];
            let rhs = result.limbs[i] - two_pow_16 * borrows[i + 1];
            evals[i] = lhs - rhs;
        }

        evals
    }
}

/// Wrapping subtraction (mod 2^256)
impl std::ops::Sub for U256Limbs {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        U256Sub::sub(&self, &rhs).0
    }
}

impl std::ops::Sub<&U256Limbs> for &U256Limbs {
    type Output = U256Limbs;

    fn sub(self, rhs: &U256Limbs) -> U256Limbs {
        U256Sub::sub(self, rhs).0
    }
}

impl std::ops::SubAssign for U256Limbs {
    fn sub_assign(&mut self, rhs: Self) {
        *self = U256Sub::sub(self, &rhs).0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_sub() {
        let a = U256Limbs::from_u64(300);
        let b = U256Limbs::from_u64(100);
        let (diff, underflow) = U256Sub::sub(&a, &b);

        assert!(!underflow);
        assert_eq!(diff.limbs[0].to_u64(), 200);
    }

    #[test]
    fn test_sub_with_borrow() {
        // 0x10000 - 1 = 0xFFFF
        let a = U256Limbs::from_u64(0x10000);
        let b = U256Limbs::from_u64(1);
        let (diff, underflow) = U256Sub::sub(&a, &b);

        assert!(!underflow);
        assert_eq!(diff.limbs[0].to_u64(), 0xFFFF);
        assert_eq!(diff.limbs[1].to_u64(), 0);
    }

    #[test]
    fn test_sub_underflow() {
        let a = U256Limbs::from_u64(100);
        let b = U256Limbs::from_u64(200);
        let (_, underflow) = U256Sub::sub(&a, &b);

        assert!(underflow);
    }

    #[test]
    fn test_sub_zero() {
        let a = U256Limbs::from_u64(100);
        let b = U256Limbs::from_u64(100);
        let (diff, underflow) = U256Sub::sub(&a, &b);

        assert!(!underflow);
        assert!(diff.is_zero());
    }

    #[test]
    fn test_sub_with_borrows_verification() {
        let a = U256Limbs::from_u64(0xFEDCBA0987654321);
        let b = U256Limbs::from_u64(0x1234567890ABCDEF);

        let (result, borrows) = U256Sub::sub_with_borrows(&a, &b);

        // Verify constraints
        assert!(U256Sub::verify_sub(&a, &b, &result, &borrows));

        // Check constraint evals are all zero
        let evals = U256Sub::constraint_evals(&a, &b, &result, &borrows);
        for eval in &evals {
            assert!(eval.is_zero());
        }
    }

    #[test]
    fn test_negate() {
        let a = U256Limbs::from_u64(1);
        let neg_a = U256Sub::negate(&a);

        // neg_a + a should be 0 (mod 2^256)
        let (sum, overflow) = super::super::add::U256Add::add(&a, &neg_a);
        assert!(overflow); // Should overflow back to 0
        assert!(sum.is_zero());
    }

    #[test]
    fn test_negate_zero() {
        let zero = U256Limbs::zero();
        let neg_zero = U256Sub::negate(&zero);
        assert!(neg_zero.is_zero());
    }

    #[test]
    fn test_add_sub_inverse() {
        let a = U256Limbs::from_u64(12345);
        let b = U256Limbs::from_u64(67890);

        let (sum, _) = super::super::add::U256Add::add(&a, &b);
        let (diff, _) = U256Sub::sub(&sum, &b);

        assert_eq!(diff, a);
    }
}
