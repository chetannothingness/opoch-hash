//! 256-bit Addition with Carry Propagation
//!
//! Implements addition with explicit carry columns for AIR constraints.

use crate::field::Fp;
use super::{LIMB_BITS, LIMB_COUNT, LIMB_MAX};
use super::limbs::U256Limbs;

/// 256-bit addition operations
pub struct U256Add;

impl U256Add {
    /// Add two 256-bit integers, returning (sum, overflow)
    pub fn add(a: &U256Limbs, b: &U256Limbs) -> (U256Limbs, bool) {
        let mut result = [Fp::ZERO; LIMB_COUNT];
        let mut carry = 0u64;

        for i in 0..LIMB_COUNT {
            let sum = a.limbs[i].to_u64() + b.limbs[i].to_u64() + carry;
            result[i] = Fp::new(sum & LIMB_MAX);
            carry = sum >> LIMB_BITS;
        }

        (U256Limbs { limbs: result }, carry != 0)
    }

    /// Add with explicit carry output
    pub fn add_with_carries(a: &U256Limbs, b: &U256Limbs) -> (U256Limbs, [Fp; LIMB_COUNT + 1]) {
        let mut result = [Fp::ZERO; LIMB_COUNT];
        let mut carries = [Fp::ZERO; LIMB_COUNT + 1];
        // carries[0] = 0 (no initial carry)

        for i in 0..LIMB_COUNT {
            let sum = a.limbs[i].to_u64() + b.limbs[i].to_u64() + carries[i].to_u64();
            result[i] = Fp::new(sum & LIMB_MAX);
            carries[i + 1] = Fp::new(sum >> LIMB_BITS);
        }

        (U256Limbs { limbs: result }, carries)
    }

    /// Add with initial carry
    pub fn add_with_carry_in(a: &U256Limbs, b: &U256Limbs, carry_in: bool) -> (U256Limbs, bool) {
        let mut result = [Fp::ZERO; LIMB_COUNT];
        let mut carry = if carry_in { 1u64 } else { 0u64 };

        for i in 0..LIMB_COUNT {
            let sum = a.limbs[i].to_u64() + b.limbs[i].to_u64() + carry;
            result[i] = Fp::new(sum & LIMB_MAX);
            carry = sum >> LIMB_BITS;
        }

        (U256Limbs { limbs: result }, carry != 0)
    }

    /// Add u64 to U256
    pub fn add_u64(a: &U256Limbs, b: u64) -> (U256Limbs, bool) {
        let b_limbs = U256Limbs::from_u64(b);
        Self::add(a, &b_limbs)
    }

    /// Increment by 1
    pub fn inc(a: &U256Limbs) -> (U256Limbs, bool) {
        Self::add_u64(a, 1)
    }

    /// Generate AIR constraints for addition
    ///
    /// Constraint: a_i + b_i + c_i = r_i + 2^16 × c_{i+1}
    ///
    /// Returns constraint values (should all be zero for valid addition)
    pub fn verify_add(
        a: &U256Limbs,
        b: &U256Limbs,
        result: &U256Limbs,
        carries: &[Fp; LIMB_COUNT + 1],
    ) -> bool {
        // Check initial carry is zero
        if carries[0] != Fp::ZERO {
            return false;
        }

        // Check each limb
        for i in 0..LIMB_COUNT {
            let lhs = a.limbs[i].to_u64() + b.limbs[i].to_u64() + carries[i].to_u64();
            let rhs = result.limbs[i].to_u64() + (carries[i + 1].to_u64() << LIMB_BITS);
            if lhs != rhs {
                return false;
            }

            // Check carry is 0 or 1
            if carries[i + 1].to_u64() > 1 {
                return false;
            }
        }

        true
    }

    /// Compute constraint polynomial evaluations for addition
    ///
    /// For AIR: returns evaluations of the constraint polynomial
    /// a_i + b_i + c_i - r_i - 2^16 × c_{i+1}
    pub fn constraint_evals(
        a: &U256Limbs,
        b: &U256Limbs,
        result: &U256Limbs,
        carries: &[Fp; LIMB_COUNT + 1],
    ) -> [Fp; LIMB_COUNT] {
        let two_pow_16 = Fp::new(1 << LIMB_BITS);
        let mut evals = [Fp::ZERO; LIMB_COUNT];

        for i in 0..LIMB_COUNT {
            let lhs = a.limbs[i] + b.limbs[i] + carries[i];
            let rhs = result.limbs[i] + two_pow_16 * carries[i + 1];
            evals[i] = lhs - rhs;
        }

        evals
    }
}

/// Wrapping addition (mod 2^256)
impl std::ops::Add for U256Limbs {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        U256Add::add(&self, &rhs).0
    }
}

impl std::ops::Add<&U256Limbs> for &U256Limbs {
    type Output = U256Limbs;

    fn add(self, rhs: &U256Limbs) -> U256Limbs {
        U256Add::add(self, rhs).0
    }
}

impl std::ops::AddAssign for U256Limbs {
    fn add_assign(&mut self, rhs: Self) {
        *self = U256Add::add(self, &rhs).0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_add() {
        let a = U256Limbs::from_u64(100);
        let b = U256Limbs::from_u64(200);
        let (sum, overflow) = U256Add::add(&a, &b);

        assert!(!overflow);
        assert_eq!(sum.limbs[0].to_u64(), 300);
    }

    #[test]
    fn test_add_with_carry() {
        // Add two values that cause carry across limbs
        let a = U256Limbs::from_u64(0xFFFF); // Max in limb 0
        let b = U256Limbs::from_u64(1);
        let (sum, overflow) = U256Add::add(&a, &b);

        assert!(!overflow);
        assert_eq!(sum.limbs[0].to_u64(), 0);
        assert_eq!(sum.limbs[1].to_u64(), 1);
    }

    #[test]
    fn test_add_overflow() {
        // Max value + 1 should overflow
        let max = {
            let mut limbs = [Fp::ZERO; LIMB_COUNT];
            for i in 0..LIMB_COUNT {
                limbs[i] = Fp::new(LIMB_MAX);
            }
            U256Limbs { limbs }
        };
        let one = U256Limbs::one();
        let (sum, overflow) = U256Add::add(&max, &one);

        assert!(overflow);
        assert!(sum.is_zero()); // Wraps to zero
    }

    #[test]
    fn test_add_with_carries_verification() {
        let a = U256Limbs::from_u64(0x1234567890ABCDEF);
        let b = U256Limbs::from_u64(0xFEDCBA0987654321);

        let (result, carries) = U256Add::add_with_carries(&a, &b);

        // Verify constraints
        assert!(U256Add::verify_add(&a, &b, &result, &carries));

        // Check constraint evals are all zero
        let evals = U256Add::constraint_evals(&a, &b, &result, &carries);
        for eval in &evals {
            assert!(eval.is_zero());
        }
    }

    #[test]
    fn test_add_commutativity() {
        let a = U256Limbs::from_u64(12345);
        let b = U256Limbs::from_u64(67890);

        let (sum1, _) = U256Add::add(&a, &b);
        let (sum2, _) = U256Add::add(&b, &a);

        assert_eq!(sum1, sum2);
    }

    #[test]
    fn test_add_associativity() {
        let a = U256Limbs::from_u64(100);
        let b = U256Limbs::from_u64(200);
        let c = U256Limbs::from_u64(300);

        let (ab, _) = U256Add::add(&a, &b);
        let (ab_c, _) = U256Add::add(&ab, &c);

        let (bc, _) = U256Add::add(&b, &c);
        let (a_bc, _) = U256Add::add(&a, &bc);

        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn test_add_identity() {
        let a = U256Limbs::from_u64(42);
        let zero = U256Limbs::zero();

        let (sum, overflow) = U256Add::add(&a, &zero);
        assert!(!overflow);
        assert_eq!(sum, a);
    }
}
