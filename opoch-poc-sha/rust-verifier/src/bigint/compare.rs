//! 256-bit Comparison Operations
//!
//! Implements comparison with explicit constraint-friendly representations.

use crate::field::Fp;
use super::{LIMB_COUNT, LIMB_BITS, LIMB_MAX};
use super::limbs::U256Limbs;

/// 256-bit comparison operations
pub struct U256Compare;

impl U256Compare {
    /// Compare two values, returning ordering
    pub fn cmp(a: &U256Limbs, b: &U256Limbs) -> std::cmp::Ordering {
        // Compare from most significant limb to least
        for i in (0..LIMB_COUNT).rev() {
            let a_limb = a.limbs[i].to_u64();
            let b_limb = b.limbs[i].to_u64();

            match a_limb.cmp(&b_limb) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }
        std::cmp::Ordering::Equal
    }

    /// a < b
    pub fn lt(a: &U256Limbs, b: &U256Limbs) -> bool {
        Self::cmp(a, b) == std::cmp::Ordering::Less
    }

    /// a <= b
    pub fn le(a: &U256Limbs, b: &U256Limbs) -> bool {
        Self::cmp(a, b) != std::cmp::Ordering::Greater
    }

    /// a > b
    pub fn gt(a: &U256Limbs, b: &U256Limbs) -> bool {
        Self::cmp(a, b) == std::cmp::Ordering::Greater
    }

    /// a >= b
    pub fn gte(a: &U256Limbs, b: &U256Limbs) -> bool {
        Self::cmp(a, b) != std::cmp::Ordering::Less
    }

    /// a == b
    pub fn eq(a: &U256Limbs, b: &U256Limbs) -> bool {
        Self::cmp(a, b) == std::cmp::Ordering::Equal
    }

    /// Check if a < b with explicit witness for constraint system
    ///
    /// Returns (is_less, diff_limb_idx, borrow_witness)
    /// where borrow_witness proves the comparison
    pub fn lt_with_witness(a: &U256Limbs, b: &U256Limbs) -> (bool, Option<usize>, [Fp; LIMB_COUNT]) {
        // Compute a - b with borrow tracking
        let (_, borrows) = super::sub::U256Sub::sub_with_borrows(a, b);

        // a < b iff final borrow is 1
        let is_less = borrows[LIMB_COUNT] == Fp::ONE;

        // Find first differing limb (from MSB)
        let mut diff_limb = None;
        for i in (0..LIMB_COUNT).rev() {
            if a.limbs[i] != b.limbs[i] {
                diff_limb = Some(i);
                break;
            }
        }

        let mut borrow_witness = [Fp::ZERO; LIMB_COUNT];
        for i in 0..LIMB_COUNT {
            borrow_witness[i] = borrows[i + 1];
        }

        (is_less, diff_limb, borrow_witness)
    }

    /// Verify comparison constraint
    ///
    /// For a < b (is_less = true):
    /// - Subtraction a - b must have final borrow = 1
    ///
    /// For a >= b (is_less = false):
    /// - Subtraction a - b must have final borrow = 0
    pub fn verify_lt(
        a: &U256Limbs,
        b: &U256Limbs,
        is_less: bool,
        borrows: &[Fp; LIMB_COUNT],
    ) -> bool {
        // Verify subtraction constraints
        let (_, actual_borrows) = super::sub::U256Sub::sub_with_borrows(a, b);

        // Check borrows match
        for i in 0..LIMB_COUNT {
            if borrows[i] != actual_borrows[i + 1] {
                return false;
            }
        }

        // Check result matches
        let final_borrow = actual_borrows[LIMB_COUNT] == Fp::ONE;
        final_borrow == is_less
    }

    /// Check if value is in range [0, bound)
    pub fn in_range(value: &U256Limbs, bound: &U256Limbs) -> bool {
        Self::lt(value, bound)
    }

    /// Check if value is in range [lower, upper)
    pub fn in_range_inclusive(value: &U256Limbs, lower: &U256Limbs, upper: &U256Limbs) -> bool {
        Self::gte(value, lower) && Self::lt(value, upper)
    }

    /// Compute min(a, b)
    pub fn min<'a>(a: &'a U256Limbs, b: &'a U256Limbs) -> &'a U256Limbs {
        if Self::le(a, b) { a } else { b }
    }

    /// Compute max(a, b)
    pub fn max<'a>(a: &'a U256Limbs, b: &'a U256Limbs) -> &'a U256Limbs {
        if Self::gte(a, b) { a } else { b }
    }

    /// Constraint-friendly equality check
    ///
    /// Returns product (a - b) * ... = 0 iff a = b
    pub fn eq_constraint(a: &U256Limbs, b: &U256Limbs) -> Fp {
        // For equality, all limbs must match
        // (a0 - b0)^2 + (a1 - b1)^2 + ... = 0 iff all diffs are 0
        let mut sum = Fp::ZERO;
        for i in 0..LIMB_COUNT {
            let diff = a.limbs[i] - b.limbs[i];
            sum = sum + diff * diff;
        }
        sum
    }

    /// Non-zero check constraint
    ///
    /// Returns witness inv such that x * inv = 1 if x != 0
    pub fn is_nonzero_witness(x: &U256Limbs) -> Option<U256Limbs> {
        if x.is_zero() {
            None
        } else {
            // Find any non-zero limb and compute its inverse
            // For full correctness, use modular inverse
            Some(U256Limbs::one()) // Simplified - real impl needs proper inverse
        }
    }
}

impl std::cmp::PartialOrd for U256Limbs {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(U256Compare::cmp(self, other))
    }
}

impl std::cmp::Ord for U256Limbs {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        U256Compare::cmp(self, other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_equal() {
        let a = U256Limbs::from_u64(12345);
        let b = U256Limbs::from_u64(12345);

        assert!(U256Compare::eq(&a, &b));
        assert!(U256Compare::le(&a, &b));
        assert!(U256Compare::gte(&a, &b));
        assert!(!U256Compare::lt(&a, &b));
        assert!(!U256Compare::gt(&a, &b));
    }

    #[test]
    fn test_compare_less() {
        let a = U256Limbs::from_u64(100);
        let b = U256Limbs::from_u64(200);

        assert!(U256Compare::lt(&a, &b));
        assert!(U256Compare::le(&a, &b));
        assert!(!U256Compare::gt(&a, &b));
        assert!(!U256Compare::gte(&a, &b));
        assert!(!U256Compare::eq(&a, &b));
    }

    #[test]
    fn test_compare_greater() {
        let a = U256Limbs::from_u64(200);
        let b = U256Limbs::from_u64(100);

        assert!(U256Compare::gt(&a, &b));
        assert!(U256Compare::gte(&a, &b));
        assert!(!U256Compare::lt(&a, &b));
        assert!(!U256Compare::le(&a, &b));
        assert!(!U256Compare::eq(&a, &b));
    }

    #[test]
    fn test_compare_multi_limb() {
        // Test values that differ in higher limbs
        let a = U256Limbs::from_u128(0x10000_0000_0000_0000u128);
        let b = U256Limbs::from_u128(0x20000_0000_0000_0000u128);

        assert!(U256Compare::lt(&a, &b));
    }

    #[test]
    fn test_lt_with_witness() {
        let a = U256Limbs::from_u64(100);
        let b = U256Limbs::from_u64(200);

        let (is_less, diff_limb, borrows) = U256Compare::lt_with_witness(&a, &b);

        assert!(is_less);
        assert!(diff_limb.is_some());
        assert!(U256Compare::verify_lt(&a, &b, is_less, &borrows));
    }

    #[test]
    fn test_lt_witness_not_less() {
        let a = U256Limbs::from_u64(200);
        let b = U256Limbs::from_u64(100);

        let (is_less, _, borrows) = U256Compare::lt_with_witness(&a, &b);

        assert!(!is_less);
        assert!(U256Compare::verify_lt(&a, &b, is_less, &borrows));
    }

    #[test]
    fn test_in_range() {
        let value = U256Limbs::from_u64(50);
        let bound = U256Limbs::from_u64(100);

        assert!(U256Compare::in_range(&value, &bound));

        let large_value = U256Limbs::from_u64(150);
        assert!(!U256Compare::in_range(&large_value, &bound));
    }

    #[test]
    fn test_min_max() {
        let a = U256Limbs::from_u64(100);
        let b = U256Limbs::from_u64(200);

        assert_eq!(U256Compare::min(&a, &b), &a);
        assert_eq!(U256Compare::max(&a, &b), &b);
    }

    #[test]
    fn test_eq_constraint() {
        let a = U256Limbs::from_u64(12345);
        let b = U256Limbs::from_u64(12345);

        // Equal values should give 0 constraint
        let constraint = U256Compare::eq_constraint(&a, &b);
        assert!(constraint.is_zero());

        // Different values should give non-zero
        let c = U256Limbs::from_u64(54321);
        let constraint = U256Compare::eq_constraint(&a, &c);
        assert!(!constraint.is_zero());
    }

    #[test]
    fn test_zero_comparison() {
        let zero = U256Limbs::zero();
        let one = U256Limbs::one();

        assert!(U256Compare::lt(&zero, &one));
        assert!(!U256Compare::lt(&one, &zero));
        assert!(!U256Compare::lt(&zero, &zero));
    }
}
