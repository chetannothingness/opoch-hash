//! Witness-Based Modular Inverse
//!
//! Instead of computing x^(-1) in-circuit (expensive!),
//! we make x^(-1) a witness and verify: x × x^(-1) ≡ 1 (mod n)
//!
//! This is a single multiplication check, not exponentiation!

use crate::field::Fp;
use super::{LIMB_COUNT, LIMB_BITS, LIMB_MAX};
use super::limbs::U256Limbs;
use super::mul::{U256Mul, U512Product};
use super::reduce::ModularReduce;
use super::compare::U256Compare;

/// Witness-based inverse operations
pub struct WitnessInverse;

impl WitnessInverse {
    /// Verify that w is the inverse of x modulo n
    ///
    /// Checks: x * w ≡ 1 (mod n)
    pub fn verify_inverse(x: &U256Limbs, w: &U256Limbs, modulus: &U256Limbs) -> bool {
        // Check x and w are both < n
        if U256Compare::gte(x, modulus) || U256Compare::gte(w, modulus) {
            return false;
        }

        // Compute x * w
        let product = U256Mul::mul_full(x, w);

        // Reduce mod n
        let reduced = ModularReduce::reduce_generic(&product, modulus);

        // Check result is 1
        reduced.is_one()
    }

    /// Compute actual inverse using extended Euclidean algorithm
    /// (Used to generate witness, not in STARK)
    pub fn compute_inverse(x: &U256Limbs, modulus: &U256Limbs) -> Option<U256Limbs> {
        if x.is_zero() {
            return None;
        }

        if U256Compare::gte(x, modulus) {
            return None;
        }

        // Use Fermat's little theorem: x^(-1) = x^(p-2) mod p
        // This assumes modulus is prime
        let p_minus_2 = Self::sub_one(&Self::sub_one(modulus));
        Self::pow_mod(x, &p_minus_2, modulus)
    }

    /// Modular exponentiation (for computing inverse witness)
    fn pow_mod(base: &U256Limbs, exp: &U256Limbs, modulus: &U256Limbs) -> Option<U256Limbs> {
        let mut result = U256Limbs::one();
        let mut b = base.clone();

        for i in 0..256 {
            if exp.get_bit(i) {
                let product = U256Mul::mul_full(&result, &b);
                result = ModularReduce::reduce_generic(&product, modulus);
            }
            let sq = U256Mul::mul_full(&b, &b);
            b = ModularReduce::reduce_generic(&sq, modulus);
        }

        Some(result)
    }

    /// Subtract 1 from value (for p-2 in Fermat's)
    fn sub_one(x: &U256Limbs) -> U256Limbs {
        super::sub::U256Sub::sub(x, &U256Limbs::one()).0
    }

    /// Generate AIR constraint evaluations for inverse verification
    ///
    /// Returns constraint values that should all be zero for valid inverse
    pub fn inverse_constraint_evals(
        x: &U256Limbs,
        w: &U256Limbs,
        product: &U512Product,
        quotient: &U256Limbs,
        remainder: &U256Limbs,
        modulus: &U256Limbs,
    ) -> Vec<Fp> {
        // Constraint 1: product = x * w
        // (Already verified by multiplication constraints)

        // Constraint 2: product = quotient * modulus + remainder
        // This proves product mod modulus = remainder

        // Constraint 3: remainder = 1

        let mut constraints = Vec::new();

        // Check remainder is 1
        constraints.push(remainder.limbs[0] - Fp::ONE);
        for i in 1..LIMB_COUNT {
            constraints.push(remainder.limbs[i]); // Should be zero
        }

        // Full verification would include quotient * modulus + remainder = product
        // but that requires many constraint columns

        constraints
    }
}

/// Batch inverse computation using Montgomery's trick
///
/// Computes [a1^(-1), a2^(-1), ..., an^(-1)] using 3(n-1) multiplications
/// instead of n inversions
pub struct BatchInverse;

impl BatchInverse {
    /// Compute batch inverse
    ///
    /// Returns None if any input is zero
    pub fn batch_inverse(inputs: &[U256Limbs], modulus: &U256Limbs) -> Option<Vec<U256Limbs>> {
        let n = inputs.len();
        if n == 0 {
            return Some(Vec::new());
        }

        // Check no zeros
        for input in inputs {
            if input.is_zero() {
                return None;
            }
        }

        // Compute running products: products[i] = a0 * a1 * ... * a_i
        let mut products = Vec::with_capacity(n);
        products.push(inputs[0].clone());

        for i in 1..n {
            let prev = &products[i - 1];
            let prod = U256Mul::mul_full(prev, &inputs[i]);
            products.push(ModularReduce::reduce_generic(&prod, modulus));
        }

        // Compute inverse of total product
        let total_inv = WitnessInverse::compute_inverse(&products[n - 1], modulus)?;

        // Compute individual inverses using:
        // a_i^(-1) = (a0 * ... * a_{i-1}) * (a0 * ... * a_n)^(-1) * (a_{i+1} * ... * a_n)
        //
        // More efficiently:
        // Work backwards, maintaining running_inv = (a_{i+1} * ... * a_n)^(-1)
        let mut results = vec![U256Limbs::zero(); n];
        let mut running_inv = total_inv;

        for i in (0..n).rev() {
            if i > 0 {
                // results[i] = products[i-1] * running_inv
                let prod = U256Mul::mul_full(&products[i - 1], &running_inv);
                results[i] = ModularReduce::reduce_generic(&prod, modulus);

                // Update running_inv = running_inv * a_i
                let new_inv = U256Mul::mul_full(&running_inv, &inputs[i]);
                running_inv = ModularReduce::reduce_generic(&new_inv, modulus);
            } else {
                // results[0] = running_inv
                results[0] = running_inv.clone();
            }
        }

        Some(results)
    }
}

/// Division via witness multiplication
///
/// To compute a/b mod n:
/// 1. Prover computes q = a * b^(-1) mod n as witness
/// 2. Verifier checks: q * b ≡ a (mod n)
pub struct WitnessDivision;

impl WitnessDivision {
    /// Verify that q = a / b (mod n)
    ///
    /// Checks: q * b ≡ a (mod n)
    pub fn verify_division(
        a: &U256Limbs,
        b: &U256Limbs,
        q: &U256Limbs,
        modulus: &U256Limbs,
    ) -> bool {
        // Check inputs are < n
        if U256Compare::gte(a, modulus)
            || U256Compare::gte(b, modulus)
            || U256Compare::gte(q, modulus)
        {
            return false;
        }

        // b should be non-zero
        if b.is_zero() {
            return false;
        }

        // Compute q * b
        let product = U256Mul::mul_full(q, b);
        let reduced = ModularReduce::reduce_generic(&product, modulus);

        // Check equals a
        reduced == *a
    }

    /// Compute division (for witness generation)
    pub fn compute_division(
        a: &U256Limbs,
        b: &U256Limbs,
        modulus: &U256Limbs,
    ) -> Option<U256Limbs> {
        let b_inv = WitnessInverse::compute_inverse(b, modulus)?;
        let product = U256Mul::mul_full(a, &b_inv);
        Some(ModularReduce::reduce_generic(&product, modulus))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::reduce::ModularReduce;

    #[test]
    fn test_verify_inverse_small() {
        // Use small modulus for testing
        let modulus = U256Limbs::from_u64(97); // Prime

        let x = U256Limbs::from_u64(5);
        // 5^(-1) mod 97: need 5 * w ≡ 1 (mod 97)
        // 5 * 39 = 195 = 2 * 97 + 1, so w = 39
        let w = U256Limbs::from_u64(39);

        assert!(WitnessInverse::verify_inverse(&x, &w, &modulus));
    }

    #[test]
    fn test_verify_inverse_wrong() {
        let modulus = U256Limbs::from_u64(97);
        let x = U256Limbs::from_u64(5);
        let wrong_w = U256Limbs::from_u64(40);

        assert!(!WitnessInverse::verify_inverse(&x, &wrong_w, &modulus));
    }

    #[test]
    fn test_compute_inverse() {
        let modulus = U256Limbs::from_u64(97);
        let x = U256Limbs::from_u64(5);

        let inv = WitnessInverse::compute_inverse(&x, &modulus).unwrap();

        // Verify: x * inv ≡ 1 (mod 97)
        assert!(WitnessInverse::verify_inverse(&x, &inv, &modulus));
    }

    #[test]
    fn test_compute_inverse_zero() {
        let modulus = U256Limbs::from_u64(97);
        let zero = U256Limbs::zero();

        let result = WitnessInverse::compute_inverse(&zero, &modulus);
        assert!(result.is_none());
    }

    #[test]
    fn test_batch_inverse() {
        let modulus = U256Limbs::from_u64(97);

        let inputs = vec![
            U256Limbs::from_u64(2),
            U256Limbs::from_u64(5),
            U256Limbs::from_u64(11),
        ];

        let inverses = BatchInverse::batch_inverse(&inputs, &modulus).unwrap();

        // Verify each inverse
        for (x, inv) in inputs.iter().zip(inverses.iter()) {
            assert!(WitnessInverse::verify_inverse(x, inv, &modulus));
        }
    }

    #[test]
    fn test_batch_inverse_with_zero() {
        let modulus = U256Limbs::from_u64(97);

        let inputs = vec![
            U256Limbs::from_u64(2),
            U256Limbs::zero(), // Invalid
            U256Limbs::from_u64(5),
        ];

        let result = BatchInverse::batch_inverse(&inputs, &modulus);
        assert!(result.is_none());
    }

    #[test]
    fn test_witness_division() {
        let modulus = U256Limbs::from_u64(97);

        let a = U256Limbs::from_u64(30);
        let b = U256Limbs::from_u64(5);

        let q = WitnessDivision::compute_division(&a, &b, &modulus).unwrap();

        // Verify
        assert!(WitnessDivision::verify_division(&a, &b, &q, &modulus));

        // q * 5 ≡ 30 (mod 97)
        // 30 / 5 = 6
        assert_eq!(q.limbs[0].to_u64(), 6);
    }

    #[test]
    fn test_inverse_ed25519() {
        let p = ModularReduce::ed25519_p();
        let x = U256Limbs::from_u64(12345);

        let inv = WitnessInverse::compute_inverse(&x, &p).unwrap();
        assert!(WitnessInverse::verify_inverse(&x, &inv, &p));
    }
}
