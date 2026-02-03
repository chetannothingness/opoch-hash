//! Poseidon S-box
//!
//! Implements x^7 S-box optimized for Goldilocks field.

use crate::field::Fp;

/// S-box: x^7 in Goldilocks field
///
/// Computed efficiently as:
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

/// S-box with intermediate values (for AIR constraints)
///
/// Returns (x2, x3, x6, x7)
pub fn sbox_with_intermediates(x: Fp) -> (Fp, Fp, Fp, Fp) {
    let x2 = x * x;
    let x3 = x2 * x;
    let x6 = x3 * x3;
    let x7 = x6 * x;
    (x2, x3, x6, x7)
}

/// S-box intermediates struct (for constraint generation)
#[derive(Clone, Copy, Debug)]
pub struct SboxIntermediates {
    pub x2: Fp,
    pub x3: Fp,
    pub x6: Fp,
    pub x7: Fp,
}

impl SboxIntermediates {
    /// Compute S-box intermediates
    pub fn compute(x: Fp) -> Self {
        let (x2, x3, x6, x7) = sbox_with_intermediates(x);
        SboxIntermediates { x2, x3, x6, x7 }
    }

    /// Verify S-box constraints
    ///
    /// Returns true if all constraints are satisfied:
    /// - x2 = x * x
    /// - x3 = x2 * x
    /// - x6 = x3 * x3
    /// - x7 = x6 * x
    pub fn verify(&self, x: Fp) -> bool {
        self.x2 == x * x
            && self.x3 == self.x2 * x
            && self.x6 == self.x3 * self.x3
            && self.x7 == self.x6 * x
    }

    /// Get constraint evaluations
    ///
    /// Returns [x2 - x*x, x3 - x2*x, x6 - x3*x3, x7 - x6*x]
    /// All should be zero for valid S-box
    pub fn constraint_evals(&self, x: Fp) -> [Fp; 4] {
        [
            self.x2 - x * x,
            self.x3 - self.x2 * x,
            self.x6 - self.x3 * self.x3,
            self.x7 - self.x6 * x,
        ]
    }
}

/// S-box inverse: x^(1/7) in Goldilocks field
///
/// Computed using Fermat's little theorem:
/// x^(1/7) = x^((p-1)/7 * (p-1) + 1 - (p-1)) / 7 = ...
/// For Goldilocks p = 2^64 - 2^32 + 1, we need to find (p-1)/gcd(7, p-1)
pub fn sbox_inverse(x: Fp) -> Fp {
    if x.is_zero() {
        return Fp::ZERO;
    }

    // For p = 2^64 - 2^32 + 1 = 18446744069414584321
    // p - 1 = 2^64 - 2^32 = 2^32 * (2^32 - 1)
    // gcd(7, p-1) = 1 (7 doesn't divide p-1)
    // So x^(1/7) = x^d where d*7 ≡ 1 (mod p-1)
    //
    // Using extended Euclidean algorithm:
    // d = (p-1+1)/7 when 7 | (p-1+1), otherwise compute modular inverse
    //
    // Actually, d = modular_inverse(7, p-1)

    // For Goldilocks: d = 10540996611094048183
    // Computed as 7^(-1) mod (p-1) using extended Euclidean algorithm
    const SBOX_INV_EXP: u64 = 10540996611094048183;
    x.pow(SBOX_INV_EXP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbox_basic() {
        let x = Fp::new(5);
        let y = sbox(x);

        // 5^7 = 78125
        assert_eq!(y, Fp::new(78125));
    }

    #[test]
    fn test_sbox_zero() {
        assert_eq!(sbox(Fp::ZERO), Fp::ZERO);
    }

    #[test]
    fn test_sbox_one() {
        assert_eq!(sbox(Fp::ONE), Fp::ONE);
    }

    #[test]
    fn test_sbox_intermediates() {
        let x = Fp::new(3);
        let inter = SboxIntermediates::compute(x);

        assert!(inter.verify(x));

        let evals = inter.constraint_evals(x);
        for eval in &evals {
            assert!(eval.is_zero());
        }

        // Verify values
        // 3^2 = 9, 3^3 = 27, 3^6 = 729, 3^7 = 2187
        assert_eq!(inter.x2, Fp::new(9));
        assert_eq!(inter.x3, Fp::new(27));
        assert_eq!(inter.x6, Fp::new(729));
        assert_eq!(inter.x7, Fp::new(2187));
    }

    #[test]
    fn test_sbox_inverse() {
        // For small values, verify sbox_inverse(sbox(x)) = x
        for i in 1..100 {
            let x = Fp::new(i);
            let y = sbox(x);
            let x_recovered = sbox_inverse(y);
            assert_eq!(x, x_recovered, "Failed for x = {}", i);
        }
    }

    #[test]
    fn test_sbox_inverse_zero() {
        assert_eq!(sbox_inverse(Fp::ZERO), Fp::ZERO);
    }
}
