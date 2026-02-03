//! Ed25519 Field Arithmetic
//!
//! Modular arithmetic over p = 2^255 - 19 using U256Limbs.

use crate::bigint::{U256Limbs, U256Add, U256Sub, U256Mul, ModularReduce, U256Compare};

/// Field element (mod p = 2^255 - 19)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldElement(pub U256Limbs);

impl FieldElement {
    /// Zero
    pub fn zero() -> Self {
        FieldElement(U256Limbs::zero())
    }

    /// One
    pub fn one() -> Self {
        FieldElement(U256Limbs::one())
    }

    /// Create from U256Limbs
    pub fn from_limbs(limbs: U256Limbs) -> Self {
        // Reduce mod p
        let p = super::params::ed25519_p();
        if U256Compare::gte(&limbs, &p) {
            FieldElement(U256Sub::sub(&limbs, &p).0)
        } else {
            FieldElement(limbs)
        }
    }

    /// Create from bytes (little-endian as per Ed25519 spec)
    pub fn from_bytes_le(bytes: &[u8; 32]) -> Self {
        let mut limbs = U256Limbs::from_bytes_le(bytes);
        // Clear top bit (bit 255) as per Ed25519
        let limb_15 = limbs.limbs[15].to_u64();
        limbs.limbs[15] = crate::field::Fp::new(limb_15 & 0x7FFF);
        Self::from_limbs(limbs)
    }

    /// Convert to bytes (little-endian)
    pub fn to_bytes_le(&self) -> [u8; 32] {
        self.0.to_bytes_le()
    }

    /// Field modulus p
    pub fn modulus() -> U256Limbs {
        super::params::ed25519_p()
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Check if one
    pub fn is_one(&self) -> bool {
        self.0.is_one()
    }

    /// Add two field elements
    pub fn add(&self, other: &Self) -> Self {
        let (sum, overflow) = U256Add::add(&self.0, &other.0);
        let p = Self::modulus();
        if overflow || U256Compare::gte(&sum, &p) {
            FieldElement(U256Sub::sub(&sum, &p).0)
        } else {
            FieldElement(sum)
        }
    }

    /// Subtract two field elements
    pub fn sub(&self, other: &Self) -> Self {
        let (diff, underflow) = U256Sub::sub(&self.0, &other.0);
        if underflow {
            let p = Self::modulus();
            FieldElement(U256Add::add(&diff, &p).0)
        } else {
            FieldElement(diff)
        }
    }

    /// Negate
    pub fn neg(&self) -> Self {
        if self.is_zero() {
            self.clone()
        } else {
            let p = Self::modulus();
            FieldElement(U256Sub::sub(&p, &self.0).0)
        }
    }

    /// Multiply two field elements
    pub fn mul(&self, other: &Self) -> Self {
        let product = U256Mul::mul_full(&self.0, &other.0);
        FieldElement(ModularReduce::reduce_ed25519(&product))
    }

    /// Square
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Double (2x)
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Multiply by small constant
    pub fn mul_small(&self, k: u64) -> Self {
        let product = U256Mul::mul_u64(&self.0, k);
        FieldElement(ModularReduce::reduce_ed25519(&product))
    }

    /// Compute modular inverse using Fermat's little theorem
    /// a^(-1) = a^(p-2) mod p
    pub fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        Some(self.pow(&Self::p_minus_2()))
    }

    /// p - 2 (for Fermat's inverse)
    fn p_minus_2() -> U256Limbs {
        let p = Self::modulus();
        U256Sub::sub(&p, &U256Limbs::from_u64(2)).0
    }

    /// Exponentiation
    pub fn pow(&self, exp: &U256Limbs) -> Self {
        let mut result = Self::one();
        let mut base = self.clone();

        for i in 0..256 {
            if exp.get_bit(i) {
                result = result.mul(&base);
            }
            base = base.square();
        }

        result
    }

    /// Compute square root (if exists)
    /// Uses p ≡ 5 (mod 8), so sqrt(a) = a^((p+3)/8) or i*a^((p+3)/8)
    pub fn sqrt(&self) -> Option<Self> {
        // For p = 2^255 - 19, (p+3)/8 = 2^252 - 2
        // sqrt(a) = a^((p+3)/8) if a is a QR
        // Otherwise, sqrt(a) = sqrt(-1) * a^((p+3)/8)

        if self.is_zero() {
            return Some(Self::zero());
        }

        // Compute a^((p-5)/8)
        let exp = Self::p_plus_3_div_8();
        let beta = self.pow(&exp);

        // Check if beta^2 = a
        let beta_sq = beta.square();
        if beta_sq == *self {
            return Some(beta);
        }

        // Try with sqrt(-1)
        let sqrt_minus_1 = Self::sqrt_minus_1();
        let result = beta.mul(&sqrt_minus_1);
        if result.square() == *self {
            return Some(result);
        }

        None // Not a quadratic residue
    }

    /// (p+3)/8 for square root
    fn p_plus_3_div_8() -> U256Limbs {
        // 2^252 - 2
        let mut result = U256Limbs::zero();
        // Set bit 252
        result.limbs[15] = crate::field::Fp::new(0x1000);
        U256Sub::sub(&result, &U256Limbs::from_u64(2)).0
    }

    /// sqrt(-1) mod p (precomputed)
    fn sqrt_minus_1() -> Self {
        // sqrt(-1) = 2^((p-1)/4) mod p
        // Hex: 2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
        let bytes: [u8; 32] = [
            0x2b, 0x83, 0x24, 0x80, 0x4f, 0xc1, 0xdf, 0x0b,
            0x2b, 0x4d, 0x00, 0x99, 0x3d, 0xfb, 0xd7, 0xa7,
            0x2f, 0x43, 0x18, 0x06, 0xad, 0x2f, 0xe4, 0x78,
            0xc4, 0xee, 0x1b, 0x27, 0x4a, 0x0e, 0xa0, 0xb0,
        ];
        FieldElement(U256Limbs::from_bytes_be(&bytes))
    }
}

impl std::ops::Add for FieldElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        FieldElement::add(&self, &rhs)
    }
}

impl std::ops::Sub for FieldElement {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        FieldElement::sub(&self, &rhs)
    }
}

impl std::ops::Mul for FieldElement {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        FieldElement::mul(&self, &rhs)
    }
}

impl std::ops::Neg for FieldElement {
    type Output = Self;
    fn neg(self) -> Self {
        FieldElement::neg(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_add() {
        let a = FieldElement::from_limbs(U256Limbs::from_u64(100));
        let b = FieldElement::from_limbs(U256Limbs::from_u64(200));
        let c = a.add(&b);
        assert_eq!(c.0.limbs[0].to_u64(), 300);
    }

    #[test]
    fn test_field_sub() {
        let a = FieldElement::from_limbs(U256Limbs::from_u64(100));
        let b = FieldElement::from_limbs(U256Limbs::from_u64(200));
        let c = a.sub(&b);
        // 100 - 200 mod p = p - 100
        assert!(!c.is_zero());
    }

    #[test]
    fn test_field_mul() {
        let a = FieldElement::from_limbs(U256Limbs::from_u64(3));
        let b = FieldElement::from_limbs(U256Limbs::from_u64(7));
        let c = a.mul(&b);
        assert_eq!(c.0.limbs[0].to_u64(), 21);
    }

    #[test]
    fn test_field_inverse() {
        let a = FieldElement::from_limbs(U256Limbs::from_u64(3));
        let a_inv = a.inverse().unwrap();
        let product = a.mul(&a_inv);
        assert!(product.is_one());
    }

    #[test]
    fn test_field_neg() {
        let a = FieldElement::from_limbs(U256Limbs::from_u64(100));
        let neg_a = a.neg();
        let sum = a.add(&neg_a);
        assert!(sum.is_zero());
    }
}
