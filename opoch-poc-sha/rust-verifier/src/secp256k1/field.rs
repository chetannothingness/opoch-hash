//! secp256k1 Field Arithmetic
//!
//! Modular arithmetic over p = 2^256 - 2^32 - 977 using U256Limbs.

use crate::bigint::{U256Limbs, U256Add, U256Sub, U256Mul, ModularReduce, U256Compare};

/// Field element (mod p = 2^256 - 2^32 - 977)
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
        // Reduce mod p if needed
        let p = super::params::secp256k1_p();
        if U256Compare::gte(&limbs, &p) {
            FieldElement(U256Sub::sub(&limbs, &p).0)
        } else {
            FieldElement(limbs)
        }
    }

    /// Create from bytes (big-endian as per Bitcoin/Ethereum conventions)
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Self {
        Self::from_limbs(U256Limbs::from_bytes_be(bytes))
    }

    /// Convert to bytes (big-endian)
    pub fn to_bytes_be(&self) -> [u8; 32] {
        self.0.to_bytes_be()
    }

    /// Field modulus p
    pub fn modulus() -> U256Limbs {
        super::params::secp256k1_p()
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
        FieldElement(ModularReduce::reduce_secp256k1(&product))
    }

    /// Square
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Double (2x)
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Triple (3x)
    pub fn triple(&self) -> Self {
        self.add(&self.double())
    }

    /// Multiply by small constant
    pub fn mul_small(&self, k: u64) -> Self {
        let product = U256Mul::mul_u64(&self.0, k);
        FieldElement(ModularReduce::reduce_secp256k1(&product))
    }

    /// Compute modular inverse using Fermat's little theorem
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
    /// For p ≡ 3 (mod 4), sqrt(a) = a^((p+1)/4)
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() {
            return Some(Self::zero());
        }

        // p = 2^256 - 2^32 - 977
        // p ≡ 3 (mod 4), so sqrt(a) = a^((p+1)/4)
        let exp = Self::p_plus_1_div_4();
        let result = self.pow(&exp);

        // Verify
        if result.square() == *self {
            Some(result)
        } else {
            None // Not a quadratic residue
        }
    }

    /// (p+1)/4 for square root
    fn p_plus_1_div_4() -> U256Limbs {
        // (p+1)/4 = (2^256 - 2^32 - 976) / 4 = 2^254 - 2^30 - 244
        let mut result = U256Limbs::zero();
        // Set appropriate bits
        result.limbs[15] = crate::field::Fp::new(0x4000); // Bit 254
        let term2 = U256Limbs::from_u64(1 << 30);
        let term3 = U256Limbs::from_u64(244);
        result = U256Sub::sub(&result, &term2).0;
        result = U256Sub::sub(&result, &term3).0;
        result
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
