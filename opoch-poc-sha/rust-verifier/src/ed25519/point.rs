//! Ed25519 Point Operations
//!
//! Extended coordinates (X, Y, Z, T) where x = X/Z, y = Y/Z, x*y = T/Z.

use super::field::FieldElement;
use super::params;
use crate::bigint::U256Limbs;

/// Affine point (x, y)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    pub x: FieldElement,
    pub y: FieldElement,
}

impl AffinePoint {
    /// Identity point (0, 1)
    pub fn identity() -> Self {
        AffinePoint {
            x: FieldElement::zero(),
            y: FieldElement::one(),
        }
    }

    /// Create from coordinates
    pub fn new(x: FieldElement, y: FieldElement) -> Self {
        AffinePoint { x, y }
    }

    /// Base point B
    pub fn base_point() -> Self {
        AffinePoint {
            x: FieldElement::from_limbs(params::base_point_x()),
            y: FieldElement::from_limbs(params::base_point_y()),
        }
    }

    /// Check if identity
    pub fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.is_one()
    }

    /// Convert to extended coordinates
    pub fn to_extended(&self) -> EdwardsPoint {
        EdwardsPoint {
            x: self.x.clone(),
            y: self.y.clone(),
            z: FieldElement::one(),
            t: self.x.mul(&self.y),
        }
    }

    /// Create from bytes (32 bytes, compressed format)
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        // Ed25519 point encoding: y-coordinate with x sign in top bit
        let mut y_bytes = *bytes;
        let x_sign = (y_bytes[31] >> 7) & 1;
        y_bytes[31] &= 0x7F; // Clear sign bit

        let y = FieldElement::from_bytes_le(&y_bytes);

        // Recover x from curve equation: -x² + y² = 1 + d·x²·y²
        // x² = (y² - 1) / (d·y² + 1)
        let y2 = y.square();
        let d = FieldElement::from_limbs(params::ed25519_d());

        let numerator = y2.sub(&FieldElement::one());
        let denominator = d.mul(&y2).add(&FieldElement::one());

        let x2 = numerator.mul(&denominator.inverse()?);
        let mut x = x2.sqrt()?;

        // Choose correct sign
        if (x.to_bytes_le()[0] & 1) as u8 != x_sign {
            x = x.neg();
        }

        Some(AffinePoint { x, y })
    }

    /// Encode to bytes (32 bytes, compressed format)
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = self.y.to_bytes_le();
        // Set sign bit based on x
        let x_sign = self.x.to_bytes_le()[0] & 1;
        bytes[31] |= x_sign << 7;
        bytes
    }
}

/// Extended Edwards point (X, Y, Z, T)
/// Represents (x, y) where x = X/Z, y = Y/Z, x*y = T/Z
#[derive(Clone, Debug)]
pub struct EdwardsPoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
    pub t: FieldElement,
}

impl EdwardsPoint {
    /// Identity point
    pub fn identity() -> Self {
        EdwardsPoint {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one(),
            t: FieldElement::zero(),
        }
    }

    /// Base point B
    pub fn base_point() -> Self {
        AffinePoint::base_point().to_extended()
    }

    /// Check if identity
    pub fn is_identity(&self) -> bool {
        // (0, 1, Z, 0) for any Z
        self.x.is_zero() && self.t.is_zero()
    }

    /// Convert to affine coordinates
    pub fn to_affine(&self) -> AffinePoint {
        if self.z.is_zero() {
            return AffinePoint::identity();
        }

        let z_inv = self.z.inverse().unwrap();
        AffinePoint {
            x: self.x.mul(&z_inv),
            y: self.y.mul(&z_inv),
        }
    }

    /// Point negation: -(x, y) = (-x, y)
    pub fn neg(&self) -> Self {
        EdwardsPoint {
            x: self.x.neg(),
            y: self.y.clone(),
            z: self.z.clone(),
            t: self.t.neg(),
        }
    }

    /// Point addition (unified formula)
    ///
    /// For -x² + y² = 1 + d·x²·y²:
    /// Uses extended coordinates formula
    pub fn add(&self, other: &Self) -> Self {
        let d = FieldElement::from_limbs(params::ed25519_d());

        // A = X1 * X2
        let a = self.x.mul(&other.x);
        // B = Y1 * Y2
        let b = self.y.mul(&other.y);
        // C = T1 * d * T2
        let c = self.t.mul(&d).mul(&other.t);
        // D = Z1 * Z2
        let d_val = self.z.mul(&other.z);
        // E = (X1 + Y1) * (X2 + Y2) - A - B
        let e = self.x.add(&self.y).mul(&other.x.add(&other.y)).sub(&a).sub(&b);
        // F = D - C
        let f = d_val.sub(&c);
        // G = D + C
        let g = d_val.add(&c);
        // H = B + A (since a = -1)
        let h = b.add(&a);

        EdwardsPoint {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// Point doubling (more efficient than generic add)
    pub fn double(&self) -> Self {
        // A = X1²
        let a = self.x.square();
        // B = Y1²
        let b = self.y.square();
        // C = 2 * Z1²
        let c = self.z.square().double();
        // D = -A (since a = -1)
        let d = a.neg();
        // E = (X1 + Y1)² - A - B
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        // G = D + B
        let g = d.add(&b);
        // F = G - C
        let f = g.sub(&c);
        // H = D - B
        let h = d.sub(&b);

        EdwardsPoint {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// Scalar multiplication using double-and-add
    pub fn scalar_mul(&self, scalar: &U256Limbs) -> Self {
        let mut result = Self::identity();
        let mut base = self.clone();

        for i in 0..256 {
            if scalar.get_bit(i) {
                result = result.add(&base);
            }
            base = base.double();
        }

        result
    }
}

impl PartialEq for EdwardsPoint {
    fn eq(&self, other: &Self) -> bool {
        // (X1, Y1, Z1) == (X2, Y2, Z2) iff X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1
        let x1z2 = self.x.mul(&other.z);
        let x2z1 = other.x.mul(&self.z);
        let y1z2 = self.y.mul(&other.z);
        let y2z1 = other.y.mul(&self.z);

        x1z2 == x2z1 && y1z2 == y2z1
    }
}

impl Eq for EdwardsPoint {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity() {
        let id = EdwardsPoint::identity();
        assert!(id.is_identity());

        let affine = id.to_affine();
        assert!(affine.is_identity());
    }

    #[test]
    fn test_base_point() {
        let b = EdwardsPoint::base_point();
        assert!(!b.is_identity());
    }

    #[test]
    fn test_add_identity() {
        let b = EdwardsPoint::base_point();
        let id = EdwardsPoint::identity();

        let result = b.add(&id);
        assert_eq!(b.to_affine(), result.to_affine());
    }

    #[test]
    fn test_double() {
        let b = EdwardsPoint::base_point();
        let b2_add = b.add(&b);
        let b2_double = b.double();

        assert_eq!(b2_add.to_affine(), b2_double.to_affine());
    }

    #[test]
    fn test_neg() {
        let b = EdwardsPoint::base_point();
        let neg_b = b.neg();
        let sum = b.add(&neg_b);

        assert!(sum.is_identity());
    }

    #[test]
    fn test_scalar_mul_zero() {
        let b = EdwardsPoint::base_point();
        let result = b.scalar_mul(&U256Limbs::zero());
        assert!(result.is_identity());
    }

    #[test]
    fn test_scalar_mul_one() {
        let b = EdwardsPoint::base_point();
        let result = b.scalar_mul(&U256Limbs::one());
        assert_eq!(b.to_affine(), result.to_affine());
    }
}
