//! secp256k1 Point Operations
//!
//! Jacobian coordinates (X, Y, Z) where x = X/Z², y = Y/Z³.

use super::field::FieldElement;
use super::params;
use crate::bigint::U256Limbs;

/// Affine point (x, y) or point at infinity
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub infinity: bool,
}

impl AffinePoint {
    /// Point at infinity (identity)
    pub fn infinity() -> Self {
        AffinePoint {
            x: FieldElement::zero(),
            y: FieldElement::zero(),
            infinity: true,
        }
    }

    /// Create from coordinates
    pub fn new(x: FieldElement, y: FieldElement) -> Self {
        AffinePoint {
            x,
            y,
            infinity: false,
        }
    }

    /// Generator point G
    pub fn generator() -> Self {
        AffinePoint {
            x: FieldElement::from_limbs(params::generator_x()),
            y: FieldElement::from_limbs(params::generator_y()),
            infinity: false,
        }
    }

    /// Check if point at infinity
    pub fn is_infinity(&self) -> bool {
        self.infinity
    }

    /// Convert to Jacobian coordinates
    pub fn to_jacobian(&self) -> JacobianPoint {
        if self.infinity {
            JacobianPoint::infinity()
        } else {
            JacobianPoint {
                x: self.x.clone(),
                y: self.y.clone(),
                z: FieldElement::one(),
            }
        }
    }

    /// Check if point is on curve: y² = x³ + 7 (mod p)
    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }

        let y2 = self.y.square();
        let x3 = self.x.square().mul(&self.x);
        let b = FieldElement::from_limbs(params::secp256k1_b());
        let rhs = x3.add(&b);

        y2 == rhs
    }

    /// Create from compressed bytes (33 bytes: prefix + x)
    pub fn from_compressed(bytes: &[u8; 33]) -> Option<Self> {
        let prefix = bytes[0];
        if prefix != 0x02 && prefix != 0x03 {
            return None;
        }

        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[1..33]);
        let x = FieldElement::from_bytes_be(&x_bytes);

        // Compute y from curve equation: y² = x³ + 7
        let x3 = x.square().mul(&x);
        let b = FieldElement::from_limbs(params::secp256k1_b());
        let y2 = x3.add(&b);

        let y = y2.sqrt()?;

        // Select correct y based on parity
        let y_parity = y.0.to_bytes_be()[31] & 1;
        let expected_parity = if prefix == 0x02 { 0 } else { 1 };

        let y = if y_parity != expected_parity {
            y.neg()
        } else {
            y
        };

        let point = AffinePoint::new(x, y);
        if point.is_on_curve() {
            Some(point)
        } else {
            None
        }
    }

    /// Create from uncompressed bytes (65 bytes: 0x04 + x + y)
    pub fn from_uncompressed(bytes: &[u8; 65]) -> Option<Self> {
        if bytes[0] != 0x04 {
            return None;
        }

        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[1..33]);
        let x = FieldElement::from_bytes_be(&x_bytes);

        let mut y_bytes = [0u8; 32];
        y_bytes.copy_from_slice(&bytes[33..65]);
        let y = FieldElement::from_bytes_be(&y_bytes);

        let point = AffinePoint::new(x, y);
        if point.is_on_curve() {
            Some(point)
        } else {
            None
        }
    }

    /// Encode to uncompressed bytes (65 bytes)
    pub fn to_uncompressed(&self) -> [u8; 65] {
        let mut result = [0u8; 65];
        result[0] = 0x04;
        result[1..33].copy_from_slice(&self.x.to_bytes_be());
        result[33..65].copy_from_slice(&self.y.to_bytes_be());
        result
    }
}

/// Jacobian point (X, Y, Z)
/// Represents (x, y) where x = X/Z², y = Y/Z³
#[derive(Clone, Debug)]
pub struct JacobianPoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
}

impl JacobianPoint {
    /// Point at infinity
    pub fn infinity() -> Self {
        JacobianPoint {
            x: FieldElement::one(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        }
    }

    /// Generator point G
    pub fn generator() -> Self {
        AffinePoint::generator().to_jacobian()
    }

    /// Check if point at infinity
    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Convert to affine coordinates
    pub fn to_affine(&self) -> AffinePoint {
        if self.is_infinity() {
            return AffinePoint::infinity();
        }

        let z_inv = self.z.inverse().unwrap();
        let z_inv2 = z_inv.square();
        let z_inv3 = z_inv2.mul(&z_inv);

        AffinePoint {
            x: self.x.mul(&z_inv2),
            y: self.y.mul(&z_inv3),
            infinity: false,
        }
    }

    /// Point negation: -(x, y) = (x, -y)
    pub fn neg(&self) -> Self {
        JacobianPoint {
            x: self.x.clone(),
            y: self.y.neg(),
            z: self.z.clone(),
        }
    }

    /// Point doubling
    ///
    /// For y² = x³ + 7 (a = 0):
    /// A = Y1²
    /// B = 4·X1·A
    /// C = 8·A²
    /// D = 3·X1² (since a = 0)
    /// X3 = D² - 2·B
    /// Y3 = D·(B - X3) - C
    /// Z3 = 2·Y1·Z1
    pub fn double(&self) -> Self {
        if self.is_infinity() || self.y.is_zero() {
            return Self::infinity();
        }

        let a = self.y.square();
        let b = self.x.mul(&a).mul_small(4);
        let c = a.square().mul_small(8);
        let d = self.x.square().mul_small(3);

        let d2 = d.square();
        let x3 = d2.sub(&b.double());
        let y3 = d.mul(&b.sub(&x3)).sub(&c);
        let z3 = self.y.mul(&self.z).double();

        JacobianPoint {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Point addition (mixed: Jacobian + Affine)
    pub fn add_affine(&self, other: &AffinePoint) -> Self {
        if other.is_infinity() {
            return self.clone();
        }
        if self.is_infinity() {
            return other.to_jacobian();
        }

        // U1 = X1
        // U2 = X2·Z1²
        // S1 = Y1
        // S2 = Y2·Z1³
        let z1_2 = self.z.square();
        let z1_3 = z1_2.mul(&self.z);

        let u2 = other.x.mul(&z1_2);
        let s2 = other.y.mul(&z1_3);

        let h = u2.sub(&self.x);
        let r = s2.sub(&self.y);

        if h.is_zero() {
            if r.is_zero() {
                return self.double();
            } else {
                return Self::infinity();
            }
        }

        let h2 = h.square();
        let h3 = h2.mul(&h);

        let x3 = r.square().sub(&h3).sub(&self.x.mul(&h2).double());
        let y3 = r.mul(&self.x.mul(&h2).sub(&x3)).sub(&self.y.mul(&h3));
        let z3 = self.z.mul(&h);

        JacobianPoint {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Point addition (Jacobian + Jacobian)
    pub fn add(&self, other: &Self) -> Self {
        if self.is_infinity() {
            return other.clone();
        }
        if other.is_infinity() {
            return self.clone();
        }

        // U1 = X1·Z2²
        // U2 = X2·Z1²
        // S1 = Y1·Z2³
        // S2 = Y2·Z1³
        let z1_2 = self.z.square();
        let z1_3 = z1_2.mul(&self.z);
        let z2_2 = other.z.square();
        let z2_3 = z2_2.mul(&other.z);

        let u1 = self.x.mul(&z2_2);
        let u2 = other.x.mul(&z1_2);
        let s1 = self.y.mul(&z2_3);
        let s2 = other.y.mul(&z1_3);

        let h = u2.sub(&u1);
        let r = s2.sub(&s1);

        if h.is_zero() {
            if r.is_zero() {
                return self.double();
            } else {
                return Self::infinity();
            }
        }

        let h2 = h.square();
        let h3 = h2.mul(&h);
        let u1h2 = u1.mul(&h2);

        let x3 = r.square().sub(&h3).sub(&u1h2.double());
        let y3 = r.mul(&u1h2.sub(&x3)).sub(&s1.mul(&h3));
        let z3 = self.z.mul(&other.z).mul(&h);

        JacobianPoint {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Scalar multiplication using double-and-add
    pub fn scalar_mul(&self, scalar: &U256Limbs) -> Self {
        let mut result = Self::infinity();
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

impl PartialEq for JacobianPoint {
    fn eq(&self, other: &Self) -> bool {
        if self.is_infinity() && other.is_infinity() {
            return true;
        }
        if self.is_infinity() || other.is_infinity() {
            return false;
        }

        // (X1, Y1, Z1) == (X2, Y2, Z2) iff
        // X1·Z2² == X2·Z1² and Y1·Z2³ == Y2·Z1³
        let z1_2 = self.z.square();
        let z1_3 = z1_2.mul(&self.z);
        let z2_2 = other.z.square();
        let z2_3 = z2_2.mul(&other.z);

        self.x.mul(&z2_2) == other.x.mul(&z1_2)
            && self.y.mul(&z2_3) == other.y.mul(&z1_3)
    }
}

impl Eq for JacobianPoint {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_on_curve() {
        let g = AffinePoint::generator();
        assert!(g.is_on_curve());
    }

    #[test]
    fn test_infinity() {
        let inf = JacobianPoint::infinity();
        assert!(inf.is_infinity());

        let affine = inf.to_affine();
        assert!(affine.is_infinity());
    }

    #[test]
    fn test_double() {
        let g = JacobianPoint::generator();
        let g2_add = g.add(&g);
        let g2_double = g.double();

        assert_eq!(g2_add.to_affine(), g2_double.to_affine());
    }

    #[test]
    fn test_neg() {
        let g = JacobianPoint::generator();
        let neg_g = g.neg();
        let sum = g.add(&neg_g);

        assert!(sum.is_infinity());
    }

    #[test]
    fn test_scalar_mul_zero() {
        let g = JacobianPoint::generator();
        let result = g.scalar_mul(&U256Limbs::zero());
        assert!(result.is_infinity());
    }

    #[test]
    fn test_scalar_mul_one() {
        let g = JacobianPoint::generator();
        let result = g.scalar_mul(&U256Limbs::one());
        assert_eq!(g.to_affine(), result.to_affine());
    }
}
