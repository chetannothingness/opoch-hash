//! ECDSA Signature Verification
//!
//! Implements secp256k1 ECDSA verification for Bitcoin/Ethereum.

use super::point::{JacobianPoint, AffinePoint};
use super::scalar_mul::{scalar_mul, double_scalar_mul};
use super::params;
use crate::bigint::{U256Limbs, U256Compare, U256Mul, ModularReduce, WitnessInverse};

/// ECDSA signature (r, s)
#[derive(Clone, Debug)]
pub struct ECDSASignature {
    /// r component (x-coordinate of R)
    pub r: U256Limbs,
    /// s component
    pub s: U256Limbs,
}

impl ECDSASignature {
    /// Create from r and s
    pub fn new(r: U256Limbs, s: U256Limbs) -> Self {
        ECDSASignature { r, s }
    }

    /// Create from 64-byte signature (r || s in big-endian)
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&bytes[0..32]);
        let r = U256Limbs::from_bytes_be(&r_bytes);

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);
        let s = U256Limbs::from_bytes_be(&s_bytes);

        let n = params::secp256k1_n();

        // r and s must be in [1, n-1]
        if r.is_zero() || s.is_zero() {
            return None;
        }
        if U256Compare::gte(&r, &n) || U256Compare::gte(&s, &n) {
            return None;
        }

        Some(ECDSASignature { r, s })
    }

    /// Encode to 64 bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[0..32].copy_from_slice(&self.r.to_bytes_be());
        result[32..64].copy_from_slice(&self.s.to_bytes_be());
        result
    }

    /// Normalize signature to low S form (required by Bitcoin/Ethereum)
    pub fn normalize(&self) -> Self {
        let n = params::secp256k1_n();
        let half_n = params::half_n();

        let s = if U256Compare::gt(&self.s, &half_n) {
            crate::bigint::U256Sub::sub(&n, &self.s).0
        } else {
            self.s.clone()
        };

        ECDSASignature {
            r: self.r.clone(),
            s,
        }
    }
}

/// ECDSA public key (point on curve)
#[derive(Clone, Debug)]
pub struct ECDSAPublicKey {
    pub point: AffinePoint,
}

impl ECDSAPublicKey {
    /// Create from affine point
    pub fn new(point: AffinePoint) -> Self {
        ECDSAPublicKey { point }
    }

    /// Create from compressed bytes (33 bytes)
    pub fn from_compressed(bytes: &[u8; 33]) -> Option<Self> {
        let point = AffinePoint::from_compressed(bytes)?;
        Some(ECDSAPublicKey { point })
    }

    /// Create from uncompressed bytes (65 bytes)
    pub fn from_uncompressed(bytes: &[u8; 65]) -> Option<Self> {
        let point = AffinePoint::from_uncompressed(bytes)?;
        Some(ECDSAPublicKey { point })
    }

    /// Encode to uncompressed bytes
    pub fn to_uncompressed(&self) -> [u8; 65] {
        self.point.to_uncompressed()
    }
}

/// Verify ECDSA signature
///
/// Given signature (r, s), public key Q, and message hash z:
/// 1. w = s⁻¹ mod n
/// 2. u1 = z·w mod n
/// 3. u2 = r·w mod n
/// 4. P = u1·G + u2·Q
/// 5. Accept iff P.x mod n = r
pub fn verify_ecdsa(
    public_key: &ECDSAPublicKey,
    message_hash: &[u8; 32],
    signature: &ECDSASignature,
) -> bool {
    let n = params::secp256k1_n();

    // z = message hash (already reduced mod n if needed)
    let z = U256Limbs::from_bytes_be(message_hash);

    // w = s⁻¹ mod n
    let w = match compute_mod_inverse(&signature.s, &n) {
        Some(w) => w,
        None => return false,
    };

    // u1 = z·w mod n
    let u1 = mul_mod(&z, &w, &n);

    // u2 = r·w mod n
    let u2 = mul_mod(&signature.r, &w, &n);

    // P = u1·G + u2·Q
    let q = public_key.point.to_jacobian();
    let p = double_scalar_mul(&u1, &u2, &q);

    if p.is_infinity() {
        return false;
    }

    // Get x-coordinate of P
    let p_affine = p.to_affine();
    let px = p_affine.x.0;

    // Reduce x mod n (in case x >= n)
    let px_mod_n = if U256Compare::gte(&px, &n) {
        crate::bigint::U256Sub::sub(&px, &n).0
    } else {
        px
    };

    // Check r == P.x mod n
    px_mod_n == signature.r
}

/// Compute modular inverse using extended Euclidean algorithm
fn compute_mod_inverse(a: &U256Limbs, n: &U256Limbs) -> Option<U256Limbs> {
    WitnessInverse::compute_inverse(a, n)
}

/// Multiply and reduce mod n
fn mul_mod(a: &U256Limbs, b: &U256Limbs, n: &U256Limbs) -> U256Limbs {
    let product = U256Mul::mul_full(a, b);
    ModularReduce::reduce_generic(&product, n)
}

/// ECDSA verification with detailed result
pub fn verify_ecdsa_detailed(
    public_key: &ECDSAPublicKey,
    message_hash: &[u8; 32],
    signature: &ECDSASignature,
) -> ECDSAVerifyResult {
    let n = params::secp256k1_n();
    let z = U256Limbs::from_bytes_be(message_hash);

    let w = compute_mod_inverse(&signature.s, &n);
    if w.is_none() {
        return ECDSAVerifyResult {
            valid: false,
            w: U256Limbs::zero(),
            u1: U256Limbs::zero(),
            u2: U256Limbs::zero(),
            p: JacobianPoint::infinity(),
        };
    }
    let w = w.unwrap();

    let u1 = mul_mod(&z, &w, &n);
    let u2 = mul_mod(&signature.r, &w, &n);

    let q = public_key.point.to_jacobian();
    let p = double_scalar_mul(&u1, &u2, &q);

    let valid = if p.is_infinity() {
        false
    } else {
        let p_affine = p.to_affine();
        let px = p_affine.x.0;
        let px_mod_n = if U256Compare::gte(&px, &n) {
            crate::bigint::U256Sub::sub(&px, &n).0
        } else {
            px
        };
        px_mod_n == signature.r
    };

    ECDSAVerifyResult {
        valid,
        w,
        u1,
        u2,
        p,
    }
}

/// Detailed verification result
#[derive(Clone, Debug)]
pub struct ECDSAVerifyResult {
    pub valid: bool,
    pub w: U256Limbs,
    pub u1: U256Limbs,
    pub u2: U256Limbs,
    pub p: JacobianPoint,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_encoding() {
        let r = U256Limbs::from_u64(12345);
        let s = U256Limbs::from_u64(67890);
        let sig = ECDSASignature::new(r.clone(), s.clone());

        let bytes = sig.to_bytes();
        let recovered = ECDSASignature::from_bytes(&bytes).unwrap();

        assert_eq!(sig.r, recovered.r);
        assert_eq!(sig.s, recovered.s);
    }

    #[test]
    fn test_signature_normalization() {
        let n = params::secp256k1_n();
        let half_n = params::half_n();

        // Create signature with high S
        let r = U256Limbs::from_u64(12345);
        let s = crate::bigint::U256Sub::sub(&n, &U256Limbs::from_u64(1)).0; // n-1 is high

        let sig = ECDSASignature::new(r, s);
        let normalized = sig.normalize();

        assert!(U256Compare::le(&normalized.s, &half_n));
    }

    #[test]
    fn test_mul_mod() {
        let n = params::secp256k1_n();
        let a = U256Limbs::from_u64(123);
        let b = U256Limbs::from_u64(456);

        let result = mul_mod(&a, &b, &n);
        // 123 * 456 = 56088, which is < n
        assert_eq!(result.limbs[0].to_u64(), 56088);
    }
}
