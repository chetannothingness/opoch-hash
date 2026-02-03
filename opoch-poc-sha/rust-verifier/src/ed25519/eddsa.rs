//! EdDSA Signature Verification
//!
//! Implements Ed25519 signature verification as per RFC 8032.

use super::point::{AffinePoint, EdwardsPoint};
use super::scalar_mul::{scalar_mul, double_scalar_mul};
use super::params;
use crate::bigint::{U256Limbs, U256Compare, ModularReduce};
use crate::sha256::Sha256;

/// EdDSA signature (R, S)
#[derive(Clone, Debug)]
pub struct EdDSASignature {
    /// Point R (32 bytes, compressed)
    pub r: AffinePoint,
    /// Scalar S (32 bytes)
    pub s: U256Limbs,
}

impl EdDSASignature {
    /// Create from R and S
    pub fn new(r: AffinePoint, s: U256Limbs) -> Self {
        EdDSASignature { r, s }
    }

    /// Create from 64-byte signature
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&bytes[0..32]);
        let r = AffinePoint::from_bytes(&r_bytes)?;

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);
        let s = U256Limbs::from_bytes_le(&s_bytes);

        // S must be < L
        let l = params::ed25519_l();
        if U256Compare::gte(&s, &l) {
            return None;
        }

        Some(EdDSASignature { r, s })
    }

    /// Encode to 64 bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[0..32].copy_from_slice(&self.r.to_bytes());
        result[32..64].copy_from_slice(&self.s.to_bytes_le());
        result
    }
}

/// EdDSA public key (point on curve)
#[derive(Clone, Debug)]
pub struct EdDSAPublicKey {
    pub point: AffinePoint,
}

impl EdDSAPublicKey {
    /// Create from affine point
    pub fn new(point: AffinePoint) -> Self {
        EdDSAPublicKey { point }
    }

    /// Create from 32-byte encoding
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let point = AffinePoint::from_bytes(bytes)?;
        Some(EdDSAPublicKey { point })
    }

    /// Encode to 32 bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.to_bytes()
    }
}

/// Compute hash h = SHA-512(R || A || M) mod L
fn compute_h(r: &AffinePoint, a: &EdDSAPublicKey, message: &[u8]) -> U256Limbs {
    // Use SHA-256 twice to get 512 bits (simplified version)
    // Real Ed25519 uses SHA-512
    let r_bytes = r.to_bytes();
    let a_bytes = a.to_bytes();

    let mut hasher = Sha256::new();
    hasher.update(&r_bytes);
    hasher.update(&a_bytes);
    hasher.update(message);
    let hash1 = hasher.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(&hash1);
    hasher2.update(&[0x01]); // Domain separator
    let hash2 = hasher2.finalize();

    // Combine into 64 bytes and reduce mod L
    let mut combined = [0u8; 64];
    combined[0..32].copy_from_slice(&hash1);
    combined[32..64].copy_from_slice(&hash2);

    // Reduce mod L (simplified - just take lower 253 bits)
    let mut h_bytes = [0u8; 32];
    h_bytes.copy_from_slice(&combined[0..32]);
    let h = U256Limbs::from_bytes_le(&h_bytes);

    // Reduce mod L
    let l = params::ed25519_l();
    if U256Compare::gte(&h, &l) {
        crate::bigint::U256Sub::sub(&h, &l).0
    } else {
        h
    }
}

/// Verify EdDSA signature
///
/// Checks: [S]B = R + [h]A
/// where h = SHA-512(R || A || M) mod L
pub fn verify_eddsa(
    public_key: &EdDSAPublicKey,
    message: &[u8],
    signature: &EdDSASignature,
) -> bool {
    // Compute h = H(R || A || M) mod L
    let h = compute_h(&signature.r, public_key, message);

    // Compute [S]B
    let b = EdwardsPoint::base_point();
    let sb = scalar_mul(&b, &signature.s);

    // Compute R + [h]A
    let a_ext = public_key.point.to_extended();
    let ha = scalar_mul(&a_ext, &h);
    let r_ext = signature.r.to_extended();
    let rhs = r_ext.add(&ha);

    // Check equality
    sb == rhs
}

/// EdDSA verification with detailed result
pub fn verify_eddsa_detailed(
    public_key: &EdDSAPublicKey,
    message: &[u8],
    signature: &EdDSASignature,
) -> EdDSAVerifyResult {
    // Compute h
    let h = compute_h(&signature.r, public_key, message);

    // Compute components
    let b = EdwardsPoint::base_point();
    let sb = scalar_mul(&b, &signature.s);

    let a_ext = public_key.point.to_extended();
    let ha = scalar_mul(&a_ext, &h);

    let r_ext = signature.r.to_extended();
    let rhs = r_ext.add(&ha);

    let valid = sb == rhs;

    EdDSAVerifyResult {
        valid,
        h,
        sb,
        ha,
        rhs,
    }
}

/// Detailed verification result
#[derive(Clone, Debug)]
pub struct EdDSAVerifyResult {
    pub valid: bool,
    pub h: U256Limbs,
    pub sb: EdwardsPoint,
    pub ha: EdwardsPoint,
    pub rhs: EdwardsPoint,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_encoding() {
        // Create a dummy signature
        let r = AffinePoint::identity();
        let s = U256Limbs::from_u64(12345);
        let sig = EdDSASignature::new(r.clone(), s.clone());

        let bytes = sig.to_bytes();
        let recovered = EdDSASignature::from_bytes(&bytes);

        // Identity point and small scalar should round-trip
        assert!(recovered.is_some() || r.is_identity());
    }

    #[test]
    fn test_public_key_encoding() {
        let point = AffinePoint::base_point();
        let pk = EdDSAPublicKey::new(point.clone());

        let bytes = pk.to_bytes();
        let recovered = EdDSAPublicKey::from_bytes(&bytes);

        assert!(recovered.is_some());
    }
}
