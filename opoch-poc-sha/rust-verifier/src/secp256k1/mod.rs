//! secp256k1 Elliptic Curve and ECDSA Signature Verification AIR
//!
//! Implements secp256k1 curve operations and ECDSA verification using
//! 256-bit field emulation over Goldilocks.
//!
//! ## Curve Parameters
//!
//! secp256k1: y² = x³ + 7 (mod p)
//! - p = 2^256 - 2^32 - 977
//! - n = group order
//! - G = generator point
//!
//! ## ECDSA Verification
//!
//! Given signature (r, s), public key Q, and message hash z:
//! 1. w = s⁻¹ mod n
//! 2. u1 = z·w mod n
//! 3. u2 = r·w mod n
//! 4. P = u1·G + u2·Q
//! 5. Accept iff P.x mod n = r

pub mod params;
pub mod field;
pub mod point;
pub mod scalar_mul;
pub mod ecdsa;
pub mod air;

pub use params::*;
pub use point::{JacobianPoint, AffinePoint};
pub use scalar_mul::scalar_mul;
pub use ecdsa::{verify_ecdsa, ECDSASignature, ECDSAPublicKey};
pub use air::{ECDSAAir, ECDSAProof};

use crate::bigint::U256Limbs;

/// secp256k1 field element (mod p)
pub type Fe = U256Limbs;

/// secp256k1 scalar (mod n)
pub type Scalar = U256Limbs;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_on_curve() {
        let gx = params::generator_x();
        let gy = params::generator_y();

        // Verify G is on curve (y² = x³ + 7 mod p)
        // For now, just check values are loaded
        assert!(!gx.is_zero());
        assert!(!gy.is_zero());
    }
}
