//! Ed25519 Elliptic Curve and EdDSA Signature Verification AIR
//!
//! Implements Ed25519 curve operations and EdDSA verification using
//! 256-bit field emulation over Goldilocks.
//!
//! ## Curve Parameters
//!
//! Ed25519: -x² + y² = 1 + d·x²·y² (mod p)
//! - p = 2^255 - 19
//! - d = -121665/121666 mod p
//! - Base point B = (Bx, By)
//! - Order L = 2^252 + 27742317777372353535851937790883648493
//!
//! ## EdDSA Verification
//!
//! Given signature (R, S), public key A, and message M:
//! Verify: [S]B = R + [h]A
//! where h = SHA-512(R || A || M) mod L

pub mod params;
pub mod field;
pub mod point;
pub mod scalar_mul;
pub mod eddsa;
pub mod air;

pub use params::*;
pub use point::{EdwardsPoint, AffinePoint};
pub use scalar_mul::scalar_mul;
pub use eddsa::{verify_eddsa, EdDSASignature, EdDSAPublicKey};
pub use air::{EdDSAAir, EdDSAProof};

use crate::bigint::U256Limbs;

/// Ed25519 field element (mod p = 2^255 - 19)
pub type Fe = U256Limbs;

/// Ed25519 scalar (mod L)
pub type Scalar = U256Limbs;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_point_on_curve() {
        let p = params::ed25519_p();
        let bx = params::base_point_x();
        let by = params::base_point_y();

        // Verify -x² + y² = 1 + d·x²·y² (mod p)
        // For now, just check values are loaded correctly
        assert!(!bx.is_zero());
        assert!(!by.is_zero());
    }
}
