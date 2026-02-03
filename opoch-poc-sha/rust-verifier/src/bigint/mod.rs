//! 256-bit Integer Arithmetic for STARK Proofs
//!
//! This module implements 256-bit integer operations using 16 × 16-bit limbs.
//! This representation is optimal for STARKs with lookup-based carries.
//!
//! ## Architecture
//!
//! A 256-bit integer X is represented as:
//! ```text
//! X = Σ x_i × 2^(16i) for i = 0..15
//! ```
//!
//! where each x_i ∈ [0, 65535].
//!
//! ## Supported Operations
//!
//! - Addition with carry propagation
//! - Subtraction with borrow
//! - Multiplication (schoolbook and Karatsuba)
//! - Modular reduction (Ed25519 p, secp256k1 p, secp256k1 n)
//! - Witness-based inversion

pub mod limbs;
pub mod add;
pub mod sub;
pub mod mul;
pub mod reduce;
pub mod inverse;
pub mod compare;

pub use limbs::U256Limbs;
pub use add::U256Add;
pub use sub::U256Sub;
pub use mul::U256Mul;
pub use reduce::{ModularReduce, ED25519_P, SECP256K1_P, SECP256K1_N};
pub use inverse::WitnessInverse;
pub use compare::U256Compare;

use crate::field::Fp;

/// Number of bits per limb
pub const LIMB_BITS: usize = 16;

/// Number of limbs in 256-bit integer
pub const LIMB_COUNT: usize = 16;

/// Maximum value of a limb
pub const LIMB_MAX: u64 = (1 << LIMB_BITS) - 1;

/// Double the limbs for 512-bit products
pub const DOUBLE_LIMB_COUNT: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(LIMB_BITS, 16);
        assert_eq!(LIMB_COUNT, 16);
        assert_eq!(LIMB_MAX, 65535);
        assert_eq!(16 * 16, 256); // 16 limbs × 16 bits = 256 bits
    }
}
