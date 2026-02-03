//! Poseidon Hash Function AIR
//!
//! Implements Poseidon hash optimized for the Goldilocks field.
//!
//! ## Parameters (Pinned)
//!
//! - State width: t = 12
//! - Capacity: c = 4
//! - Rate: r = 8
//! - Full rounds: R_f = 8 (4 before, 4 after partial)
//! - Partial rounds: R_p = 22
//! - S-box: x^7 (optimal for Goldilocks)
//!
//! ## Security
//!
//! These parameters provide 128+ bit security against:
//! - Algebraic attacks
//! - Statistical attacks
//! - Interpolation attacks

pub mod constants;
pub mod sbox;
pub mod round;
pub mod hash;
pub mod air;

pub use constants::{POSEIDON_T, POSEIDON_C, POSEIDON_R, POSEIDON_RF, POSEIDON_RP};
pub use constants::{POSEIDON_MDS, POSEIDON_RC};
pub use sbox::sbox;
pub use round::{full_round, partial_round};
pub use hash::{poseidon_hash, poseidon_hash_many};
pub use air::{PoseidonAir, PoseidonProof};

use crate::field::Fp;

/// Poseidon state
#[derive(Clone, Debug)]
pub struct PoseidonState {
    pub elements: [Fp; constants::POSEIDON_T],
}

impl PoseidonState {
    /// Create zero state
    pub fn zero() -> Self {
        PoseidonState {
            elements: [Fp::ZERO; constants::POSEIDON_T],
        }
    }

    /// Create from elements
    pub fn from_elements(elements: [Fp; constants::POSEIDON_T]) -> Self {
        PoseidonState { elements }
    }

    /// Get element at index
    pub fn get(&self, index: usize) -> Fp {
        self.elements[index]
    }

    /// Set element at index
    pub fn set(&mut self, index: usize, value: Fp) {
        self.elements[index] = value;
    }
}

impl Default for PoseidonState {
    fn default() -> Self {
        Self::zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_basic() {
        // Test basic hash functionality
        let input = [Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4)];
        let result = poseidon_hash(&input);

        // Result should be deterministic
        let result2 = poseidon_hash(&input);
        for i in 0..result.len() {
            assert_eq!(result[i], result2[i]);
        }
    }

    #[test]
    fn test_poseidon_different_inputs() {
        let input1 = [Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4)];
        let input2 = [Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(5)];

        let result1 = poseidon_hash(&input1);
        let result2 = poseidon_hash(&input2);

        // Different inputs should give different outputs
        assert_ne!(result1[0], result2[0]);
    }
}
