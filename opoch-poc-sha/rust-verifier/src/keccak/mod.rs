//! Keccak-256 AIR for STARK Proofs
//!
//! Implements Keccak-256 (Ethereum's hash function) with bytewise state representation
//! optimized for lookup-based operations.
//!
//! ## Architecture
//!
//! - State: 200 bytes (25 lanes × 8 bytes)
//! - Bytewise representation for efficient XOR/AND/NOT via lookup tables
//! - 24 rounds of θ, ρ, π, χ, ι steps
//!
//! ## Specification
//!
//! Follows FIPS 202 (SHA-3 Standard) for Keccak-f[1600].

pub mod constants;
pub mod state;
pub mod theta;
pub mod rho_pi;
pub mod chi;
pub mod iota;
pub mod round;
pub mod hash;
pub mod air;

pub use constants::*;
pub use state::KeccakState;
pub use round::keccak_round;
pub use hash::{keccak256, Keccak256Hasher};
pub use air::{KeccakAir, KeccakProof};

use crate::field::Fp;

/// Number of bytes in Keccak state
pub const STATE_BYTES: usize = 200;

/// Number of lanes (5x5)
pub const LANES: usize = 25;

/// Bytes per lane
pub const LANE_BYTES: usize = 8;

/// Number of rounds
pub const ROUNDS: usize = 24;

/// Rate for Keccak-256 (in bytes)
pub const KECCAK256_RATE: usize = 136; // 1088 bits

/// Capacity for Keccak-256 (in bytes)
pub const KECCAK256_CAPACITY: usize = 64; // 512 bits

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_empty() {
        let result = keccak256(&[]);
        // Empty string hash from NIST test vectors
        let expected = hex::decode(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        ).unwrap();
        assert_eq!(result.to_vec(), expected);
    }

    #[test]
    fn test_keccak256_abc() {
        let result = keccak256(b"abc");
        // "abc" hash for Keccak-256 (Ethereum's version)
        let expected = hex::decode(
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        ).unwrap();
        assert_eq!(result.to_vec(), expected);
    }
}
