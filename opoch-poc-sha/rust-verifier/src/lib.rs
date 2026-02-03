//! OPOCH-PoC-SHA: Proof of Computation for SHA-256 Hash Chains
//!
//! This library implements a STARK-based proof system that proves
//! the correct computation of SHA-256 hash chains:
//!
//! ```text
//! d₀ = SHA-256(x)
//! h_{t+1} = SHA-256(h_t)
//! y = h_N
//! ```
//!
//! For N = 10^9 steps, verification completes in < 1ms.
//!
//! ## Architecture
//!
//! The system uses recursive STARKs with FRI-based low-degree testing:
//!
//! 1. **Segment Proofs**: Prove L consecutive hash steps
//! 2. **Level-1 Aggregation**: Aggregate ~976 segment proofs
//! 3. **Level-2 Aggregation**: Aggregate ~1000 level-1 proofs
//! 4. **Final Proof**: Single proof ~150KB, verifies in < 1ms
//!
//! ## Usage
//!
//! ```no_run
//! use opoch_poc_sha::{Verifier, VerifierConfig, verify_quick};
//!
//! // Quick verification
//! let input = b"my input";
//! let proof_bytes = vec![]; // Load from file
//! let valid = verify_quick(input, &proof_bytes);
//!
//! // Custom configuration
//! let config = VerifierConfig::default_1b();
//! let verifier = Verifier::new(config);
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod sha256;
pub mod field;
pub mod merkle;
pub mod transcript;
pub mod fri;
pub mod proof;
pub mod verifier;
pub mod air;
pub mod air_bytewise;  // Production-grade bytewise SHA-256 AIR with lookup tables
pub mod segment;
pub mod aggregation;
pub mod endtoend;
pub mod soundness;
pub mod sequentiality;

// Benchmark-beating components
pub mod lookup;
pub mod bigint;
pub mod poseidon;
pub mod keccak;
pub mod ed25519;
pub mod secp256k1;

// Foundation modules (Phase 1)
pub mod serpi;
pub mod mixer;
pub mod machines;
pub mod receipt;

// WASM module
pub mod wasm;

// Security tests
#[cfg(test)]
mod adversarial_tests;

// Re-exports for convenience
pub use sha256::{Sha256, sha256_32, hash_chain};
pub use field::{Fp, Fp2, GOLDILOCKS_PRIME};
pub use merkle::{MerkleTree, MerklePath};
pub use transcript::Transcript;
pub use fri::{FriConfig, FriProof, FriProver, FriVerifier};
pub use proof::{OpochProof, ProofHeader, SegmentProof, AggregationProof};
pub use verifier::{Verifier, VerifierConfig, VerifyResult, verify_quick, verify_timed};
pub use air::{Sha256Air, generate_trace, TRACE_WIDTH, ROWS_PER_HASH};
pub use segment::{SegmentConfig, SegmentProver, SegmentVerifier, compute_segment_end};
pub use aggregation::{AggregationConfig, AggregationProver, AggregationVerifier, AggregationLevel};

// Benchmark-beating component re-exports
pub use lookup::{LookupTable, LookupAccumulator, GrandProductLookup, LogDerivativeLookup};
pub use bigint::{U256Limbs, U256Add, U256Sub, U256Mul, U256Compare, ModularReduce, WitnessInverse};
pub use poseidon::{PoseidonState, PoseidonAir, PoseidonProof, poseidon_hash};
pub use keccak::{KeccakState, KeccakAir, KeccakProof, keccak256};
pub use ed25519::{EdDSASignature, EdDSAPublicKey, EdDSAAir, EdDSAProof, verify_eddsa};
pub use secp256k1::{ECDSASignature, ECDSAPublicKey, ECDSAAir, ECDSAProof, verify_ecdsa};

// Foundation module re-exports (Phase 1)
pub use serpi::{SerPi, CanonicalTape, SemanticObject};
pub use mixer::{opoch_hash, TreeSpongeMixer};
pub use machines::{Machine, MachineId};
pub use receipt::{Receipt, ReceiptChain};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol identifier
pub const PROTOCOL_ID: &[u8; 4] = b"OPSH";

/// Pinned parameters for N = 10^9
pub mod params {
    /// Chain length
    pub const N: u64 = 1_000_000_000;

    /// Segment length
    pub const L: u64 = 1024;

    /// Number of segments
    pub const NUM_SEGMENTS: u64 = N / L; // 976,562

    /// FRI queries for 128+ bit security
    pub const FRI_QUERIES: usize = 68;

    /// FRI blowup factor (rate = 1/8)
    pub const FRI_BLOWUP: usize = 8;

    /// Maximum polynomial degree
    pub const MAX_DEGREE: usize = 65536;

    /// Target verification time
    pub const TARGET_VERIFY_MS: u64 = 1;

    /// Expected proof size (bytes)
    pub const EXPECTED_PROOF_SIZE: usize = 150_000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_fips() {
        // FIPS 180-4 test vectors
        assert_eq!(
            hex::encode(Sha256::hash(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        assert_eq!(
            hex::encode(Sha256::hash(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_chain_computation() {
        let x = b"test input";
        let d0 = Sha256::hash(x);

        // Compute 10 steps manually
        let mut h = d0;
        for _ in 0..10 {
            h = sha256_32(&h);
        }

        // Should match hash_chain
        assert_eq!(h, hash_chain(&d0, 10));
    }
}
