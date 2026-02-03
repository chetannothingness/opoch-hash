//! OPOCH SDK - Simple API for Proof Generation and Verification
//!
//! This module provides a simplified interface for the OPOCH proof system.
//!
//! # Example
//!
//! ```rust
//! use opoch_sdk::{sha256, prove_chain, verify_chain};
//!
//! // Compute d0 (bit-identical to standard SHA-256)
//! let input = b"my data";
//! let d0 = sha256(input);
//!
//! // Generate proof for N iterations
//! let n = 1000;
//! let (y, proof) = prove_chain(d0, n);
//!
//! // Verify the proof
//! let valid = verify_chain(d0, y, n, &proof);
//! assert!(valid);
//! ```

use opoch_poc_sha::sha256::{Sha256, sha256_32, hash_chain};
use opoch_poc_sha::segment::{SegmentConfig, SegmentProver};
use opoch_poc_sha::aggregation::{AggregationConfig, AggregationProver};
use opoch_poc_sha::proof::{OpochProof, ProofHeader, compute_params_hash};
use opoch_poc_sha::endtoend::production_fri_config;
use opoch_poc_sha::fri::FriVerifier;
use opoch_poc_sha::transcript::Transcript;

/// Compute SHA-256 hash (bit-identical to FIPS 180-4)
///
/// This is the exact same function used by legacy systems.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::hash(input)
}

/// Generate a proof for SHA-256 chain computation
///
/// Proves that y = SHA256^n(d0)
///
/// # Arguments
/// * `d0` - Initial hash (32 bytes)
/// * `n` - Number of SHA-256 iterations
///
/// # Returns
/// * `([u8; 32], Vec<u8>)` - (final hash y, serialized proof)
pub fn prove_chain(d0: [u8; 32], n: u64) -> ([u8; 32], Vec<u8>) {
    let segment_length = 64u64;
    let num_segments = (n + segment_length - 1) / segment_length;

    let fri_config = production_fri_config();
    let segment_config = SegmentConfig {
        segment_length: segment_length as usize,
        fri_config: fri_config.clone(),
    };
    let segment_prover = SegmentProver::new(segment_config);

    // Generate segment proofs
    let mut segment_proofs = Vec::with_capacity(num_segments as usize);
    let mut current_hash = d0;

    for i in 0..num_segments {
        let proof = segment_prover.prove(i as u32, &current_hash);
        current_hash = proof.end_hash;
        segment_proofs.push(proof);
    }

    let y = current_hash;

    // Aggregate into L1
    let agg_config = AggregationConfig {
        max_children: segment_proofs.len() + 1,
        fri_config: fri_config.clone(),
    };
    let agg_prover = AggregationProver::new(agg_config);
    let l1_proof = agg_prover.aggregate_segments(&segment_proofs);

    // Aggregate into L2
    let final_proof = agg_prover.aggregate_level1(&[l1_proof]);

    // Create complete proof
    let params_hash = compute_params_hash(n, segment_length);
    let header = ProofHeader::new(n, segment_length, d0, y, params_hash);

    let proof = OpochProof {
        header,
        final_proof,
    };

    (y, proof.serialize())
}

/// Verify a SHA-256 chain proof
///
/// Verifies that the proof demonstrates y = SHA256^n(d0)
///
/// # Arguments
/// * `d0` - Claimed initial hash (32 bytes)
/// * `y` - Claimed final hash (32 bytes)
/// * `n` - Claimed number of iterations
/// * `proof` - Serialized proof bytes
///
/// # Returns
/// `true` if the proof is valid
pub fn verify_chain(d0: [u8; 32], y: [u8; 32], n: u64, proof: &[u8]) -> bool {
    // Parse proof
    let parsed = match OpochProof::deserialize(proof) {
        Some(p) => p,
        None => return false,
    };

    // Verify header bindings
    if parsed.header.d0 != d0 {
        return false;
    }
    if parsed.header.y != y {
        return false;
    }
    if parsed.header.n != n {
        return false;
    }

    // Verify chain bindings in final proof
    if parsed.final_proof.chain_start != d0 {
        return false;
    }
    if parsed.final_proof.chain_end != y {
        return false;
    }

    // Verify FRI proof
    let mut transcript = Transcript::new();
    transcript.append_commitment(&parsed.final_proof.children_root);
    transcript.append(&parsed.final_proof.chain_start);
    transcript.append(&parsed.final_proof.chain_end);

    // CRITICAL: Must call challenge_aggregation to match prover's transcript state
    let _alpha = transcript.challenge_aggregation();

    let fri_config = production_fri_config();
    let fri_verifier = FriVerifier::new(fri_config);

    fri_verifier.verify(&parsed.final_proof.fri_proof, &mut transcript)
}

/// Compute chain without proof (for testing)
///
/// Computes y = SHA256^n(d0) directly.
pub fn compute_chain(d0: [u8; 32], n: u64) -> [u8; 32] {
    hash_chain(&d0, n)
}

/// Get SDK version
pub fn version() -> &'static str {
    "1.0.0"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_fips() {
        // FIPS 180-4 test vector
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_compute_chain() {
        let d0 = sha256(b"test");
        let y = compute_chain(d0, 10);

        // Manual computation
        let mut h = d0;
        for _ in 0..10 {
            h = sha256_32(&h);
        }

        assert_eq!(y, h);
    }

    #[test]
    fn test_prove_and_verify() {
        let d0 = sha256(b"sdk test");
        let n = 128; // Small N for fast testing

        let (y, proof) = prove_chain(d0, n);

        // Verify y is correct
        let expected_y = compute_chain(d0, n);
        assert_eq!(y, expected_y);

        // Verify proof
        let valid = verify_chain(d0, y, n, &proof);
        assert!(valid, "Valid proof should verify");
    }

    #[test]
    fn test_reject_wrong_y() {
        let d0 = sha256(b"sdk test");
        let n = 128;

        let (y, proof) = prove_chain(d0, n);

        // Wrong y
        let mut wrong_y = y;
        wrong_y[0] ^= 0xFF;

        let valid = verify_chain(d0, wrong_y, n, &proof);
        assert!(!valid, "Wrong y should fail");
    }
}
