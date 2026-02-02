//! Segment Prover and Verifier
//!
//! Proves and verifies a segment of L consecutive hash chain steps.
//! Uses the SHA-256 AIR with FRI for low-degree testing.

use crate::air::{Sha256Air, generate_trace, TRACE_WIDTH, ROWS_PER_HASH};
use crate::field::Fp;
use crate::fri::{FriConfig, FriProver, FriVerifier, FriProof};
use crate::merkle::MerkleTree;
use crate::proof::SegmentProof;
use crate::sha256::sha256_32;
use crate::transcript::Transcript;

/// Segment prover configuration
#[derive(Clone, Debug)]
pub struct SegmentConfig {
    /// Number of hash steps per segment
    pub segment_length: usize,
    /// FRI configuration
    pub fri_config: FriConfig,
}

impl Default for SegmentConfig {
    fn default() -> Self {
        SegmentConfig {
            segment_length: 1024,
            fri_config: FriConfig::default(),
        }
    }
}

/// Segment prover
pub struct SegmentProver {
    config: SegmentConfig,
    air: Sha256Air,
}

impl SegmentProver {
    /// Create a new segment prover
    pub fn new(config: SegmentConfig) -> Self {
        let air = Sha256Air::new(config.segment_length);
        SegmentProver { config, air }
    }

    /// Generate proof for a segment starting at given hash
    ///
    /// Proves that: SHA-256^L(start_hash) = end_hash
    pub fn prove(
        &self,
        segment_index: u32,
        start_hash: &[u8; 32],
    ) -> SegmentProof {
        // 1. Generate execution trace
        let trace = generate_trace(start_hash, self.config.segment_length);
        let trace_length = trace.len();

        // 2. Compute end hash
        let end_hash = compute_segment_end(start_hash, self.config.segment_length);

        // 3. Commit to trace columns using Merkle tree
        let mut transcript = Transcript::new();

        // Add public inputs
        transcript.append(start_hash);
        transcript.append(&end_hash);
        transcript.append(&segment_index.to_be_bytes());

        // Commit each column
        let column_commitments = self.commit_trace(&trace, &mut transcript);

        // 4. Get random challenge for constraint composition
        let alpha = transcript.challenge_segment();

        // 5. Compute constraint polynomial composition
        let constraint_poly = self.compute_constraint_polynomial(&trace, alpha);

        // 6. Extend and commit constraint polynomial
        let extended_constraints = self.extend_polynomial(&constraint_poly);

        // 7. Generate FRI proof
        let fri_prover = FriProver::new(self.config.fri_config.clone());
        let fri_proof = fri_prover.prove(extended_constraints, &mut transcript);

        SegmentProof {
            segment_index,
            start_hash: *start_hash,
            end_hash,
            fri_proof,
        }
    }

    /// Commit to trace using Merkle trees
    fn commit_trace(&self, trace: &[Vec<Fp>], transcript: &mut Transcript) -> Vec<[u8; 32]> {
        let mut commitments = Vec::with_capacity(TRACE_WIDTH);

        for col in 0..TRACE_WIDTH {
            // Extract column values
            let column: Vec<Vec<u8>> = trace
                .iter()
                .map(|row| row[col].to_bytes().to_vec())
                .collect();

            // Build Merkle tree
            let tree = MerkleTree::new(column);
            commitments.push(tree.root);
            transcript.append_commitment(&tree.root);
        }

        commitments
    }

    /// Compute constraint polynomial from trace and challenge
    fn compute_constraint_polynomial(&self, trace: &[Vec<Fp>], alpha: crate::field::Fp2) -> Vec<Fp> {
        let n = trace.len();
        let mut constraints = vec![Fp::ZERO; n];

        // Evaluate transition constraints at each row
        for i in 0..n - 1 {
            let current = &trace[i];
            let next = &trace[i + 1];

            let transition_evals = self.air.evaluate_transition(current, next);

            // Combine constraints using powers of alpha
            let mut combined = Fp::ZERO;
            let mut alpha_power = alpha.c0; // Use real part for simplicity

            for eval in transition_evals {
                combined = combined + alpha_power * eval;
                alpha_power = alpha_power * alpha.c0;
            }

            constraints[i] = combined;
        }

        constraints
    }

    /// Extend polynomial using FFT for FRI
    fn extend_polynomial(&self, poly: &[Fp]) -> Vec<Fp> {
        // For simplicity, we'll pad to power of 2 and apply blowup
        let n = poly.len().next_power_of_two();
        let blowup = self.config.fri_config.blowup_factor;
        let extended_len = n * blowup;

        let mut extended = vec![Fp::ZERO; extended_len];

        // Copy original values (at rate positions)
        for (i, &val) in poly.iter().enumerate() {
            extended[i * blowup] = val;
        }

        // In a full implementation, we'd use FFT/iFFT for proper extension
        // For now, this is a placeholder that maintains the structure

        extended
    }
}

/// Segment verifier
pub struct SegmentVerifier {
    config: SegmentConfig,
}

impl SegmentVerifier {
    /// Create a new segment verifier
    pub fn new(config: SegmentConfig) -> Self {
        SegmentVerifier { config }
    }

    /// Verify a segment proof
    pub fn verify(
        &self,
        proof: &SegmentProof,
        expected_start: &[u8; 32],
    ) -> bool {
        // 1. Check start hash matches
        if proof.start_hash != *expected_start {
            return false;
        }

        // 2. Reconstruct transcript
        let mut transcript = Transcript::new();
        transcript.append(&proof.start_hash);
        transcript.append(&proof.end_hash);
        transcript.append(&proof.segment_index.to_be_bytes());

        // Note: In full implementation, we'd also verify:
        // - Column commitments match
        // - Boundary constraints
        // - Specific query positions

        // 3. Verify FRI proof
        let fri_verifier = FriVerifier::new(self.config.fri_config.clone());
        fri_verifier.verify(&proof.fri_proof, &mut transcript)
    }

    /// Verify segment chain consistency
    ///
    /// Checks that the end of segment i matches the start of segment i+1
    pub fn verify_chain(proofs: &[SegmentProof]) -> bool {
        for i in 0..proofs.len() - 1 {
            if proofs[i].end_hash != proofs[i + 1].start_hash {
                return false;
            }
            if proofs[i].segment_index + 1 != proofs[i + 1].segment_index {
                return false;
            }
        }
        true
    }
}

/// Compute end hash for a segment
pub fn compute_segment_end(start: &[u8; 32], steps: usize) -> [u8; 32] {
    let mut h = *start;
    for _ in 0..steps {
        h = sha256_32(&h);
    }
    h
}

/// Quick segment proof generation (for testing)
pub fn prove_segment_quick(
    segment_index: u32,
    start_hash: &[u8; 32],
    segment_length: usize,
) -> SegmentProof {
    let config = SegmentConfig {
        segment_length,
        fri_config: FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 1024,
        },
    };

    let prover = SegmentProver::new(config);
    prover.prove(segment_index, start_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256::Sha256;

    #[test]
    fn test_segment_end_computation() {
        let start = Sha256::hash(b"test");
        let end = compute_segment_end(&start, 100);

        // Verify manually
        let mut h = start;
        for _ in 0..100 {
            h = sha256_32(&h);
        }
        assert_eq!(end, h);
    }

    #[test]
    fn test_segment_prover() {
        let config = SegmentConfig {
            segment_length: 4, // Small for testing
            fri_config: FriConfig {
                num_queries: 5,
                blowup_factor: 4,
                max_degree: 256,
            },
        };

        let start = Sha256::hash(b"segment test");
        let prover = SegmentProver::new(config.clone());
        let proof = prover.prove(0, &start);

        assert_eq!(proof.segment_index, 0);
        assert_eq!(proof.start_hash, start);

        let expected_end = compute_segment_end(&start, 4);
        assert_eq!(proof.end_hash, expected_end);
    }

    #[test]
    fn test_chain_consistency() {
        let start = Sha256::hash(b"chain test");

        let seg0_end = compute_segment_end(&start, 10);
        let seg1_end = compute_segment_end(&seg0_end, 10);

        // Create mock proofs
        let proof0 = SegmentProof {
            segment_index: 0,
            start_hash: start,
            end_hash: seg0_end,
            fri_proof: crate::fri::FriProof {
                layer_commitments: vec![],
                final_value: Fp::ZERO,
                query_responses: vec![],
            },
        };

        let proof1 = SegmentProof {
            segment_index: 1,
            start_hash: seg0_end,
            end_hash: seg1_end,
            fri_proof: crate::fri::FriProof {
                layer_commitments: vec![],
                final_value: Fp::ZERO,
                query_responses: vec![],
            },
        };

        assert!(SegmentVerifier::verify_chain(&[proof0, proof1]));
    }
}
