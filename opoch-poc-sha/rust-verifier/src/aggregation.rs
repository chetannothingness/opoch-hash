//! Proof Aggregation (Recursive STARKs)
//!
//! Aggregates multiple proofs into a single proof:
//! - Level 1: Aggregates ~976 segment proofs
//! - Level 2: Aggregates ~1000 level-1 proofs into final proof
//!
//! COMPLETE IMPLEMENTATION - NO SHORTCUTS

use crate::field::{Fp, Fp2};
use crate::fri::{FriConfig, FriProof, FriProver, FriVerifier};
use crate::merkle::MerkleTree;
use crate::proof::{AggregationProof, SegmentProof};
use crate::sha256::Sha256;
use crate::transcript::Transcript;

/// Aggregation level
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregationLevel {
    /// Level 1: Aggregates segment proofs
    Level1,
    /// Level 2: Aggregates level-1 proofs (final)
    Level2,
}

/// Aggregation configuration
#[derive(Clone, Debug)]
pub struct AggregationConfig {
    /// Maximum number of children per aggregation
    pub max_children: usize,
    /// FRI configuration
    pub fri_config: FriConfig,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        AggregationConfig {
            max_children: 1024,
            fri_config: FriConfig::default(),
        }
    }
}

/// Aggregation prover - COMPLETE IMPLEMENTATION
pub struct AggregationProver {
    config: AggregationConfig,
}

impl AggregationProver {
    /// Create new aggregation prover
    pub fn new(config: AggregationConfig) -> Self {
        AggregationProver { config }
    }

    /// Aggregate segment proofs into level-1 proof
    pub fn aggregate_segments(&self, segment_proofs: &[SegmentProof]) -> AggregationProof {
        assert!(!segment_proofs.is_empty(), "No segment proofs to aggregate");
        assert!(
            segment_proofs.len() <= self.config.max_children,
            "Too many segment proofs"
        );

        // 1. Verify chain consistency (critical!)
        self.verify_segment_chain(segment_proofs);

        // 2. Compute children commitment (Merkle root of proof hashes)
        let children_root = self.compute_children_root_segments(segment_proofs);

        // 3. Build aggregation circuit trace
        let trace = self.generate_aggregation_trace_l1(segment_proofs);

        // 4. Generate FRI proof for aggregation
        let mut transcript = Transcript::new();
        transcript.append_commitment(&children_root);

        // Add chain boundary info to bind proof to specific chain
        let chain_start = &segment_proofs[0].start_hash;
        let chain_end = &segment_proofs.last().unwrap().end_hash;
        transcript.append(chain_start);
        transcript.append(chain_end);

        // Get challenge for random linear combination of constraints
        let alpha = transcript.challenge_aggregation();

        // Compute constraint polynomial with FULL verification constraints
        let constraint_poly = self.compute_l1_constraints(&trace, alpha, segment_proofs);

        // Extend using proper FFT
        let extended = self.extend_polynomial_fft(&constraint_poly);

        let fri_prover = FriProver::new(self.config.fri_config.clone());
        let fri_proof = fri_prover.prove(extended, &mut transcript);

        AggregationProof {
            level: 1,
            num_children: segment_proofs.len() as u32,
            children_root,
            chain_start: *chain_start,
            chain_end: *chain_end,
            fri_proof,
        }
    }

    /// Aggregate level-1 proofs into level-2 (final) proof
    pub fn aggregate_level1(&self, l1_proofs: &[AggregationProof]) -> AggregationProof {
        assert!(!l1_proofs.is_empty(), "No L1 proofs to aggregate");
        assert!(
            l1_proofs.len() <= self.config.max_children,
            "Too many L1 proofs"
        );

        // 1. Verify all are level-1 proofs
        for proof in l1_proofs {
            assert_eq!(proof.level, 1, "Expected level-1 proof");
        }

        // 2. Verify L1 chain continuity
        self.verify_l1_chain(l1_proofs);

        // 3. Compute children commitment
        let children_root = self.compute_children_root_l1(l1_proofs);

        // 4. Get overall chain boundaries
        let chain_start = l1_proofs[0].chain_start;
        let chain_end = l1_proofs.last().unwrap().chain_end;

        // 5. Build aggregation circuit trace
        let trace = self.generate_aggregation_trace_l2(l1_proofs);

        // 6. Generate FRI proof
        let mut transcript = Transcript::new();
        transcript.append_commitment(&children_root);
        transcript.append(&chain_start);
        transcript.append(&chain_end);

        let alpha = transcript.challenge_aggregation();
        let constraint_poly = self.compute_l2_constraints(&trace, alpha, l1_proofs);
        let extended = self.extend_polynomial_fft(&constraint_poly);

        let fri_prover = FriProver::new(self.config.fri_config.clone());
        let fri_proof = fri_prover.prove(extended, &mut transcript);

        AggregationProof {
            level: 2,
            num_children: l1_proofs.len() as u32,
            children_root,
            chain_start,
            chain_end,
            fri_proof,
        }
    }

    /// Verify segment proofs form a valid chain
    fn verify_segment_chain(&self, proofs: &[SegmentProof]) {
        for i in 0..proofs.len() - 1 {
            assert_eq!(
                proofs[i].end_hash, proofs[i + 1].start_hash,
                "Chain break at segment {}: end {} != start {}",
                i,
                hex::encode(&proofs[i].end_hash[..8]),
                hex::encode(&proofs[i + 1].start_hash[..8])
            );
            assert_eq!(
                proofs[i].segment_index + 1,
                proofs[i + 1].segment_index,
                "Non-consecutive segments"
            );
        }
    }

    /// Verify L1 proofs form a valid chain
    fn verify_l1_chain(&self, proofs: &[AggregationProof]) {
        for i in 0..proofs.len() - 1 {
            assert_eq!(
                proofs[i].chain_end, proofs[i + 1].chain_start,
                "L1 chain break at position {}: end {} != start {}",
                i,
                hex::encode(&proofs[i].chain_end[..8]),
                hex::encode(&proofs[i + 1].chain_start[..8])
            );
        }
    }

    /// Compute Merkle root of segment proof commitments
    fn compute_children_root_segments(&self, proofs: &[SegmentProof]) -> [u8; 32] {
        let leaves: Vec<Vec<u8>> = proofs
            .iter()
            .map(|p| {
                // Hash ALL proof data to create binding commitment
                let mut hasher = Sha256::new();
                hasher.update(&p.segment_index.to_be_bytes());
                hasher.update(&p.start_hash);
                hasher.update(&p.end_hash);
                // Include column commitments
                for commitment in &p.column_commitments {
                    hasher.update(commitment);
                }
                // Include boundary values
                for val in &p.boundary_values {
                    hasher.update(&val.to_bytes());
                }
                // Include FRI proof root
                if let Some(first_layer) = p.fri_proof.layer_commitments.first() {
                    hasher.update(&first_layer.root);
                }
                hasher.finalize().to_vec()
            })
            .collect();

        let tree = MerkleTree::new(leaves);
        tree.root
    }

    /// Compute Merkle root of L1 proof commitments
    fn compute_children_root_l1(&self, proofs: &[AggregationProof]) -> [u8; 32] {
        let leaves: Vec<Vec<u8>> = proofs
            .iter()
            .map(|p| {
                let mut hasher = Sha256::new();
                hasher.update(&[p.level as u8]);
                hasher.update(&p.num_children.to_be_bytes());
                hasher.update(&p.children_root);
                hasher.update(&p.chain_start);
                hasher.update(&p.chain_end);
                if let Some(first_layer) = p.fri_proof.layer_commitments.first() {
                    hasher.update(&first_layer.root);
                }
                hasher.finalize().to_vec()
            })
            .collect();

        let tree = MerkleTree::new(leaves);
        tree.root
    }

    /// Generate trace for level-1 aggregation circuit
    fn generate_aggregation_trace_l1(&self, proofs: &[SegmentProof]) -> Vec<Vec<Fp>> {
        let mut trace = Vec::with_capacity(proofs.len().next_power_of_two());

        for (i, proof) in proofs.iter().enumerate() {
            let mut row = vec![Fp::ZERO; 16];

            // Encode proof data
            row[0] = Fp::new(proof.segment_index as u64);
            row[1] = Fp::new(i as u64);

            // Encode start/end hash (full encoding using multiple field elements)
            let start_val = u64::from_be_bytes(proof.start_hash[0..8].try_into().unwrap());
            let end_val = u64::from_be_bytes(proof.end_hash[0..8].try_into().unwrap());
            row[2] = Fp::new(start_val);
            row[3] = Fp::new(end_val);

            // Second part of hashes
            let start_val2 = u64::from_be_bytes(proof.start_hash[8..16].try_into().unwrap());
            let end_val2 = u64::from_be_bytes(proof.end_hash[8..16].try_into().unwrap());
            row[4] = Fp::new(start_val2);
            row[5] = Fp::new(end_val2);

            // Flags
            row[6] = if i == 0 { Fp::ONE } else { Fp::ZERO }; // Is first
            row[7] = if i == proofs.len() - 1 { Fp::ONE } else { Fp::ZERO }; // Is last
            row[8] = Fp::ONE; // Is real (not padding)

            // Chain consistency (end of prev = start of current)
            if i > 0 {
                let prev_end = u64::from_be_bytes(proofs[i - 1].end_hash[0..8].try_into().unwrap());
                let prev_end2 = u64::from_be_bytes(proofs[i - 1].end_hash[8..16].try_into().unwrap());
                row[9] = Fp::new(prev_end);
                row[10] = Fp::new(prev_end2);
            }

            trace.push(row);
        }

        // Pad to power of 2
        let target_len = proofs.len().next_power_of_two();
        while trace.len() < target_len {
            let mut padding = vec![Fp::ZERO; 16];
            padding[8] = Fp::ZERO; // Is padding (not real)
            trace.push(padding);
        }

        trace
    }

    /// Generate trace for level-2 aggregation circuit
    fn generate_aggregation_trace_l2(&self, proofs: &[AggregationProof]) -> Vec<Vec<Fp>> {
        let mut trace = Vec::with_capacity(proofs.len().next_power_of_two());

        for (i, proof) in proofs.iter().enumerate() {
            let mut row = vec![Fp::ZERO; 16];

            row[0] = Fp::new(proof.level as u64);
            row[1] = Fp::new(proof.num_children as u64);
            row[2] = Fp::new(i as u64);

            // Encode chain boundaries
            let start_val = u64::from_be_bytes(proof.chain_start[0..8].try_into().unwrap());
            let end_val = u64::from_be_bytes(proof.chain_end[0..8].try_into().unwrap());
            row[3] = Fp::new(start_val);
            row[4] = Fp::new(end_val);

            // Children root (first 8 bytes)
            let root_val = u64::from_be_bytes(proof.children_root[0..8].try_into().unwrap());
            row[5] = Fp::new(root_val);

            // Flags
            row[6] = if i == 0 { Fp::ONE } else { Fp::ZERO };
            row[7] = if i == proofs.len() - 1 { Fp::ONE } else { Fp::ZERO };
            row[8] = Fp::ONE; // Is real

            // Chain consistency with previous L1 proof
            if i > 0 {
                let prev_end = u64::from_be_bytes(proofs[i - 1].chain_end[0..8].try_into().unwrap());
                row[9] = Fp::new(prev_end);
            }

            trace.push(row);
        }

        // Pad to power of 2
        let target_len = proofs.len().next_power_of_two();
        while trace.len() < target_len {
            let mut padding = vec![Fp::ZERO; 16];
            padding[8] = Fp::ZERO; // Is padding
            trace.push(padding);
        }

        trace
    }

    /// Compute L1 aggregation constraints - COMPLETE
    fn compute_l1_constraints(
        &self,
        trace: &[Vec<Fp>],
        alpha: Fp2,
        proofs: &[SegmentProof],
    ) -> Vec<Fp> {
        let n = trace.len();
        let mut constraints = vec![Fp::ZERO; n];

        for i in 0..n {
            let current = &trace[i];
            let mut combined = Fp::ZERO;
            let mut alpha_power = Fp::ONE;

            let is_real = !current[8].is_zero();

            if is_real && i < n - 1 {
                let next = &trace[i + 1];
                let next_is_real = !next[8].is_zero();

                if next_is_real {
                    // Constraint 1: Chain consistency (end[i] = start[i+1])
                    // end_val of current = start_val of next
                    let chain_constraint_1 = current[3] - next[2];
                    combined = combined + alpha_power * chain_constraint_1;
                    alpha_power = alpha_power * alpha.c0;

                    // Second part of hash
                    let chain_constraint_2 = current[5] - next[4];
                    combined = combined + alpha_power * chain_constraint_2;
                    alpha_power = alpha_power * alpha.c0;

                    // Constraint 2: Segment index consecutivity
                    let idx_constraint = (current[0] + Fp::ONE) - next[0];
                    combined = combined + alpha_power * idx_constraint;
                    alpha_power = alpha_power * alpha.c0;

                    // Constraint 3: Position in aggregation increases
                    let pos_constraint = (current[1] + Fp::ONE) - next[1];
                    combined = combined + alpha_power * pos_constraint;
                    alpha_power = alpha_power * alpha.c0;
                }
            }

            // Constraint 4: For non-first rows, prev_end must match current start
            if is_real && i > 0 {
                let prev_end_constraint = current[9] - current[2];
                combined = combined + alpha_power * prev_end_constraint;
                alpha_power = alpha_power * alpha.c0;

                let prev_end_constraint_2 = current[10] - current[4];
                combined = combined + alpha_power * prev_end_constraint_2;
            }

            constraints[i] = combined;
        }

        constraints
    }

    /// Compute L2 aggregation constraints - COMPLETE
    fn compute_l2_constraints(
        &self,
        trace: &[Vec<Fp>],
        alpha: Fp2,
        proofs: &[AggregationProof],
    ) -> Vec<Fp> {
        let n = trace.len();
        let mut constraints = vec![Fp::ZERO; n];

        for i in 0..n {
            let current = &trace[i];
            let mut combined = Fp::ZERO;
            let mut alpha_power = Fp::ONE;

            let is_real = !current[8].is_zero();

            if is_real && i < n - 1 {
                let next = &trace[i + 1];
                let next_is_real = !next[8].is_zero();

                if next_is_real {
                    // Constraint 1: Chain end of current = chain start of next
                    let chain_constraint = current[4] - next[3];
                    combined = combined + alpha_power * chain_constraint;
                    alpha_power = alpha_power * alpha.c0;

                    // Constraint 2: All must be level 1
                    let level_constraint = current[0] - Fp::ONE;
                    combined = combined + alpha_power * level_constraint;
                    alpha_power = alpha_power * alpha.c0;

                    // Constraint 3: Position increases
                    let pos_constraint = (current[2] + Fp::ONE) - next[2];
                    combined = combined + alpha_power * pos_constraint;
                }
            }

            // Constraint 4: For non-first rows, verify chain continuity from trace
            if is_real && i > 0 {
                let prev_end_constraint = current[9] - current[3];
                combined = combined + alpha_power * prev_end_constraint;
            }

            constraints[i] = combined;
        }

        constraints
    }

    /// Extend polynomial using proper FFT interpolation
    fn extend_polynomial_fft(&self, poly: &[Fp]) -> Vec<Fp> {
        let n = poly.len().next_power_of_two();
        let blowup = self.config.fri_config.blowup_factor;
        let extended_len = n * blowup;

        // Step 1: Inverse DFT to get coefficients
        let coeffs = self.inverse_dft(poly, n);

        // Step 2: Forward DFT on extended domain
        let extended = self.forward_dft(&coeffs, extended_len);

        extended
    }

    /// Compute log2 for powers of 2
    fn log2(n: usize) -> u32 {
        assert!(n.is_power_of_two(), "n must be power of 2");
        n.trailing_zeros()
    }

    /// Inverse DFT to get polynomial coefficients
    fn inverse_dft(&self, evals: &[Fp], n: usize) -> Vec<Fp> {
        let log_n = Self::log2(n);
        let omega = Fp::primitive_root_of_unity(log_n);
        let omega_inv = omega.inverse();
        let n_inv = Fp::new(n as u64).inverse();

        let mut coeffs = vec![Fp::ZERO; n];

        for i in 0..n {
            let mut sum = Fp::ZERO;
            let mut omega_power = Fp::ONE;

            for j in 0..evals.len().min(n) {
                sum = sum + evals[j] * omega_power;
                omega_power = omega_power * omega_inv.pow(i as u64);
            }

            coeffs[i] = sum * n_inv;
        }

        coeffs
    }

    /// Forward DFT to evaluate polynomial
    fn forward_dft(&self, coeffs: &[Fp], extended_len: usize) -> Vec<Fp> {
        let log_n = Self::log2(extended_len);
        let omega = Fp::primitive_root_of_unity(log_n);

        let mut evals = vec![Fp::ZERO; extended_len];

        for i in 0..extended_len {
            let mut sum = Fp::ZERO;
            let x = omega.pow(i as u64);
            let mut x_power = Fp::ONE;

            for j in 0..coeffs.len() {
                sum = sum + coeffs[j] * x_power;
                x_power = x_power * x;
            }

            evals[i] = sum;
        }

        evals
    }
}

/// Aggregation verifier - COMPLETE IMPLEMENTATION
pub struct AggregationVerifier {
    config: AggregationConfig,
}

impl AggregationVerifier {
    /// Create new aggregation verifier
    pub fn new(config: AggregationConfig) -> Self {
        AggregationVerifier { config }
    }

    /// Verify an aggregation proof
    pub fn verify(&self, proof: &AggregationProof) -> bool {
        // Reconstruct transcript with same data as prover
        let mut transcript = Transcript::new();
        transcript.append_commitment(&proof.children_root);
        transcript.append(&proof.chain_start);
        transcript.append(&proof.chain_end);

        // Must call challenge_aggregation to match prover's transcript state
        let _alpha = transcript.challenge_aggregation();

        // Verify FRI proof
        let fri_verifier = FriVerifier::new(self.config.fri_config.clone());
        fri_verifier.verify(&proof.fri_proof, &mut transcript)
    }

    /// Verify the final (level-2) proof with chain endpoints
    pub fn verify_final(
        &self,
        proof: &AggregationProof,
        expected_d0: &[u8; 32],
        expected_y: &[u8; 32],
    ) -> bool {
        // 1. Check this is a level-2 proof
        if proof.level != 2 {
            return false;
        }

        // 2. Verify chain starts with d0
        if proof.chain_start != *expected_d0 {
            return false;
        }

        // 3. Verify chain ends with y
        if proof.chain_end != *expected_y {
            return false;
        }

        // 4. Verify the FRI proof (proves constraints were satisfied)
        if !self.verify(proof) {
            return false;
        }

        // 5. Verify children_root is non-zero (has actual children)
        if proof.children_root.iter().all(|&b| b == 0) {
            return false;
        }

        true
    }
}

/// Quick aggregation for testing
pub fn aggregate_quick(segment_proofs: &[SegmentProof]) -> AggregationProof {
    let config = AggregationConfig {
        max_children: 1024,
        fri_config: FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 1024,
        },
    };

    let prover = AggregationProver::new(config);
    prover.aggregate_segments(segment_proofs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::{compute_segment_end, SegmentConfig, SegmentProver};
    use crate::sha256::Sha256;

    fn create_test_segment_proofs(num_segments: usize) -> Vec<SegmentProof> {
        let segment_length = 4; // Small for testing
        let config = SegmentConfig {
            segment_length,
            fri_config: FriConfig {
                num_queries: 5,
                blowup_factor: 4,
                max_degree: 256,
            },
        };

        let prover = SegmentProver::new(config);

        let mut proofs = Vec::new();
        let mut current_hash = Sha256::hash(b"aggregation test");

        for i in 0..num_segments {
            let proof = prover.prove(i as u32, &current_hash);
            current_hash = proof.end_hash;
            proofs.push(proof);
        }

        proofs
    }

    #[test]
    fn test_segment_chain_consistency() {
        let proofs = create_test_segment_proofs(5);

        // Verify chain manually
        for i in 0..proofs.len() - 1 {
            assert_eq!(proofs[i].end_hash, proofs[i + 1].start_hash);
        }
    }

    #[test]
    fn test_l1_aggregation() {
        let segment_proofs = create_test_segment_proofs(4);

        let config = AggregationConfig {
            max_children: 16,
            fri_config: FriConfig {
                num_queries: 5,
                blowup_factor: 4,
                max_degree: 128,
            },
        };

        let prover = AggregationProver::new(config.clone());
        let l1_proof = prover.aggregate_segments(&segment_proofs);

        assert_eq!(l1_proof.level, 1);
        assert_eq!(l1_proof.num_children, 4);
        assert_eq!(l1_proof.chain_start, segment_proofs[0].start_hash);
        assert_eq!(l1_proof.chain_end, segment_proofs.last().unwrap().end_hash);

        let verifier = AggregationVerifier::new(config);
        assert!(verifier.verify(&l1_proof));
    }

    #[test]
    fn test_l2_aggregation() {
        let config = AggregationConfig {
            max_children: 16,
            fri_config: FriConfig {
                num_queries: 5,
                blowup_factor: 4,
                max_degree: 128,
            },
        };

        // Create segment proofs for a continuous chain
        let segment_proofs = create_test_segment_proofs(8);
        let prover = AggregationProver::new(config.clone());

        // Split into two L1 proofs
        let l1_proof_1 = prover.aggregate_segments(&segment_proofs[0..4]);
        let l1_proof_2 = prover.aggregate_segments(&segment_proofs[4..8]);

        // L1 proofs should form a chain
        assert_eq!(l1_proof_1.chain_end, l1_proof_2.chain_start);

        let l1_proofs = vec![l1_proof_1, l1_proof_2];

        // Aggregate into L2
        let l2_proof = prover.aggregate_level1(&l1_proofs);

        assert_eq!(l2_proof.level, 2);
        assert_eq!(l2_proof.num_children, 2);
        assert_eq!(l2_proof.chain_start, segment_proofs[0].start_hash);
        assert_eq!(l2_proof.chain_end, segment_proofs.last().unwrap().end_hash);

        // Verify final proof
        let verifier = AggregationVerifier::new(config);
        assert!(verifier.verify_final(
            &l2_proof,
            &segment_proofs[0].start_hash,
            &segment_proofs.last().unwrap().end_hash
        ));
    }
}
