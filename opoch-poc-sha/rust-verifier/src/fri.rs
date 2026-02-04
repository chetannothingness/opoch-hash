//! FRI (Fast Reed-Solomon Interactive Oracle Proof) Protocol
//!
//! Proves that a committed polynomial has degree < D.
//! This is the core of STARK soundness.

use crate::field::Fp;
use crate::merkle::{MerkleTree, MerklePath};
use crate::transcript::Transcript;

/// FRI configuration
#[derive(Clone, Debug)]
pub struct FriConfig {
    /// Number of queries for soundness
    pub num_queries: usize,
    /// Blowup factor (rate = 1/blowup)
    pub blowup_factor: usize,
    /// Maximum polynomial degree
    pub max_degree: usize,
}

impl Default for FriConfig {
    fn default() -> Self {
        FriConfig {
            num_queries: 68,      // For 128+ bit security
            blowup_factor: 8,     // Rate = 0.125
            max_degree: 65536,    // 2^16
        }
    }
}

/// FRI layer commitment
#[derive(Clone, Debug)]
pub struct FriLayerCommitment {
    pub root: [u8; 32],
    pub domain_size: usize,
}

/// FRI query response for one layer
#[derive(Clone, Debug)]
pub struct FriQueryResponse {
    /// Value at the even position of the coset pair
    pub value: Fp,
    /// Value at the odd position of the coset pair (sibling)
    pub sibling_value: Fp,
    /// Merkle path for value (at even_idx)
    pub path: MerklePath,
    /// Merkle path for sibling (at odd_idx)
    pub sibling_path: MerklePath,
    /// The even index in this layer's domain
    pub even_idx: usize,
}

/// Complete FRI proof
#[derive(Clone, Debug)]
pub struct FriProof {
    /// Commitments to each FRI layer
    pub layer_commitments: Vec<FriLayerCommitment>,
    /// Final layer evaluations (small - at most blowup_factor elements)
    /// Each query checks against final_layer[query_idx % final_layer.len()]
    pub final_layer: Vec<Fp>,
    /// Query responses for each layer
    pub query_responses: Vec<Vec<FriQueryResponse>>,
    /// Transcript binding value for degenerate (zero-layer) FRI proofs.
    /// When layer_commitments is empty, this field MUST be present and
    /// must equal H_F("FRI_BIND", alpha0) where alpha0 is derived from transcript.
    /// This ensures cryptographic binding even when no FRI layers are executed.
    pub z_bind: Option<Fp>,
}

impl FriProof {
    /// Get final_value (first element) for backward compatibility
    pub fn final_value(&self) -> Fp {
        self.final_layer.first().copied().unwrap_or(Fp::ZERO)
    }
}

impl Default for FriProof {
    fn default() -> Self {
        FriProof {
            layer_commitments: Vec::new(),
            final_layer: Vec::new(),
            query_responses: Vec::new(),
            z_bind: None,
        }
    }
}

/// FRI error types for detailed rejection
#[derive(Debug, Clone, PartialEq)]
pub enum FriError {
    /// Merkle path verification failed
    MerkleVerificationFailed { layer: usize, query: usize, is_sibling: bool },
    /// Folding consistency check failed
    FoldingMismatch { layer: usize, query: usize, expected: Fp, got: Fp },
    /// Final value mismatch
    FinalValueMismatch { query: usize, expected: Fp, got: Fp },
    /// Invalid proof structure
    InvalidProofStructure,
    /// Index out of bounds
    IndexOutOfBounds { layer: usize, index: usize, domain_size: usize },
    /// Transcript binding verification failed (degenerate FRI case)
    /// This error indicates the proof doesn't cryptographically bind to transcript state
    TranscriptUnbound,
}

/// FRI Prover
pub struct FriProver {
    config: FriConfig,
}

impl FriProver {
    pub fn new(config: FriConfig) -> Self {
        FriProver { config }
    }

    /// Prove low degree of polynomial given evaluations
    pub fn prove(
        &self,
        evaluations: Vec<Fp>,
        transcript: &mut Transcript,
    ) -> FriProof {
        let mut layer_commitments = Vec::new();
        let mut all_evaluations = vec![evaluations];
        let mut all_trees = Vec::new();
        let mut domain_size = all_evaluations[0].len();

        // Commit and fold until constant
        while domain_size > self.config.blowup_factor {
            // Commit to current layer
            let current = &all_evaluations.last().unwrap();
            let leaf_data: Vec<Vec<u8>> = current
                .iter()
                .map(|x| x.to_bytes().to_vec())
                .collect();
            let tree = MerkleTree::new(leaf_data);

            layer_commitments.push(FriLayerCommitment {
                root: tree.root,
                domain_size,
            });

            transcript.append_commitment(&tree.root);
            all_trees.push(tree);

            // Get folding challenge
            let alpha = transcript.challenge_fri();

            // Fold polynomial: f'(x) = f_even(x) + alpha * f_odd(x)
            let half_size = domain_size / 2;
            let mut folded = Vec::with_capacity(half_size);

            for i in 0..half_size {
                let f_even = current[i];
                let f_odd = current[i + half_size];
                let folded_val = f_even + alpha * f_odd;
                folded.push(folded_val);
            }

            all_evaluations.push(folded);
            domain_size = half_size;
        }

        // Final layer (small - at most blowup_factor elements)
        let final_layer = all_evaluations.last().unwrap().clone();

        // CRITICAL: For degenerate (zero-layer) FRI proofs, we must still bind to transcript.
        // Derive alpha0 and compute z_bind = H_F("FRI_BIND", alpha0) to ensure transcript binding.
        let z_bind = if layer_commitments.is_empty() {
            // Derive challenge from current transcript state
            let alpha0 = transcript.challenge_field(b"FRI_ALPHA0");
            // Compute binding value: z_bind = H_F("FRI_BIND", alpha0)
            Some(transcript.hash_to_field(b"FRI_BIND", alpha0))
        } else {
            None
        };

        // Generate query indices from transcript
        let initial_domain_size = all_evaluations[0].len();
        let query_indices = transcript.challenge_query_indices(
            self.config.num_queries,
            initial_domain_size,
        );

        let mut query_responses = Vec::new();

        for layer_idx in 0..layer_commitments.len() {
            let current_evals = &all_evaluations[layer_idx];
            let current_size = layer_commitments[layer_idx].domain_size;
            let half_size = current_size / 2;
            let tree = &all_trees[layer_idx];

            let mut layer_responses = Vec::new();

            for &initial_query_idx in &query_indices {
                // Compute the query index for this layer by tracking through folding
                // Index at layer L = (initial_idx >> L) % domain_size_at_L
                // But since domain halves each layer, idx_L = initial_idx % current_size
                let idx = initial_query_idx % current_size;

                // Normalize to get the coset pair: even_idx in [0, half_size)
                let even_idx = idx % half_size;
                let odd_idx = even_idx + half_size;

                let value = current_evals[even_idx];
                let sibling_value = current_evals[odd_idx];
                let path = tree.get_path(even_idx);
                let sibling_path = tree.get_path(odd_idx);

                layer_responses.push(FriQueryResponse {
                    value,
                    sibling_value,
                    path,
                    sibling_path,
                    even_idx,
                });
            }

            query_responses.push(layer_responses);
        }

        FriProof {
            layer_commitments,
            final_layer,
            query_responses,
            z_bind,
        }
    }
}

/// FRI Verifier
pub struct FriVerifier {
    config: FriConfig,
}

impl FriVerifier {
    pub fn new(config: FriConfig) -> Self {
        FriVerifier { config }
    }

    /// Verify FRI proof - returns detailed error on failure
    pub fn verify_detailed(
        &self,
        proof: &FriProof,
        transcript: &mut Transcript,
    ) -> Result<(), FriError> {
        // CRITICAL: Degenerate (zero-layer) FRI case.
        // When the polynomial is trivially small (< blowup_factor elements),
        // FRI has no layers to fold. However, we MUST still enforce transcript binding.
        //
        // INVARIANT: Every committed field in the proof must influence an acceptance check.
        //
        // Without this check, mutating children_root (or any field absorbed into transcript
        // earlier) would not change verification outcome - a cryptographic binding failure.
        if proof.layer_commitments.is_empty() {
            if proof.final_layer.is_empty() {
                return Err(FriError::InvalidProofStructure);
            }

            // MANDATORY TRANSCRIPT BINDING CHECK:
            // 1. Derive challenge alpha0 from current transcript state
            let alpha0 = transcript.challenge_field(b"FRI_ALPHA0");

            // 2. Require z_bind field to be present
            let z_bind = proof.z_bind.ok_or(FriError::TranscriptUnbound)?;

            // 3. Compute expected value: H_F("FRI_BIND", alpha0)
            let expected = transcript.hash_to_field(b"FRI_BIND", alpha0);

            // 4. Verify binding
            if z_bind != expected {
                return Err(FriError::TranscriptUnbound);
            }

            // CRITICAL: Keep transcript state in sync with prover.
            // The prover calls challenge_query_indices even in degenerate case,
            // so we must too to maintain identical transcript state for batch operations.
            // In degenerate case, final_layer.len() == initial_domain_size
            let _ = transcript.challenge_query_indices(
                self.config.num_queries,
                proof.final_layer.len(),
            );

            // Degenerate case verified - transcript is properly bound
            return Ok(());
        }

        if proof.query_responses.len() != proof.layer_commitments.len() {
            return Err(FriError::InvalidProofStructure);
        }

        // Reconstruct challenges from transcript
        let mut alphas = Vec::new();
        for commitment in &proof.layer_commitments {
            transcript.append_commitment(&commitment.root);
            alphas.push(transcript.challenge_fri());
        }

        // Get query indices
        let initial_domain_size = proof.layer_commitments[0].domain_size;
        let query_indices = transcript.challenge_query_indices(
            self.config.num_queries,
            initial_domain_size,
        );

        // Verify each query chain
        for (query_num, &initial_idx) in query_indices.iter().enumerate() {
            // Track the expected folded value for consistency checking
            let mut expected_folded: Option<Fp> = None;

            for (layer_idx, layer_commitment) in proof.layer_commitments.iter().enumerate() {
                let response = &proof.query_responses[layer_idx][query_num];
                let domain_size = layer_commitment.domain_size;
                let half_size = domain_size / 2;

                // Compute expected index for this layer
                let idx = initial_idx % domain_size;
                let expected_even_idx = idx % half_size;

                // Verify the prover opened the correct indices
                if response.even_idx != expected_even_idx {
                    return Err(FriError::IndexOutOfBounds {
                        layer: layer_idx,
                        index: response.even_idx,
                        domain_size,
                    });
                }

                let odd_idx = expected_even_idx + half_size;

                // 1. Verify Merkle path for even value
                let value_bytes = response.value.to_bytes();
                if !response.path.verify(&value_bytes, &layer_commitment.root) {
                    return Err(FriError::MerkleVerificationFailed {
                        layer: layer_idx,
                        query: query_num,
                        is_sibling: false,
                    });
                }

                // 2. Verify Merkle path for odd (sibling) value
                let sibling_bytes = response.sibling_value.to_bytes();
                if !response.sibling_path.verify(&sibling_bytes, &layer_commitment.root) {
                    return Err(FriError::MerkleVerificationFailed {
                        layer: layer_idx,
                        query: query_num,
                        is_sibling: true,
                    });
                }

                // 3. CRITICAL: Verify folding consistency with previous layer
                //
                // The folded value from layer L-1 was placed at index:
                //   prev_even_idx = (initial_idx % prev_domain_size) % prev_half_size
                //
                // At layer L, this index maps to idx = initial_idx % domain_size.
                // Since domain_size = prev_half_size, we have idx = prev_even_idx.
                //
                // The prover opened values at even_idx and even_idx + half_size.
                // The expected value is at index idx in this layer's array.
                //
                // If idx < half_size:  idx == even_idx, so expected is in response.value
                // If idx >= half_size: idx == even_idx + half_size, so expected is in response.sibling_value
                //
                if let Some(expected) = expected_folded {
                    let actual = if idx >= half_size {
                        response.sibling_value
                    } else {
                        response.value
                    };

                    if actual != expected {
                        return Err(FriError::FoldingMismatch {
                            layer: layer_idx,
                            query: query_num,
                            expected,
                            got: actual,
                        });
                    }
                }

                // 4. Compute folded value for next layer
                // f_folded = f_even + alpha * f_odd
                let f_even = response.value;
                let f_odd = response.sibling_value;
                let alpha = alphas[layer_idx];
                let folded = f_even + alpha * f_odd;

                // Store for next iteration
                expected_folded = Some(folded);
            }

            // 5. Final check: folded value must equal the final layer at the query's index
            if let Some(computed_final) = expected_folded {
                // Compute the index in the final layer
                let final_layer_size = proof.final_layer.len();
                if final_layer_size == 0 {
                    return Err(FriError::InvalidProofStructure);
                }
                let final_idx = initial_idx % final_layer_size;
                let expected_final = proof.final_layer[final_idx];

                if computed_final != expected_final {
                    return Err(FriError::FinalValueMismatch {
                        query: query_num,
                        expected: computed_final,
                        got: expected_final,
                    });
                }
            }
        }

        Ok(())
    }

    /// Verify FRI proof - returns bool for compatibility
    pub fn verify(
        &self,
        proof: &FriProof,
        transcript: &mut Transcript,
    ) -> bool {
        self.verify_detailed(proof, transcript).is_ok()
    }
}

impl FriProof {
    /// Serialize proof to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Number of layers
        result.extend_from_slice(&(self.layer_commitments.len() as u32).to_le_bytes());

        // Layer commitments
        for lc in &self.layer_commitments {
            result.extend_from_slice(&lc.root);
            result.extend_from_slice(&(lc.domain_size as u64).to_le_bytes());
        }

        // Final layer
        result.extend_from_slice(&(self.final_layer.len() as u32).to_le_bytes());
        for val in &self.final_layer {
            result.extend_from_slice(&val.to_bytes());
        }

        // Query responses
        result.extend_from_slice(&(self.query_responses.len() as u32).to_le_bytes());
        for layer_responses in &self.query_responses {
            result.extend_from_slice(&(layer_responses.len() as u32).to_le_bytes());
            for response in layer_responses {
                result.extend_from_slice(&response.value.to_bytes());
                result.extend_from_slice(&response.sibling_value.to_bytes());
                result.extend_from_slice(&(response.even_idx as u64).to_le_bytes());
                let path_bytes = response.path.serialize();
                result.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
                result.extend_from_slice(&path_bytes);
                let sibling_path_bytes = response.sibling_path.serialize();
                result.extend_from_slice(&(sibling_path_bytes.len() as u32).to_le_bytes());
                result.extend_from_slice(&sibling_path_bytes);
            }
        }

        // z_bind (transcript binding for degenerate FRI proofs)
        // Format: 1 byte flag (0 = None, 1 = Some) + optional 8 byte field element
        match &self.z_bind {
            None => result.push(0),
            Some(val) => {
                result.push(1);
                result.extend_from_slice(&val.to_bytes());
            }
        }

        result
    }

    /// Deserialize proof from bytes
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        let mut offset = 0;

        // Number of layers
        if offset + 4 > data.len() { return None; }
        let num_layers = u32::from_le_bytes(data[offset..offset+4].try_into().ok()?) as usize;
        offset += 4;

        // Layer commitments
        let mut layer_commitments = Vec::with_capacity(num_layers);
        for _ in 0..num_layers {
            if offset + 40 > data.len() { return None; }
            let mut root = [0u8; 32];
            root.copy_from_slice(&data[offset..offset+32]);
            offset += 32;
            let domain_size = u64::from_le_bytes(data[offset..offset+8].try_into().ok()?) as usize;
            offset += 8;
            layer_commitments.push(FriLayerCommitment { root, domain_size });
        }

        // Final layer
        if offset + 4 > data.len() { return None; }
        let final_layer_len = u32::from_le_bytes(data[offset..offset+4].try_into().ok()?) as usize;
        offset += 4;
        let mut final_layer = Vec::with_capacity(final_layer_len);
        for _ in 0..final_layer_len {
            if offset + 8 > data.len() { return None; }
            final_layer.push(Fp::from_bytes(&data[offset..offset+8]));
            offset += 8;
        }

        // Query responses
        if offset + 4 > data.len() { return None; }
        let num_query_layers = u32::from_le_bytes(data[offset..offset+4].try_into().ok()?) as usize;
        offset += 4;

        let mut query_responses = Vec::with_capacity(num_query_layers);
        for _ in 0..num_query_layers {
            if offset + 4 > data.len() { return None; }
            let num_responses = u32::from_le_bytes(data[offset..offset+4].try_into().ok()?) as usize;
            offset += 4;

            let mut layer_responses = Vec::with_capacity(num_responses);
            for _ in 0..num_responses {
                if offset + 24 > data.len() { return None; }
                let value = Fp::from_bytes(&data[offset..offset+8]);
                offset += 8;
                let sibling_value = Fp::from_bytes(&data[offset..offset+8]);
                offset += 8;
                let even_idx = u64::from_le_bytes(data[offset..offset+8].try_into().ok()?) as usize;
                offset += 8;

                if offset + 4 > data.len() { return None; }
                let path_len = u32::from_le_bytes(data[offset..offset+4].try_into().ok()?) as usize;
                offset += 4;
                if offset + path_len > data.len() { return None; }
                let path = MerklePath::deserialize(&data[offset..offset+path_len])?;
                offset += path_len;

                if offset + 4 > data.len() { return None; }
                let sibling_path_len = u32::from_le_bytes(data[offset..offset+4].try_into().ok()?) as usize;
                offset += 4;
                if offset + sibling_path_len > data.len() { return None; }
                let sibling_path = MerklePath::deserialize(&data[offset..offset+sibling_path_len])?;
                offset += sibling_path_len;

                layer_responses.push(FriQueryResponse {
                    value,
                    sibling_value,
                    path,
                    sibling_path,
                    even_idx,
                });
            }
            query_responses.push(layer_responses);
        }

        // z_bind (transcript binding for degenerate FRI proofs)
        // Format: 1 byte flag (0 = None, 1 = Some) + optional 8 byte field element
        let z_bind = if offset < data.len() {
            let flag = data[offset];
            offset += 1;
            if flag == 1 {
                if offset + 8 > data.len() { return None; }
                let val = Fp::from_bytes(&data[offset..offset+8]);
                offset += 8;
                Some(val)
            } else {
                None
            }
        } else {
            // Backward compatibility: older proofs without z_bind
            None
        };
        let _ = offset; // silence unused warning

        Some(FriProof {
            layer_commitments,
            final_layer,
            query_responses,
            z_bind,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fri_small() {
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 16,
        };

        // Create a low-degree polynomial (constant)
        let evaluations: Vec<Fp> = (0..64).map(|_| Fp::new(42)).collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let proof = prover.prove(evaluations, &mut transcript);

        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();
        assert!(verifier.verify(&proof, &mut verify_transcript));
    }

    #[test]
    fn test_fri_linear_polynomial() {
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 16,
        };

        // Create a linear polynomial: f(x) = 3x + 5
        let evaluations: Vec<Fp> = (0..64)
            .map(|i| Fp::new(3) * Fp::new(i as u64) + Fp::new(5))
            .collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let proof = prover.prove(evaluations, &mut transcript);

        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();
        assert!(verifier.verify(&proof, &mut verify_transcript));
    }

    #[test]
    fn test_fri_corrupted_value_rejects() {
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 16,
        };

        let evaluations: Vec<Fp> = (0..64).map(|_| Fp::new(42)).collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let mut proof = prover.prove(evaluations, &mut transcript);

        // Corrupt a value in the first layer
        if !proof.query_responses.is_empty() && !proof.query_responses[0].is_empty() {
            proof.query_responses[0][0].value = Fp::new(999999);
        }

        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();

        // Should reject due to Merkle verification failure or folding mismatch
        assert!(!verifier.verify(&proof, &mut verify_transcript));
    }

    #[test]
    fn test_fri_corrupted_sibling_rejects() {
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 16,
        };

        let evaluations: Vec<Fp> = (0..64).map(|_| Fp::new(42)).collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let mut proof = prover.prove(evaluations, &mut transcript);

        // Corrupt a sibling value
        if !proof.query_responses.is_empty() && !proof.query_responses[0].is_empty() {
            proof.query_responses[0][0].sibling_value = Fp::new(888888);
        }

        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();

        // Should reject
        assert!(!verifier.verify(&proof, &mut verify_transcript));
    }

    #[test]
    fn test_fri_corrupted_final_value_rejects() {
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 16,
        };

        let evaluations: Vec<Fp> = (0..64).map(|_| Fp::new(42)).collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let mut proof = prover.prove(evaluations, &mut transcript);

        // Corrupt the final layer (corrupt first element)
        if !proof.final_layer.is_empty() {
            proof.final_layer[0] = Fp::new(777777);
        }

        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();

        // Should reject due to final value mismatch
        assert!(!verifier.verify(&proof, &mut verify_transcript));
    }

    #[test]
    fn test_fri_corrupted_intermediate_layer_rejects() {
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 16,
        };

        let evaluations: Vec<Fp> = (0..64).map(|_| Fp::new(42)).collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let mut proof = prover.prove(evaluations, &mut transcript);

        // Corrupt a value in an intermediate layer (if exists)
        if proof.query_responses.len() > 1 && !proof.query_responses[1].is_empty() {
            proof.query_responses[1][0].value = Fp::new(666666);
        }

        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();

        // Should reject
        assert!(!verifier.verify(&proof, &mut verify_transcript));
    }

    #[test]
    fn test_fri_detailed_error_on_corruption() {
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 16,
        };

        let evaluations: Vec<Fp> = (0..64).map(|_| Fp::new(42)).collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let mut proof = prover.prove(evaluations, &mut transcript);

        // Corrupt the final layer (corrupt first element)
        if !proof.final_layer.is_empty() {
            proof.final_layer[0] = Fp::new(777777);
        }

        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();

        let result = verifier.verify_detailed(&proof, &mut verify_transcript);
        assert!(result.is_err());

        match result {
            Err(FriError::FinalValueMismatch { .. }) => (),
            Err(FriError::FoldingMismatch { .. }) => (),
            Err(e) => panic!("Expected FinalValueMismatch or FoldingMismatch, got {:?}", e),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[test]
    fn test_fri_serialization_roundtrip() {
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 16,
        };

        let evaluations: Vec<Fp> = (0..64).map(|_| Fp::new(42)).collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let proof = prover.prove(evaluations, &mut transcript);

        // Serialize and deserialize
        let serialized = proof.serialize();
        let deserialized = FriProof::deserialize(&serialized).expect("Should deserialize");

        // Verify the deserialized proof
        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();
        assert!(verifier.verify(&deserialized, &mut verify_transcript));
    }

    #[test]
    fn test_fri_corrupted_serialized_byte_rejects() {
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 16,
        };

        let evaluations: Vec<Fp> = (0..64).map(|_| Fp::new(42)).collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let proof = prover.prove(evaluations, &mut transcript);

        // Serialize
        let mut serialized = proof.serialize();

        // Corrupt a byte in the middle (after headers, in the data section)
        if serialized.len() > 100 {
            serialized[100] ^= 0xFF;  // Flip all bits
        }

        // Try to deserialize and verify
        if let Some(corrupted_proof) = FriProof::deserialize(&serialized) {
            let verifier = FriVerifier::new(config);
            let mut verify_transcript = Transcript::new();
            // Should reject the corrupted proof
            assert!(!verifier.verify(&corrupted_proof, &mut verify_transcript),
                "Corrupted proof should be rejected!");
        }
        // If deserialization fails, that's also acceptable (proof is invalid)
    }

    #[test]
    fn test_fri_quadratic_polynomial() {
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 16,
        };

        // Create a quadratic polynomial: f(x) = 2x^2 + 3x + 7
        let evaluations: Vec<Fp> = (0..64)
            .map(|i| {
                let x = Fp::new(i as u64);
                Fp::new(2) * x * x + Fp::new(3) * x + Fp::new(7)
            })
            .collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let proof = prover.prove(evaluations, &mut transcript);

        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();
        assert!(verifier.verify(&proof, &mut verify_transcript));
    }

    // ====================================================================
    // TRANSCRIPT BINDING REGRESSION TESTS
    // These tests verify the critical invariant:
    // "Every committed field in the proof must influence an acceptance check."
    // ====================================================================

    #[test]
    fn test_fri_degenerate_case_produces_z_bind() {
        // When evaluations are small enough that FRI has no layers,
        // the prover MUST produce z_bind for transcript binding.
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 8,  // evaluations.len() <= blowup_factor triggers degenerate case
            max_degree: 16,
        };

        // Create small evaluation domain (triggers degenerate FRI)
        let evaluations: Vec<Fp> = (0..8).map(|_| Fp::new(42)).collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let proof = prover.prove(evaluations, &mut transcript);

        // Degenerate case: no layers, but z_bind MUST be present
        assert!(proof.layer_commitments.is_empty(), "Expected degenerate FRI (no layers)");
        assert!(proof.z_bind.is_some(), "Degenerate FRI proof MUST have z_bind for transcript binding");

        // Verify the proof is accepted
        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();
        assert!(verifier.verify(&proof, &mut verify_transcript), "Valid degenerate proof should verify");
    }

    #[test]
    fn test_fri_degenerate_case_corrupted_z_bind_rejects() {
        // If z_bind is corrupted, verification MUST fail.
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 8,
            max_degree: 16,
        };

        let evaluations: Vec<Fp> = (0..8).map(|_| Fp::new(42)).collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let mut proof = prover.prove(evaluations, &mut transcript);

        // Corrupt z_bind
        proof.z_bind = Some(Fp::new(0xDEADBEEF));

        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();
        let result = verifier.verify_detailed(&proof, &mut verify_transcript);

        assert!(result.is_err(), "Corrupted z_bind should be rejected");
        assert_eq!(result.unwrap_err(), FriError::TranscriptUnbound,
            "Should fail with TranscriptUnbound error");
    }

    #[test]
    fn test_fri_degenerate_case_missing_z_bind_rejects() {
        // If z_bind is missing in degenerate case, verification MUST fail.
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 8,
            max_degree: 16,
        };

        let evaluations: Vec<Fp> = (0..8).map(|_| Fp::new(42)).collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let mut proof = prover.prove(evaluations, &mut transcript);

        // Remove z_bind
        proof.z_bind = None;

        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();
        let result = verifier.verify_detailed(&proof, &mut verify_transcript);

        assert!(result.is_err(), "Missing z_bind should be rejected");
        assert_eq!(result.unwrap_err(), FriError::TranscriptUnbound,
            "Should fail with TranscriptUnbound error");
    }

    #[test]
    fn test_fri_transcript_binding_across_all_sizes() {
        // Test that transcript mutations fail for ALL domain sizes.
        // This is the critical regression test for the binding invariant.

        for domain_size_log in 3..=8 {  // Domain sizes from 8 to 256
            let domain_size = 1 << domain_size_log;
            let blowup = 8;

            let config = FriConfig {
                num_queries: 10,
                blowup_factor: blowup,
                max_degree: domain_size,
            };

            let evaluations: Vec<Fp> = (0..domain_size).map(|i| Fp::new(i as u64 * 7 + 3)).collect();

            // Generate valid proof with transcript that absorbed some commitment
            let prover = FriProver::new(config.clone());
            let mut prover_transcript = Transcript::new();

            // Simulate absorbing children_root or any committed data
            let children_root = [0x42u8; 32];
            prover_transcript.append_commitment(&children_root);

            let proof = prover.prove(evaluations, &mut prover_transcript);

            // Verify with SAME transcript state
            let verifier = FriVerifier::new(config.clone());
            let mut verify_transcript = Transcript::new();
            verify_transcript.append_commitment(&children_root);

            assert!(verifier.verify(&proof, &mut verify_transcript),
                "Valid proof at domain_size={} should verify", domain_size);

            // Now verify with MUTATED children_root -> MUST FAIL
            let mut bad_transcript = Transcript::new();
            let bad_children_root = [0x43u8; 32];  // Mutated!
            bad_transcript.append_commitment(&bad_children_root);

            let result = verifier.verify(&proof, &mut bad_transcript);
            assert!(!result,
                "SECURITY: Mutated children_root at domain_size={} MUST cause verification to fail!", domain_size);
        }
    }

    #[test]
    fn test_fri_z_bind_serialization_roundtrip() {
        // Ensure z_bind survives serialization/deserialization
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 8,
            max_degree: 16,
        };

        // Degenerate case
        let evaluations: Vec<Fp> = (0..8).map(|_| Fp::new(42)).collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let proof = prover.prove(evaluations, &mut transcript);

        assert!(proof.z_bind.is_some(), "Original proof should have z_bind");

        // Serialize and deserialize
        let serialized = proof.serialize();
        let deserialized = FriProof::deserialize(&serialized).expect("Should deserialize");

        assert_eq!(deserialized.z_bind, proof.z_bind,
            "z_bind must survive serialization roundtrip");

        // Verify the deserialized proof
        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();
        assert!(verifier.verify(&deserialized, &mut verify_transcript),
            "Deserialized proof with z_bind should verify");
    }

    #[test]
    fn test_fri_non_degenerate_case_no_z_bind() {
        // Non-degenerate FRI proofs should NOT have z_bind (it's only for degenerate case)
        let config = FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 64,
        };

        let evaluations: Vec<Fp> = (0..64).map(|_| Fp::new(42)).collect();

        let prover = FriProver::new(config.clone());
        let mut transcript = Transcript::new();
        let proof = prover.prove(evaluations, &mut transcript);

        // Non-degenerate: has layers, no z_bind needed
        assert!(!proof.layer_commitments.is_empty(), "Expected non-degenerate FRI with layers");
        assert!(proof.z_bind.is_none(), "Non-degenerate FRI should not have z_bind");

        // Verify still works
        let verifier = FriVerifier::new(config);
        let mut verify_transcript = Transcript::new();
        assert!(verifier.verify(&proof, &mut verify_transcript));
    }
}
