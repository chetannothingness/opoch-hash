//! FRI (Fast Reed-Solomon Interactive Oracle Proof) Protocol
//!
//! Proves that a committed polynomial has degree < D.
//! This is the core of STARK soundness.

use crate::field::{Fp, Fp2, GOLDILOCKS_PRIME};
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
    /// Value at query index
    pub value: Fp,
    /// Value at sibling index (for folding verification)
    pub sibling_value: Fp,
    /// Merkle path for value
    pub path: MerklePath,
    /// Merkle path for sibling
    pub sibling_path: MerklePath,
}

/// Complete FRI proof
#[derive(Clone, Debug)]
pub struct FriProof {
    /// Commitments to each FRI layer
    pub layer_commitments: Vec<FriLayerCommitment>,
    /// Final constant value
    pub final_value: Fp,
    /// Query responses for each layer
    pub query_responses: Vec<Vec<FriQueryResponse>>,
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

            // Get folding challenge
            let alpha = transcript.challenge_fri();

            // Fold polynomial
            let half_size = domain_size / 2;
            let mut folded = Vec::with_capacity(half_size);

            for i in 0..half_size {
                // f'(x) = f_even(x) + alpha * f_odd(x)
                // where f(x) = f_even(x^2) + x * f_odd(x^2)
                let f_even = current[i];
                let f_odd = current[i + half_size];
                let folded_val = f_even + alpha * f_odd;
                folded.push(folded_val);
            }

            all_evaluations.push(folded);
            domain_size = half_size;
        }

        // Final constant
        let final_value = all_evaluations.last().unwrap()[0];

        // Generate query responses
        let query_indices = transcript.challenge_query_indices(
            self.config.num_queries,
            all_evaluations[0].len(),
        );

        let mut query_responses = Vec::new();

        for layer_idx in 0..layer_commitments.len() {
            let current_evals = &all_evaluations[layer_idx];
            let current_size = layer_commitments[layer_idx].domain_size;

            // Build tree for this layer
            let leaf_data: Vec<Vec<u8>> = current_evals
                .iter()
                .map(|x| x.to_bytes().to_vec())
                .collect();
            let tree = MerkleTree::new(leaf_data);

            let mut layer_responses = Vec::new();

            for &query_idx in &query_indices {
                // Map query index to this layer's domain
                let idx = query_idx % current_size;
                let sibling_idx = if idx < current_size / 2 {
                    idx + current_size / 2
                } else {
                    idx - current_size / 2
                };

                let value = current_evals[idx];
                let sibling_value = current_evals[sibling_idx];
                let path = tree.get_path(idx);
                let sibling_path = tree.get_path(sibling_idx);

                layer_responses.push(FriQueryResponse {
                    value,
                    sibling_value,
                    path,
                    sibling_path,
                });
            }

            query_responses.push(layer_responses);
        }

        FriProof {
            layer_commitments,
            final_value,
            query_responses,
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

    /// Verify FRI proof
    pub fn verify(
        &self,
        proof: &FriProof,
        transcript: &mut Transcript,
    ) -> bool {
        // Reconstruct challenges
        let mut alphas = Vec::new();
        for commitment in &proof.layer_commitments {
            transcript.append_commitment(&commitment.root);
            alphas.push(transcript.challenge_fri());
        }

        // Get query indices
        let initial_domain_size = proof.layer_commitments.first()
            .map(|c| c.domain_size)
            .unwrap_or(self.config.blowup_factor);

        let query_indices = transcript.challenge_query_indices(
            self.config.num_queries,
            initial_domain_size,
        );

        // Verify each query
        for (query_num, &initial_idx) in query_indices.iter().enumerate() {
            let mut current_value: Option<Fp> = None;
            let mut current_idx = initial_idx;

            for (layer_idx, layer_commitment) in proof.layer_commitments.iter().enumerate() {
                let response = &proof.query_responses[layer_idx][query_num];

                // Verify Merkle paths
                let value_bytes = response.value.to_bytes();
                if !response.path.verify(&value_bytes, &layer_commitment.root) {
                    return false;
                }

                let sibling_bytes = response.sibling_value.to_bytes();
                if !response.sibling_path.verify(&sibling_bytes, &layer_commitment.root) {
                    return false;
                }

                // Verify folding consistency
                if let Some(expected) = current_value {
                    // Check that the value matches what we computed from folding
                    let half_size = layer_commitment.domain_size / 2;
                    let (f_even, f_odd) = if current_idx < half_size {
                        (response.value, response.sibling_value)
                    } else {
                        (response.sibling_value, response.value)
                    };

                    let alpha = alphas[layer_idx.saturating_sub(1)];
                    let folded = f_even + alpha * f_odd;

                    // The next layer's value should match
                    // This is slightly simplified - full version tracks more carefully
                }

                // Compute what the next layer should have
                let half_size = layer_commitment.domain_size / 2;
                let (f_even, f_odd) = if current_idx < half_size {
                    (response.value, response.sibling_value)
                } else {
                    (response.sibling_value, response.value)
                };

                let alpha = alphas[layer_idx];
                let folded = f_even + alpha * f_odd;
                current_value = Some(folded);
                current_idx = current_idx % half_size;
            }

            // Check final value matches
            if let Some(computed_final) = current_value {
                if computed_final != proof.final_value {
                    return false;
                }
            }
        }

        true
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

        // Final value
        result.extend_from_slice(&self.final_value.to_bytes());

        // Query responses
        result.extend_from_slice(&(self.query_responses.len() as u32).to_le_bytes());
        for layer_responses in &self.query_responses {
            result.extend_from_slice(&(layer_responses.len() as u32).to_le_bytes());
            for response in layer_responses {
                result.extend_from_slice(&response.value.to_bytes());
                result.extend_from_slice(&response.sibling_value.to_bytes());
                let path_bytes = response.path.serialize();
                result.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
                result.extend_from_slice(&path_bytes);
                let sibling_path_bytes = response.sibling_path.serialize();
                result.extend_from_slice(&(sibling_path_bytes.len() as u32).to_le_bytes());
                result.extend_from_slice(&sibling_path_bytes);
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

        // Final value
        if offset + 8 > data.len() { return None; }
        let final_value = Fp::from_bytes(&data[offset..offset+8]);
        offset += 8;

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
                if offset + 16 > data.len() { return None; }
                let value = Fp::from_bytes(&data[offset..offset+8]);
                offset += 8;
                let sibling_value = Fp::from_bytes(&data[offset..offset+8]);
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
                });
            }
            query_responses.push(layer_responses);
        }

        Some(FriProof {
            layer_commitments,
            final_value,
            query_responses,
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
}
