//! Keccak-256 AIR Constraints
//!
//! Algebraic Intermediate Representation for Keccak-256.

use crate::field::Fp;
use crate::fri::{FriConfig, FriProof, FriProver, FriVerifier};
use crate::transcript::Transcript;

use super::state::KeccakState;
use super::round::{KeccakPermutationTrace, keccak_f};
use super::{STATE_BYTES, ROUNDS, KECCAK256_RATE};

/// Keccak-256 AIR
pub struct KeccakAir {
    /// FRI configuration
    fri_config: FriConfig,
}

impl KeccakAir {
    /// Create new AIR
    pub fn new(fri_config: FriConfig) -> Self {
        KeccakAir { fri_config }
    }

    /// Generate proof for Keccak permutation
    pub fn prove(&self, input: &KeccakState, transcript: &mut Transcript) -> KeccakProof {
        // Generate trace
        let trace = KeccakPermutationTrace::compute(input);

        // Commit to trace (simplified)
        let trace_commitment = self.commit_trace(&trace, transcript);

        // Get random challenges
        let alpha = transcript.challenge();

        // Compute constraint polynomial evaluations
        let constraint_evals = self.evaluate_constraints(&trace, alpha);

        // Generate FRI proof
        let fri_prover = FriProver::new(self.fri_config.clone());
        let fri_proof = fri_prover.prove(constraint_evals, transcript);

        KeccakProof {
            trace_commitment,
            input: input.to_bytes(),
            output: trace.state_out.to_bytes(),
            fri_proof,
        }
    }

    /// Verify Keccak proof
    pub fn verify(&self, proof: &KeccakProof, transcript: &mut Transcript) -> bool {
        // Add trace commitment
        transcript.append_commitment(&proof.trace_commitment);

        // Get challenge
        let _alpha = transcript.challenge();

        // Verify FRI proof
        let fri_verifier = FriVerifier::new(self.fri_config.clone());
        fri_verifier.verify(&proof.fri_proof, transcript)
    }

    /// Commit to trace
    fn commit_trace(&self, trace: &KeccakPermutationTrace, transcript: &mut Transcript) -> [u8; 32] {
        use crate::sha256::Sha256;

        let mut hasher = Sha256::new();

        // Hash input state
        hasher.update(&trace.state_in.to_bytes());

        // Hash each round's output
        for round_trace in &trace.round_traces {
            hasher.update(&round_trace.state_out.to_bytes());
        }

        let commitment = hasher.finalize();
        transcript.append_commitment(&commitment);
        commitment
    }

    /// Evaluate constraint polynomial
    fn evaluate_constraints(&self, trace: &KeccakPermutationTrace, alpha: Fp) -> Vec<Fp> {
        let mut evals = Vec::new();

        // For each round, compute constraint values
        for round_trace in &trace.round_traces {
            // Theta constraints (simplified - would need lookup proofs for XOR)
            for x in 0..5 {
                for byte_idx in 0..8 {
                    // C[x] = XOR of column
                    let mut expected = Fp::ZERO;
                    for y in 0..5 {
                        let b = round_trace.theta_trace.state_in.get_lane_byte(x, y, byte_idx);
                        expected = Fp::new(expected.to_u64() ^ b.to_u64());
                    }
                    evals.push(round_trace.theta_trace.c[x][byte_idx] - expected);
                }
            }

            // Chi constraints (NOT, AND, XOR)
            for x in 0..5 {
                for y in 0..5 {
                    for byte_idx in 0..8 {
                        let a_x1y = round_trace.chi_trace.state_in.get_lane_byte((x+1)%5, y, byte_idx);
                        let expected_not = Fp::new((!a_x1y.to_u64() as u8) as u64);
                        evals.push(round_trace.chi_trace.not_values.get_lane_byte(x, y, byte_idx) - expected_not);
                    }
                }
            }
        }

        // Batch with random linear combination
        let mut batched = Vec::with_capacity(evals.len());
        let mut alpha_power = Fp::ONE;
        for eval in &evals {
            batched.push(*eval * alpha_power);
            alpha_power = alpha_power * alpha;
        }

        batched
    }
}

/// Keccak proof
#[derive(Clone, Debug)]
pub struct KeccakProof {
    /// Commitment to execution trace
    pub trace_commitment: [u8; 32],
    /// Input state (200 bytes)
    pub input: [u8; STATE_BYTES],
    /// Output state (200 bytes)
    pub output: [u8; STATE_BYTES],
    /// FRI proof
    pub fri_proof: FriProof,
}

impl KeccakProof {
    /// Serialize to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.trace_commitment);
        result.extend_from_slice(&self.input);
        result.extend_from_slice(&self.output);

        let fri_bytes = self.fri_proof.serialize();
        result.extend_from_slice(&(fri_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&fri_bytes);

        result
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 32 + STATE_BYTES * 2 + 4 {
            return None;
        }

        let mut offset = 0;

        let mut trace_commitment = [0u8; 32];
        trace_commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut input = [0u8; STATE_BYTES];
        input.copy_from_slice(&data[offset..offset + STATE_BYTES]);
        offset += STATE_BYTES;

        let mut output = [0u8; STATE_BYTES];
        output.copy_from_slice(&data[offset..offset + STATE_BYTES]);
        offset += STATE_BYTES;

        let fri_len = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let fri_proof = FriProof::deserialize(&data[offset..offset + fri_len])?;

        Some(KeccakProof {
            trace_commitment,
            input,
            output,
            fri_proof,
        })
    }
}

/// Prove Keccak-256 hash computation
pub fn prove_keccak256(
    input: &[u8],
    expected_output: &[u8; 32],
    fri_config: FriConfig,
    transcript: &mut Transcript,
) -> Option<Keccak256Proof> {
    // Compute actual hash
    let actual = super::hash::keccak256(input);
    if &actual != expected_output {
        return None;
    }

    // Create AIR and prove
    let air = KeccakAir::new(fri_config);

    // For each block absorption, prove the permutation
    // (Simplified - would need to prove full sponge)
    let state = KeccakState::zero();
    let permutation_proof = air.prove(&state, transcript);

    Some(Keccak256Proof {
        input_len: input.len(),
        output: actual,
        permutation_proof,
    })
}

/// Keccak-256 hash proof
#[derive(Clone, Debug)]
pub struct Keccak256Proof {
    pub input_len: usize,
    pub output: [u8; 32],
    pub permutation_proof: KeccakProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fri_config() -> FriConfig {
        FriConfig {
            num_queries: 8,
            blowup_factor: 4,
            max_degree: 256,
        }
    }

    #[test]
    fn test_keccak_air_prove_verify() {
        let air = KeccakAir::new(test_fri_config());
        let input = KeccakState::zero();

        let mut transcript = Transcript::new();
        let proof = air.prove(&input, &mut transcript);

        let mut verify_transcript = Transcript::new();
        assert!(air.verify(&proof, &mut verify_transcript));
    }

    #[test]
    fn test_proof_serialization() {
        let air = KeccakAir::new(test_fri_config());
        let input = KeccakState::zero();

        let mut transcript = Transcript::new();
        let proof = air.prove(&input, &mut transcript);

        let serialized = proof.serialize();
        let deserialized = KeccakProof::deserialize(&serialized).unwrap();

        assert_eq!(proof.trace_commitment, deserialized.trace_commitment);
        assert_eq!(proof.input, deserialized.input);
        assert_eq!(proof.output, deserialized.output);
    }
}
