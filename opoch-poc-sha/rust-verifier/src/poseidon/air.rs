//! Poseidon AIR Constraints
//!
//! Algebraic Intermediate Representation for Poseidon hash.

use crate::field::Fp;
use crate::fri::{FriConfig, FriProof, FriProver, FriVerifier};
use crate::transcript::Transcript;

use super::constants::{POSEIDON_T, POSEIDON_RF, POSEIDON_RP, POSEIDON_TOTAL_ROUNDS};
use super::round::{FullRoundTrace, PartialRoundTrace};
use super::sbox::SboxIntermediates;
use super::PoseidonState;

/// Number of trace columns for Poseidon AIR
///
/// State: 12 columns
/// S-box intermediates for full round: 12 * 4 = 48 columns
/// S-box intermediates for partial round: 4 columns
/// Total per full round: 12 + 48 = 60
/// Total per partial round: 12 + 4 = 16
///
/// Simplified: We use a fixed trace width and iterate
pub const POSEIDON_TRACE_WIDTH: usize = POSEIDON_T + 4 * POSEIDON_T; // State + all possible intermediates

/// Poseidon execution trace row
#[derive(Clone, Debug)]
pub struct PoseidonTraceRow {
    /// Current state
    pub state: [Fp; POSEIDON_T],
    /// S-box intermediates (x2, x3, x6, x7) for each element
    /// In partial rounds, only element 0 has valid intermediates
    pub sbox_intermediates: [[Fp; 4]; POSEIDON_T],
    /// Round number
    pub round: usize,
    /// Is full round
    pub is_full_round: bool,
}

impl PoseidonTraceRow {
    /// Create from full round trace
    pub fn from_full_round(trace: &FullRoundTrace, round: usize) -> Self {
        let mut sbox_intermediates = [[Fp::ZERO; 4]; POSEIDON_T];
        for i in 0..POSEIDON_T {
            sbox_intermediates[i] = [
                trace.sbox_intermediates[i].x2,
                trace.sbox_intermediates[i].x3,
                trace.sbox_intermediates[i].x6,
                trace.sbox_intermediates[i].x7,
            ];
        }

        PoseidonTraceRow {
            state: trace.state_in.elements,
            sbox_intermediates,
            round,
            is_full_round: true,
        }
    }

    /// Create from partial round trace
    pub fn from_partial_round(trace: &PartialRoundTrace, round: usize) -> Self {
        let mut sbox_intermediates = [[Fp::ZERO; 4]; POSEIDON_T];
        sbox_intermediates[0] = [
            trace.sbox_intermediate.x2,
            trace.sbox_intermediate.x3,
            trace.sbox_intermediate.x6,
            trace.sbox_intermediate.x7,
        ];

        PoseidonTraceRow {
            state: trace.state_in.elements,
            sbox_intermediates,
            round,
            is_full_round: false,
        }
    }
}

/// Complete Poseidon execution trace
#[derive(Clone, Debug)]
pub struct PoseidonTrace {
    /// Rows of the trace
    pub rows: Vec<PoseidonTraceRow>,
    /// Final output state
    pub output: PoseidonState,
}

impl PoseidonTrace {
    /// Generate trace for a Poseidon permutation
    pub fn generate(input: &PoseidonState) -> Self {
        let mut rows = Vec::with_capacity(POSEIDON_TOTAL_ROUNDS);
        let mut state = input.clone();

        // First 4 full rounds
        for r in 0..POSEIDON_RF / 2 {
            let trace = FullRoundTrace::compute(&state, r);
            rows.push(PoseidonTraceRow::from_full_round(&trace, r));
            state = trace.state_out;
        }

        // 22 partial rounds
        for r in 0..POSEIDON_RP {
            let round_num = POSEIDON_RF / 2 + r;
            let trace = PartialRoundTrace::compute(&state, round_num);
            rows.push(PoseidonTraceRow::from_partial_round(&trace, round_num));
            state = trace.state_out;
        }

        // Last 4 full rounds
        for r in 0..POSEIDON_RF / 2 {
            let round_num = POSEIDON_RF / 2 + POSEIDON_RP + r;
            let trace = FullRoundTrace::compute(&state, round_num);
            rows.push(PoseidonTraceRow::from_full_round(&trace, round_num));
            state = trace.state_out;
        }

        PoseidonTrace {
            rows,
            output: state,
        }
    }
}

/// Poseidon AIR
pub struct PoseidonAir {
    /// FRI configuration
    fri_config: FriConfig,
}

impl PoseidonAir {
    /// Create new AIR
    pub fn new(fri_config: FriConfig) -> Self {
        PoseidonAir { fri_config }
    }

    /// Generate proof for Poseidon computation
    pub fn prove(&self, input: &PoseidonState, transcript: &mut Transcript) -> PoseidonProof {
        // Generate trace
        let trace = PoseidonTrace::generate(input);

        // Commit to trace columns
        let trace_commitment = self.commit_trace(&trace, transcript);

        // Get random challenges for constraint batching
        let alpha = transcript.challenge();

        // Compute constraint polynomial
        let constraint_evals = self.evaluate_constraints(&trace, alpha);

        // Generate FRI proof
        let fri_prover = FriProver::new(self.fri_config.clone());
        let fri_proof = fri_prover.prove(constraint_evals, transcript);

        PoseidonProof {
            trace_commitment,
            input: input.elements,
            output: trace.output.elements,
            fri_proof,
        }
    }

    /// Verify Poseidon proof
    pub fn verify(&self, proof: &PoseidonProof, transcript: &mut Transcript) -> bool {
        // Add trace commitment
        transcript.append_commitment(&proof.trace_commitment);

        // Get challenge (must match prover)
        let _alpha = transcript.challenge();

        // Verify FRI proof
        let fri_verifier = FriVerifier::new(self.fri_config.clone());
        fri_verifier.verify(&proof.fri_proof, transcript)
    }

    /// Commit to trace (simplified - real impl uses Merkle tree)
    fn commit_trace(&self, trace: &PoseidonTrace, transcript: &mut Transcript) -> [u8; 32] {
        use crate::sha256::Sha256;

        // Hash all trace data
        let mut hasher = Sha256::new();

        for row in &trace.rows {
            for &elem in &row.state {
                hasher.update(&elem.to_bytes());
            }
            for inter in &row.sbox_intermediates {
                for &elem in inter {
                    hasher.update(&elem.to_bytes());
                }
            }
        }

        let commitment = hasher.finalize();
        transcript.append_commitment(&commitment);
        commitment
    }

    /// Evaluate constraint polynomial at all points
    fn evaluate_constraints(&self, trace: &PoseidonTrace, alpha: Fp) -> Vec<Fp> {
        let mut evals = Vec::new();

        // For each row, compute constraint values
        for (i, row) in trace.rows.iter().enumerate() {
            // S-box constraints
            for j in 0..POSEIDON_T {
                if row.is_full_round || j == 0 {
                    // x + rc should go through S-box
                    let x = row.state[j] + super::constants::rc(row.round, j);
                    let [x2, x3, x6, x7] = row.sbox_intermediates[j];

                    // x2 = x * x
                    evals.push(x2 - x * x);
                    // x3 = x2 * x
                    evals.push(x3 - x2 * x);
                    // x6 = x3 * x3
                    evals.push(x6 - x3 * x3);
                    // x7 = x6 * x
                    evals.push(x7 - x6 * x);
                }
            }

            // MDS constraint: next_state = MDS * sbox_output
            // (Would need next row - simplified here)
        }

        // Batch constraints with random linear combination
        let mut batched = Vec::with_capacity(evals.len());
        let mut alpha_power = Fp::ONE;
        for eval in &evals {
            batched.push(*eval * alpha_power);
            alpha_power = alpha_power * alpha;
        }

        batched
    }
}

/// Poseidon proof
#[derive(Clone, Debug)]
pub struct PoseidonProof {
    /// Commitment to execution trace
    pub trace_commitment: [u8; 32],
    /// Input state
    pub input: [Fp; POSEIDON_T],
    /// Output state
    pub output: [Fp; POSEIDON_T],
    /// FRI proof for constraint polynomial
    pub fri_proof: FriProof,
}

impl PoseidonProof {
    /// Serialize to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.trace_commitment);

        for &elem in &self.input {
            result.extend_from_slice(&elem.to_bytes());
        }
        for &elem in &self.output {
            result.extend_from_slice(&elem.to_bytes());
        }

        let fri_bytes = self.fri_proof.serialize();
        result.extend_from_slice(&(fri_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&fri_bytes);

        result
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 32 + 8 * POSEIDON_T * 2 + 4 {
            return None;
        }

        let mut offset = 0;

        let mut trace_commitment = [0u8; 32];
        trace_commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut input = [Fp::ZERO; POSEIDON_T];
        for i in 0..POSEIDON_T {
            input[i] = Fp::from_bytes(&data[offset..offset + 8]);
            offset += 8;
        }

        let mut output = [Fp::ZERO; POSEIDON_T];
        for i in 0..POSEIDON_T {
            output[i] = Fp::from_bytes(&data[offset..offset + 8]);
            offset += 8;
        }

        let fri_len = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let fri_proof = FriProof::deserialize(&data[offset..offset + fri_len])?;

        Some(PoseidonProof {
            trace_commitment,
            input,
            output,
            fri_proof,
        })
    }
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
    fn test_trace_generation() {
        let input = PoseidonState::zero();
        let trace = PoseidonTrace::generate(&input);

        assert_eq!(trace.rows.len(), POSEIDON_TOTAL_ROUNDS);
    }

    #[test]
    fn test_poseidon_air_prove_verify() {
        let air = PoseidonAir::new(test_fri_config());

        let mut input = PoseidonState::zero();
        input.elements[0] = Fp::new(1);
        input.elements[1] = Fp::new(2);

        let mut transcript = Transcript::new();
        let proof = air.prove(&input, &mut transcript);

        let mut verify_transcript = Transcript::new();
        assert!(air.verify(&proof, &mut verify_transcript));
    }

    #[test]
    fn test_proof_serialization() {
        let air = PoseidonAir::new(test_fri_config());
        let input = PoseidonState::zero();

        let mut transcript = Transcript::new();
        let proof = air.prove(&input, &mut transcript);

        let serialized = proof.serialize();
        let deserialized = PoseidonProof::deserialize(&serialized).unwrap();

        assert_eq!(proof.trace_commitment, deserialized.trace_commitment);
        for i in 0..POSEIDON_T {
            assert_eq!(proof.input[i], deserialized.input[i]);
            assert_eq!(proof.output[i], deserialized.output[i]);
        }
    }
}
