//! EdDSA Verification AIR
//!
//! Algebraic constraints for proving EdDSA signature verification.

use crate::field::Fp;
use crate::fri::{FriConfig, FriProof, FriProver, FriVerifier};
use crate::transcript::Transcript;

use super::point::EdwardsPoint;
use super::scalar_mul::ScalarMulTrace;
use super::eddsa::{EdDSASignature, EdDSAPublicKey, verify_eddsa_detailed, EdDSAVerifyResult};
use crate::bigint::U256Limbs;

/// EdDSA verification AIR
pub struct EdDSAAir {
    fri_config: FriConfig,
}

impl EdDSAAir {
    /// Create new AIR
    pub fn new(fri_config: FriConfig) -> Self {
        EdDSAAir { fri_config }
    }

    /// Prove EdDSA verification
    pub fn prove(
        &self,
        public_key: &EdDSAPublicKey,
        message: &[u8],
        signature: &EdDSASignature,
        transcript: &mut Transcript,
    ) -> Option<EdDSAProof> {
        // Verify the signature first
        let verify_result = verify_eddsa_detailed(public_key, message, signature);
        if !verify_result.valid {
            return None;
        }

        // Generate traces for scalar multiplications
        let b = EdwardsPoint::base_point();
        let sb_trace = ScalarMulTrace::compute(&b, &signature.s);

        let a_ext = public_key.point.to_extended();
        let ha_trace = ScalarMulTrace::compute(&a_ext, &verify_result.h);

        // Commit to traces
        let trace_commitment = self.commit_traces(&sb_trace, &ha_trace, transcript);

        // Get challenge
        let alpha = transcript.challenge();

        // Compute constraint evaluations
        let constraint_evals = self.evaluate_constraints(&sb_trace, &ha_trace, alpha);

        // Generate FRI proof
        let fri_prover = FriProver::new(self.fri_config.clone());
        let fri_proof = fri_prover.prove(constraint_evals, transcript);

        Some(EdDSAProof {
            trace_commitment,
            public_key_bytes: public_key.to_bytes(),
            signature_bytes: signature.to_bytes(),
            message_hash: self.hash_message(message),
            fri_proof,
        })
    }

    /// Verify EdDSA proof
    pub fn verify(&self, proof: &EdDSAProof, transcript: &mut Transcript) -> bool {
        // Add trace commitment
        transcript.append_commitment(&proof.trace_commitment);

        // Get challenge
        let _alpha = transcript.challenge();

        // Verify FRI proof
        let fri_verifier = FriVerifier::new(self.fri_config.clone());
        fri_verifier.verify(&proof.fri_proof, transcript)
    }

    /// Commit to computation traces
    fn commit_traces(
        &self,
        sb_trace: &ScalarMulTrace,
        ha_trace: &ScalarMulTrace,
        transcript: &mut Transcript,
    ) -> [u8; 32] {
        use crate::sha256::Sha256;

        let mut hasher = Sha256::new();

        // Hash scalar multiplication results
        let sb_affine = sb_trace.result.to_affine();
        hasher.update(&sb_affine.to_bytes());

        let ha_affine = ha_trace.result.to_affine();
        hasher.update(&ha_affine.to_bytes());

        let commitment = hasher.finalize();
        transcript.append_commitment(&commitment);
        commitment
    }

    /// Evaluate constraint polynomial
    fn evaluate_constraints(
        &self,
        sb_trace: &ScalarMulTrace,
        ha_trace: &ScalarMulTrace,
        alpha: Fp,
    ) -> Vec<Fp> {
        let mut evals = Vec::new();

        // Simplified: just check that intermediates are consistent
        // Real AIR would include full point addition constraints

        // Scalar mul consistency: each step is either double or double-and-add
        for i in 1..sb_trace.intermediates.len() {
            // Constraint: intermediate[i] is valid given intermediate[i-1]
            // This is complex to express algebraically without full point coords
            evals.push(Fp::ZERO); // Placeholder
        }

        // Batch with random linear combination
        let mut batched = Vec::new();
        let mut alpha_power = Fp::ONE;
        for eval in &evals {
            batched.push(*eval * alpha_power);
            alpha_power = alpha_power * alpha;
        }

        batched
    }

    /// Hash message for proof
    fn hash_message(&self, message: &[u8]) -> [u8; 32] {
        crate::sha256::Sha256::hash(message)
    }
}

/// EdDSA verification proof
#[derive(Clone, Debug)]
pub struct EdDSAProof {
    pub trace_commitment: [u8; 32],
    pub public_key_bytes: [u8; 32],
    pub signature_bytes: [u8; 64],
    pub message_hash: [u8; 32],
    pub fri_proof: FriProof,
}

impl EdDSAProof {
    /// Serialize to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.trace_commitment);
        result.extend_from_slice(&self.public_key_bytes);
        result.extend_from_slice(&self.signature_bytes);
        result.extend_from_slice(&self.message_hash);

        let fri_bytes = self.fri_proof.serialize();
        result.extend_from_slice(&(fri_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&fri_bytes);

        result
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 32 + 32 + 64 + 32 + 4 {
            return None;
        }

        let mut offset = 0;

        let mut trace_commitment = [0u8; 32];
        trace_commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut public_key_bytes = [0u8; 32];
        public_key_bytes.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut signature_bytes = [0u8; 64];
        signature_bytes.copy_from_slice(&data[offset..offset + 64]);
        offset += 64;

        let mut message_hash = [0u8; 32];
        message_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let fri_len = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let fri_proof = FriProof::deserialize(&data[offset..offset + fri_len])?;

        Some(EdDSAProof {
            trace_commitment,
            public_key_bytes,
            signature_bytes,
            message_hash,
            fri_proof,
        })
    }

    /// Size in bytes
    pub fn size(&self) -> usize {
        self.serialize().len()
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
    fn test_proof_serialization() {
        // Create a dummy proof (without actual verification)
        let proof = EdDSAProof {
            trace_commitment: [1u8; 32],
            public_key_bytes: [2u8; 32],
            signature_bytes: [3u8; 64],
            message_hash: [4u8; 32],
            fri_proof: FriProof::default(),
        };

        let serialized = proof.serialize();
        let deserialized = EdDSAProof::deserialize(&serialized);

        assert!(deserialized.is_some());
        let recovered = deserialized.unwrap();
        assert_eq!(proof.trace_commitment, recovered.trace_commitment);
        assert_eq!(proof.public_key_bytes, recovered.public_key_bytes);
    }
}
