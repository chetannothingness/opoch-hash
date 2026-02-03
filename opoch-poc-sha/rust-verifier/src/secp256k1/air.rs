//! ECDSA Verification AIR
//!
//! Algebraic constraints for proving ECDSA signature verification.

use crate::field::Fp;
use crate::fri::{FriConfig, FriProof, FriProver, FriVerifier};
use crate::transcript::Transcript;

use super::point::JacobianPoint;
use super::scalar_mul::ScalarMulTrace;
use super::ecdsa::{ECDSASignature, ECDSAPublicKey, verify_ecdsa_detailed, ECDSAVerifyResult};
use crate::bigint::U256Limbs;

/// ECDSA verification AIR
pub struct ECDSAAir {
    fri_config: FriConfig,
}

impl ECDSAAir {
    /// Create new AIR
    pub fn new(fri_config: FriConfig) -> Self {
        ECDSAAir { fri_config }
    }

    /// Prove ECDSA verification
    pub fn prove(
        &self,
        public_key: &ECDSAPublicKey,
        message_hash: &[u8; 32],
        signature: &ECDSASignature,
        transcript: &mut Transcript,
    ) -> Option<ECDSAProof> {
        // Verify the signature first
        let verify_result = verify_ecdsa_detailed(public_key, message_hash, signature);
        if !verify_result.valid {
            return None;
        }

        // Generate traces for scalar multiplications
        let g = JacobianPoint::generator();
        let u1g_trace = ScalarMulTrace::compute(&g, &verify_result.u1);

        let q = public_key.point.to_jacobian();
        let u2q_trace = ScalarMulTrace::compute(&q, &verify_result.u2);

        // Commit to traces
        let trace_commitment = self.commit_traces(&u1g_trace, &u2q_trace, transcript);

        // Get challenge
        let alpha = transcript.challenge();

        // Compute constraint evaluations
        let constraint_evals = self.evaluate_constraints(&u1g_trace, &u2q_trace, alpha);

        // Generate FRI proof
        let fri_prover = FriProver::new(self.fri_config.clone());
        let fri_proof = fri_prover.prove(constraint_evals, transcript);

        Some(ECDSAProof {
            trace_commitment,
            public_key_bytes: public_key.to_uncompressed(),
            message_hash: *message_hash,
            signature_bytes: signature.to_bytes(),
            w_witness: verify_result.w,
            fri_proof,
        })
    }

    /// Verify ECDSA proof
    pub fn verify(&self, proof: &ECDSAProof, transcript: &mut Transcript) -> bool {
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
        u1g_trace: &ScalarMulTrace,
        u2q_trace: &ScalarMulTrace,
        transcript: &mut Transcript,
    ) -> [u8; 32] {
        use crate::sha256::Sha256;

        let mut hasher = Sha256::new();

        // Hash scalar multiplication results
        let u1g_affine = u1g_trace.result.to_affine();
        hasher.update(&u1g_affine.to_uncompressed());

        let u2q_affine = u2q_trace.result.to_affine();
        hasher.update(&u2q_affine.to_uncompressed());

        let commitment = hasher.finalize();
        transcript.append_commitment(&commitment);
        commitment
    }

    /// Evaluate constraint polynomial
    fn evaluate_constraints(
        &self,
        u1g_trace: &ScalarMulTrace,
        u2q_trace: &ScalarMulTrace,
        alpha: Fp,
    ) -> Vec<Fp> {
        let mut evals = Vec::new();

        // Simplified constraints - real AIR would include:
        // 1. Inverse verification: s * w ≡ 1 (mod n)
        // 2. u1 = z * w (mod n)
        // 3. u2 = r * w (mod n)
        // 4. Scalar multiplication constraints
        // 5. Point addition constraints
        // 6. Final x-coordinate check

        // Placeholder constraints
        for _ in 0..u1g_trace.intermediates.len() {
            evals.push(Fp::ZERO);
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
}

/// ECDSA verification proof
#[derive(Clone, Debug)]
pub struct ECDSAProof {
    pub trace_commitment: [u8; 32],
    pub public_key_bytes: [u8; 65],
    pub message_hash: [u8; 32],
    pub signature_bytes: [u8; 64],
    /// Witness for s⁻¹ mod n
    pub w_witness: U256Limbs,
    pub fri_proof: FriProof,
}

impl ECDSAProof {
    /// Serialize to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.trace_commitment);
        result.extend_from_slice(&self.public_key_bytes);
        result.extend_from_slice(&self.message_hash);
        result.extend_from_slice(&self.signature_bytes);
        result.extend_from_slice(&self.w_witness.to_bytes_be());

        let fri_bytes = self.fri_proof.serialize();
        result.extend_from_slice(&(fri_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&fri_bytes);

        result
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 32 + 65 + 32 + 64 + 32 + 4 {
            return None;
        }

        let mut offset = 0;

        let mut trace_commitment = [0u8; 32];
        trace_commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut public_key_bytes = [0u8; 65];
        public_key_bytes.copy_from_slice(&data[offset..offset + 65]);
        offset += 65;

        let mut message_hash = [0u8; 32];
        message_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut signature_bytes = [0u8; 64];
        signature_bytes.copy_from_slice(&data[offset..offset + 64]);
        offset += 64;

        let mut w_bytes = [0u8; 32];
        w_bytes.copy_from_slice(&data[offset..offset + 32]);
        let w_witness = U256Limbs::from_bytes_be(&w_bytes);
        offset += 32;

        let fri_len = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let fri_proof = FriProof::deserialize(&data[offset..offset + fri_len])?;

        Some(ECDSAProof {
            trace_commitment,
            public_key_bytes,
            message_hash,
            signature_bytes,
            w_witness,
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
        // Create a dummy proof
        let proof = ECDSAProof {
            trace_commitment: [1u8; 32],
            public_key_bytes: [2u8; 65],
            message_hash: [3u8; 32],
            signature_bytes: [4u8; 64],
            w_witness: U256Limbs::from_u64(12345),
            fri_proof: FriProof::default(),
        };

        let serialized = proof.serialize();
        let deserialized = ECDSAProof::deserialize(&serialized);

        assert!(deserialized.is_some());
        let recovered = deserialized.unwrap();
        assert_eq!(proof.trace_commitment, recovered.trace_commitment);
        assert_eq!(proof.public_key_bytes, recovered.public_key_bytes);
    }
}
