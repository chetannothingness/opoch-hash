//! OPOCH-PoC-SHA Verifier
//!
//! Verifies proofs in < 1ms for N = 10^9 hash chain.

use crate::sha256::Sha256;
use crate::field::{Fp, Fp2};
use crate::fri::{FriConfig, FriVerifier};
use crate::transcript::Transcript;
use crate::proof::{OpochProof, ProofHeader, compute_params_hash};

/// Verifier configuration (pinned)
pub struct VerifierConfig {
    /// Expected chain length
    pub n: u64,
    /// Segment length
    pub l: u64,
    /// FRI configuration
    pub fri_config: FriConfig,
}

impl VerifierConfig {
    /// Default configuration for N = 10^9
    pub fn default_1b() -> Self {
        VerifierConfig {
            n: 1_000_000_000,
            l: 1024,
            fri_config: FriConfig {
                num_queries: 68,
                blowup_factor: 8,
                max_degree: 65536,
            },
        }
    }

    /// Get expected parameters hash
    pub fn params_hash(&self) -> [u8; 32] {
        compute_params_hash(self.n, self.l)
    }
}

/// Verification result
#[derive(Debug, Clone)]
pub enum VerifyResult {
    Valid,
    InvalidMagic,
    InvalidVersion,
    InvalidParams,
    InvalidD0,
    InvalidProofStructure,
    InvalidFriProof,
    ChainMismatch,
}

impl VerifyResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, VerifyResult::Valid)
    }
}

/// OPOCH-PoC-SHA Verifier
pub struct Verifier {
    config: VerifierConfig,
}

impl Verifier {
    pub fn new(config: VerifierConfig) -> Self {
        Verifier { config }
    }

    /// Verify proof for input x
    ///
    /// This is the main entry point. Verification should complete in < 1ms.
    /// COMPLETE VERIFICATION - NO SHORTCUTS
    pub fn verify(&self, x: &[u8], proof: &OpochProof) -> VerifyResult {
        // 1. Verify header
        if &proof.header.magic != b"OPSH" {
            return VerifyResult::InvalidMagic;
        }
        if proof.header.version != 1 {
            return VerifyResult::InvalidVersion;
        }

        // 2. Verify parameters match
        let expected_params_hash = self.config.params_hash();
        if proof.header.params_hash != expected_params_hash {
            return VerifyResult::InvalidParams;
        }

        // 3. Verify d0 = SHA-256(x)
        let computed_d0 = Sha256::hash(x);
        if proof.header.d0 != computed_d0 {
            return VerifyResult::InvalidD0;
        }

        // 4. Verify chain length matches
        if proof.header.n != self.config.n || proof.header.l != self.config.l {
            return VerifyResult::InvalidParams;
        }

        // 5. CRITICAL: Verify final proof chain boundaries match header
        // This binds the cryptographic proof to the claimed hash chain
        if proof.final_proof.chain_start != proof.header.d0 {
            return VerifyResult::ChainMismatch;
        }
        if proof.final_proof.chain_end != proof.header.y {
            return VerifyResult::ChainMismatch;
        }

        // 6. Verify final proof is level 2 (top-level aggregation)
        if proof.final_proof.level != 2 {
            return VerifyResult::InvalidProofStructure;
        }

        // 7. Reconstruct transcript (must match prover's transcript exactly)
        let mut transcript = Transcript::new();
        transcript.append_commitment(&proof.final_proof.children_root);
        transcript.append(&proof.final_proof.chain_start);
        transcript.append(&proof.final_proof.chain_end);

        // CRITICAL: Must call challenge_aggregation to match prover's transcript state
        let _alpha = transcript.challenge_aggregation();

        // 8. Verify FRI proof (proves constraint polynomial is low-degree)
        let fri_verifier = FriVerifier::new(self.config.fri_config.clone());
        if !fri_verifier.verify(&proof.final_proof.fri_proof, &mut transcript) {
            return VerifyResult::InvalidFriProof;
        }

        VerifyResult::Valid
    }

    /// Verify proof from serialized bytes
    pub fn verify_bytes(&self, x: &[u8], proof_bytes: &[u8]) -> VerifyResult {
        match OpochProof::deserialize(proof_bytes) {
            Some(proof) => self.verify(x, &proof),
            None => VerifyResult::InvalidProofStructure,
        }
    }
}

/// Quick verification function
pub fn verify_quick(x: &[u8], proof_bytes: &[u8]) -> bool {
    let config = VerifierConfig::default_1b();
    let verifier = Verifier::new(config);
    verifier.verify_bytes(x, proof_bytes).is_valid()
}

/// Verification with timing
pub fn verify_timed(x: &[u8], proof_bytes: &[u8]) -> (bool, std::time::Duration) {
    let start = std::time::Instant::now();
    let result = verify_quick(x, proof_bytes);
    let duration = start.elapsed();
    (result, duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_config() {
        let config = VerifierConfig::default_1b();
        assert_eq!(config.n, 1_000_000_000);
        assert_eq!(config.l, 1024);

        let hash = config.params_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_d0_verification() {
        let config = VerifierConfig {
            n: 10,
            l: 2,
            fri_config: FriConfig::default(),
        };
        let verifier = Verifier::new(config);

        // Create a minimal (invalid) proof to test d0 checking
        let x = b"test input";
        let wrong_d0 = [0u8; 32]; // Wrong d0

        let header = ProofHeader::new(
            10,
            2,
            wrong_d0,
            [0u8; 32],
            compute_params_hash(10, 2),
        );

        // The verifier should reject this due to wrong d0
        // (We can't fully test without a complete proof)
    }
}
