//! secp256k1 ECDSA Verification Machine (M_SECP256K1_ECDSA_VERIFY)
//!
//! Proves ECDSA signature verification on the secp256k1 curve.

use super::{Machine, MachineId};
use crate::secp256k1::{verify_ecdsa, ECDSASignature, ECDSAPublicKey};

/// secp256k1 ECDSA verification machine
pub struct Secp256k1Machine {
    /// Public key
    pub public_key: Option<ECDSAPublicKey>,
    /// Message hash (32 bytes)
    pub message_hash: [u8; 32],
    /// Signature
    pub signature: Option<ECDSASignature>,
}

impl Secp256k1Machine {
    /// Create a new secp256k1 verification machine
    pub fn new(public_key: ECDSAPublicKey, message_hash: [u8; 32], signature: ECDSASignature) -> Self {
        Self {
            public_key: Some(public_key),
            message_hash,
            signature: Some(signature),
        }
    }

    /// Create from raw bytes (compressed public key)
    pub fn from_bytes_compressed(
        public_key: [u8; 33],
        message_hash: [u8; 32],
        signature: [u8; 64],
    ) -> Self {
        Self {
            public_key: ECDSAPublicKey::from_compressed(&public_key),
            message_hash,
            signature: ECDSASignature::from_bytes(&signature),
        }
    }

    /// Create from raw bytes (uncompressed public key - 65 bytes with 0x04 prefix)
    pub fn from_bytes_uncompressed(
        public_key: [u8; 65],
        message_hash: [u8; 32],
        signature: [u8; 64],
    ) -> Self {
        Self {
            public_key: ECDSAPublicKey::from_uncompressed(&public_key),
            message_hash,
            signature: ECDSASignature::from_bytes(&signature),
        }
    }

    /// Verify the signature
    pub fn verify(&self) -> bool {
        match (&self.public_key, &self.signature) {
            (Some(pk), Some(sig)) => verify_ecdsa(pk, &self.message_hash, sig),
            _ => false,
        }
    }

    /// Compute verification (returns result)
    pub fn compute(&self) -> bool {
        self.verify()
    }

    /// Number of scalar multiplications needed
    pub fn num_scalar_muls(&self) -> usize {
        // u1*G and u2*Q
        2
    }

    /// Check if keys and signature are valid
    pub fn is_valid(&self) -> bool {
        self.public_key.is_some() && self.signature.is_some()
    }

    /// Verify witness inverse: s * w ≡ 1 (mod n)
    pub fn check_witness_inverse(&self) -> bool {
        // This would verify that the witness inverse w = s^(-1) is correct
        // For proof generation, this is a constraint that must hold
        true // Placeholder - actual implementation in proof system
    }
}

impl Machine for Secp256k1Machine {
    fn machine_id(&self) -> MachineId {
        MachineId::Secp256k1EcdsaVerify
    }

    fn input_type(&self) -> &'static str {
        "(pk: [u8; 33|65], msg_hash: [u8; 32], sig: [u8; 64])"
    }

    fn output_type(&self) -> &'static str {
        "valid: bool"
    }

    fn estimated_cycles(&self) -> u64 {
        // ~300k cycles per scalar multiplication on secp256k1
        (self.num_scalar_muls() as u64) * 300_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256k1_machine_creation() {
        // Create with zeros - will fail validation but tests structure
        let pk = [2u8; 33]; // Invalid but tests structure
        let sig = [0u8; 64];
        let machine = Secp256k1Machine::from_bytes_compressed(pk, [0u8; 32], sig);

        assert_eq!(machine.machine_id(), MachineId::Secp256k1EcdsaVerify);
        assert_eq!(machine.num_scalar_muls(), 2);
    }

    #[test]
    fn test_secp256k1_estimated_cycles() {
        let pk = [2u8; 33];
        let sig = [0u8; 64];
        let machine = Secp256k1Machine::from_bytes_compressed(pk, [0u8; 32], sig);

        assert_eq!(machine.estimated_cycles(), 600_000);
    }

    #[test]
    fn test_from_bytes_compressed() {
        let machine = Secp256k1Machine::from_bytes_compressed(
            [2u8; 33],
            [0u8; 32],
            [1u8; 64],
        );
        assert_eq!(machine.message_hash, [0u8; 32]);
    }

    #[test]
    fn test_from_bytes_uncompressed() {
        let mut pk = [0u8; 65];
        pk[0] = 0x04; // Uncompressed prefix
        let machine = Secp256k1Machine::from_bytes_uncompressed(
            pk,
            [0u8; 32],
            [1u8; 64],
        );
        assert_eq!(machine.message_hash, [0u8; 32]);
    }
}
