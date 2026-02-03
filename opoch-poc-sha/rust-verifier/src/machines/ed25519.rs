//! Ed25519 Verification Machine (M_ED25519_VERIFY)
//!
//! Proves EdDSA signature verification: [S]B = R + [h]A

use super::{Machine, MachineId};
use crate::ed25519::{verify_eddsa, EdDSASignature, EdDSAPublicKey};

/// Ed25519 signature verification machine
pub struct Ed25519Machine {
    /// Public key
    pub public_key: Option<EdDSAPublicKey>,
    /// Message to verify
    pub message: Vec<u8>,
    /// Signature
    pub signature: Option<EdDSASignature>,
}

impl Ed25519Machine {
    /// Create a new Ed25519 verification machine
    pub fn new(public_key: EdDSAPublicKey, message: &[u8], signature: EdDSASignature) -> Self {
        Self {
            public_key: Some(public_key),
            message: message.to_vec(),
            signature: Some(signature),
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(
        public_key: [u8; 32],
        message: &[u8],
        signature: [u8; 64],
    ) -> Self {
        Self {
            public_key: EdDSAPublicKey::from_bytes(&public_key),
            message: message.to_vec(),
            signature: EdDSASignature::from_bytes(&signature),
        }
    }

    /// Verify the signature
    pub fn verify(&self) -> bool {
        match (&self.public_key, &self.signature) {
            (Some(pk), Some(sig)) => verify_eddsa(pk, &self.message, sig),
            _ => false,
        }
    }

    /// Compute verification (returns result)
    pub fn compute(&self) -> bool {
        self.verify()
    }

    /// Number of scalar multiplications needed
    pub fn num_scalar_muls(&self) -> usize {
        // [S]B and [h]A, plus point addition
        2
    }

    /// Check if keys and signature are valid
    pub fn is_valid(&self) -> bool {
        self.public_key.is_some() && self.signature.is_some()
    }
}

impl Machine for Ed25519Machine {
    fn machine_id(&self) -> MachineId {
        MachineId::Ed25519Verify
    }

    fn input_type(&self) -> &'static str {
        "(pk: [u8; 32], msg: Vec<u8>, sig: [u8; 64])"
    }

    fn output_type(&self) -> &'static str {
        "valid: bool"
    }

    fn estimated_cycles(&self) -> u64 {
        // ~200k cycles per scalar multiplication on Ed25519
        (self.num_scalar_muls() as u64) * 200_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_machine_creation() {
        let machine = Ed25519Machine::from_bytes(
            [0u8; 32],
            b"test message",
            [0u8; 64],
        );

        assert_eq!(machine.machine_id(), MachineId::Ed25519Verify);
        assert_eq!(machine.num_scalar_muls(), 2);
    }

    #[test]
    fn test_ed25519_machine_estimated_cycles() {
        let machine = Ed25519Machine::from_bytes(
            [0u8; 32],
            b"message",
            [0u8; 64],
        );

        assert_eq!(machine.estimated_cycles(), 400_000);
    }

    #[test]
    fn test_from_bytes() {
        let machine = Ed25519Machine::from_bytes(
            [1u8; 32],
            b"hello",
            [2u8; 64],
        );
        assert_eq!(machine.message, b"hello");
    }
}
