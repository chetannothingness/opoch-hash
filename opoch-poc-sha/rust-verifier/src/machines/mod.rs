//! Machine ID Definitions
//!
//! Defines all 7 machine types for the OPOCH proof system.
//!
//! ## Machine Types
//!
//! 1. `PocShaChain` - SHA-256 hash chain computation
//! 2. `Keccak256` - Keccak-256 hash computation
//! 3. `Poseidon` - Poseidon hash (Goldilocks field)
//! 4. `Ed25519Verify` - EdDSA signature verification
//! 5. `Secp256k1EcdsaVerify` - ECDSA signature verification
//! 6. `BigInt256Emu` - 256-bit integer emulation
//! 7. `LookupCore` - Lookup table operations

pub mod poc_sha;
pub mod keccak;
pub mod poseidon;
pub mod ed25519;
pub mod secp256k1;
pub mod bigint;
pub mod lookup;

use serde::{Serialize, Deserialize};

/// Machine identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum MachineId {
    /// SHA-256 hash chain (PoC)
    PocShaChain = 0x0001,
    /// Keccak-256 hash
    Keccak256 = 0x0002,
    /// Poseidon hash
    Poseidon = 0x0003,
    /// Ed25519 signature verification
    Ed25519Verify = 0x0004,
    /// secp256k1 ECDSA verification
    Secp256k1EcdsaVerify = 0x0005,
    /// 256-bit integer emulation
    BigInt256Emu = 0x0006,
    /// Lookup table core
    LookupCore = 0x0007,
}

impl MachineId {
    /// Get the machine ID as bytes
    pub fn to_bytes(self) -> [u8; 2] {
        (self as u16).to_le_bytes()
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 2]) -> Option<Self> {
        let id = u16::from_le_bytes(bytes);
        Self::from_u16(id)
    }

    /// Create from u16
    pub fn from_u16(id: u16) -> Option<Self> {
        match id {
            0x0001 => Some(MachineId::PocShaChain),
            0x0002 => Some(MachineId::Keccak256),
            0x0003 => Some(MachineId::Poseidon),
            0x0004 => Some(MachineId::Ed25519Verify),
            0x0005 => Some(MachineId::Secp256k1EcdsaVerify),
            0x0006 => Some(MachineId::BigInt256Emu),
            0x0007 => Some(MachineId::LookupCore),
            _ => None,
        }
    }

    /// Get the machine name
    pub fn name(&self) -> &'static str {
        match self {
            MachineId::PocShaChain => "POC_SHA_CHAIN",
            MachineId::Keccak256 => "KECCAK256",
            MachineId::Poseidon => "POSEIDON",
            MachineId::Ed25519Verify => "ED25519_VERIFY",
            MachineId::Secp256k1EcdsaVerify => "SECP256K1_ECDSA_VERIFY",
            MachineId::BigInt256Emu => "256BIT_EMU",
            MachineId::LookupCore => "LOOKUP_CORE",
        }
    }

    /// Get description
    pub fn description(&self) -> &'static str {
        match self {
            MachineId::PocShaChain => "SHA-256 hash chain proof of computation",
            MachineId::Keccak256 => "Keccak-256 hash function",
            MachineId::Poseidon => "Poseidon hash over Goldilocks field",
            MachineId::Ed25519Verify => "Ed25519 EdDSA signature verification",
            MachineId::Secp256k1EcdsaVerify => "secp256k1 ECDSA signature verification",
            MachineId::BigInt256Emu => "256-bit integer arithmetic emulation",
            MachineId::LookupCore => "Core lookup table operations",
        }
    }

    /// Get all machine IDs
    pub fn all() -> &'static [MachineId] {
        &[
            MachineId::PocShaChain,
            MachineId::Keccak256,
            MachineId::Poseidon,
            MachineId::Ed25519Verify,
            MachineId::Secp256k1EcdsaVerify,
            MachineId::BigInt256Emu,
            MachineId::LookupCore,
        ]
    }
}

/// Trait for machine implementations
pub trait Machine {
    /// Get the machine ID
    fn machine_id(&self) -> MachineId;

    /// Get the input type description
    fn input_type(&self) -> &'static str;

    /// Get the output type description
    fn output_type(&self) -> &'static str;

    /// Estimated cycles per operation
    fn estimated_cycles(&self) -> u64;
}

/// Machine state for proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineState {
    /// Machine identifier
    pub machine_id: MachineId,
    /// Current step number
    pub step: u64,
    /// Total steps
    pub total_steps: u64,
    /// State hash
    pub state_hash: [u8; 32],
    /// Input commitment
    pub input_commitment: [u8; 32],
    /// Output (if complete)
    pub output: Option<Vec<u8>>,
}

impl MachineState {
    /// Create a new machine state
    pub fn new(machine_id: MachineId, total_steps: u64, input_commitment: [u8; 32]) -> Self {
        Self {
            machine_id,
            step: 0,
            total_steps,
            state_hash: [0u8; 32],
            input_commitment,
            output: None,
        }
    }

    /// Check if computation is complete
    pub fn is_complete(&self) -> bool {
        self.step >= self.total_steps && self.output.is_some()
    }

    /// Progress as a fraction (0.0 to 1.0)
    pub fn progress(&self) -> f64 {
        if self.total_steps == 0 {
            1.0
        } else {
            self.step as f64 / self.total_steps as f64
        }
    }
}

// Re-export machine-specific types
pub use poc_sha::PocShaMachine;
pub use keccak::KeccakMachine;
pub use poseidon::PoseidonMachine;
pub use ed25519::Ed25519Machine;
pub use secp256k1::Secp256k1Machine;
pub use bigint::BigIntMachine;
pub use lookup::LookupMachine;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_id_roundtrip() {
        for &id in MachineId::all() {
            let bytes = id.to_bytes();
            let recovered = MachineId::from_bytes(bytes).expect("should recover");
            assert_eq!(id, recovered);
        }
    }

    #[test]
    fn test_machine_id_values() {
        assert_eq!(MachineId::PocShaChain as u16, 0x0001);
        assert_eq!(MachineId::Keccak256 as u16, 0x0002);
        assert_eq!(MachineId::Poseidon as u16, 0x0003);
        assert_eq!(MachineId::Ed25519Verify as u16, 0x0004);
        assert_eq!(MachineId::Secp256k1EcdsaVerify as u16, 0x0005);
        assert_eq!(MachineId::BigInt256Emu as u16, 0x0006);
        assert_eq!(MachineId::LookupCore as u16, 0x0007);
    }

    #[test]
    fn test_machine_state() {
        let state = MachineState::new(
            MachineId::PocShaChain,
            1000,
            [0u8; 32],
        );
        assert!(!state.is_complete());
        assert_eq!(state.progress(), 0.0);
    }

    #[test]
    fn test_all_machines() {
        assert_eq!(MachineId::all().len(), 7);
    }
}
