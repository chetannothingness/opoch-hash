//! Poseidon Hash Machine (M_POSEIDON)
//!
//! Proves computation of Poseidon hash over the Goldilocks field.

use super::{Machine, MachineId};
use crate::poseidon::poseidon_hash;
use crate::field::Fp;

/// Poseidon hash machine
pub struct PoseidonMachine {
    /// Input field elements
    pub input: Vec<Fp>,
}

impl PoseidonMachine {
    /// Create a new Poseidon machine from field elements
    pub fn new(input: &[Fp]) -> Self {
        Self {
            input: input.to_vec(),
        }
    }

    /// Create from u64 values
    pub fn from_u64(values: &[u64]) -> Self {
        Self {
            input: values.iter().map(|&v| Fp::new(v)).collect(),
        }
    }

    /// Create from bytes (packs into field elements)
    pub fn from_bytes(data: &[u8]) -> Self {
        // Pack 7 bytes per field element (to stay < p)
        let mut elements = Vec::new();
        for chunk in data.chunks(7) {
            let mut value = 0u64;
            for (i, &byte) in chunk.iter().enumerate() {
                value |= (byte as u64) << (i * 8);
            }
            elements.push(Fp::new(value));
        }
        if elements.is_empty() {
            elements.push(Fp::ZERO);
        }
        Self { input: elements }
    }

    /// Compute the Poseidon hash (returns single Fp)
    pub fn compute(&self) -> Fp {
        let result = poseidon_hash(&self.input);
        if result.is_empty() {
            Fp::ZERO
        } else {
            result[0]
        }
    }

    /// Compute and return as bytes
    pub fn compute_bytes(&self) -> [u8; 8] {
        self.compute().to_u64().to_le_bytes()
    }

    /// Number of full/partial rounds
    pub fn num_rounds(&self) -> (usize, usize) {
        // Poseidon with t=12: 4 full rounds before, 4 after, 22 partial
        (8, 22)
    }

    /// Verify a claimed hash
    pub fn verify(input: &[Fp], claimed: Fp) -> bool {
        let machine = PoseidonMachine::new(input);
        machine.compute() == claimed
    }
}

impl Machine for PoseidonMachine {
    fn machine_id(&self) -> MachineId {
        MachineId::Poseidon
    }

    fn input_type(&self) -> &'static str {
        "elements: Vec<Fp>"
    }

    fn output_type(&self) -> &'static str {
        "hash: Fp"
    }

    fn estimated_cycles(&self) -> u64 {
        // ~100 cycles per field multiplication
        // 8 full rounds * 12 muls + 22 partial rounds * 1 mul
        let (full, partial) = self.num_rounds();
        ((full * 12 + partial) as u64) * 100
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_machine_basic() {
        let input = vec![Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4)];
        let machine = PoseidonMachine::new(&input);
        let hash = machine.compute();
        assert_ne!(hash, Fp::ZERO);
    }

    #[test]
    fn test_poseidon_machine_deterministic() {
        let input = vec![Fp::new(42), Fp::new(123), Fp::ZERO, Fp::ZERO];
        let m1 = PoseidonMachine::new(&input);
        let m2 = PoseidonMachine::new(&input);
        assert_eq!(m1.compute(), m2.compute());
    }

    #[test]
    fn test_poseidon_machine_from_u64() {
        let machine = PoseidonMachine::from_u64(&[1, 2, 3, 4]);
        let hash = machine.compute();
        assert_ne!(hash, Fp::ZERO);
    }

    #[test]
    fn test_poseidon_machine_from_bytes() {
        let machine = PoseidonMachine::from_bytes(b"hello world");
        let hash = machine.compute();
        assert_ne!(hash, Fp::ZERO);
    }

    #[test]
    fn test_poseidon_verify() {
        let input = vec![Fp::new(100), Fp::new(200), Fp::ZERO, Fp::ZERO];
        let machine = PoseidonMachine::new(&input);
        let hash = machine.compute();
        assert!(PoseidonMachine::verify(&input, hash));
        assert!(!PoseidonMachine::verify(&input, Fp::new(999)));
    }

    #[test]
    fn test_different_inputs() {
        let m1 = PoseidonMachine::from_u64(&[1, 2, 3, 4]);
        let m2 = PoseidonMachine::from_u64(&[5, 6, 7, 8]);
        assert_ne!(m1.compute(), m2.compute());
    }
}
