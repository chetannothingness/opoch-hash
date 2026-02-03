//! Keccak-256 Machine (M_KECCAK256)
//!
//! Proves computation of Keccak-256 hash operations.

use super::{Machine, MachineId};
use crate::keccak::keccak256;

/// Keccak-256 hash machine
pub struct KeccakMachine {
    /// Input data
    pub input: Vec<u8>,
}

impl KeccakMachine {
    /// Create a new Keccak machine
    pub fn new(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
        }
    }

    /// Compute the Keccak-256 hash
    pub fn compute(&self) -> [u8; 32] {
        keccak256(&self.input)
    }

    /// Verify a claimed hash
    pub fn verify(input: &[u8], claimed: &[u8; 32]) -> bool {
        keccak256(input) == *claimed
    }

    /// Number of Keccak-f[1600] permutations needed
    pub fn num_permutations(&self) -> usize {
        // 136 bytes per block (rate for Keccak-256)
        // Plus 1 for padding
        (self.input.len() / 136) + 1
    }
}

impl Machine for KeccakMachine {
    fn machine_id(&self) -> MachineId {
        MachineId::Keccak256
    }

    fn input_type(&self) -> &'static str {
        "data: Vec<u8>"
    }

    fn output_type(&self) -> &'static str {
        "hash: [u8; 32]"
    }

    fn estimated_cycles(&self) -> u64 {
        // ~5000 cycles per permutation
        (self.num_permutations() as u64) * 5000
    }
}

/// Test vectors for Keccak-256 (from NIST)
pub mod test_vectors {
    use super::*;

    /// Empty string
    pub fn empty() -> (&'static [u8], [u8; 32]) {
        (b"", hex_to_bytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"))
    }

    /// "abc"
    pub fn abc() -> (&'static [u8], [u8; 32]) {
        (b"abc", hex_to_bytes("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"))
    }

    /// Long message
    /// Note: This is Keccak-256 (pre-NIST, Ethereum-style), NOT SHA3-256
    pub fn long_message() -> (Vec<u8>, [u8; 32]) {
        let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_vec();
        // Keccak-256 hash (NOT SHA3-256 which would be 5f313c39...)
        let expected = hex_to_bytes("f519747ed599024f3882238e5ab43960132572b7345fbeb9a90769dafd21ad67");
        (input, expected)
    }

    fn hex_to_bytes(hex: &str) -> [u8; 32] {
        let mut result = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            if i >= 32 { break; }
            let s = std::str::from_utf8(chunk).unwrap();
            result[i] = u8::from_str_radix(s, 16).unwrap();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak_machine_empty() {
        let (input, expected) = test_vectors::empty();
        let machine = KeccakMachine::new(input);
        assert_eq!(machine.compute(), expected);
    }

    #[test]
    fn test_keccak_machine_abc() {
        let (input, expected) = test_vectors::abc();
        let machine = KeccakMachine::new(input);
        assert_eq!(machine.compute(), expected);
    }

    #[test]
    fn test_keccak_machine_long() {
        let (input, expected) = test_vectors::long_message();
        let machine = KeccakMachine::new(&input);
        assert_eq!(machine.compute(), expected);
    }

    #[test]
    fn test_keccak_verify() {
        let data = b"test data";
        let hash = keccak256(data);
        assert!(KeccakMachine::verify(data, &hash));
        assert!(!KeccakMachine::verify(b"other data", &hash));
    }

    #[test]
    fn test_num_permutations() {
        let small = KeccakMachine::new(&[0u8; 10]);
        assert_eq!(small.num_permutations(), 1);

        let medium = KeccakMachine::new(&[0u8; 200]);
        assert_eq!(medium.num_permutations(), 2);

        let large = KeccakMachine::new(&[0u8; 500]);
        assert_eq!(large.num_permutations(), 4);
    }
}
