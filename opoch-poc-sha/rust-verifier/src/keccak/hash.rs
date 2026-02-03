//! Keccak-256 Hash Function
//!
//! Complete hash function using sponge construction.

use super::state::KeccakState;
use super::round::keccak_f;
use super::{KECCAK256_RATE, STATE_BYTES};

/// Keccak-256 hash (Ethereum's version)
///
/// Returns 32-byte hash
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256Hasher::new();
    hasher.update(input);
    hasher.finalize()
}

/// Incremental Keccak-256 hasher
pub struct Keccak256Hasher {
    state: KeccakState,
    buffer: Vec<u8>,
    absorbed: usize,
}

impl Keccak256Hasher {
    /// Create new hasher
    pub fn new() -> Self {
        Keccak256Hasher {
            state: KeccakState::zero(),
            buffer: Vec::with_capacity(KECCAK256_RATE),
            absorbed: 0,
        }
    }

    /// Update with more input
    pub fn update(&mut self, input: &[u8]) {
        self.buffer.extend_from_slice(input);

        // Process full blocks
        while self.buffer.len() >= KECCAK256_RATE {
            let block = &self.buffer[..KECCAK256_RATE];
            self.state.xor_bytes(block, 0);
            self.state = keccak_f(&self.state);
            self.buffer = self.buffer[KECCAK256_RATE..].to_vec();
            self.absorbed += KECCAK256_RATE;
        }
    }

    /// Finalize and get hash
    pub fn finalize(mut self) -> [u8; 32] {
        // Pad with 0x01 || 0x00... || 0x80
        // For Keccak-256: domain separator is 0x01 (not 0x06 like SHA3-256)
        let mut padded = self.buffer.clone();
        padded.push(0x01);

        // Pad with zeros until one byte before rate
        while (padded.len() % KECCAK256_RATE) != KECCAK256_RATE - 1 {
            padded.push(0x00);
        }

        // Final byte has high bit set
        padded.push(0x80);

        // Process remaining blocks
        for chunk in padded.chunks(KECCAK256_RATE) {
            self.state.xor_bytes(chunk, 0);
            self.state = keccak_f(&self.state);
        }

        // Squeeze out 32 bytes
        let mut result = [0u8; 32];
        result.copy_from_slice(&self.state.extract_bytes(32));
        result
    }

    /// Reset hasher to initial state
    pub fn reset(&mut self) {
        self.state = KeccakState::zero();
        self.buffer.clear();
        self.absorbed = 0;
    }
}

impl Default for Keccak256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash multiple byte slices
pub fn keccak256_many(inputs: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256Hasher::new();
    for input in inputs {
        hasher.update(input);
    }
    hasher.finalize()
}

/// Hash two 32-byte values (common for Merkle trees)
pub fn keccak256_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(a);
    combined[32..].copy_from_slice(b);
    keccak256(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_empty() {
        let result = keccak256(&[]);
        let expected = hex::decode(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        ).unwrap();
        assert_eq!(result.to_vec(), expected);
    }

    #[test]
    fn test_keccak256_abc() {
        let result = keccak256(b"abc");
        // Keccak-256 (Ethereum) of "abc"
        let expected = hex::decode(
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        ).unwrap();
        assert_eq!(result.to_vec(), expected);
    }

    #[test]
    fn test_keccak256_incremental() {
        let direct = keccak256(b"Hello, World!");

        let mut hasher = Keccak256Hasher::new();
        hasher.update(b"Hello, ");
        hasher.update(b"World!");
        let incremental = hasher.finalize();

        assert_eq!(direct, incremental);
    }

    #[test]
    fn test_keccak256_long_input() {
        // Input longer than rate
        let input = vec![0xABu8; 200];
        let result = keccak256(&input);

        // Should produce some non-zero hash
        assert!(result.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_keccak256_pair() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        let result = keccak256_pair(&a, &b);

        // Should match concatenated hash
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&a);
        combined[32..].copy_from_slice(&b);
        let expected = keccak256(&combined);

        assert_eq!(result, expected);
    }
}
