//! Fiat-Shamir Transcript
//!
//! Deterministic challenge derivation using SHA-256 in sponge mode.

use crate::sha256::Sha256;
use crate::field::{Fp, Fp2};

/// Transcript tags
const TAG_CHAL_FRI: &[u8] = b"CHAL_FRI";
const TAG_CHAL_QUERY: &[u8] = b"CHAL_QUERY";
const TAG_CHAL_SEG: &[u8] = b"CHAL_SEG";
const TAG_CHAL_AGG: &[u8] = b"CHAL_AGG";
const TAG_CHAL_TOP: &[u8] = b"CHAL_TOP";

/// Fiat-Shamir transcript
pub struct Transcript {
    state: [u8; 32],
}

impl Transcript {
    /// Initialize transcript with domain separator
    pub fn new() -> Self {
        let state = Sha256::hash(b"OPOCH-PoC-SHA-v1-TRANSCRIPT");
        Transcript { state }
    }

    /// Append data to transcript
    pub fn append(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.state);
        hasher.update(&(data.len() as u64).to_le_bytes());
        hasher.update(data);
        self.state = hasher.finalize();
    }

    /// Append a 32-byte commitment
    pub fn append_commitment(&mut self, commitment: &[u8; 32]) {
        self.append(commitment);
    }

    /// Append field element
    pub fn append_fp(&mut self, x: Fp) {
        self.append(&x.to_bytes());
    }

    /// Get challenge bytes with tag
    fn challenge_bytes(&mut self, tag: &[u8], num_bytes: usize) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.state);
        hasher.update(tag);
        let hash = hasher.finalize();

        // Update state
        self.state = hash;

        // Expand if needed using counter mode
        let mut result = Vec::with_capacity(num_bytes);
        let mut counter = 0u64;

        while result.len() < num_bytes {
            let mut h = Sha256::new();
            h.update(&hash);
            h.update(&counter.to_le_bytes());
            let chunk = h.finalize();
            let take = std::cmp::min(32, num_bytes - result.len());
            result.extend_from_slice(&chunk[..take]);
            counter += 1;
        }

        result
    }

    /// Get FRI challenge (field element)
    pub fn challenge_fri(&mut self) -> Fp {
        let bytes = self.challenge_bytes(TAG_CHAL_FRI, 8);
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[..8]);
        Fp::new(u64::from_le_bytes(arr))
    }

    /// Get FRI challenge in extension field
    pub fn challenge_fri_ext(&mut self) -> Fp2 {
        let bytes = self.challenge_bytes(TAG_CHAL_FRI, 16);
        let mut arr0 = [0u8; 8];
        let mut arr1 = [0u8; 8];
        arr0.copy_from_slice(&bytes[..8]);
        arr1.copy_from_slice(&bytes[8..16]);
        Fp2::new(
            Fp::new(u64::from_le_bytes(arr0)),
            Fp::new(u64::from_le_bytes(arr1)),
        )
    }

    /// Get query indices
    pub fn challenge_query_indices(&mut self, count: usize, domain_size: usize) -> Vec<usize> {
        let bytes = self.challenge_bytes(TAG_CHAL_QUERY, count * 8);
        let mut indices = Vec::with_capacity(count);

        for i in 0..count {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            let val = u64::from_le_bytes(arr) as usize;
            indices.push(val % domain_size);
        }

        indices
    }

    /// Get segment challenge
    pub fn challenge_segment(&mut self) -> Fp2 {
        let bytes = self.challenge_bytes(TAG_CHAL_SEG, 16);
        let mut arr0 = [0u8; 8];
        let mut arr1 = [0u8; 8];
        arr0.copy_from_slice(&bytes[..8]);
        arr1.copy_from_slice(&bytes[8..16]);
        Fp2::new(
            Fp::new(u64::from_le_bytes(arr0)),
            Fp::new(u64::from_le_bytes(arr1)),
        )
    }

    /// Get aggregation challenge
    pub fn challenge_aggregation(&mut self) -> Fp2 {
        let bytes = self.challenge_bytes(TAG_CHAL_AGG, 16);
        let mut arr0 = [0u8; 8];
        let mut arr1 = [0u8; 8];
        arr0.copy_from_slice(&bytes[..8]);
        arr1.copy_from_slice(&bytes[8..16]);
        Fp2::new(
            Fp::new(u64::from_le_bytes(arr0)),
            Fp::new(u64::from_le_bytes(arr1)),
        )
    }

    /// Get current state hash
    pub fn state(&self) -> [u8; 32] {
        self.state
    }

    /// Get generic challenge (field element) - used by AIR modules
    pub fn challenge(&mut self) -> Fp {
        self.challenge_fri()
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determinism() {
        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        t1.append(b"hello");
        t2.append(b"hello");

        let c1 = t1.challenge_fri();
        let c2 = t2.challenge_fri();

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_different_inputs() {
        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        t1.append(b"hello");
        t2.append(b"world");

        let c1 = t1.challenge_fri();
        let c2 = t2.challenge_fri();

        assert_ne!(c1, c2);
    }
}
