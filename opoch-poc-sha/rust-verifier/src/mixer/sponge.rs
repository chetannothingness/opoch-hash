//! Sponge Construction
//!
//! A simplified sponge construction over SHA-256 for the mixer.
//! Note: In production, this would use Keccak-f[1600], but we use
//! SHA-256 here for simplicity and to avoid circular dependencies.

use crate::sha256::Sha256;
use super::tags::MixerTag;

/// Sponge state
#[derive(Clone)]
pub struct Sponge {
    /// Internal state (256 bits)
    state: [u8; 32],
    /// Rate portion (first 16 bytes for absorb)
    rate: usize,
    /// Capacity portion (last 16 bytes, never directly exposed)
    capacity: usize,
    /// Domain tag for separation
    domain: MixerTag,
}

impl Sponge {
    /// Rate in bytes (how much we can absorb at once)
    pub const RATE: usize = 16;

    /// Capacity in bytes
    pub const CAPACITY: usize = 16;

    /// Create a new sponge with domain separation
    pub fn new(domain: MixerTag) -> Self {
        let domain_bytes = domain.domain_bytes();
        let initial_state = Sha256::hash(&domain_bytes);

        Self {
            state: initial_state,
            rate: Self::RATE,
            capacity: Self::CAPACITY,
            domain,
        }
    }

    /// Absorb data into the sponge
    pub fn absorb(&mut self, data: &[u8]) {
        // Process data in rate-sized chunks
        for chunk in data.chunks(self.rate) {
            // XOR chunk into rate portion
            for (i, &byte) in chunk.iter().enumerate() {
                self.state[i] ^= byte;
            }
            // Apply permutation (using SHA-256 as a stand-in)
            self.permute();
        }
    }

    /// Absorb a single chunk (must be <= rate)
    pub fn absorb_chunk(&mut self, chunk: &[u8]) {
        assert!(chunk.len() <= self.rate);
        for (i, &byte) in chunk.iter().enumerate() {
            self.state[i] ^= byte;
        }
        self.permute();
    }

    /// Squeeze output from the sponge
    pub fn squeeze(&mut self, output: &mut [u8]) {
        let mut offset = 0;
        while offset < output.len() {
            let to_copy = std::cmp::min(self.rate, output.len() - offset);
            output[offset..offset + to_copy].copy_from_slice(&self.state[..to_copy]);
            offset += to_copy;
            if offset < output.len() {
                self.permute();
            }
        }
    }

    /// Squeeze exactly 32 bytes
    pub fn squeeze_32(&mut self) -> [u8; 32] {
        let mut output = [0u8; 32];
        self.squeeze(&mut output);
        output
    }

    /// Apply the permutation function
    fn permute(&mut self) {
        // Using SHA-256 compression as a permutation
        // This is a simplified construction; production would use Keccak-f
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&self.state);
        input[32..40].copy_from_slice(&self.domain.domain_bytes());
        self.state = Sha256::hash(&input);
    }

    /// Finalize and get the hash output
    pub fn finalize(mut self) -> [u8; 32] {
        // Add padding indicator
        self.state[self.rate - 1] ^= 0x80;
        self.permute();
        self.state
    }

    /// Reset to initial state
    pub fn reset(&mut self) {
        let domain_bytes = self.domain.domain_bytes();
        self.state = Sha256::hash(&domain_bytes);
    }

    /// Get a copy of the current state
    pub fn state(&self) -> [u8; 32] {
        self.state
    }
}

impl Default for Sponge {
    fn default() -> Self {
        Self::new(MixerTag::Init)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sponge_basic() {
        let mut sponge = Sponge::new(MixerTag::Leaf);
        sponge.absorb(b"hello");
        let output = sponge.finalize();
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_sponge_deterministic() {
        let mut s1 = Sponge::new(MixerTag::Leaf);
        let mut s2 = Sponge::new(MixerTag::Leaf);

        s1.absorb(b"test data");
        s2.absorb(b"test data");

        assert_eq!(s1.finalize(), s2.finalize());
    }

    #[test]
    fn test_sponge_domain_separation() {
        let mut s1 = Sponge::new(MixerTag::Leaf);
        let mut s2 = Sponge::new(MixerTag::Parent);

        s1.absorb(b"same input");
        s2.absorb(b"same input");

        // Different domains should produce different outputs
        assert_ne!(s1.finalize(), s2.finalize());
    }

    #[test]
    fn test_sponge_large_input() {
        let mut sponge = Sponge::new(MixerTag::Tree);
        let large_data = vec![0xab; 1000];
        sponge.absorb(&large_data);
        let output = sponge.finalize();
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_squeeze_multiple() {
        let mut sponge = Sponge::new(MixerTag::Root);
        sponge.absorb(b"input");

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        sponge.squeeze(&mut out1);
        sponge.squeeze(&mut out2);

        // Sequential squeezes should be different
        assert_ne!(out1, out2);
    }
}
