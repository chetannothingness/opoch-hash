//! OpochHash Mixer
//!
//! Domain-separated tree sponge with two regimes:
//! - SMALL: Direct hash for inputs < SMALL_THRESHOLD
//! - TREE: Merkle-like tree structure for larger inputs

pub mod sponge;
pub mod tags;

pub use sponge::Sponge;
pub use tags::{MixerTag, PocTag};

use crate::sha256::Sha256;
use crate::serpi::CanonicalTape;

/// Threshold for switching from SMALL to TREE regime (in bytes)
pub const SMALL_THRESHOLD: usize = 256;

/// Chunk size for tree leaves
pub const LEAF_CHUNK_SIZE: usize = 64;

/// Tree Sponge Mixer for domain-separated hashing
pub struct TreeSpongeMixer {
    domain: [u8; 8],
}

impl TreeSpongeMixer {
    /// Create a new mixer with a domain tag
    pub fn new(domain: MixerTag) -> Self {
        Self {
            domain: domain.domain_bytes(),
        }
    }

    /// Create a mixer for a PoC operation
    pub fn for_poc(tag: PocTag) -> Self {
        Self {
            domain: tag.domain_bytes(),
        }
    }

    /// Hash data using the appropriate regime
    pub fn hash(&self, data: &[u8]) -> [u8; 32] {
        if data.len() < SMALL_THRESHOLD {
            self.hash_small(data)
        } else {
            self.hash_tree(data)
        }
    }

    /// Hash small inputs directly
    fn hash_small(&self, data: &[u8]) -> [u8; 32] {
        let mut sponge = Sponge::new(MixerTag::Small);
        sponge.absorb(&self.domain);
        sponge.absorb(data);
        sponge.finalize()
    }

    /// Hash large inputs using tree structure
    fn hash_tree(&self, data: &[u8]) -> [u8; 32] {
        // Split into leaves
        let chunks: Vec<&[u8]> = data.chunks(LEAF_CHUNK_SIZE).collect();

        // Hash all leaves
        let mut leaves: Vec<[u8; 32]> = chunks
            .iter()
            .map(|chunk| {
                let mut sponge = Sponge::new(MixerTag::Leaf);
                sponge.absorb(&self.domain);
                sponge.absorb(chunk);
                sponge.finalize()
            })
            .collect();

        // Build tree up to root
        while leaves.len() > 1 {
            let mut next_level = Vec::new();

            for pair in leaves.chunks(2) {
                let mut sponge = Sponge::new(MixerTag::Parent);
                sponge.absorb(&pair[0]);
                if pair.len() > 1 {
                    sponge.absorb(&pair[1]);
                }
                next_level.push(sponge.finalize());
            }

            leaves = next_level;
        }

        // Final root hash
        let mut root_sponge = Sponge::new(MixerTag::Root);
        root_sponge.absorb(&self.domain);
        if !leaves.is_empty() {
            root_sponge.absorb(&leaves[0]);
        }
        root_sponge.finalize()
    }

    /// Mix multiple digests together
    pub fn mix_digests(&self, digests: &[[u8; 32]]) -> [u8; 32] {
        let mut sponge = Sponge::new(MixerTag::Parent);
        sponge.absorb(&self.domain);
        for digest in digests {
            sponge.absorb(digest);
        }
        sponge.finalize()
    }
}

impl Default for TreeSpongeMixer {
    fn default() -> Self {
        Self::new(MixerTag::Init)
    }
}

/// Main entry point: compute OpochHash of arbitrary data
pub fn opoch_hash(input: &[u8]) -> [u8; 32] {
    let mixer = TreeSpongeMixer::default();
    mixer.hash(input)
}

/// Hash a canonical tape (for semantic objects)
pub fn mix(tape: &CanonicalTape) -> [u8; 32] {
    let bytes = tape.to_bytes();
    opoch_hash(&bytes)
}

/// Hash with a specific domain tag
pub fn opoch_hash_domain(input: &[u8], tag: MixerTag) -> [u8; 32] {
    let mixer = TreeSpongeMixer::new(tag);
    mixer.hash(input)
}

/// Mix two hashes together
pub fn mix_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mixer = TreeSpongeMixer::new(MixerTag::Parent);
    mixer.mix_digests(&[*left, *right])
}

/// Chain hash: H(domain || step || previous)
pub fn chain_hash(domain: &[u8], step: u64, previous: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(domain.len() + 8 + 32);
    input.extend_from_slice(domain);
    input.extend_from_slice(&step.to_le_bytes());
    input.extend_from_slice(previous);
    opoch_hash(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opoch_hash_basic() {
        let hash = opoch_hash(b"hello");
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_opoch_hash_deterministic() {
        let h1 = opoch_hash(b"test input");
        let h2 = opoch_hash(b"test input");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_opoch_hash_different_inputs() {
        let h1 = opoch_hash(b"input one");
        let h2 = opoch_hash(b"input two");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_small_regime() {
        // Input below threshold should use SMALL regime
        let small_input = vec![0u8; SMALL_THRESHOLD - 1];
        let hash = opoch_hash(&small_input);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_tree_regime() {
        // Input at or above threshold should use TREE regime
        let large_input = vec![0xab; SMALL_THRESHOLD * 2];
        let hash = opoch_hash(&large_input);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_domain_separation() {
        let h1 = opoch_hash_domain(b"data", MixerTag::Leaf);
        let h2 = opoch_hash_domain(b"data", MixerTag::Root);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_mix_pair() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let mixed = mix_pair(&a, &b);
        assert_ne!(mixed, a);
        assert_ne!(mixed, b);
    }

    #[test]
    fn test_mix_pair_order_matters() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let ab = mix_pair(&a, &b);
        let ba = mix_pair(&b, &a);
        assert_ne!(ab, ba);
    }

    #[test]
    fn test_chain_hash() {
        let domain = b"TEST";
        let prev = [0u8; 32];

        let h1 = chain_hash(domain, 0, &prev);
        let h2 = chain_hash(domain, 1, &prev);

        assert_ne!(h1, h2);
    }

    #[test]
    fn test_empty_input() {
        let hash = opoch_hash(&[]);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_mixer_custom_domain() {
        let mixer = TreeSpongeMixer::for_poc(PocTag::Seed);
        let h1 = mixer.hash(b"data");

        let default = TreeSpongeMixer::default();
        let h2 = default.hash(b"data");

        assert_ne!(h1, h2);
    }
}
