//! Mixer Domain Tags
//!
//! Domain separation tags for the tree sponge mixer.

use serde::{Serialize, Deserialize};

/// Mixer domain tags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum MixerTag {
    /// Leaf node in tree
    Leaf = 0x10,
    /// Parent/internal node in tree
    Parent = 0x11,
    /// Root node
    Root = 0x12,
    /// Small input (< threshold, direct hash)
    Small = 0x20,
    /// Tree input (>= threshold, tree structure)
    Tree = 0x21,
    /// Initialization
    Init = 0x30,
    /// Absorb phase
    Absorb = 0x31,
    /// Squeeze phase
    Squeeze = 0x32,
    /// Final
    Final = 0x33,
}

impl MixerTag {
    /// Convert to byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Convert from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x10 => Some(MixerTag::Leaf),
            0x11 => Some(MixerTag::Parent),
            0x12 => Some(MixerTag::Root),
            0x20 => Some(MixerTag::Small),
            0x21 => Some(MixerTag::Tree),
            0x30 => Some(MixerTag::Init),
            0x31 => Some(MixerTag::Absorb),
            0x32 => Some(MixerTag::Squeeze),
            0x33 => Some(MixerTag::Final),
            _ => None,
        }
    }

    /// Get the domain separator bytes
    pub fn domain_bytes(self) -> [u8; 8] {
        let mut result = [0u8; 8];
        result[0] = b'O';
        result[1] = b'P';
        result[2] = b'M';
        result[3] = b'X';
        result[4] = self.to_byte();
        result
    }
}

/// PoC-specific tags for hash chain proofs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PocTag {
    /// Seed/initial input
    Seed = 0x70,
    /// Initial state
    Init = 0x71,
    /// Single step
    Step = 0x72,
    /// Segment boundary
    Segment = 0x73,
    /// Level-1 aggregation
    L1Agg = 0x74,
    /// Level-2 aggregation
    L2Agg = 0x75,
    /// Final result
    Final = 0x76,
}

impl PocTag {
    /// Convert to byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Get the domain separator bytes
    pub fn domain_bytes(self) -> [u8; 8] {
        let mut result = [0u8; 8];
        result[0] = b'O';
        result[1] = b'P';
        result[2] = b'P';
        result[3] = b'C';
        result[4] = self.to_byte();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mixer_tag_roundtrip() {
        let tags = [
            MixerTag::Leaf,
            MixerTag::Parent,
            MixerTag::Root,
            MixerTag::Small,
            MixerTag::Tree,
        ];

        for tag in tags {
            let byte = tag.to_byte();
            let recovered = MixerTag::from_byte(byte).expect("should recover");
            assert_eq!(tag, recovered);
        }
    }

    #[test]
    fn test_domain_bytes_unique() {
        let leaf = MixerTag::Leaf.domain_bytes();
        let parent = MixerTag::Parent.domain_bytes();
        assert_ne!(leaf, parent);
    }

    #[test]
    fn test_poc_tag_domain() {
        let seed = PocTag::Seed.domain_bytes();
        assert_eq!(&seed[0..4], b"OPPC");
    }
}
