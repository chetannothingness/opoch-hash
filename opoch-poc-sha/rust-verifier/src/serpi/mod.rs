//! SerΠ: Semantic Serialization with Π-Fixed Meaning
//!
//! This module provides canonical serialization where every byte sequence
//! has a fixed semantic interpretation, enabling deterministic hashing
//! and cross-implementation compatibility.
//!
//! ## Format
//!
//! A CanonicalTape has the following structure:
//! ```text
//! [MAGIC: 4 bytes "OPCH"]
//! [VERSION: 1 byte]
//! [CONTEXT_TAG: 2 bytes LE]
//! [TYPE_TAG: 1 byte]
//! [PAYLOAD: variable]
//! ```
//!
//! ## v0 vs v1
//!
//! - **v0**: Rules-only canonicalization - applies fixed normalization rules
//! - **v1**: Partition-lattice normal form with:
//!   1. Partition hash P_W(τ) for equivalence on meaning
//!   2. Coequalization of redundant normalizations
//!   3. Compression to minimal-cost representative
//!   4. Parallel composition (product partitions)
//!
//! ## Usage
//!
//! ```ignore
//! use opoch_poc_sha::serpi::{CanonicalTape, SerPi, SString};
//!
//! let obj = SString::new("hello");
//! let tape = SerPi::serialize(&obj, 0x0001);
//! let hash = tape.hash();
//! ```

pub mod types;
pub mod primitives;
pub mod partition;

pub use types::{TypeTag, SemanticObject, SerPiError};
pub use primitives::{SNull, SBool, SInt, SBytes, SString, SDigest};
pub use partition::{
    PartitionHash, PartitionKey, PartitionSerializer,
    CompressionMap, CompressionStats, CoequalizationStats,
    SemanticMap, product_partition,
};

use crate::sha256::Sha256;

/// Magic bytes for canonical tapes
pub const MAGIC: &[u8; 4] = b"OPCH";

/// Current SerΠ version
pub const VERSION: u8 = 1;

/// A canonical tape holding serialized semantic data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTape {
    /// Context tag for domain separation
    pub context_tag: u16,
    /// Type tag of the serialized object
    pub type_tag: TypeTag,
    /// Serialized payload
    pub payload: Vec<u8>,
}

impl CanonicalTape {
    /// Create a new canonical tape
    pub fn new(context_tag: u16, type_tag: TypeTag, payload: Vec<u8>) -> Self {
        Self {
            context_tag,
            type_tag,
            payload,
        }
    }

    /// Serialize the tape to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(8 + self.payload.len());
        result.extend_from_slice(MAGIC);
        result.push(VERSION);
        result.extend_from_slice(&self.context_tag.to_le_bytes());
        result.push(self.type_tag.to_byte());
        result.extend_from_slice(&self.payload);
        result
    }

    /// Deserialize a tape from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SerPiError> {
        if bytes.len() < 8 {
            return Err(SerPiError::InsufficientData { expected: 8, actual: bytes.len() });
        }

        // Check magic
        if &bytes[0..4] != MAGIC {
            return Err(SerPiError::InvalidMagic);
        }

        // Check version
        let _version = bytes[4];

        // Parse context tag
        let context_tag = u16::from_le_bytes([bytes[5], bytes[6]]);

        // Parse type tag
        let type_tag = TypeTag::from_byte(bytes[7])
            .ok_or(SerPiError::InvalidTypeTag(bytes[7]))?;

        // Extract payload
        let payload = bytes[8..].to_vec();

        Ok(Self {
            context_tag,
            type_tag,
            payload,
        })
    }

    /// Compute the SHA-256 hash of this tape
    pub fn hash(&self) -> [u8; 32] {
        Sha256::hash(&self.to_bytes())
    }

    /// Get the length of the serialized tape
    pub fn len(&self) -> usize {
        8 + self.payload.len()
    }

    /// Check if the tape is empty (no payload)
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

/// SerΠ serialization interface
pub struct SerPi;

impl SerPi {
    /// Serialize a semantic object into a canonical tape
    pub fn serialize<T: SemanticObject>(obj: &T, context: u16) -> CanonicalTape {
        CanonicalTape::new(
            context,
            obj.type_tag(),
            obj.serialize_payload(),
        )
    }

    /// Serialize and hash in one step
    pub fn hash<T: SemanticObject>(obj: &T, context: u16) -> [u8; 32] {
        Self::serialize(obj, context).hash()
    }

    /// Deserialize a semantic object from a canonical tape
    pub fn deserialize<T: SemanticObject>(tape: &CanonicalTape) -> Result<T, SerPiError> {
        T::deserialize_payload(&tape.payload)
    }
}

/// Compute the canonical hash of a tape
pub fn hash(tape: &CanonicalTape) -> [u8; 32] {
    tape.hash()
}

/// Context tags for different uses
pub mod context {
    /// Benchmark specification
    pub const BENCHMARK_SPEC: u16 = 0x0001;
    /// Receipt data
    pub const RECEIPT: u16 = 0x0002;
    /// Proof data
    pub const PROOF: u16 = 0x0003;
    /// Machine state
    pub const MACHINE_STATE: u16 = 0x0004;
    /// Input data
    pub const INPUT: u16 = 0x0010;
    /// Output data
    pub const OUTPUT: u16 = 0x0011;
    /// Intermediate state
    pub const INTERMEDIATE: u16 = 0x0020;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tape_roundtrip() {
        let obj = SString::new("test");
        let tape = SerPi::serialize(&obj, context::INPUT);

        let bytes = tape.to_bytes();
        let recovered = CanonicalTape::from_bytes(&bytes).unwrap();

        assert_eq!(tape, recovered);
    }

    #[test]
    fn test_tape_hash_deterministic() {
        let obj = SBytes::new(&[1, 2, 3, 4, 5]);
        let tape = SerPi::serialize(&obj, 0x1234);

        let hash1 = tape.hash();
        let hash2 = tape.hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_context_separation() {
        let obj = SInt(42);

        let tape1 = SerPi::serialize(&obj, 0x0001);
        let tape2 = SerPi::serialize(&obj, 0x0002);

        // Different contexts should produce different hashes
        assert_ne!(tape1.hash(), tape2.hash());
    }

    #[test]
    fn test_magic_check() {
        let mut bytes = vec![b'B', b'A', b'D', b'!', 1, 0, 0, 0];
        let result = CanonicalTape::from_bytes(&bytes);
        assert!(matches!(result, Err(SerPiError::InvalidMagic)));
    }

    #[test]
    fn test_serialize_deserialize() {
        let original = SString::new("Hello, World!");
        let tape = SerPi::serialize(&original, 0x0001);
        let recovered: SString = SerPi::deserialize(&tape).unwrap();
        assert_eq!(original, recovered);
    }
}
