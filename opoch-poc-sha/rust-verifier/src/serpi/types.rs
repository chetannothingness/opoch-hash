//! SerΠ Type Tags and Semantic Object Trait
//!
//! Defines the canonical type tags for semantic serialization.

use serde::{Serialize, Deserialize};

/// Type tag for semantic objects
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TypeTag {
    /// Null/None value
    Null = 0x00,
    /// Boolean value
    Bool = 0x01,
    /// Variable-length integer
    Int = 0x02,
    /// Byte array
    Bytes = 0x03,
    /// UTF-8 string
    String = 0x04,
    /// Array/list
    Array = 0x05,
    /// Map/dictionary
    Map = 0x06,
    /// Field element (Goldilocks)
    FieldElement = 0x10,
    /// Point on curve
    Point = 0x11,
    /// 256-bit integer
    U256 = 0x12,
    /// Hash digest (32 bytes)
    Digest = 0x20,
    /// Merkle root
    MerkleRoot = 0x21,
    /// Merkle path
    MerklePath = 0x22,
    /// Proof data
    Proof = 0x30,
    /// Commitment
    Commitment = 0x31,
    /// Machine state
    MachineState = 0x40,
    /// Receipt
    Receipt = 0x50,
    /// Receipt chain
    ReceiptChain = 0x51,
}

impl TypeTag {
    /// Convert to byte representation
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Convert from byte, returning None if invalid
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(TypeTag::Null),
            0x01 => Some(TypeTag::Bool),
            0x02 => Some(TypeTag::Int),
            0x03 => Some(TypeTag::Bytes),
            0x04 => Some(TypeTag::String),
            0x05 => Some(TypeTag::Array),
            0x06 => Some(TypeTag::Map),
            0x10 => Some(TypeTag::FieldElement),
            0x11 => Some(TypeTag::Point),
            0x12 => Some(TypeTag::U256),
            0x20 => Some(TypeTag::Digest),
            0x21 => Some(TypeTag::MerkleRoot),
            0x22 => Some(TypeTag::MerklePath),
            0x30 => Some(TypeTag::Proof),
            0x31 => Some(TypeTag::Commitment),
            0x40 => Some(TypeTag::MachineState),
            0x50 => Some(TypeTag::Receipt),
            0x51 => Some(TypeTag::ReceiptChain),
            _ => None,
        }
    }
}

/// Trait for objects that can be semantically serialized
pub trait SemanticObject {
    /// Get the type tag for this object
    fn type_tag(&self) -> TypeTag;

    /// Serialize the payload (without type tag)
    fn serialize_payload(&self) -> Vec<u8>;

    /// Deserialize from payload bytes
    fn deserialize_payload(bytes: &[u8]) -> Result<Self, SerPiError>
    where
        Self: Sized;
}

/// Errors during SerΠ operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerPiError {
    /// Invalid type tag
    InvalidTypeTag(u8),
    /// Insufficient data
    InsufficientData { expected: usize, actual: usize },
    /// Invalid magic bytes
    InvalidMagic,
    /// Invalid UTF-8 string
    InvalidUtf8,
    /// Overflow in integer decoding
    IntegerOverflow,
    /// Custom error
    Custom(String),
}

impl std::fmt::Display for SerPiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SerPiError::InvalidTypeTag(tag) => write!(f, "Invalid type tag: 0x{:02x}", tag),
            SerPiError::InsufficientData { expected, actual } => {
                write!(f, "Insufficient data: expected {} bytes, got {}", expected, actual)
            }
            SerPiError::InvalidMagic => write!(f, "Invalid magic bytes"),
            SerPiError::InvalidUtf8 => write!(f, "Invalid UTF-8 string"),
            SerPiError::IntegerOverflow => write!(f, "Integer overflow"),
            SerPiError::Custom(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for SerPiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_tag_roundtrip() {
        let tags = [
            TypeTag::Null,
            TypeTag::Bool,
            TypeTag::Int,
            TypeTag::Bytes,
            TypeTag::String,
            TypeTag::Array,
            TypeTag::Map,
            TypeTag::FieldElement,
            TypeTag::Digest,
            TypeTag::Proof,
            TypeTag::Receipt,
        ];

        for tag in tags {
            let byte = tag.to_byte();
            let recovered = TypeTag::from_byte(byte).expect("should recover");
            assert_eq!(tag, recovered);
        }
    }

    #[test]
    fn test_invalid_type_tag() {
        assert!(TypeTag::from_byte(0xFF).is_none());
        assert!(TypeTag::from_byte(0x99).is_none());
    }
}
