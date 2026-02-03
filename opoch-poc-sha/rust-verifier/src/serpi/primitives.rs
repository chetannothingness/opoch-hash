//! SerΠ Primitive Types
//!
//! Basic types: Null, Bool, Int, Bytes, String

use super::types::{TypeTag, SemanticObject, SerPiError};

/// Null semantic object
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SNull;

impl SemanticObject for SNull {
    fn type_tag(&self) -> TypeTag {
        TypeTag::Null
    }

    fn serialize_payload(&self) -> Vec<u8> {
        Vec::new()
    }

    fn deserialize_payload(_bytes: &[u8]) -> Result<Self, SerPiError> {
        Ok(SNull)
    }
}

/// Boolean semantic object
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SBool(pub bool);

impl SemanticObject for SBool {
    fn type_tag(&self) -> TypeTag {
        TypeTag::Bool
    }

    fn serialize_payload(&self) -> Vec<u8> {
        vec![if self.0 { 1 } else { 0 }]
    }

    fn deserialize_payload(bytes: &[u8]) -> Result<Self, SerPiError> {
        if bytes.is_empty() {
            return Err(SerPiError::InsufficientData { expected: 1, actual: 0 });
        }
        Ok(SBool(bytes[0] != 0))
    }
}

impl From<bool> for SBool {
    fn from(b: bool) -> Self {
        SBool(b)
    }
}

impl From<SBool> for bool {
    fn from(s: SBool) -> Self {
        s.0
    }
}

/// Variable-length integer semantic object (LEB128 encoding)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SInt(pub i64);

impl SInt {
    /// Encode as LEB128
    fn encode_leb128(&self) -> Vec<u8> {
        let mut result = Vec::new();
        let mut value = self.0 as u64;
        let negative = self.0 < 0;

        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;

            // Sign extend for negative numbers
            if negative {
                value |= !0u64 << 57; // Fill high bits with 1s
            }

            // Check if more bytes needed
            let done = if negative {
                value == !0u64 && (byte & 0x40) != 0
            } else {
                value == 0 && (byte & 0x40) == 0
            };

            if !done {
                byte |= 0x80;
            }
            result.push(byte);

            if done {
                break;
            }
        }
        result
    }

    /// Decode from LEB128
    fn decode_leb128(bytes: &[u8]) -> Result<(Self, usize), SerPiError> {
        let mut result: i64 = 0;
        let mut shift = 0;
        let mut pos = 0;

        loop {
            if pos >= bytes.len() {
                return Err(SerPiError::InsufficientData { expected: pos + 1, actual: pos });
            }

            let byte = bytes[pos];
            pos += 1;

            if shift >= 64 {
                return Err(SerPiError::IntegerOverflow);
            }

            result |= ((byte & 0x7f) as i64) << shift;
            shift += 7;

            if (byte & 0x80) == 0 {
                // Sign extend if negative
                if shift < 64 && (byte & 0x40) != 0 {
                    result |= !0i64 << shift;
                }
                break;
            }
        }

        Ok((SInt(result), pos))
    }
}

impl SemanticObject for SInt {
    fn type_tag(&self) -> TypeTag {
        TypeTag::Int
    }

    fn serialize_payload(&self) -> Vec<u8> {
        self.encode_leb128()
    }

    fn deserialize_payload(bytes: &[u8]) -> Result<Self, SerPiError> {
        let (value, _) = Self::decode_leb128(bytes)?;
        Ok(value)
    }
}

impl From<i64> for SInt {
    fn from(i: i64) -> Self {
        SInt(i)
    }
}

impl From<SInt> for i64 {
    fn from(s: SInt) -> Self {
        s.0
    }
}

/// Byte array semantic object
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SBytes(pub Vec<u8>);

impl SBytes {
    /// Create from slice
    pub fn new(data: &[u8]) -> Self {
        SBytes(data.to_vec())
    }

    /// Create from array
    pub fn from_array<const N: usize>(arr: [u8; N]) -> Self {
        SBytes(arr.to_vec())
    }
}

impl SemanticObject for SBytes {
    fn type_tag(&self) -> TypeTag {
        TypeTag::Bytes
    }

    fn serialize_payload(&self) -> Vec<u8> {
        let mut result = Vec::new();
        // Length prefix (4 bytes, little-endian)
        let len = self.0.len() as u32;
        result.extend_from_slice(&len.to_le_bytes());
        result.extend_from_slice(&self.0);
        result
    }

    fn deserialize_payload(bytes: &[u8]) -> Result<Self, SerPiError> {
        if bytes.len() < 4 {
            return Err(SerPiError::InsufficientData { expected: 4, actual: bytes.len() });
        }
        let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + len {
            return Err(SerPiError::InsufficientData { expected: 4 + len, actual: bytes.len() });
        }
        Ok(SBytes(bytes[4..4 + len].to_vec()))
    }
}

impl From<Vec<u8>> for SBytes {
    fn from(v: Vec<u8>) -> Self {
        SBytes(v)
    }
}

impl From<&[u8]> for SBytes {
    fn from(s: &[u8]) -> Self {
        SBytes(s.to_vec())
    }
}

/// UTF-8 string semantic object
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SString(pub String);

impl SString {
    /// Create from str
    pub fn new(s: &str) -> Self {
        SString(s.to_string())
    }
}

impl SemanticObject for SString {
    fn type_tag(&self) -> TypeTag {
        TypeTag::String
    }

    fn serialize_payload(&self) -> Vec<u8> {
        let bytes = self.0.as_bytes();
        let mut result = Vec::new();
        // Length prefix (4 bytes, little-endian)
        let len = bytes.len() as u32;
        result.extend_from_slice(&len.to_le_bytes());
        result.extend_from_slice(bytes);
        result
    }

    fn deserialize_payload(bytes: &[u8]) -> Result<Self, SerPiError> {
        if bytes.len() < 4 {
            return Err(SerPiError::InsufficientData { expected: 4, actual: bytes.len() });
        }
        let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + len {
            return Err(SerPiError::InsufficientData { expected: 4 + len, actual: bytes.len() });
        }
        let s = std::str::from_utf8(&bytes[4..4 + len])
            .map_err(|_| SerPiError::InvalidUtf8)?;
        Ok(SString(s.to_string()))
    }
}

impl From<String> for SString {
    fn from(s: String) -> Self {
        SString(s)
    }
}

impl From<&str> for SString {
    fn from(s: &str) -> Self {
        SString(s.to_string())
    }
}

/// 32-byte digest semantic object
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SDigest(pub [u8; 32]);

impl SDigest {
    /// Create a zero digest
    pub fn zero() -> Self {
        SDigest([0u8; 32])
    }
}

impl SemanticObject for SDigest {
    fn type_tag(&self) -> TypeTag {
        TypeTag::Digest
    }

    fn serialize_payload(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn deserialize_payload(bytes: &[u8]) -> Result<Self, SerPiError> {
        if bytes.len() < 32 {
            return Err(SerPiError::InsufficientData { expected: 32, actual: bytes.len() });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(SDigest(arr))
    }
}

impl From<[u8; 32]> for SDigest {
    fn from(arr: [u8; 32]) -> Self {
        SDigest(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_roundtrip() {
        let null = SNull;
        let payload = null.serialize_payload();
        assert!(payload.is_empty());
        let recovered = SNull::deserialize_payload(&payload).unwrap();
        assert_eq!(null, recovered);
    }

    #[test]
    fn test_bool_roundtrip() {
        for b in [true, false] {
            let sbool = SBool(b);
            let payload = sbool.serialize_payload();
            let recovered = SBool::deserialize_payload(&payload).unwrap();
            assert_eq!(sbool, recovered);
        }
    }

    #[test]
    fn test_int_roundtrip() {
        let values = [0i64, 1, -1, 127, 128, -128, 255, 256, i64::MAX, i64::MIN];
        for v in values {
            let sint = SInt(v);
            let payload = sint.serialize_payload();
            let recovered = SInt::deserialize_payload(&payload).unwrap();
            assert_eq!(sint, recovered, "Failed for value {}", v);
        }
    }

    #[test]
    fn test_bytes_roundtrip() {
        let data = vec![1u8, 2, 3, 4, 5];
        let sbytes = SBytes(data.clone());
        let payload = sbytes.serialize_payload();
        let recovered = SBytes::deserialize_payload(&payload).unwrap();
        assert_eq!(sbytes, recovered);
    }

    #[test]
    fn test_string_roundtrip() {
        let s = "Hello, SerΠ!";
        let sstring = SString::new(s);
        let payload = sstring.serialize_payload();
        let recovered = SString::deserialize_payload(&payload).unwrap();
        assert_eq!(sstring, recovered);
    }

    #[test]
    fn test_digest_roundtrip() {
        let arr = [42u8; 32];
        let digest = SDigest(arr);
        let payload = digest.serialize_payload();
        let recovered = SDigest::deserialize_payload(&payload).unwrap();
        assert_eq!(digest, recovered);
    }
}
