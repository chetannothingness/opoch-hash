//! Keccak State Representation
//!
//! Bytewise representation optimized for lookup-based operations.

use crate::field::Fp;
use super::{STATE_BYTES, LANES, LANE_BYTES};

/// Keccak state as 200 bytes
///
/// Lane ordering: state[8*(5*y + x) .. 8*(5*y + x) + 8] = Lane[x][y]
#[derive(Clone, Debug)]
pub struct KeccakState {
    /// State as 200 field elements (each representing one byte)
    pub bytes: [Fp; STATE_BYTES],
}

impl Default for KeccakState {
    fn default() -> Self {
        Self::zero()
    }
}

impl KeccakState {
    /// Zero state
    pub fn zero() -> Self {
        KeccakState {
            bytes: [Fp::ZERO; STATE_BYTES],
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(input: &[u8; STATE_BYTES]) -> Self {
        let mut bytes = [Fp::ZERO; STATE_BYTES];
        for (i, &b) in input.iter().enumerate() {
            bytes[i] = Fp::new(b as u64);
        }
        KeccakState { bytes }
    }

    /// Convert to raw bytes
    pub fn to_bytes(&self) -> [u8; STATE_BYTES] {
        let mut result = [0u8; STATE_BYTES];
        for (i, &b) in self.bytes.iter().enumerate() {
            result[i] = b.to_u64() as u8;
        }
        result
    }

    /// Get lane offset in byte array
    pub fn lane_offset(x: usize, y: usize) -> usize {
        LANE_BYTES * (5 * y + x)
    }

    /// Get byte at position within lane
    pub fn get_lane_byte(&self, x: usize, y: usize, byte_idx: usize) -> Fp {
        let offset = Self::lane_offset(x, y) + byte_idx;
        self.bytes[offset]
    }

    /// Set byte at position within lane
    pub fn set_lane_byte(&mut self, x: usize, y: usize, byte_idx: usize, value: Fp) {
        let offset = Self::lane_offset(x, y) + byte_idx;
        self.bytes[offset] = value;
    }

    /// Get entire lane as 8 bytes
    pub fn get_lane(&self, x: usize, y: usize) -> [Fp; LANE_BYTES] {
        let offset = Self::lane_offset(x, y);
        let mut lane = [Fp::ZERO; LANE_BYTES];
        lane.copy_from_slice(&self.bytes[offset..offset + LANE_BYTES]);
        lane
    }

    /// Set entire lane
    pub fn set_lane(&mut self, x: usize, y: usize, lane: &[Fp; LANE_BYTES]) {
        let offset = Self::lane_offset(x, y);
        self.bytes[offset..offset + LANE_BYTES].copy_from_slice(lane);
    }

    /// Get lane as u64 (little-endian)
    pub fn get_lane_u64(&self, x: usize, y: usize) -> u64 {
        let lane = self.get_lane(x, y);
        let mut value = 0u64;
        for (i, &b) in lane.iter().enumerate() {
            value |= (b.to_u64()) << (8 * i);
        }
        value
    }

    /// Set lane from u64 (little-endian)
    pub fn set_lane_u64(&mut self, x: usize, y: usize, value: u64) {
        let offset = Self::lane_offset(x, y);
        for i in 0..LANE_BYTES {
            self.bytes[offset + i] = Fp::new((value >> (8 * i)) & 0xFF);
        }
    }

    /// XOR another state into this one
    pub fn xor_with(&mut self, other: &KeccakState) {
        for i in 0..STATE_BYTES {
            let a = self.bytes[i].to_u64() as u8;
            let b = other.bytes[i].to_u64() as u8;
            self.bytes[i] = Fp::new((a ^ b) as u64);
        }
    }

    /// XOR bytes into state (for absorption)
    pub fn xor_bytes(&mut self, input: &[u8], offset: usize) {
        for (i, &b) in input.iter().enumerate() {
            if offset + i < STATE_BYTES {
                let current = self.bytes[offset + i].to_u64() as u8;
                self.bytes[offset + i] = Fp::new((current ^ b) as u64);
            }
        }
    }

    /// Extract bytes from state (for squeezing)
    pub fn extract_bytes(&self, count: usize) -> Vec<u8> {
        let count = count.min(STATE_BYTES);
        self.bytes[..count]
            .iter()
            .map(|&b| b.to_u64() as u8)
            .collect()
    }
}

/// Keccak state columns for AIR
#[derive(Clone, Debug)]
pub struct KeccakStateColumns {
    /// Column indices for each byte
    pub columns: [usize; STATE_BYTES],
}

impl KeccakStateColumns {
    /// Create from starting column index
    pub fn new(start: usize) -> Self {
        let mut columns = [0; STATE_BYTES];
        for i in 0..STATE_BYTES {
            columns[i] = start + i;
        }
        KeccakStateColumns { columns }
    }

    /// Get column for lane byte
    pub fn get_lane_byte_col(&self, x: usize, y: usize, byte_idx: usize) -> usize {
        let offset = KeccakState::lane_offset(x, y) + byte_idx;
        self.columns[offset]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_state() {
        let state = KeccakState::zero();
        for &b in &state.bytes {
            assert!(b.is_zero());
        }
    }

    #[test]
    fn test_lane_access() {
        let mut state = KeccakState::zero();

        // Set lane (1, 2) to some value
        state.set_lane_u64(1, 2, 0x123456789ABCDEF0);

        // Read back
        assert_eq!(state.get_lane_u64(1, 2), 0x123456789ABCDEF0);

        // Other lanes should be zero
        assert_eq!(state.get_lane_u64(0, 0), 0);
        assert_eq!(state.get_lane_u64(4, 4), 0);
    }

    #[test]
    fn test_byte_access() {
        let mut state = KeccakState::zero();

        state.set_lane_byte(2, 3, 4, Fp::new(0xAB));
        assert_eq!(state.get_lane_byte(2, 3, 4), Fp::new(0xAB));
    }

    #[test]
    fn test_bytes_roundtrip() {
        let mut input = [0u8; STATE_BYTES];
        for (i, b) in input.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }

        let state = KeccakState::from_bytes(&input);
        let output = state.to_bytes();

        assert_eq!(input, output);
    }

    #[test]
    fn test_xor_bytes() {
        let mut state = KeccakState::zero();
        let input = [0xFF, 0xAA, 0x55];

        state.xor_bytes(&input, 0);

        assert_eq!(state.bytes[0], Fp::new(0xFF));
        assert_eq!(state.bytes[1], Fp::new(0xAA));
        assert_eq!(state.bytes[2], Fp::new(0x55));
    }

    #[test]
    fn test_extract_bytes() {
        let mut state = KeccakState::zero();
        state.bytes[0] = Fp::new(0x12);
        state.bytes[1] = Fp::new(0x34);
        state.bytes[2] = Fp::new(0x56);

        let extracted = state.extract_bytes(3);
        assert_eq!(extracted, vec![0x12, 0x34, 0x56]);
    }
}
