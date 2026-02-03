//! 256-bit Integer Limb Representation
//!
//! Represents a 256-bit integer as 16 × 16-bit limbs in little-endian order.

use crate::field::Fp;
use super::{LIMB_BITS, LIMB_COUNT, LIMB_MAX};

/// 256-bit integer represented as 16 × 16-bit limbs
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct U256Limbs {
    /// Limbs in little-endian order
    /// limbs[0] is least significant
    pub limbs: [Fp; LIMB_COUNT],
}

impl Default for U256Limbs {
    fn default() -> Self {
        Self::zero()
    }
}

impl U256Limbs {
    /// Zero
    pub const ZERO: Self = U256Limbs {
        limbs: [Fp::ZERO; LIMB_COUNT],
    };

    /// One
    pub fn one() -> Self {
        let mut limbs = [Fp::ZERO; LIMB_COUNT];
        limbs[0] = Fp::ONE;
        U256Limbs { limbs }
    }

    /// Zero
    pub fn zero() -> Self {
        U256Limbs {
            limbs: [Fp::ZERO; LIMB_COUNT],
        }
    }

    /// Create from raw limbs
    pub fn from_limbs(limbs: [Fp; LIMB_COUNT]) -> Self {
        U256Limbs { limbs }
    }

    /// Create from u64 value
    pub fn from_u64(value: u64) -> Self {
        let mut limbs = [Fp::ZERO; LIMB_COUNT];
        limbs[0] = Fp::new(value & LIMB_MAX);
        limbs[1] = Fp::new((value >> 16) & LIMB_MAX);
        limbs[2] = Fp::new((value >> 32) & LIMB_MAX);
        limbs[3] = Fp::new((value >> 48) & LIMB_MAX);
        U256Limbs { limbs }
    }

    /// Create from u128 value
    pub fn from_u128(value: u128) -> Self {
        let mut limbs = [Fp::ZERO; LIMB_COUNT];
        for i in 0..8 {
            limbs[i] = Fp::new(((value >> (16 * i)) & LIMB_MAX as u128) as u64);
        }
        U256Limbs { limbs }
    }

    /// Create from bytes (big-endian, as in crypto standards)
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Self {
        let mut limbs = [Fp::ZERO; LIMB_COUNT];
        for i in 0..16 {
            let hi = bytes[30 - 2 * i] as u64;
            let lo = bytes[31 - 2 * i] as u64;
            limbs[i] = Fp::new((hi << 8) | lo);
        }
        U256Limbs { limbs }
    }

    /// Create from bytes (little-endian)
    pub fn from_bytes_le(bytes: &[u8; 32]) -> Self {
        let mut limbs = [Fp::ZERO; LIMB_COUNT];
        for i in 0..16 {
            let lo = bytes[2 * i] as u64;
            let hi = bytes[2 * i + 1] as u64;
            limbs[i] = Fp::new((hi << 8) | lo);
        }
        U256Limbs { limbs }
    }

    /// Convert to bytes (big-endian)
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..16 {
            let limb = self.limbs[i].to_u64();
            bytes[30 - 2 * i] = (limb >> 8) as u8;
            bytes[31 - 2 * i] = (limb & 0xFF) as u8;
        }
        bytes
    }

    /// Convert to bytes (little-endian)
    pub fn to_bytes_le(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..16 {
            let limb = self.limbs[i].to_u64();
            bytes[2 * i] = (limb & 0xFF) as u8;
            bytes[2 * i + 1] = (limb >> 8) as u8;
        }
        bytes
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|x| x.is_zero())
    }

    /// Check if one
    pub fn is_one(&self) -> bool {
        self.limbs[0] == Fp::ONE && self.limbs[1..].iter().all(|x| x.is_zero())
    }

    /// Get limb at index
    pub fn get_limb(&self, index: usize) -> Fp {
        self.limbs[index]
    }

    /// Set limb at index
    pub fn set_limb(&mut self, index: usize, value: Fp) {
        self.limbs[index] = value;
    }

    /// Check if all limbs are in valid range [0, 2^16 - 1]
    pub fn is_normalized(&self) -> bool {
        self.limbs.iter().all(|x| x.to_u64() <= LIMB_MAX)
    }

    /// Get the bit at position `bit_index` (0-indexed from LSB)
    pub fn get_bit(&self, bit_index: usize) -> bool {
        if bit_index >= 256 {
            return false;
        }
        let limb_idx = bit_index / 16;
        let bit_in_limb = bit_index % 16;
        let limb = self.limbs[limb_idx].to_u64();
        (limb >> bit_in_limb) & 1 == 1
    }

    /// Count leading zeros
    pub fn leading_zeros(&self) -> usize {
        let mut count = 0;
        for i in (0..LIMB_COUNT).rev() {
            let limb = self.limbs[i].to_u64();
            if limb == 0 {
                count += 16;
            } else {
                count += (limb as u16).leading_zeros() as usize;
                break;
            }
        }
        count
    }

    /// Bit length (256 - leading_zeros)
    pub fn bit_length(&self) -> usize {
        256 - self.leading_zeros()
    }

    /// Left shift by `bits` positions
    pub fn shl(&self, bits: usize) -> Self {
        if bits >= 256 {
            return Self::zero();
        }

        let limb_shift = bits / 16;
        let bit_shift = bits % 16;

        let mut result = [Fp::ZERO; LIMB_COUNT];

        if bit_shift == 0 {
            for i in limb_shift..LIMB_COUNT {
                result[i] = self.limbs[i - limb_shift];
            }
        } else {
            for i in limb_shift..LIMB_COUNT {
                let current = self.limbs[i - limb_shift].to_u64();
                let prev = if i > limb_shift {
                    self.limbs[i - limb_shift - 1].to_u64()
                } else {
                    0
                };
                let shifted = ((current << bit_shift) | (prev >> (16 - bit_shift))) & LIMB_MAX;
                result[i] = Fp::new(shifted);
            }
        }

        U256Limbs { limbs: result }
    }

    /// Right shift by `bits` positions
    pub fn shr(&self, bits: usize) -> Self {
        if bits >= 256 {
            return Self::zero();
        }

        let limb_shift = bits / 16;
        let bit_shift = bits % 16;

        let mut result = [Fp::ZERO; LIMB_COUNT];

        if bit_shift == 0 {
            for i in 0..(LIMB_COUNT - limb_shift) {
                result[i] = self.limbs[i + limb_shift];
            }
        } else {
            for i in 0..(LIMB_COUNT - limb_shift) {
                let current = self.limbs[i + limb_shift].to_u64();
                let next = if i + limb_shift + 1 < LIMB_COUNT {
                    self.limbs[i + limb_shift + 1].to_u64()
                } else {
                    0
                };
                let shifted = ((current >> bit_shift) | (next << (16 - bit_shift))) & LIMB_MAX;
                result[i] = Fp::new(shifted);
            }
        }

        U256Limbs { limbs: result }
    }

    /// Bitwise AND
    pub fn bitand(&self, other: &Self) -> Self {
        let mut limbs = [Fp::ZERO; LIMB_COUNT];
        for i in 0..LIMB_COUNT {
            limbs[i] = Fp::new(self.limbs[i].to_u64() & other.limbs[i].to_u64());
        }
        U256Limbs { limbs }
    }

    /// Bitwise OR
    pub fn bitor(&self, other: &Self) -> Self {
        let mut limbs = [Fp::ZERO; LIMB_COUNT];
        for i in 0..LIMB_COUNT {
            limbs[i] = Fp::new(self.limbs[i].to_u64() | other.limbs[i].to_u64());
        }
        U256Limbs { limbs }
    }

    /// Bitwise XOR
    pub fn bitxor(&self, other: &Self) -> Self {
        let mut limbs = [Fp::ZERO; LIMB_COUNT];
        for i in 0..LIMB_COUNT {
            limbs[i] = Fp::new(self.limbs[i].to_u64() ^ other.limbs[i].to_u64());
        }
        U256Limbs { limbs }
    }

    /// Bitwise NOT (complement)
    pub fn bitnot(&self) -> Self {
        let mut limbs = [Fp::ZERO; LIMB_COUNT];
        for i in 0..LIMB_COUNT {
            limbs[i] = Fp::new(!self.limbs[i].to_u64() & LIMB_MAX);
        }
        U256Limbs { limbs }
    }
}

impl std::fmt::Display for U256Limbs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
        for byte in self.to_bytes_be() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_one() {
        let zero = U256Limbs::zero();
        let one = U256Limbs::one();

        assert!(zero.is_zero());
        assert!(!zero.is_one());
        assert!(!one.is_zero());
        assert!(one.is_one());
    }

    #[test]
    fn test_from_u64() {
        let x = U256Limbs::from_u64(0x123456789ABCDEF0);
        assert_eq!(x.limbs[0].to_u64(), 0xDEF0);
        assert_eq!(x.limbs[1].to_u64(), 0x9ABC);
        assert_eq!(x.limbs[2].to_u64(), 0x5678);
        assert_eq!(x.limbs[3].to_u64(), 0x1234);
        assert_eq!(x.limbs[4].to_u64(), 0);
    }

    #[test]
    fn test_bytes_roundtrip_be() {
        let bytes: [u8; 32] = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
        ];

        let x = U256Limbs::from_bytes_be(&bytes);
        let recovered = x.to_bytes_be();
        assert_eq!(bytes, recovered);
    }

    #[test]
    fn test_bytes_roundtrip_le() {
        let bytes: [u8; 32] = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
        ];

        let x = U256Limbs::from_bytes_le(&bytes);
        let recovered = x.to_bytes_le();
        assert_eq!(bytes, recovered);
    }

    #[test]
    fn test_get_bit() {
        // 0x8001 in first limb = bit 0 and bit 15 set
        let mut limbs = [Fp::ZERO; LIMB_COUNT];
        limbs[0] = Fp::new(0x8001);
        let x = U256Limbs::from_limbs(limbs);

        assert!(x.get_bit(0));
        assert!(!x.get_bit(1));
        assert!(x.get_bit(15));
        assert!(!x.get_bit(16));
    }

    #[test]
    fn test_shift_left() {
        let x = U256Limbs::from_u64(1);

        let shifted = x.shl(16);
        assert_eq!(shifted.limbs[0].to_u64(), 0);
        assert_eq!(shifted.limbs[1].to_u64(), 1);

        let shifted = x.shl(17);
        assert_eq!(shifted.limbs[0].to_u64(), 0);
        assert_eq!(shifted.limbs[1].to_u64(), 2);
    }

    #[test]
    fn test_shift_right() {
        let x = U256Limbs::from_u64(0x10000); // 1 in limb[1]

        let shifted = x.shr(16);
        assert_eq!(shifted.limbs[0].to_u64(), 1);
        assert_eq!(shifted.limbs[1].to_u64(), 0);
    }

    #[test]
    fn test_bitwise_ops() {
        let a = U256Limbs::from_u64(0xFF00FF00);
        let b = U256Limbs::from_u64(0xF0F0F0F0);

        let and = a.bitand(&b);
        assert_eq!(and.limbs[0].to_u64(), 0xF000);
        assert_eq!(and.limbs[1].to_u64(), 0xF000);

        let or = a.bitor(&b);
        assert_eq!(or.limbs[0].to_u64(), 0xFFF0);
        assert_eq!(or.limbs[1].to_u64(), 0xFFF0);

        let xor = a.bitxor(&b);
        assert_eq!(xor.limbs[0].to_u64(), 0x0FF0);
        assert_eq!(xor.limbs[1].to_u64(), 0x0FF0);
    }

    #[test]
    fn test_leading_zeros() {
        let zero = U256Limbs::zero();
        assert_eq!(zero.leading_zeros(), 256);

        let one = U256Limbs::one();
        assert_eq!(one.leading_zeros(), 255);

        let max_u64 = U256Limbs::from_u64(u64::MAX);
        assert_eq!(max_u64.leading_zeros(), 192); // 256 - 64
    }
}
