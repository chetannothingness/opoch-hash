//! secp256k1 Curve Parameters
//!
//! All constants as defined in SEC 2: Recommended Elliptic Curve Domain Parameters.

use crate::bigint::U256Limbs;

/// secp256k1 field modulus: p = 2^256 - 2^32 - 977
/// = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
pub const SECP256K1_P_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
];

/// secp256k1 group order: n
/// = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
pub const SECP256K1_N_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Generator point G x-coordinate
/// = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
pub const SECP256K1_GX_BYTES: [u8; 32] = [
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
];

/// Generator point G y-coordinate
/// = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
pub const SECP256K1_GY_BYTES: [u8; 32] = [
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
    0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
    0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
];

/// Curve parameter a = 0
pub const SECP256K1_A: u64 = 0;

/// Curve parameter b = 7
pub const SECP256K1_B: u64 = 7;

/// Get p as U256Limbs
pub fn secp256k1_p() -> U256Limbs {
    U256Limbs::from_bytes_be(&SECP256K1_P_BYTES)
}

/// Get n (group order) as U256Limbs
pub fn secp256k1_n() -> U256Limbs {
    U256Limbs::from_bytes_be(&SECP256K1_N_BYTES)
}

/// Get generator x-coordinate
pub fn generator_x() -> U256Limbs {
    U256Limbs::from_bytes_be(&SECP256K1_GX_BYTES)
}

/// Get generator y-coordinate
pub fn generator_y() -> U256Limbs {
    U256Limbs::from_bytes_be(&SECP256K1_GY_BYTES)
}

/// Get b constant (= 7)
pub fn secp256k1_b() -> U256Limbs {
    U256Limbs::from_u64(SECP256K1_B)
}

/// Half of n (for low S normalization)
pub fn half_n() -> U256Limbs {
    let n = secp256k1_n();
    n.shr(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p_value() {
        let p = secp256k1_p();
        let bytes = p.to_bytes_be();
        assert_eq!(bytes[0], 0xFF);
        assert_eq!(bytes[27], 0xFE);
        assert_eq!(bytes[31], 0x2F);
    }

    #[test]
    fn test_n_value() {
        let n = secp256k1_n();
        let bytes = n.to_bytes_be();
        assert_eq!(bytes[0], 0xFF);
        assert_eq!(bytes[15], 0xFE);
        assert_eq!(bytes[31], 0x41);
    }

    #[test]
    fn test_generator() {
        let gx = generator_x();
        let gy = generator_y();

        assert!(!gx.is_zero());
        assert!(!gy.is_zero());
    }
}
