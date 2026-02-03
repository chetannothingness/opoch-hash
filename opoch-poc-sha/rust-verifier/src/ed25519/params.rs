//! Ed25519 Curve Parameters
//!
//! All constants as defined in RFC 8032.

use crate::bigint::U256Limbs;

/// Ed25519 field modulus: p = 2^255 - 19
pub const ED25519_P_BYTES: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED,
];

/// Curve parameter d = -121665/121666 mod p
/// In hex: 52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
pub const ED25519_D_BYTES: [u8; 32] = [
    0x52, 0x03, 0x6c, 0xee, 0x2b, 0x6f, 0xfe, 0x73,
    0x8c, 0xc7, 0x40, 0x79, 0x77, 0x79, 0xe8, 0x98,
    0x00, 0x70, 0x0a, 0x4d, 0x41, 0x41, 0xd8, 0xab,
    0x75, 0xeb, 0x4d, 0xca, 0x13, 0x59, 0x78, 0xa3,
];

/// Base point x-coordinate
/// In hex: 216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
pub const ED25519_BX_BYTES: [u8; 32] = [
    0x21, 0x69, 0x36, 0xd3, 0xcd, 0x6e, 0x53, 0xfe,
    0xc0, 0xa4, 0xe2, 0x31, 0xfd, 0xd6, 0xdc, 0x5c,
    0x69, 0x2c, 0xc7, 0x60, 0x95, 0x25, 0xa7, 0xb2,
    0xc9, 0x56, 0x2d, 0x60, 0x8f, 0x25, 0xd5, 0x1a,
];

/// Base point y-coordinate
/// In hex: 6666666666666666666666666666666666666666666666666666666666666658
pub const ED25519_BY_BYTES: [u8; 32] = [
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58,
];

/// Group order L = 2^252 + 27742317777372353535851937790883648493
/// In hex: 1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
pub const ED25519_L_BYTES: [u8; 32] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
    0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
];

/// Get p as U256Limbs
pub fn ed25519_p() -> U256Limbs {
    U256Limbs::from_bytes_be(&ED25519_P_BYTES)
}

/// Get d as U256Limbs
pub fn ed25519_d() -> U256Limbs {
    U256Limbs::from_bytes_be(&ED25519_D_BYTES)
}

/// Get base point x-coordinate
pub fn base_point_x() -> U256Limbs {
    U256Limbs::from_bytes_be(&ED25519_BX_BYTES)
}

/// Get base point y-coordinate
pub fn base_point_y() -> U256Limbs {
    U256Limbs::from_bytes_be(&ED25519_BY_BYTES)
}

/// Get group order L
pub fn ed25519_l() -> U256Limbs {
    U256Limbs::from_bytes_be(&ED25519_L_BYTES)
}

/// 2*d for point doubling formula
pub fn ed25519_2d() -> U256Limbs {
    // 2*d mod p (precomputed)
    let d = ed25519_d();
    // Would use modular arithmetic here
    d // Placeholder - real impl needs mod p doubling
}

/// Curve parameter a = -1
pub const ED25519_A: i8 = -1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p_value() {
        let p = ed25519_p();
        let bytes = p.to_bytes_be();
        assert_eq!(bytes[0], 0x7F);
        assert_eq!(bytes[31], 0xED);
    }

    #[test]
    fn test_l_value() {
        let l = ed25519_l();
        let bytes = l.to_bytes_be();
        assert_eq!(bytes[0], 0x10);
        assert_eq!(bytes[31], 0xED);
    }

    #[test]
    fn test_base_point() {
        let bx = base_point_x();
        let by = base_point_y();

        assert!(!bx.is_zero());
        assert!(!by.is_zero());
    }
}
