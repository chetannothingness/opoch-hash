//! Keccak Constants
//!
//! Round constants and rotation offsets for Keccak-f[1600].

/// Round constants (24 rounds)
pub const KECCAK_RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Rotation offsets for ρ step
/// RHO_OFFSETS[x][y] gives the rotation for lane (x, y)
pub const RHO_OFFSETS: [[usize; 5]; 5] = [
    [ 0, 36,  3, 41, 18],
    [ 1, 44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
];

/// π step permutation coefficients
/// (x, y) -> (y, 2*x + 3*y mod 5)
pub const fn pi_x(x: usize, _y: usize) -> usize {
    _y
}

pub const fn pi_y(x: usize, y: usize) -> usize {
    (2 * x + 3 * y) % 5
}

/// Precomputed π permutation for (x, y) -> (new_x, new_y)
pub const PI_PERMUTATION: [[(usize, usize); 5]; 5] = [
    [(0, 0), (1, 2), (2, 4), (3, 1), (4, 3)],
    [(0, 3), (1, 0), (2, 2), (3, 4), (4, 1)],
    [(0, 1), (1, 3), (2, 0), (3, 2), (4, 4)],
    [(0, 4), (1, 1), (2, 3), (3, 0), (4, 2)],
    [(0, 2), (1, 4), (2, 1), (3, 3), (4, 0)],
];

/// Get round constant as byte array (little-endian)
pub fn rc_bytes(round: usize) -> [u8; 8] {
    KECCAK_RC[round].to_le_bytes()
}

/// Get rotation offset for lane (x, y)
pub fn rho_offset(x: usize, y: usize) -> usize {
    RHO_OFFSETS[x][y]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_constants() {
        assert_eq!(KECCAK_RC.len(), 24);
        assert_eq!(KECCAK_RC[0], 1);
        assert_eq!(KECCAK_RC[23], 0x8000000080008008);
    }

    #[test]
    fn test_rho_offsets() {
        // Lane (0, 0) has rotation 0
        assert_eq!(RHO_OFFSETS[0][0], 0);
        // Lane (1, 0) has rotation 1
        assert_eq!(RHO_OFFSETS[0][1], 36);
    }

    #[test]
    fn test_pi_permutation() {
        // (1, 0) -> (0, 2*1 + 3*0 mod 5) = (0, 2)
        assert_eq!(pi_x(1, 0), 0);
        assert_eq!(pi_y(1, 0), 2);
    }
}
