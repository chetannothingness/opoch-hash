//! Table Generation Functions
//!
//! Functions to generate lookup tables at compile time or runtime.
//! All tables are deterministic and reproducible.

use crate::field::Fp;

/// Generate XOR8 table as vector of (a, b, a^b) tuples
pub fn generate_xor8_table() -> Vec<(u8, u8, u8)> {
    let mut table = Vec::with_capacity(65536);
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            table.push((a, b, a ^ b));
        }
    }
    table
}

/// Generate AND8 table as vector of (a, b, a&b) tuples
pub fn generate_and8_table() -> Vec<(u8, u8, u8)> {
    let mut table = Vec::with_capacity(65536);
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            table.push((a, b, a & b));
        }
    }
    table
}

/// Generate NOT8 table as vector of (a, !a) tuples
pub fn generate_not8_table() -> Vec<(u8, u8)> {
    (0..=255u8).map(|a| (a, !a)).collect()
}

/// Generate ADD8C table as vector of (a, b, cin, sum, cout) tuples
pub fn generate_add8c_table() -> Vec<(u8, u8, u8, u8, u8)> {
    let mut table = Vec::with_capacity(131072);
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            for cin in 0..=1u8 {
                let sum_full = a as u16 + b as u16 + cin as u16;
                let cout = (sum_full >> 8) as u8;
                let s = (sum_full & 0xFF) as u8;
                table.push((a, b, cin, s, cout));
            }
        }
    }
    table
}

/// Generate CARRY16 table as vector of (x, carry, rem) tuples
/// where x = rem + 65536*carry
pub fn generate_carry16_table() -> Vec<(u32, u16, u16)> {
    let mut table = Vec::with_capacity(131072);
    for x in 0..131072u32 {
        let carry = (x >> 16) as u16;
        let rem = (x & 0xFFFF) as u16;
        table.push((x, carry, rem));
    }
    table
}

/// Generate ROT1BYTE table as vector of (byte, carry_in, byte_rot, carry_out) tuples
pub fn generate_rot1byte_table() -> Vec<(u8, u8, u8, u8)> {
    let mut table = Vec::with_capacity(512);
    for byte in 0..=255u8 {
        for carry_in in 0..=1u8 {
            let combined = ((carry_in as u16) << 8) | (byte as u16);
            let rotated = (combined >> 1) | ((combined & 1) << 8);
            let byte_rot = (rotated & 0xFF) as u8;
            let carry_out = ((rotated >> 8) & 1) as u8;
            table.push((byte, carry_in, byte_rot, carry_out));
        }
    }
    table
}

/// Generate MUL8 table as vector of (a, b, lo, hi) tuples
/// where a*b = lo + 256*hi
pub fn generate_mul8_table() -> Vec<(u8, u8, u8, u8)> {
    let mut table = Vec::with_capacity(65536);
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            let product = (a as u16) * (b as u16);
            let lo = (product & 0xFF) as u8;
            let hi = (product >> 8) as u8;
            table.push((a, b, lo, hi));
        }
    }
    table
}

/// Generate SHIFTk table for right shift by k bits
/// Returns vector of (byte, shifted, overflow) tuples
pub fn generate_shiftk_table(k: u8) -> Vec<(u8, u8, u8)> {
    assert!(k >= 1 && k <= 7, "k must be in [1, 7]");
    let mut table = Vec::with_capacity(256);
    for byte in 0..=255u8 {
        let shifted = byte >> k;
        let overflow = byte & ((1 << k) - 1);
        table.push((byte, shifted, overflow));
    }
    table
}

/// Generate all SHIFT tables (k = 1..7)
pub fn generate_all_shift_tables() -> Vec<Vec<(u8, u8, u8)>> {
    (1..=7).map(|k| generate_shiftk_table(k)).collect()
}

/// Generate U8 table as field elements
pub fn generate_u8_table() -> Vec<Fp> {
    (0..=255u64).map(Fp::new).collect()
}

/// Generate U16 table as field elements
pub fn generate_u16_table() -> Vec<Fp> {
    (0..=65535u64).map(Fp::new).collect()
}

/// Encode XOR8 entry as single field element
/// Encoding: a + 256*b + 65536*result
pub fn encode_xor8_entry(a: u8, b: u8, result: u8) -> Fp {
    Fp::new((a as u64) + (b as u64) * 256 + (result as u64) * 65536)
}

/// Decode XOR8 entry from field element
pub fn decode_xor8_entry(encoded: Fp) -> (u8, u8, u8) {
    let v = encoded.to_u64();
    let a = (v % 256) as u8;
    let b = ((v / 256) % 256) as u8;
    let result = (v / 65536) as u8;
    (a, b, result)
}

/// Encode AND8 entry as single field element
pub fn encode_and8_entry(a: u8, b: u8, result: u8) -> Fp {
    Fp::new((a as u64) + (b as u64) * 256 + (result as u64) * 65536)
}

/// Encode NOT8 entry as single field element
pub fn encode_not8_entry(a: u8, result: u8) -> Fp {
    Fp::new((a as u64) + (result as u64) * 256)
}

/// Encode ADD8C entry as single field element
/// Encoding: a + 256*b + 65536*cin + 131072*sum + 33554432*cout
pub fn encode_add8c_entry(a: u8, b: u8, cin: u8, sum: u8, cout: u8) -> Fp {
    Fp::new(
        (a as u64)
            + (b as u64) * 256
            + (cin as u64) * 65536
            + (sum as u64) * 131072
            + (cout as u64) * 33554432,
    )
}

/// Generate XOR8 table as encoded field elements
pub fn generate_xor8_table_encoded() -> Vec<Fp> {
    let mut table = Vec::with_capacity(65536);
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            table.push(encode_xor8_entry(a, b, a ^ b));
        }
    }
    table
}

/// Generate AND8 table as encoded field elements
pub fn generate_and8_table_encoded() -> Vec<Fp> {
    let mut table = Vec::with_capacity(65536);
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            table.push(encode_and8_entry(a, b, a & b));
        }
    }
    table
}

/// Generate NOT8 table as encoded field elements
pub fn generate_not8_table_encoded() -> Vec<Fp> {
    (0..=255u8).map(|a| encode_not8_entry(a, !a)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_xor8() {
        let table = generate_xor8_table();
        assert_eq!(table.len(), 65536);

        // Check specific entries
        assert!(table.contains(&(0x12, 0x34, 0x26)));
        assert!(table.contains(&(0xFF, 0xFF, 0x00)));
        assert!(table.contains(&(0x00, 0x00, 0x00)));
    }

    #[test]
    fn test_generate_and8() {
        let table = generate_and8_table();
        assert_eq!(table.len(), 65536);

        assert!(table.contains(&(0xFF, 0x0F, 0x0F)));
        assert!(table.contains(&(0xAA, 0x55, 0x00)));
    }

    #[test]
    fn test_generate_add8c() {
        let table = generate_add8c_table();
        assert_eq!(table.len(), 131072);

        // 100 + 50 + 0 = 150, cout = 0
        assert!(table.contains(&(100, 50, 0, 150, 0)));

        // 200 + 100 + 0 = 300 = 44 + 256*1
        assert!(table.contains(&(200, 100, 0, 44, 1)));

        // 255 + 255 + 1 = 511 = 255 + 256*1
        assert!(table.contains(&(255, 255, 1, 255, 1)));
    }

    #[test]
    fn test_generate_carry16() {
        let table = generate_carry16_table();
        assert_eq!(table.len(), 131072);

        // 70000 = 4464 + 65536*1
        assert!(table.contains(&(70000, 1, 4464)));

        // 65535 = 65535 + 65536*0
        assert!(table.contains(&(65535, 0, 65535)));

        // 65536 = 0 + 65536*1
        assert!(table.contains(&(65536, 1, 0)));
    }

    #[test]
    fn test_generate_rot1byte() {
        let table = generate_rot1byte_table();
        assert_eq!(table.len(), 512);

        // 0x80 with carry=0 -> 0x40, carry_out=0
        assert!(table.contains(&(0x80, 0, 0x40, 0)));

        // 0x01 with carry=0 -> 0x00, carry_out=1
        assert!(table.contains(&(0x01, 0, 0x00, 1)));

        // 0x00 with carry=1 -> 0x80, carry_out=0
        assert!(table.contains(&(0x00, 1, 0x80, 0)));
    }

    #[test]
    fn test_generate_mul8() {
        let table = generate_mul8_table();
        assert_eq!(table.len(), 65536);

        // 10 * 20 = 200
        assert!(table.contains(&(10, 20, 200, 0)));

        // 16 * 16 = 256 = 0 + 256*1
        assert!(table.contains(&(16, 16, 0, 1)));

        // 255 * 255 = 65025 = 1 + 256*254
        assert!(table.contains(&(255, 255, 1, 254)));
    }

    #[test]
    fn test_generate_shiftk() {
        // k = 3
        let table = generate_shiftk_table(3);
        assert_eq!(table.len(), 256);

        // 0xFF >> 3 = 0x1F, overflow = 0x07
        assert!(table.contains(&(0xFF, 0x1F, 0x07)));

        // 0x08 >> 3 = 0x01, overflow = 0x00
        assert!(table.contains(&(0x08, 0x01, 0x00)));
    }

    #[test]
    fn test_encode_decode_xor8() {
        for a in [0, 127, 255] {
            for b in [0, 127, 255] {
                let result = a ^ b;
                let encoded = encode_xor8_entry(a, b, result);
                let (dec_a, dec_b, dec_r) = decode_xor8_entry(encoded);
                assert_eq!((a, b, result), (dec_a, dec_b, dec_r));
            }
        }
    }
}
