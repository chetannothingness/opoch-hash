//! Lookup Table Definitions
//!
//! Defines all lookup tables with pinned specifications.
//! Tables are generated at compile time for efficiency.

use crate::field::Fp;
use super::LookupTable;

/// U8 range table: {0, 1, ..., 255}
pub const U8_TABLE_SIZE: usize = 256;

/// U16 range table: {0, 1, ..., 65535}
pub const U16_TABLE_SIZE: usize = 65536;

/// XOR8 table: (a, b, a^b) for a,b in [0,255]
/// Size: 256 * 256 = 65536 entries
pub const XOR8_TABLE_SIZE: usize = 65536;

/// AND8 table: (a, b, a&b) for a,b in [0,255]
pub const AND8_TABLE_SIZE: usize = 65536;

/// NOT8 table: (a, !a & 0xFF) for a in [0,255]
pub const NOT8_TABLE_SIZE: usize = 256;

/// ADD8C table: (a, b, cin, sum, cout)
/// a + b + cin = sum + 256*cout
/// Size: 256 * 256 * 2 = 131072 entries
pub const ADD8C_TABLE_SIZE: usize = 131072;

/// CARRY16 table: (x, carry, rem) where x = rem + 65536*carry
/// For x in [0, 2^17-1], carry in {0,1}, rem in [0,65535]
pub const CARRY16_TABLE_SIZE: usize = 131072;

/// MUL8 table: (a, b, lo, hi) where a*b = lo + 256*hi
pub const MUL8_TABLE_SIZE: usize = 65536;

/// BIT table: {0, 1}
pub const BIT_TABLE_SIZE: usize = 2;

/// ROT1BYTE table: (byte, carry_in, byte_rot, carry_out)
/// For 1-bit rotation across bytes
pub const ROT1BYTE_TABLE_SIZE: usize = 512;

/// SHIFTk tables for k in 1..7
/// (byte, shifted_byte, overflow_bits)
pub const SHIFT_TABLE_SIZE: usize = 256 * 7;

/// U8 Range Table
#[derive(Clone)]
pub struct U8Table {
    entries: Vec<Fp>,
}

impl U8Table {
    pub fn new() -> Self {
        let entries: Vec<Fp> = (0..=255u8).map(|x| Fp::new(x as u64)).collect();
        U8Table { entries }
    }
}

impl Default for U8Table {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupTable for U8Table {
    fn name(&self) -> &'static str {
        "U8"
    }

    fn size(&self) -> usize {
        U8_TABLE_SIZE
    }

    fn get(&self, index: usize) -> Fp {
        self.entries[index]
    }

    fn find(&self, value: Fp) -> Option<usize> {
        let v = value.to_u64();
        if v < 256 {
            Some(v as usize)
        } else {
            None
        }
    }
}

/// U16 Range Table
#[derive(Clone)]
pub struct U16Table {
    /// We don't store all 65536 entries - use lazy evaluation
    _marker: (),
}

impl U16Table {
    pub fn new() -> Self {
        U16Table { _marker: () }
    }
}

impl Default for U16Table {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupTable for U16Table {
    fn name(&self) -> &'static str {
        "U16"
    }

    fn size(&self) -> usize {
        U16_TABLE_SIZE
    }

    fn get(&self, index: usize) -> Fp {
        Fp::new(index as u64)
    }

    fn find(&self, value: Fp) -> Option<usize> {
        let v = value.to_u64();
        if v < 65536 {
            Some(v as usize)
        } else {
            None
        }
    }
}

/// XOR8 Lookup Table
/// Stores (a, b, a^b) as combined value: a + 256*b + 65536*(a^b)
#[derive(Clone)]
pub struct Xor8Table {
    /// Map from combined input (a + 256*b) to output (a^b)
    entries: Vec<u8>,
}

impl Xor8Table {
    pub fn new() -> Self {
        let mut entries = vec![0u8; XOR8_TABLE_SIZE];
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let idx = (a as usize) + (b as usize) * 256;
                entries[idx] = a ^ b;
            }
        }
        Xor8Table { entries }
    }

    /// Lookup XOR result
    pub fn lookup(&self, a: u8, b: u8) -> u8 {
        self.entries[(a as usize) + (b as usize) * 256]
    }

    /// Verify XOR relationship
    pub fn verify(&self, a: Fp, b: Fp, result: Fp) -> bool {
        let a_val = a.to_u64();
        let b_val = b.to_u64();
        let r_val = result.to_u64();

        if a_val > 255 || b_val > 255 || r_val > 255 {
            return false;
        }

        let expected = self.entries[(a_val as usize) + (b_val as usize) * 256];
        r_val == expected as u64
    }
}

impl Default for Xor8Table {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupTable for Xor8Table {
    fn name(&self) -> &'static str {
        "XOR8"
    }

    fn size(&self) -> usize {
        XOR8_TABLE_SIZE
    }

    fn get(&self, index: usize) -> Fp {
        // Index encodes (a, b), return combined value
        let a = index % 256;
        let b = index / 256;
        let result = self.entries[index];
        // Return combined: a + 256*b + 65536*result
        Fp::new((a + 256 * b + 65536 * (result as usize)) as u64)
    }

    fn find(&self, value: Fp) -> Option<usize> {
        let v = value.to_u64();
        let a = (v % 256) as usize;
        let b = ((v / 256) % 256) as usize;
        let expected_result = (v / 65536) as u8;

        let actual_result = self.entries[a + 256 * b];
        if actual_result == expected_result {
            Some(a + 256 * b)
        } else {
            None
        }
    }
}

/// AND8 Lookup Table
#[derive(Clone)]
pub struct And8Table {
    entries: Vec<u8>,
}

impl And8Table {
    pub fn new() -> Self {
        let mut entries = vec![0u8; AND8_TABLE_SIZE];
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let idx = (a as usize) + (b as usize) * 256;
                entries[idx] = a & b;
            }
        }
        And8Table { entries }
    }

    /// Lookup AND result
    pub fn lookup(&self, a: u8, b: u8) -> u8 {
        self.entries[(a as usize) + (b as usize) * 256]
    }

    /// Verify AND relationship
    pub fn verify(&self, a: Fp, b: Fp, result: Fp) -> bool {
        let a_val = a.to_u64();
        let b_val = b.to_u64();
        let r_val = result.to_u64();

        if a_val > 255 || b_val > 255 || r_val > 255 {
            return false;
        }

        let expected = self.entries[(a_val as usize) + (b_val as usize) * 256];
        r_val == expected as u64
    }
}

impl Default for And8Table {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupTable for And8Table {
    fn name(&self) -> &'static str {
        "AND8"
    }

    fn size(&self) -> usize {
        AND8_TABLE_SIZE
    }

    fn get(&self, index: usize) -> Fp {
        let a = index % 256;
        let b = index / 256;
        let result = self.entries[index];
        Fp::new((a + 256 * b + 65536 * (result as usize)) as u64)
    }

    fn find(&self, value: Fp) -> Option<usize> {
        let v = value.to_u64();
        let a = (v % 256) as usize;
        let b = ((v / 256) % 256) as usize;
        let expected_result = (v / 65536) as u8;

        let actual_result = self.entries[a + 256 * b];
        if actual_result == expected_result {
            Some(a + 256 * b)
        } else {
            None
        }
    }
}

/// NOT8 Lookup Table
#[derive(Clone)]
pub struct Not8Table {
    entries: Vec<u8>,
}

impl Not8Table {
    pub fn new() -> Self {
        let entries: Vec<u8> = (0..=255u8).map(|x| !x).collect();
        Not8Table { entries }
    }

    /// Lookup NOT result
    pub fn lookup(&self, a: u8) -> u8 {
        self.entries[a as usize]
    }

    /// Verify NOT relationship
    pub fn verify(&self, a: Fp, result: Fp) -> bool {
        let a_val = a.to_u64();
        let r_val = result.to_u64();

        if a_val > 255 || r_val > 255 {
            return false;
        }

        r_val == self.entries[a_val as usize] as u64
    }
}

impl Default for Not8Table {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupTable for Not8Table {
    fn name(&self) -> &'static str {
        "NOT8"
    }

    fn size(&self) -> usize {
        NOT8_TABLE_SIZE
    }

    fn get(&self, index: usize) -> Fp {
        // Return combined: a + 256*result
        let result = self.entries[index];
        Fp::new((index + 256 * (result as usize)) as u64)
    }

    fn find(&self, value: Fp) -> Option<usize> {
        let v = value.to_u64();
        let a = (v % 256) as usize;
        let expected_result = (v / 256) as u8;

        let actual_result = self.entries[a];
        if actual_result == expected_result {
            Some(a)
        } else {
            None
        }
    }
}

/// ADD8C Lookup Table: (a, b, cin, sum, cout)
/// where a + b + cin = sum + 256*cout
#[derive(Clone)]
pub struct Add8cTable {
    /// Store (sum, cout) for each (a, b, cin)
    entries: Vec<(u8, u8)>,
}

impl Add8cTable {
    pub fn new() -> Self {
        let mut entries = Vec::with_capacity(ADD8C_TABLE_SIZE);
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                for cin in 0..=1u8 {
                    let sum_full = a as u16 + b as u16 + cin as u16;
                    let cout = (sum_full >> 8) as u8;
                    let sum = (sum_full & 0xFF) as u8;
                    entries.push((sum, cout));
                }
            }
        }
        Add8cTable { entries }
    }

    /// Get index from (a, b, cin)
    /// Entries are generated with a in outer loop, b in middle, cin in inner
    fn index(a: u8, b: u8, cin: u8) -> usize {
        (cin as usize) + (b as usize) * 2 + (a as usize) * 512
    }

    /// Lookup add result
    pub fn lookup(&self, a: u8, b: u8, cin: u8) -> (u8, u8) {
        self.entries[Self::index(a, b, cin)]
    }

    /// Verify addition relationship
    pub fn verify(&self, a: Fp, b: Fp, cin: Fp, sum: Fp, cout: Fp) -> bool {
        let a_val = a.to_u64();
        let b_val = b.to_u64();
        let cin_val = cin.to_u64();
        let sum_val = sum.to_u64();
        let cout_val = cout.to_u64();

        if a_val > 255 || b_val > 255 || cin_val > 1 || sum_val > 255 || cout_val > 1 {
            return false;
        }

        let (expected_sum, expected_cout) = self.entries[Self::index(a_val as u8, b_val as u8, cin_val as u8)];
        sum_val == expected_sum as u64 && cout_val == expected_cout as u64
    }
}

impl Default for Add8cTable {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupTable for Add8cTable {
    fn name(&self) -> &'static str {
        "ADD8C"
    }

    fn size(&self) -> usize {
        ADD8C_TABLE_SIZE
    }

    fn get(&self, index: usize) -> Fp {
        let a = index % 256;
        let b = (index / 256) % 256;
        let cin = index / 65536;
        let (sum, cout) = self.entries[index];
        // Combined: a + 256*b + 65536*cin + 131072*sum + 33554432*cout
        Fp::new((a + 256 * b + 65536 * cin + 131072 * (sum as usize) + 33554432 * (cout as usize)) as u64)
    }

    fn find(&self, _value: Fp) -> Option<usize> {
        // Complex decoding - implement if needed
        None
    }
}

/// ROT1BYTE Lookup Table: (byte, carry_in, byte_rot, carry_out)
/// For 1-bit right rotation across bytes
#[derive(Clone)]
pub struct Rot1ByteTable {
    /// Store (byte_rot, carry_out) for each (byte, carry_in)
    entries: Vec<(u8, u8)>,
}

impl Rot1ByteTable {
    pub fn new() -> Self {
        let mut entries = Vec::with_capacity(ROT1BYTE_TABLE_SIZE);
        for byte in 0..=255u8 {
            for carry_in in 0..=1u8 {
                let combined = ((carry_in as u16) << 8) | (byte as u16);
                let rotated = (combined >> 1) | ((combined & 1) << 8);
                let byte_rot = (rotated & 0xFF) as u8;
                let carry_out = ((rotated >> 8) & 1) as u8;
                entries.push((byte_rot, carry_out));
            }
        }
        Rot1ByteTable { entries }
    }

    /// Lookup rotation result
    pub fn lookup(&self, byte: u8, carry_in: u8) -> (u8, u8) {
        // Entries are generated with byte in outer loop, carry_in in inner
        let idx = (carry_in as usize) + (byte as usize) * 2;
        self.entries[idx]
    }

    /// Verify rotation relationship
    pub fn verify(&self, byte_in: Fp, carry_in: Fp, byte_out: Fp, carry_out: Fp) -> bool {
        let b_val = byte_in.to_u64();
        let cin_val = carry_in.to_u64();
        let bout_val = byte_out.to_u64();
        let cout_val = carry_out.to_u64();

        if b_val > 255 || cin_val > 1 || bout_val > 255 || cout_val > 1 {
            return false;
        }

        let idx = (b_val as usize) + (cin_val as usize) * 256;
        let (expected_bout, expected_cout) = self.entries[idx];
        bout_val == expected_bout as u64 && cout_val == expected_cout as u64
    }
}

impl Default for Rot1ByteTable {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupTable for Rot1ByteTable {
    fn name(&self) -> &'static str {
        "ROT1BYTE"
    }

    fn size(&self) -> usize {
        ROT1BYTE_TABLE_SIZE
    }

    fn get(&self, index: usize) -> Fp {
        let byte = index % 256;
        let carry_in = index / 256;
        let (byte_rot, carry_out) = self.entries[index];
        Fp::new((byte + 256 * carry_in + 512 * (byte_rot as usize) + 131072 * (carry_out as usize)) as u64)
    }

    fn find(&self, _value: Fp) -> Option<usize> {
        None
    }
}

/// MUL8 Lookup Table: (a, b, lo, hi) where a*b = lo + 256*hi
#[derive(Clone)]
pub struct Mul8Table {
    entries: Vec<(u8, u8)>,
}

impl Mul8Table {
    pub fn new() -> Self {
        let mut entries = Vec::with_capacity(MUL8_TABLE_SIZE);
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let product = (a as u16) * (b as u16);
                let lo = (product & 0xFF) as u8;
                let hi = (product >> 8) as u8;
                entries.push((lo, hi));
            }
        }
        Mul8Table { entries }
    }

    /// Lookup multiplication result
    pub fn lookup(&self, a: u8, b: u8) -> (u8, u8) {
        let idx = (a as usize) + (b as usize) * 256;
        self.entries[idx]
    }

    /// Verify multiplication relationship
    pub fn verify(&self, a: Fp, b: Fp, lo: Fp, hi: Fp) -> bool {
        let a_val = a.to_u64();
        let b_val = b.to_u64();
        let lo_val = lo.to_u64();
        let hi_val = hi.to_u64();

        if a_val > 255 || b_val > 255 || lo_val > 255 || hi_val > 255 {
            return false;
        }

        let idx = (a_val as usize) + (b_val as usize) * 256;
        let (expected_lo, expected_hi) = self.entries[idx];
        lo_val == expected_lo as u64 && hi_val == expected_hi as u64
    }
}

impl Default for Mul8Table {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupTable for Mul8Table {
    fn name(&self) -> &'static str {
        "MUL8"
    }

    fn size(&self) -> usize {
        MUL8_TABLE_SIZE
    }

    fn get(&self, index: usize) -> Fp {
        let a = index % 256;
        let b = index / 256;
        let (lo, hi) = self.entries[index];
        Fp::new((a + 256 * b + 65536 * (lo as usize) + 16777216 * (hi as usize)) as u64)
    }

    fn find(&self, _value: Fp) -> Option<usize> {
        None
    }
}

/// All tables combined for efficient access
pub struct AllTables {
    pub u8_table: U8Table,
    pub u16_table: U16Table,
    pub xor8_table: Xor8Table,
    pub and8_table: And8Table,
    pub not8_table: Not8Table,
    pub add8c_table: Add8cTable,
    pub rot1byte_table: Rot1ByteTable,
    pub mul8_table: Mul8Table,
}

impl AllTables {
    /// Create all tables
    pub fn new() -> Self {
        AllTables {
            u8_table: U8Table::new(),
            u16_table: U16Table::new(),
            xor8_table: Xor8Table::new(),
            and8_table: And8Table::new(),
            not8_table: Not8Table::new(),
            add8c_table: Add8cTable::new(),
            rot1byte_table: Rot1ByteTable::new(),
            mul8_table: Mul8Table::new(),
        }
    }
}

impl Default for AllTables {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u8_table() {
        let table = U8Table::new();
        assert_eq!(table.size(), 256);
        assert_eq!(table.get(0), Fp::ZERO);
        assert_eq!(table.get(255), Fp::new(255));
        assert!(table.contains(Fp::new(128)));
        assert!(!table.contains(Fp::new(256)));
    }

    #[test]
    fn test_xor8_table() {
        let table = Xor8Table::new();
        assert_eq!(table.lookup(0x12, 0x34), 0x12 ^ 0x34);
        assert_eq!(table.lookup(0xFF, 0x00), 0xFF);
        assert_eq!(table.lookup(0xAB, 0xCD), 0xAB ^ 0xCD);

        assert!(table.verify(Fp::new(0x12), Fp::new(0x34), Fp::new(0x12 ^ 0x34)));
        assert!(!table.verify(Fp::new(0x12), Fp::new(0x34), Fp::new(0xFF)));
    }

    #[test]
    fn test_and8_table() {
        let table = And8Table::new();
        assert_eq!(table.lookup(0xFF, 0x0F), 0x0F);
        assert_eq!(table.lookup(0xAA, 0x55), 0x00);
        assert_eq!(table.lookup(0xFF, 0xFF), 0xFF);

        assert!(table.verify(Fp::new(0xFF), Fp::new(0x0F), Fp::new(0x0F)));
    }

    #[test]
    fn test_not8_table() {
        let table = Not8Table::new();
        assert_eq!(table.lookup(0x00), 0xFF);
        assert_eq!(table.lookup(0xFF), 0x00);
        assert_eq!(table.lookup(0xAA), 0x55);

        assert!(table.verify(Fp::new(0xAA), Fp::new(0x55)));
    }

    #[test]
    fn test_add8c_table() {
        let table = Add8cTable::new();

        // 100 + 50 + 0 = 150, carry = 0
        let (sum, cout) = table.lookup(100, 50, 0);
        assert_eq!(sum, 150);
        assert_eq!(cout, 0);

        // 200 + 100 + 0 = 44 + 256*1
        let (sum, cout) = table.lookup(200, 100, 0);
        assert_eq!(sum, 44);
        assert_eq!(cout, 1);

        // 255 + 255 + 1 = 255 + 256*1
        let (sum, cout) = table.lookup(255, 255, 1);
        assert_eq!(sum, 255);
        assert_eq!(cout, 1);
    }

    #[test]
    fn test_rot1byte_table() {
        let table = Rot1ByteTable::new();

        // 0b10000000 with carry_in=0 -> 0b01000000, carry_out=0
        let (byte_rot, carry_out) = table.lookup(0x80, 0);
        assert_eq!(byte_rot, 0x40);
        assert_eq!(carry_out, 0);

        // 0b00000001 with carry_in=0 -> 0b00000000, carry_out=1
        let (byte_rot, carry_out) = table.lookup(0x01, 0);
        assert_eq!(byte_rot, 0x00);
        assert_eq!(carry_out, 1);

        // 0b00000000 with carry_in=1 -> 0b10000000, carry_out=0
        let (byte_rot, carry_out) = table.lookup(0x00, 1);
        assert_eq!(byte_rot, 0x80);
        assert_eq!(carry_out, 0);
    }

    #[test]
    fn test_mul8_table() {
        let table = Mul8Table::new();

        // 10 * 20 = 200, hi = 0
        let (lo, hi) = table.lookup(10, 20);
        assert_eq!(lo, 200);
        assert_eq!(hi, 0);

        // 16 * 16 = 256 = 0 + 256*1
        let (lo, hi) = table.lookup(16, 16);
        assert_eq!(lo, 0);
        assert_eq!(hi, 1);

        // 255 * 255 = 65025 = 1 + 256*254
        let (lo, hi) = table.lookup(255, 255);
        assert_eq!(lo, 1);
        assert_eq!(hi, 254);
    }
}
