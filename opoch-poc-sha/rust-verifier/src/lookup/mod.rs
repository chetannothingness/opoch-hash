//! Lookup Tables Engine for STARK Proofs
//!
//! This module implements lookup arguments for efficiently proving
//! bitwise operations (XOR, AND, NOT) and range checks.
//!
//! ## Architecture
//!
//! Two lookup argument implementations are provided:
//! - **Grand Product**: Permutation-based lookup (more robust)
//! - **Log-Derivative**: Sum-based lookup (faster for large tables)
//!
//! ## Supported Tables
//!
//! - U8: Range check for bytes [0, 255]
//! - U16: Range check for 16-bit values [0, 65535]
//! - XOR8: 8-bit XOR lookup (a, b, a^b)
//! - AND8: 8-bit AND lookup (a, b, a&b)
//! - NOT8: 8-bit NOT lookup (a, ~a & 0xFF)
//! - ADD8C: 8-bit addition with carry (a, b, cin, sum, cout)
//! - CARRY16: 16-bit carry extraction
//! - MUL8: 8-bit multiplication (a, b, lo, hi)
//! - ROT1BYTE: 1-bit rotation across bytes
//! - SHIFTk: k-bit shift within bytes (k = 1..7)

pub mod tables;
pub mod generate;
pub mod grand_product;
pub mod log_derivative;

pub use tables::*;
pub use generate::*;
pub use grand_product::{GrandProductLookup, LookupProof};
pub use log_derivative::LogDerivativeLookup;

use crate::field::Fp;
use crate::transcript::Transcript;

/// Lookup table trait
pub trait LookupTable {
    /// Table name for identification
    fn name(&self) -> &'static str;

    /// Table size
    fn size(&self) -> usize;

    /// Get table entry as field element
    fn get(&self, index: usize) -> Fp;

    /// Find index of value in table (returns None if not found)
    fn find(&self, value: Fp) -> Option<usize>;

    /// Check if value exists in table
    fn contains(&self, value: Fp) -> bool {
        self.find(value).is_some()
    }
}

/// Lookup accumulator for collecting lookup queries during AIR evaluation
#[derive(Default)]
pub struct LookupAccumulator {
    /// XOR8 queries: (a, b, result)
    pub xor8_queries: Vec<(Fp, Fp, Fp)>,
    /// AND8 queries: (a, b, result)
    pub and8_queries: Vec<(Fp, Fp, Fp)>,
    /// NOT8 queries: (a, result)
    pub not8_queries: Vec<(Fp, Fp)>,
    /// ADD8C queries: (a, b, cin, sum, cout)
    pub add8c_queries: Vec<(Fp, Fp, Fp, Fp, Fp)>,
    /// U8 range queries
    pub u8_queries: Vec<Fp>,
    /// U16 range queries
    pub u16_queries: Vec<Fp>,
    /// ROT1BYTE queries: (byte_in, carry_in, byte_out, carry_out)
    pub rot1byte_queries: Vec<(Fp, Fp, Fp, Fp)>,
}

impl LookupAccumulator {
    /// Create new empty accumulator
    pub fn new() -> Self {
        Self::default()
    }

    /// Add XOR8 lookup query
    pub fn add_xor8(&mut self, a: Fp, b: Fp, result: Fp) {
        self.xor8_queries.push((a, b, result));
    }

    /// Add XOR8 lookup with constant (for ι step in Keccak)
    pub fn add_xor8_const(&mut self, a: Fp, constant: Fp, result: Fp) {
        self.xor8_queries.push((a, constant, result));
    }

    /// Add AND8 lookup query
    pub fn add_and8(&mut self, a: Fp, b: Fp, result: Fp) {
        self.and8_queries.push((a, b, result));
    }

    /// Add NOT8 lookup query
    pub fn add_not8(&mut self, a: Fp, result: Fp) {
        self.not8_queries.push((a, result));
    }

    /// Add ADD8C lookup query
    pub fn add_add8c(&mut self, a: Fp, b: Fp, cin: Fp, sum: Fp, cout: Fp) {
        self.add8c_queries.push((a, b, cin, sum, cout));
    }

    /// Add U8 range check
    pub fn add_u8(&mut self, value: Fp) {
        self.u8_queries.push(value);
    }

    /// Add U16 range check
    pub fn add_u16(&mut self, value: Fp) {
        self.u16_queries.push(value);
    }

    /// Add ROT1BYTE lookup query
    pub fn add_rot1byte(&mut self, byte_in: Fp, carry_in: Fp, byte_out: Fp, carry_out: Fp) {
        self.rot1byte_queries.push((byte_in, carry_in, byte_out, carry_out));
    }

    /// Total number of queries
    pub fn total_queries(&self) -> usize {
        self.xor8_queries.len()
            + self.and8_queries.len()
            + self.not8_queries.len()
            + self.add8c_queries.len()
            + self.u8_queries.len()
            + self.u16_queries.len()
            + self.rot1byte_queries.len()
    }

    /// Clear all accumulated queries
    pub fn clear(&mut self) {
        self.xor8_queries.clear();
        self.and8_queries.clear();
        self.not8_queries.clear();
        self.add8c_queries.clear();
        self.u8_queries.clear();
        self.u16_queries.clear();
        self.rot1byte_queries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accumulator() {
        let mut acc = LookupAccumulator::new();

        acc.add_xor8(Fp::new(0x12), Fp::new(0x34), Fp::new(0x12 ^ 0x34));
        acc.add_and8(Fp::new(0xFF), Fp::new(0x0F), Fp::new(0x0F));
        acc.add_u8(Fp::new(128));

        assert_eq!(acc.total_queries(), 3);
    }
}
