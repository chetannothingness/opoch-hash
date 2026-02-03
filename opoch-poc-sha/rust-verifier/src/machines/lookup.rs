//! Lookup Core Machine (M_LOOKUP_CORE)
//!
//! Core lookup table operations for proving bitwise and arithmetic operations.

use super::{Machine, MachineId};
use crate::lookup::{LookupTable, LookupAccumulator, GrandProductLookup, LogDerivativeLookup};

/// Lookup table machine
pub struct LookupMachine {
    /// Table type
    pub table_type: LookupTableType,
    /// Queries to perform
    pub queries: Vec<LookupQuery>,
}

/// Types of lookup tables
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupTableType {
    /// 8-bit range check (0-255)
    U8,
    /// 16-bit range check (0-65535)
    U16,
    /// 8-bit XOR
    Xor8,
    /// 8-bit AND
    And8,
    /// 8-bit NOT
    Not8,
    /// 8-bit addition with carry
    Add8C,
    /// 16-bit carry propagation
    Carry16,
    /// 8-bit multiplication
    Mul8,
    /// Byte rotation
    Rot1Byte,
    /// Bit shift
    Shift,
}

impl LookupTableType {
    /// Get the table size
    pub fn size(&self) -> usize {
        match self {
            LookupTableType::U8 => 256,
            LookupTableType::U16 => 65536,
            LookupTableType::Xor8 => 65536,  // 256 * 256
            LookupTableType::And8 => 65536,
            LookupTableType::Not8 => 256,
            LookupTableType::Add8C => 65536 * 2, // with carry in
            LookupTableType::Carry16 => 65536,
            LookupTableType::Mul8 => 65536,
            LookupTableType::Rot1Byte => 256 * 8, // 8 rotation amounts
            LookupTableType::Shift => 256 * 8,
        }
    }

    /// Get the name
    pub fn name(&self) -> &'static str {
        match self {
            LookupTableType::U8 => "U8",
            LookupTableType::U16 => "U16",
            LookupTableType::Xor8 => "XOR8",
            LookupTableType::And8 => "AND8",
            LookupTableType::Not8 => "NOT8",
            LookupTableType::Add8C => "ADD8C",
            LookupTableType::Carry16 => "CARRY16",
            LookupTableType::Mul8 => "MUL8",
            LookupTableType::Rot1Byte => "ROT1BYTE",
            LookupTableType::Shift => "SHIFT",
        }
    }
}

/// A lookup query
#[derive(Debug, Clone)]
pub struct LookupQuery {
    /// Input(s)
    pub inputs: Vec<u64>,
    /// Expected output
    pub expected_output: u64,
}

impl LookupQuery {
    /// Create a new query
    pub fn new(inputs: Vec<u64>, expected: u64) -> Self {
        Self {
            inputs,
            expected_output: expected,
        }
    }

    /// Create a binary operation query
    pub fn binary(a: u8, b: u8, result: u8) -> Self {
        Self {
            inputs: vec![a as u64, b as u64],
            expected_output: result as u64,
        }
    }

    /// Create a unary operation query
    pub fn unary(a: u8, result: u8) -> Self {
        Self {
            inputs: vec![a as u64],
            expected_output: result as u64,
        }
    }
}

impl LookupMachine {
    /// Create a new lookup machine
    pub fn new(table_type: LookupTableType) -> Self {
        Self {
            table_type,
            queries: Vec::new(),
        }
    }

    /// Add a query
    pub fn add_query(&mut self, query: LookupQuery) {
        self.queries.push(query);
    }

    /// Execute a single query and check correctness
    pub fn execute_query(&self, query: &LookupQuery) -> bool {
        match self.table_type {
            LookupTableType::Xor8 => {
                if query.inputs.len() != 2 { return false; }
                let a = query.inputs[0] as u8;
                let b = query.inputs[1] as u8;
                let expected = (a ^ b) as u64;
                query.expected_output == expected
            }
            LookupTableType::And8 => {
                if query.inputs.len() != 2 { return false; }
                let a = query.inputs[0] as u8;
                let b = query.inputs[1] as u8;
                let expected = (a & b) as u64;
                query.expected_output == expected
            }
            LookupTableType::Not8 => {
                if query.inputs.len() != 1 { return false; }
                let a = query.inputs[0] as u8;
                let expected = (!a) as u64;
                query.expected_output == expected
            }
            LookupTableType::U8 => {
                if query.inputs.len() != 1 { return false; }
                query.inputs[0] < 256 && query.inputs[0] == query.expected_output
            }
            LookupTableType::U16 => {
                if query.inputs.len() != 1 { return false; }
                query.inputs[0] < 65536 && query.inputs[0] == query.expected_output
            }
            LookupTableType::Add8C => {
                if query.inputs.len() != 3 { return false; } // a, b, carry_in
                let a = query.inputs[0] as u16;
                let b = query.inputs[1] as u16;
                let c_in = query.inputs[2] as u16;
                let sum = a + b + c_in;
                let result = sum & 0xFF;
                let _carry_out = sum >> 8;
                query.expected_output == result as u64
            }
            LookupTableType::Mul8 => {
                if query.inputs.len() != 2 { return false; }
                let a = query.inputs[0] as u16;
                let b = query.inputs[1] as u16;
                let expected = (a * b) as u64;
                query.expected_output == expected
            }
            LookupTableType::Carry16 => {
                if query.inputs.len() != 1 { return false; }
                // Carry from 16-bit value
                query.expected_output == query.inputs[0] >> 8
            }
            LookupTableType::Rot1Byte => {
                if query.inputs.len() != 2 { return false; } // byte, rotation
                let byte = query.inputs[0] as u8;
                let rot = (query.inputs[1] % 8) as u32;
                let expected = byte.rotate_left(rot) as u64;
                query.expected_output == expected
            }
            LookupTableType::Shift => {
                if query.inputs.len() != 2 { return false; } // byte, shift amount
                let byte = query.inputs[0] as u8;
                let shift = query.inputs[1] as u32;
                if shift >= 8 {
                    query.expected_output == 0
                } else {
                    query.expected_output == (byte << shift) as u64
                }
            }
        }
    }

    /// Execute all queries and return results
    pub fn compute(&self) -> Vec<bool> {
        self.queries.iter().map(|q| self.execute_query(q)).collect()
    }

    /// Verify all queries pass
    pub fn verify_all(&self) -> bool {
        self.queries.iter().all(|q| self.execute_query(q))
    }

    /// Number of queries
    pub fn num_queries(&self) -> usize {
        self.queries.len()
    }
}

impl Machine for LookupMachine {
    fn machine_id(&self) -> MachineId {
        MachineId::LookupCore
    }

    fn input_type(&self) -> &'static str {
        "(table: LookupTableType, queries: Vec<LookupQuery>)"
    }

    fn output_type(&self) -> &'static str {
        "results: Vec<bool>"
    }

    fn estimated_cycles(&self) -> u64 {
        // ~10 cycles per lookup query
        (self.queries.len() as u64) * 10
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor8_lookup() {
        let mut machine = LookupMachine::new(LookupTableType::Xor8);
        machine.add_query(LookupQuery::binary(0x5A, 0xA5, 0xFF));
        machine.add_query(LookupQuery::binary(0xFF, 0xFF, 0x00));
        machine.add_query(LookupQuery::binary(0x00, 0x00, 0x00));

        assert!(machine.verify_all());
    }

    #[test]
    fn test_and8_lookup() {
        let mut machine = LookupMachine::new(LookupTableType::And8);
        machine.add_query(LookupQuery::binary(0xFF, 0x0F, 0x0F));
        machine.add_query(LookupQuery::binary(0xAB, 0xF0, 0xA0));

        assert!(machine.verify_all());
    }

    #[test]
    fn test_not8_lookup() {
        let mut machine = LookupMachine::new(LookupTableType::Not8);
        machine.add_query(LookupQuery::unary(0x00, 0xFF));
        machine.add_query(LookupQuery::unary(0xFF, 0x00));
        machine.add_query(LookupQuery::unary(0x55, 0xAA));

        assert!(machine.verify_all());
    }

    #[test]
    fn test_u8_range() {
        let mut machine = LookupMachine::new(LookupTableType::U8);
        for i in 0u8..=255 {
            machine.add_query(LookupQuery::new(vec![i as u64], i as u64));
        }
        assert!(machine.verify_all());
    }

    #[test]
    fn test_mul8_lookup() {
        let mut machine = LookupMachine::new(LookupTableType::Mul8);
        machine.add_query(LookupQuery::new(vec![10, 20], 200));
        machine.add_query(LookupQuery::new(vec![255, 255], 65025));

        assert!(machine.verify_all());
    }

    #[test]
    fn test_add8c_lookup() {
        let mut machine = LookupMachine::new(LookupTableType::Add8C);
        // 100 + 50 + 0 = 150
        machine.add_query(LookupQuery::new(vec![100, 50, 0], 150));
        // 200 + 100 + 0 = 300 -> 44 (mod 256)
        machine.add_query(LookupQuery::new(vec![200, 100, 0], 44));
        // 255 + 0 + 1 = 256 -> 0 (mod 256)
        machine.add_query(LookupQuery::new(vec![255, 0, 1], 0));

        assert!(machine.verify_all());
    }

    #[test]
    fn test_table_sizes() {
        assert_eq!(LookupTableType::U8.size(), 256);
        assert_eq!(LookupTableType::U16.size(), 65536);
        assert_eq!(LookupTableType::Xor8.size(), 65536);
    }

    #[test]
    fn test_invalid_query() {
        let mut machine = LookupMachine::new(LookupTableType::Xor8);
        // Wrong expected output
        machine.add_query(LookupQuery::binary(0x5A, 0xA5, 0x00));
        assert!(!machine.verify_all());
    }
}
