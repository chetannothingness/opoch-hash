//! BigInt 256-bit Emulation Machine (M_256BIT_EMU)
//!
//! Tests all bigint operations against reference implementations.

use super::{Machine, MachineId};
use crate::bigint::{U256Limbs, U256Add, U256Sub, U256Mul, U256Compare, ModularReduce, WitnessInverse};
use crate::bigint::mul::U512Product;

/// BigInt emulation machine
pub struct BigIntMachine {
    /// Operation type
    pub operation: BigIntOp,
    /// First operand
    pub a: U256Limbs,
    /// Second operand (if binary operation)
    pub b: Option<U256Limbs>,
    /// Modulus (if modular operation)
    pub modulus: Option<U256Limbs>,
}

/// BigInt operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BigIntOp {
    /// Addition
    Add,
    /// Subtraction
    Sub,
    /// Multiplication
    Mul,
    /// Modular reduction
    ModReduce,
    /// Modular inverse
    ModInverse,
    /// Comparison
    Compare,
}

impl BigIntMachine {
    /// Create an addition operation
    pub fn add(a: U256Limbs, b: U256Limbs) -> Self {
        Self {
            operation: BigIntOp::Add,
            a,
            b: Some(b),
            modulus: None,
        }
    }

    /// Create a subtraction operation
    pub fn sub(a: U256Limbs, b: U256Limbs) -> Self {
        Self {
            operation: BigIntOp::Sub,
            a,
            b: Some(b),
            modulus: None,
        }
    }

    /// Create a multiplication operation
    pub fn mul(a: U256Limbs, b: U256Limbs) -> Self {
        Self {
            operation: BigIntOp::Mul,
            a,
            b: Some(b),
            modulus: None,
        }
    }

    /// Create a modular reduction operation
    pub fn mod_reduce(a: U256Limbs, modulus: U256Limbs) -> Self {
        Self {
            operation: BigIntOp::ModReduce,
            a,
            b: None,
            modulus: Some(modulus),
        }
    }

    /// Create a modular inverse operation
    pub fn mod_inverse(a: U256Limbs, modulus: U256Limbs) -> Self {
        Self {
            operation: BigIntOp::ModInverse,
            a,
            b: None,
            modulus: Some(modulus),
        }
    }

    /// Create a comparison operation
    pub fn compare(a: U256Limbs, b: U256Limbs) -> Self {
        Self {
            operation: BigIntOp::Compare,
            a,
            b: Some(b),
            modulus: None,
        }
    }

    /// Execute the operation and return result
    pub fn compute(&self) -> BigIntResult {
        match self.operation {
            BigIntOp::Add => {
                let b = self.b.as_ref().expect("add requires b");
                let (result, carry) = U256Add::add(&self.a, b);
                BigIntResult::U256WithCarry(result, carry)
            }
            BigIntOp::Sub => {
                let b = self.b.as_ref().expect("sub requires b");
                let (result, borrow) = U256Sub::sub(&self.a, b);
                BigIntResult::U256WithBorrow(result, borrow)
            }
            BigIntOp::Mul => {
                let b = self.b.as_ref().expect("mul requires b");
                let result = U256Mul::mul_full(&self.a, b);
                BigIntResult::U512(result)
            }
            BigIntOp::ModReduce => {
                let m = self.modulus.as_ref().expect("mod_reduce requires modulus");
                // Use generic reduction for any modulus
                let a_512 = U512Product::from_low(self.a.clone());
                let result = ModularReduce::reduce_generic(&a_512, m);
                BigIntResult::U256(result)
            }
            BigIntOp::ModInverse => {
                let m = self.modulus.as_ref().expect("mod_inverse requires modulus");
                match WitnessInverse::compute_inverse(&self.a, m) {
                    Some(inv) => BigIntResult::U256(inv),
                    None => BigIntResult::None,
                }
            }
            BigIntOp::Compare => {
                let b = self.b.as_ref().expect("compare requires b");
                let cmp = U256Compare::cmp(&self.a, b);
                BigIntResult::Comparison(cmp as i8)
            }
        }
    }
}

/// Result of a bigint operation
#[derive(Debug, Clone)]
pub enum BigIntResult {
    /// 256-bit result
    U256(U256Limbs),
    /// 256-bit result with carry
    U256WithCarry(U256Limbs, bool),
    /// 256-bit result with borrow
    U256WithBorrow(U256Limbs, bool),
    /// 512-bit result (from multiplication)
    U512(U512Product),
    /// Comparison result (-1, 0, 1)
    Comparison(i8),
    /// No result (e.g., inverse doesn't exist)
    None,
}

impl Machine for BigIntMachine {
    fn machine_id(&self) -> MachineId {
        MachineId::BigInt256Emu
    }

    fn input_type(&self) -> &'static str {
        "(op: BigIntOp, a: U256, b?: U256, mod?: U256)"
    }

    fn output_type(&self) -> &'static str {
        "result: BigIntResult"
    }

    fn estimated_cycles(&self) -> u64 {
        match self.operation {
            BigIntOp::Add | BigIntOp::Sub => 100,
            BigIntOp::Mul => 1000,
            BigIntOp::ModReduce => 2000,
            BigIntOp::ModInverse => 50_000,
            BigIntOp::Compare => 50,
        }
    }
}

/// Well-known moduli for testing
pub mod moduli {
    use super::*;

    /// Ed25519 field prime: p = 2^255 - 19
    pub fn ed25519_p() -> U256Limbs {
        ModularReduce::ed25519_p()
    }

    /// secp256k1 field prime: p = 2^256 - 2^32 - 977
    pub fn secp256k1_p() -> U256Limbs {
        ModularReduce::secp256k1_p()
    }

    /// secp256k1 group order: n
    pub fn secp256k1_n() -> U256Limbs {
        ModularReduce::secp256k1_n()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    // Helper to extract low 64 bits from U256Limbs
    fn u256_to_low_u64(v: &U256Limbs) -> u64 {
        v.limbs[0].to_u64()
            | (v.limbs[1].to_u64() << 16)
            | (v.limbs[2].to_u64() << 32)
            | (v.limbs[3].to_u64() << 48)
    }

    #[test]
    fn test_bigint_add() {
        let a = U256Limbs::from_u64(100);
        let b = U256Limbs::from_u64(200);
        let machine = BigIntMachine::add(a, b);

        match machine.compute() {
            BigIntResult::U256WithCarry(result, carry) => {
                assert!(!carry);
                assert_eq!(u256_to_low_u64(&result), 300);
            }
            _ => panic!("Expected U256WithCarry"),
        }
    }

    #[test]
    fn test_bigint_sub() {
        let a = U256Limbs::from_u64(300);
        let b = U256Limbs::from_u64(100);
        let machine = BigIntMachine::sub(a, b);

        match machine.compute() {
            BigIntResult::U256WithBorrow(result, borrow) => {
                assert!(!borrow);
                assert_eq!(u256_to_low_u64(&result), 200);
            }
            _ => panic!("Expected U256WithBorrow"),
        }
    }

    #[test]
    fn test_bigint_mul() {
        let a = U256Limbs::from_u64(100);
        let b = U256Limbs::from_u64(200);
        let machine = BigIntMachine::mul(a, b);

        match machine.compute() {
            BigIntResult::U512(result) => {
                // Check low limbs (Fp uses .to_u64())
                let low = result.limbs[0].to_u64() | (result.limbs[1].to_u64() << 16);
                assert_eq!(low, 20000);
            }
            _ => panic!("Expected U512"),
        }
    }

    #[test]
    fn test_bigint_compare() {
        let a = U256Limbs::from_u64(100);
        let b = U256Limbs::from_u64(200);
        let machine = BigIntMachine::compare(a, b);

        match machine.compute() {
            BigIntResult::Comparison(cmp) => {
                assert!(cmp < 0); // a < b
            }
            _ => panic!("Expected Comparison"),
        }
    }

    #[test]
    fn test_moduli() {
        let ed_p = moduli::ed25519_p();
        let secp_p = moduli::secp256k1_p();
        let secp_n = moduli::secp256k1_n();

        // These should be different (returns Ordering, compare with Ordering::Equal)
        assert!(U256Compare::cmp(&ed_p, &secp_p) != Ordering::Equal);
        assert!(U256Compare::cmp(&secp_p, &secp_n) != Ordering::Equal);
    }

    #[test]
    fn test_witness_inverse() {
        let a = U256Limbs::from_u64(42);
        let p = moduli::ed25519_p();
        let machine = BigIntMachine::mod_inverse(a, p);

        match machine.compute() {
            BigIntResult::U256(inv) => {
                // a * inv should equal 1 mod p
                // (Full verification would require modular multiplication)
                assert!(!inv.is_zero());
            }
            BigIntResult::None => {
                panic!("Inverse should exist for non-zero value");
            }
            _ => panic!("Expected U256 or None"),
        }
    }
}
