//! Goldilocks Prime Field Arithmetic
//!
//! p = 2^64 - 2^32 + 1 = 18446744069414584321
//!
//! This field has excellent properties:
//! - 64-bit operations fit in registers
//! - Two-adicity of 32 (supports FFT up to 2^32)
//! - Fast reduction using the special form

use std::ops::{Add, Sub, Mul, Div, Neg};

/// Goldilocks prime: p = 2^64 - 2^32 + 1
pub const GOLDILOCKS_PRIME: u64 = 0xFFFFFFFF00000001;

/// Two-adicity: largest k such that 2^k | (p-1)
pub const TWO_ADICITY: u32 = 32;

/// Generator of the multiplicative group
pub const GENERATOR: u64 = 7;

/// Primitive 2^32-th root of unity
/// This is GENERATOR^((p-1)/2^32) = 7^(2^32 - 1) mod p
pub const PRIMITIVE_ROOT_2_32: u64 = 1753635133440165772;

/// Field element in Goldilocks field
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fp(pub u64);

impl Fp {
    /// Zero element
    pub const ZERO: Fp = Fp(0);

    /// One element
    pub const ONE: Fp = Fp(1);

    /// Create from u64, reducing mod p
    #[inline]
    pub fn new(x: u64) -> Self {
        Fp(Self::reduce(x as u128))
    }

    /// Create from u128, reducing mod p
    #[inline]
    pub fn from_u128(x: u128) -> Self {
        Fp(Self::reduce(x))
    }

    /// Reduce a u128 modulo p using the special form of Goldilocks
    /// p = 2^64 - 2^32 + 1, so 2^64 ≡ 2^32 - 1 (mod p)
    #[inline]
    fn reduce(x: u128) -> u64 {
        // For now, use the simple approach
        // This can be optimized later with the special form
        (x % (GOLDILOCKS_PRIME as u128)) as u64
    }

    /// Optimized reduction for values that fit in u128
    /// Uses the identity: 2^64 ≡ 2^32 - 1 (mod p)
    #[inline]
    #[allow(dead_code)]
    fn reduce_fast(x: u128) -> u64 {
        // Split x = high * 2^64 + low
        let low = x as u64;
        let high = (x >> 64) as u64;

        if high == 0 {
            return if low >= GOLDILOCKS_PRIME {
                low - GOLDILOCKS_PRIME
            } else {
                low
            };
        }

        // 2^64 ≡ 2^32 - 1 (mod p)
        // high * 2^64 ≡ high * 2^32 - high (mod p)

        // Compute high * 2^32 - this fits in u64 if high < 2^32
        // For high >= 2^32, we need to handle overflow
        let (high_times_2_32, overflow1) = (high as u128).overflowing_mul(1u128 << 32);

        // Compute low + high * 2^32 - high
        let sum = (low as u128)
            .wrapping_add(high_times_2_32 as u128)
            .wrapping_sub(high as u128);

        // Handle any new overflow from the sum
        let result_low = sum as u64;
        let result_high = (sum >> 64) as u64;

        if result_high == 0 {
            if result_low >= GOLDILOCKS_PRIME {
                result_low - GOLDILOCKS_PRIME
            } else {
                result_low
            }
        } else {
            // Recurse (should only happen once)
            Self::reduce(sum)
        }
    }

    /// Check if zero
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Multiplicative inverse using Fermat's little theorem
    /// a^(-1) = a^(p-2) mod p
    pub fn inverse(&self) -> Self {
        if self.is_zero() {
            panic!("Cannot invert zero");
        }
        self.pow(GOLDILOCKS_PRIME - 2)
    }

    /// Exponentiation by squaring
    pub fn pow(&self, exp: u64) -> Self {
        let mut result = Fp::ONE;
        let mut base = *self;
        let mut e = exp;

        while e > 0 {
            if e & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            e >>= 1;
        }

        result
    }

    /// Get primitive n-th root of unity (n must be power of 2, n <= 2^32)
    /// Returns ω such that ω^n = 1 and ω^k ≠ 1 for 0 < k < n
    pub fn primitive_root_of_unity(log_n: u32) -> Self {
        assert!(log_n <= TWO_ADICITY, "Root order too large");

        // PRIMITIVE_ROOT_2_32 is the primitive 2^32-th root of unity
        // To get 2^log_n-th root, we raise it to 2^(32 - log_n)
        // Because (ω^(2^(32-log_n)))^(2^log_n) = ω^(2^32) = 1
        let omega_2_32 = Fp::new(PRIMITIVE_ROOT_2_32);
        omega_2_32.pow(1u64 << (TWO_ADICITY - log_n))
    }

    /// Convert to bytes (little-endian)
    pub fn to_bytes(&self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Convert from bytes (little-endian)
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[..8]);
        let x = u64::from_le_bytes(arr);
        Fp::new(x)
    }

    /// Get the raw u64 value
    pub fn to_u64(&self) -> u64 {
        self.0
    }
}

impl Add for Fp {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        let sum = self.0 as u128 + rhs.0 as u128;
        if sum >= GOLDILOCKS_PRIME as u128 {
            Fp((sum - GOLDILOCKS_PRIME as u128) as u64)
        } else {
            Fp(sum as u64)
        }
    }
}

impl Sub for Fp {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        if self.0 >= rhs.0 {
            Fp(self.0 - rhs.0)
        } else {
            Fp(GOLDILOCKS_PRIME - rhs.0 + self.0)
        }
    }
}

impl Mul for Fp {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let prod = self.0 as u128 * rhs.0 as u128;
        Fp(Self::reduce(prod))
    }
}

impl Div for Fp {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        self * rhs.inverse()
    }
}

impl Neg for Fp {
    type Output = Self;

    fn neg(self) -> Self {
        if self.0 == 0 {
            self
        } else {
            Fp(GOLDILOCKS_PRIME - self.0)
        }
    }
}

/// Quadratic extension field F_{p^2} = F_p[x] / (x^2 - 7)
/// Elements: a + b*α where α^2 = 7
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fp2 {
    pub c0: Fp, // Real part
    pub c1: Fp, // Imaginary part (coefficient of α)
}

/// Non-residue: α^2 = 7
const NON_RESIDUE: u64 = 7;

impl Fp2 {
    pub const ZERO: Fp2 = Fp2 { c0: Fp::ZERO, c1: Fp::ZERO };
    pub const ONE: Fp2 = Fp2 { c0: Fp::ONE, c1: Fp::ZERO };

    pub fn new(c0: Fp, c1: Fp) -> Self {
        Fp2 { c0, c1 }
    }

    pub fn from_fp(x: Fp) -> Self {
        Fp2 { c0: x, c1: Fp::ZERO }
    }

    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    /// Multiplicative inverse
    pub fn inverse(&self) -> Self {
        // (a + bα)^(-1) = (a - bα) / (a^2 - 7*b^2)
        let norm = self.c0 * self.c0 - Fp::new(NON_RESIDUE) * self.c1 * self.c1;
        let norm_inv = norm.inverse();
        Fp2 {
            c0: self.c0 * norm_inv,
            c1: -self.c1 * norm_inv,
        }
    }

    /// Exponentiation
    pub fn pow(&self, exp: u64) -> Self {
        let mut result = Fp2::ONE;
        let mut base = *self;
        let mut e = exp;

        while e > 0 {
            if e & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            e >>= 1;
        }

        result
    }
}

impl Add for Fp2 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Fp2 {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}

impl Sub for Fp2 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Fp2 {
            c0: self.c0 - rhs.c0,
            c1: self.c1 - rhs.c1,
        }
    }
}

impl Mul for Fp2 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        // (a + bα)(c + dα) = (ac + 7bd) + (ad + bc)α
        let ac = self.c0 * rhs.c0;
        let bd = self.c1 * rhs.c1;
        let ad = self.c0 * rhs.c1;
        let bc = self.c1 * rhs.c0;

        Fp2 {
            c0: ac + Fp::new(NON_RESIDUE) * bd,
            c1: ad + bc,
        }
    }
}

impl Neg for Fp2 {
    type Output = Self;

    fn neg(self) -> Self {
        Fp2 {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let a = Fp::new(123456789);
        let b = Fp::new(987654321);
        let c = a + b;
        assert_eq!(c.0, 1111111110);
    }

    #[test]
    fn test_mul() {
        let a = Fp::new(2);
        let b = Fp::new(3);
        let c = a * b;
        assert_eq!(c.0, 6);
    }

    #[test]
    fn test_inverse() {
        let a = Fp::new(12345);
        let a_inv = a.inverse();
        let should_be_one = a * a_inv;
        assert_eq!(should_be_one, Fp::ONE);
    }

    #[test]
    fn test_root_of_unity() {
        let omega = Fp::primitive_root_of_unity(4); // 16th root
        let omega_16 = omega.pow(16);
        assert_eq!(omega_16, Fp::ONE);
    }

    #[test]
    fn test_fp2_mul() {
        let a = Fp2::new(Fp::new(3), Fp::new(2)); // 3 + 2α
        let b = Fp2::new(Fp::new(1), Fp::new(4)); // 1 + 4α
        // (3 + 2α)(1 + 4α) = 3 + 12α + 2α + 8α^2 = 3 + 14α + 56 = 59 + 14α
        let c = a * b;
        assert_eq!(c.c0, Fp::new(3 + 8 * 7)); // 3 + 56 = 59
        assert_eq!(c.c1, Fp::new(14));
    }
}
