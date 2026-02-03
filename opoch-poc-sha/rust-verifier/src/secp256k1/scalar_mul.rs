//! secp256k1 Scalar Multiplication
//!
//! Optimized scalar multiplication for ECDSA verification.

use super::point::{JacobianPoint, AffinePoint};
use super::params;
use crate::bigint::U256Limbs;

/// Scalar multiplication: k * P
pub fn scalar_mul(point: &JacobianPoint, scalar: &U256Limbs) -> JacobianPoint {
    point.scalar_mul(scalar)
}

/// Fixed-base scalar multiplication: k * G
pub fn scalar_mul_generator(scalar: &U256Limbs) -> JacobianPoint {
    JacobianPoint::generator().scalar_mul(scalar)
}

/// Double scalar multiplication: a*G + b*P
///
/// Used in ECDSA verification: u1*G + u2*Q
pub fn double_scalar_mul(
    a: &U256Limbs,
    b: &U256Limbs,
    p: &JacobianPoint,
) -> JacobianPoint {
    // Use Strauss-Shamir trick for efficiency
    // Precompute G, P, G+P
    let g = JacobianPoint::generator();
    let gp = g.add(p);

    let mut result = JacobianPoint::infinity();

    // Process bits from MSB to LSB
    for i in (0..256).rev() {
        result = result.double();

        let a_bit = a.get_bit(i);
        let b_bit = b.get_bit(i);

        match (a_bit, b_bit) {
            (true, true) => result = result.add(&gp),
            (true, false) => result = result.add(&g),
            (false, true) => result = result.add(p),
            (false, false) => {}
        }
    }

    result
}

/// Scalar multiplication trace for AIR
#[derive(Clone, Debug)]
pub struct ScalarMulTrace {
    pub base: JacobianPoint,
    pub scalar: U256Limbs,
    pub intermediates: Vec<JacobianPoint>,
    pub result: JacobianPoint,
}

impl ScalarMulTrace {
    /// Compute with trace
    pub fn compute(base: &JacobianPoint, scalar: &U256Limbs) -> Self {
        let mut intermediates = Vec::with_capacity(256);
        let mut result = JacobianPoint::infinity();
        let mut current_base = base.clone();

        for i in 0..256 {
            if scalar.get_bit(i) {
                result = result.add(&current_base);
            }
            intermediates.push(result.clone());
            current_base = current_base.double();
        }

        ScalarMulTrace {
            base: base.clone(),
            scalar: scalar.clone(),
            intermediates,
            result,
        }
    }
}

/// Window-based scalar multiplication (for better performance)
pub struct WindowedScalarMul {
    window_size: usize,
}

impl WindowedScalarMul {
    /// Create with given window size
    pub fn new(window_size: usize) -> Self {
        assert!(window_size >= 1 && window_size <= 8);
        WindowedScalarMul { window_size }
    }

    /// Precompute table for base point: [0*P, 1*P, 2*P, ..., (2^w-1)*P]
    pub fn precompute(&self, base: &JacobianPoint) -> Vec<JacobianPoint> {
        let table_size = 1 << self.window_size;
        let mut table = Vec::with_capacity(table_size);

        table.push(JacobianPoint::infinity());
        table.push(base.clone());

        for i in 2..table_size {
            table.push(table[i - 1].add(base));
        }

        table
    }

    /// Scalar multiply using precomputed table
    pub fn scalar_mul(&self, table: &[JacobianPoint], scalar: &U256Limbs) -> JacobianPoint {
        let mut result = JacobianPoint::infinity();
        let bytes = scalar.to_bytes_le();

        // Process windows from MSB to LSB
        let num_windows = (256 + self.window_size - 1) / self.window_size;

        for i in (0..num_windows).rev() {
            // Double window_size times
            for _ in 0..self.window_size {
                result = result.double();
            }

            // Extract window value
            let bit_start = i * self.window_size;
            let mut window_val = 0usize;

            for j in 0..self.window_size {
                let bit_idx = bit_start + j;
                if bit_idx < 256 {
                    let byte_idx = bit_idx / 8;
                    let bit_in_byte = bit_idx % 8;
                    if (bytes[byte_idx] >> bit_in_byte) & 1 == 1 {
                        window_val |= 1 << j;
                    }
                }
            }

            // Add table[window_val]
            if window_val != 0 {
                result = result.add(&table[window_val]);
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_scalar_mul() {
        let g = JacobianPoint::generator();
        let a = U256Limbs::from_u64(5);
        let b = U256Limbs::from_u64(7);

        // 5*G + 7*G = 12*G
        let result = double_scalar_mul(&a, &b, &g);
        let expected = g.scalar_mul(&U256Limbs::from_u64(12));

        assert_eq!(result.to_affine(), expected.to_affine());
    }

    #[test]
    fn test_scalar_mul_trace() {
        let g = JacobianPoint::generator();
        let scalar = U256Limbs::from_u64(42);

        let trace = ScalarMulTrace::compute(&g, &scalar);

        let expected = scalar_mul(&g, &scalar);
        assert_eq!(trace.result.to_affine(), expected.to_affine());
        assert_eq!(trace.intermediates.len(), 256);
    }

    #[test]
    fn test_windowed_scalar_mul() {
        let g = JacobianPoint::generator();
        let scalar = U256Limbs::from_u64(12345);

        let windowed = WindowedScalarMul::new(4);
        let table = windowed.precompute(&g);
        let result = windowed.scalar_mul(&table, &scalar);

        let expected = g.scalar_mul(&scalar);
        assert_eq!(result.to_affine(), expected.to_affine());
    }
}
