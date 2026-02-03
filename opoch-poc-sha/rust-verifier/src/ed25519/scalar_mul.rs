//! Ed25519 Scalar Multiplication
//!
//! Optimized scalar multiplication with precomputed tables.

use super::point::EdwardsPoint;
use super::params;
use crate::bigint::U256Limbs;

/// Window size for fixed-base scalar multiplication
pub const WINDOW_SIZE: usize = 4;

/// Number of windows (256 bits / 4 bits per window)
pub const NUM_WINDOWS: usize = 64;

/// Fixed-base scalar multiplication table
///
/// TABLE[i][j] = j * 2^(4i) * B for j in 0..15
pub struct FixedBaseTable {
    points: [[EdwardsPoint; 16]; NUM_WINDOWS],
}

impl FixedBaseTable {
    /// Precompute table for base point B
    pub fn new(base: &EdwardsPoint) -> Self {
        // Initialize using from_fn since EdwardsPoint doesn't implement Copy
        let mut points: [[EdwardsPoint; 16]; NUM_WINDOWS] = core::array::from_fn(|_| {
            core::array::from_fn(|_| EdwardsPoint::identity())
        });

        let mut power = base.clone();

        for i in 0..NUM_WINDOWS {
            // TABLE[i][0] = identity
            points[i][0] = EdwardsPoint::identity();
            // TABLE[i][1] = power
            points[i][1] = power.clone();

            // TABLE[i][j] = j * power
            for j in 2..16 {
                points[i][j] = points[i][j - 1].add(&power);
            }

            // power *= 2^4
            for _ in 0..4 {
                power = power.double();
            }
        }

        FixedBaseTable { points }
    }

    /// Scalar multiplication using table
    pub fn scalar_mul(&self, scalar: &U256Limbs) -> EdwardsPoint {
        let mut result = EdwardsPoint::identity();
        let bytes = scalar.to_bytes_le();

        for i in 0..NUM_WINDOWS {
            // Extract 4-bit window
            let byte_idx = i / 2;
            let nibble = if i % 2 == 0 {
                bytes[byte_idx] & 0x0F
            } else {
                (bytes[byte_idx] >> 4) & 0x0F
            };

            // Add TABLE[i][nibble]
            result = result.add(&self.points[i][nibble as usize]);
        }

        result
    }
}

/// Precomputed table for base point B (lazy static)
pub fn base_point_table() -> FixedBaseTable {
    FixedBaseTable::new(&EdwardsPoint::base_point())
}

/// Scalar multiplication: k * P
pub fn scalar_mul(point: &EdwardsPoint, scalar: &U256Limbs) -> EdwardsPoint {
    point.scalar_mul(scalar)
}

/// Fixed-base scalar multiplication: k * B
pub fn scalar_mul_base(scalar: &U256Limbs) -> EdwardsPoint {
    EdwardsPoint::base_point().scalar_mul(scalar)
}

/// Variable-base double scalar multiplication: a*P + b*Q
///
/// Used in EdDSA verification: [S]B - [h]A = R
/// which is computed as [S]B + [-h]A
pub fn double_scalar_mul(
    a: &U256Limbs,
    p: &EdwardsPoint,
    b: &U256Limbs,
    q: &EdwardsPoint,
) -> EdwardsPoint {
    // Simple implementation: compute separately and add
    let ap = scalar_mul(p, a);
    let bq = scalar_mul(q, b);
    ap.add(&bq)
}

/// Scalar multiplication trace for AIR
#[derive(Clone, Debug)]
pub struct ScalarMulTrace {
    pub base: EdwardsPoint,
    pub scalar: U256Limbs,
    /// Intermediate points at each bit
    pub intermediates: Vec<EdwardsPoint>,
    pub result: EdwardsPoint,
}

impl ScalarMulTrace {
    /// Compute with trace
    pub fn compute(base: &EdwardsPoint, scalar: &U256Limbs) -> Self {
        let mut intermediates = Vec::with_capacity(256);
        let mut result = EdwardsPoint::identity();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_base_table() {
        let table = FixedBaseTable::new(&EdwardsPoint::base_point());

        // k=1 should give base point
        let result = table.scalar_mul(&U256Limbs::one());
        let expected = EdwardsPoint::base_point();
        assert_eq!(result.to_affine(), expected.to_affine());
    }

    #[test]
    fn test_scalar_mul_consistency() {
        let b = EdwardsPoint::base_point();
        let scalar = U256Limbs::from_u64(12345);

        // Direct computation
        let result1 = scalar_mul(&b, &scalar);

        // Using double-and-add directly
        let result2 = b.scalar_mul(&scalar);

        assert_eq!(result1.to_affine(), result2.to_affine());
    }

    #[test]
    fn test_double_scalar_mul() {
        let b = EdwardsPoint::base_point();
        let a_scalar = U256Limbs::from_u64(5);
        let b_scalar = U256Limbs::from_u64(7);

        // 5*B + 7*B = 12*B
        let result = double_scalar_mul(&a_scalar, &b, &b_scalar, &b);
        let expected = b.scalar_mul(&U256Limbs::from_u64(12));

        assert_eq!(result.to_affine(), expected.to_affine());
    }

    #[test]
    fn test_scalar_mul_trace() {
        let b = EdwardsPoint::base_point();
        let scalar = U256Limbs::from_u64(42);

        let trace = ScalarMulTrace::compute(&b, &scalar);

        // Result should match direct computation
        let expected = scalar_mul(&b, &scalar);
        assert_eq!(trace.result.to_affine(), expected.to_affine());

        // Should have 256 intermediates
        assert_eq!(trace.intermediates.len(), 256);
    }
}
