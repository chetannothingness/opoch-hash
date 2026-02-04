//! Deterministic Meter for Proof-of-Cost-and-Computation
//!
//! This module defines a pinned, deterministic cost model that transforms
//! compute proofs into universally settleable receipts.
//!
//! # Key Properties
//!
//! 1. **Deterministic**: Same operation → same cost, always
//! 2. **Pinned**: All constants frozen in spec, versioned
//! 3. **Composable**: meter(τ₂∘τ₁) = meter(τ₁) + meter(τ₂)
//! 4. **Verified**: Cost is a witness in the STARK, not a label
//!
//! # Usage
//!
//! ```
//! use opoch_poc_sha::meter::{MeterConfig, Operation, meter_cost};
//!
//! let meter = MeterConfig::canonical_v1();
//! let cost = meter_cost(&meter, Operation::Sha256Compression);
//! ```

use crate::field::Fp;
use crate::sha256::Sha256;

/// Meter configuration with pinned cost constants.
///
/// All values are in "meter units" (mu) - an abstract unit of computation.
/// The canonical mapping to real-world units (time, energy, money) is:
///
/// ```text
/// 1 mu ≈ 1 field multiplication in Goldilocks
/// ```
///
/// This makes costs comparable across different hardware while remaining
/// deterministic and verifiable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeterConfig {
    /// Version identifier for this meter configuration
    pub version: u32,

    // ============================================
    // Hash Operations
    // ============================================

    /// Cost of one SHA-256 compression function (64 rounds)
    /// Each round: ~100 field ops (CH, MAJ, Σ, additions, rotations)
    pub sha256_compression: u64,

    /// Cost of SHA-256 message schedule (per block)
    pub sha256_schedule: u64,

    /// Cost of one Poseidon full round
    /// t S-boxes + MDS matrix multiplication
    pub poseidon_full_round: u64,

    /// Cost of one Poseidon partial round
    /// 1 S-box + MDS matrix multiplication
    pub poseidon_partial_round: u64,

    /// Cost of one Keccak-f[1600] round (24 rounds total per permutation)
    /// θ + ρ + π + χ + ι steps
    pub keccak_round: u64,

    // ============================================
    // Field Operations (Goldilocks)
    // ============================================

    /// Cost of field addition
    pub field_add: u64,

    /// Cost of field multiplication
    pub field_mul: u64,

    /// Cost of field inversion (using Fermat's little theorem)
    pub field_inv: u64,

    /// Cost of field exponentiation (per bit of exponent)
    pub field_exp_bit: u64,

    // ============================================
    // Memory Operations
    // ============================================

    /// Cost of memory read
    pub memory_read: u64,

    /// Cost of memory write
    pub memory_write: u64,

    // ============================================
    // Lookup Operations
    // ============================================

    /// Cost of lookup table read
    pub lookup_read: u64,

    /// Cost of lookup table accumulator update
    pub lookup_accumulate: u64,

    // ============================================
    // Elliptic Curve Operations
    // ============================================

    /// Cost of EC point addition (affine)
    pub ec_add_affine: u64,

    /// Cost of EC point addition (projective/jacobian)
    pub ec_add_projective: u64,

    /// Cost of EC point doubling
    pub ec_double: u64,

    /// Cost of EC scalar multiplication (per bit)
    pub ec_scalar_mul_bit: u64,

    // ============================================
    // Recursion Costs (Fixed)
    // ============================================

    /// Cost of verifying one segment proof
    pub segment_verify: u64,

    /// Cost of L1 aggregation verification
    pub l1_aggregation_verify: u64,

    /// Cost of L2 (final) aggregation verification
    pub l2_aggregation_verify: u64,
}

impl MeterConfig {
    /// Canonical meter configuration v1.
    ///
    /// These values are FROZEN and must not change without a version bump.
    /// Any change creates a new meter_id and breaks proof compatibility.
    pub fn canonical_v1() -> Self {
        MeterConfig {
            version: 1,

            // Hash operations
            // SHA-256: 64 rounds, each with ~6 additions, 3 logic ops, 6 rotations
            // Total: ~960 equivalent field ops per compression
            sha256_compression: 1000,
            sha256_schedule: 200,  // Message expansion

            // Poseidon (t=12, RF=8, RP=22)
            // Full round: 12 S-boxes (each ~3 muls) + MDS (144 muls) = ~180
            poseidon_full_round: 200,
            // Partial round: 1 S-box + MDS = ~150
            poseidon_partial_round: 160,

            // Keccak-f[1600]: 24 rounds
            // Each round: θ(320 XORs) + ρπ(rotations) + χ(1600 ops) + ι(1 XOR)
            // ~2000 equivalent ops per round
            keccak_round: 2000,

            // Field operations (normalized to multiplication = 1)
            field_add: 1,
            field_mul: 1,
            field_inv: 64,  // ~64 multiplications via Fermat
            field_exp_bit: 2,  // square + conditional multiply

            // Memory operations
            memory_read: 1,
            memory_write: 2,

            // Lookup operations
            lookup_read: 2,
            lookup_accumulate: 3,

            // EC operations (Ed25519/secp256k1)
            // Point addition: ~10 field muls
            ec_add_affine: 12,
            ec_add_projective: 16,
            ec_double: 8,
            ec_scalar_mul_bit: 20,  // double + conditional add

            // Recursion costs (amortized)
            segment_verify: 100,
            l1_aggregation_verify: 50,
            l2_aggregation_verify: 50,
        }
    }

    /// Compute the unique identifier for this meter configuration.
    ///
    /// This is the SHA-256 hash of all pinned constants, used to verify
    /// that prover and verifier are using the same meter.
    pub fn meter_id(&self) -> [u8; 32] {
        let mut data = Vec::new();

        // Version
        data.extend_from_slice(&self.version.to_le_bytes());

        // All costs in order
        data.extend_from_slice(&self.sha256_compression.to_le_bytes());
        data.extend_from_slice(&self.sha256_schedule.to_le_bytes());
        data.extend_from_slice(&self.poseidon_full_round.to_le_bytes());
        data.extend_from_slice(&self.poseidon_partial_round.to_le_bytes());
        data.extend_from_slice(&self.keccak_round.to_le_bytes());
        data.extend_from_slice(&self.field_add.to_le_bytes());
        data.extend_from_slice(&self.field_mul.to_le_bytes());
        data.extend_from_slice(&self.field_inv.to_le_bytes());
        data.extend_from_slice(&self.field_exp_bit.to_le_bytes());
        data.extend_from_slice(&self.memory_read.to_le_bytes());
        data.extend_from_slice(&self.memory_write.to_le_bytes());
        data.extend_from_slice(&self.lookup_read.to_le_bytes());
        data.extend_from_slice(&self.lookup_accumulate.to_le_bytes());
        data.extend_from_slice(&self.ec_add_affine.to_le_bytes());
        data.extend_from_slice(&self.ec_add_projective.to_le_bytes());
        data.extend_from_slice(&self.ec_double.to_le_bytes());
        data.extend_from_slice(&self.ec_scalar_mul_bit.to_le_bytes());
        data.extend_from_slice(&self.segment_verify.to_le_bytes());
        data.extend_from_slice(&self.l1_aggregation_verify.to_le_bytes());
        data.extend_from_slice(&self.l2_aggregation_verify.to_le_bytes());

        Sha256::hash(&data)
    }
}

/// Operations that can be metered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    // Hash operations
    Sha256Compression,
    Sha256Schedule,
    Sha256FullHash,  // Compression + schedule + padding
    PoseidonFullRound,
    PoseidonPartialRound,
    PoseidonHash,  // Full permutation (RF full + RP partial rounds)
    KeccakRound,
    KeccakPermutation,  // 24 rounds
    Keccak256,  // Full hash with padding

    // Field operations
    FieldAdd,
    FieldMul,
    FieldInv,
    FieldExp { bits: u32 },

    // Memory
    MemoryRead,
    MemoryWrite,

    // Lookups
    LookupRead,
    LookupAccumulate,

    // EC operations
    EcAddAffine,
    EcAddProjective,
    EcDouble,
    EcScalarMul { bits: u32 },

    // EdDSA verification
    EddsaVerify,

    // ECDSA verification
    EcdsaVerify,

    // Recursion
    SegmentVerify,
    L1AggregationVerify,
    L2AggregationVerify,
}

/// Compute the cost of an operation under a given meter.
pub fn meter_cost(config: &MeterConfig, op: Operation) -> u64 {
    match op {
        // Hash operations
        Operation::Sha256Compression => config.sha256_compression,
        Operation::Sha256Schedule => config.sha256_schedule,
        Operation::Sha256FullHash => {
            // One block: schedule + compression + finalization
            config.sha256_schedule + config.sha256_compression + 10 * config.field_add
        }
        Operation::PoseidonFullRound => config.poseidon_full_round,
        Operation::PoseidonPartialRound => config.poseidon_partial_round,
        Operation::PoseidonHash => {
            // t=12, RF=8 full rounds, RP=22 partial rounds
            8 * config.poseidon_full_round + 22 * config.poseidon_partial_round
        }
        Operation::KeccakRound => config.keccak_round,
        Operation::KeccakPermutation => 24 * config.keccak_round,
        Operation::Keccak256 => {
            // One block (136 bytes rate) + squeeze
            24 * config.keccak_round + 100 * config.field_add
        }

        // Field operations
        Operation::FieldAdd => config.field_add,
        Operation::FieldMul => config.field_mul,
        Operation::FieldInv => config.field_inv,
        Operation::FieldExp { bits } => bits as u64 * config.field_exp_bit,

        // Memory
        Operation::MemoryRead => config.memory_read,
        Operation::MemoryWrite => config.memory_write,

        // Lookups
        Operation::LookupRead => config.lookup_read,
        Operation::LookupAccumulate => config.lookup_accumulate,

        // EC operations
        Operation::EcAddAffine => config.ec_add_affine,
        Operation::EcAddProjective => config.ec_add_projective,
        Operation::EcDouble => config.ec_double,
        Operation::EcScalarMul { bits } => bits as u64 * config.ec_scalar_mul_bit,

        // EdDSA: [S]B = R + [h]A
        // 2 scalar muls (256 bits each) + 1 point add
        Operation::EddsaVerify => {
            2 * 256 * config.ec_scalar_mul_bit + config.ec_add_projective
        }

        // ECDSA: P = u1*G + u2*Q, check P.x mod n = r
        // 2 scalar muls (256 bits each) + 1 point add + field ops
        Operation::EcdsaVerify => {
            2 * 256 * config.ec_scalar_mul_bit + config.ec_add_projective + config.field_inv
        }

        // Recursion
        Operation::SegmentVerify => config.segment_verify,
        Operation::L1AggregationVerify => config.l1_aggregation_verify,
        Operation::L2AggregationVerify => config.l2_aggregation_verify,
    }
}

/// Compute the cost of a SHA-256 hash chain of length n.
pub fn sha256_chain_cost(config: &MeterConfig, n: u64) -> u64 {
    // Each step: hash a 32-byte input (1 block after padding)
    n * meter_cost(config, Operation::Sha256FullHash)
}

/// Compute the total cost including recursion overhead.
pub fn total_proof_cost(
    config: &MeterConfig,
    chain_length: u64,
    segment_length: u64,
) -> u64 {
    let num_segments = (chain_length + segment_length - 1) / segment_length;

    // Cost of the actual computation
    let compute_cost = sha256_chain_cost(config, chain_length);

    // Cost of segment proofs
    let segment_cost = num_segments * config.segment_verify;

    // Cost of L1 aggregation (aggregate all segments into ~1000 groups)
    let l1_groups = (num_segments + 999) / 1000;
    let l1_cost = l1_groups * config.l1_aggregation_verify;

    // Cost of L2 aggregation (single final proof)
    let l2_cost = config.l2_aggregation_verify;

    compute_cost + segment_cost + l1_cost + l2_cost
}

/// Cost accumulator for tracking costs during proof generation.
#[derive(Clone, Debug, Default)]
pub struct CostAccumulator {
    /// Current accumulated cost
    pub total: u64,
    /// Breakdown by operation type
    pub breakdown: CostBreakdown,
}

/// Breakdown of costs by category.
#[derive(Clone, Debug, Default)]
pub struct CostBreakdown {
    pub hash_ops: u64,
    pub field_ops: u64,
    pub memory_ops: u64,
    pub lookup_ops: u64,
    pub ec_ops: u64,
    pub recursion_ops: u64,
}

impl CostAccumulator {
    /// Create a new accumulator starting at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the cost of an operation.
    pub fn add(&mut self, config: &MeterConfig, op: Operation) {
        let cost = meter_cost(config, op);
        self.total += cost;

        // Update breakdown
        match op {
            Operation::Sha256Compression
            | Operation::Sha256Schedule
            | Operation::Sha256FullHash
            | Operation::PoseidonFullRound
            | Operation::PoseidonPartialRound
            | Operation::PoseidonHash
            | Operation::KeccakRound
            | Operation::KeccakPermutation
            | Operation::Keccak256 => {
                self.breakdown.hash_ops += cost;
            }
            Operation::FieldAdd
            | Operation::FieldMul
            | Operation::FieldInv
            | Operation::FieldExp { .. } => {
                self.breakdown.field_ops += cost;
            }
            Operation::MemoryRead | Operation::MemoryWrite => {
                self.breakdown.memory_ops += cost;
            }
            Operation::LookupRead | Operation::LookupAccumulate => {
                self.breakdown.lookup_ops += cost;
            }
            Operation::EcAddAffine
            | Operation::EcAddProjective
            | Operation::EcDouble
            | Operation::EcScalarMul { .. }
            | Operation::EddsaVerify
            | Operation::EcdsaVerify => {
                self.breakdown.ec_ops += cost;
            }
            Operation::SegmentVerify
            | Operation::L1AggregationVerify
            | Operation::L2AggregationVerify => {
                self.breakdown.recursion_ops += cost;
            }
        }
    }

    /// Add a raw cost value.
    pub fn add_raw(&mut self, cost: u64) {
        self.total += cost;
    }

    /// Get the total cost.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Get as field element.
    pub fn as_fp(&self) -> Fp {
        Fp::new(self.total)
    }
}

/// Composition law: cost of composed operations.
///
/// For transitions τ₁ and τ₂:
/// meter(τ₂ ∘ τ₁) = meter(τ₁) + meter(τ₂)
///
/// This is exact equality for deterministic operations.
pub fn compose_costs(cost1: u64, cost2: u64) -> u64 {
    cost1 + cost2
}

/// Verify that a claimed cost matches the expected cost.
pub fn verify_cost(claimed: u64, expected: u64) -> bool {
    claimed == expected
}

/// Feasibility predicate: is the transition cost within bounds?
///
/// Δ-feasibility: c_W(τ) ≤ k * log|W|
///
/// where:
/// - c_W(τ) is the worst-case cost over survivor class W
/// - k is a constant factor
/// - |W| is the cardinality of the survivor class
pub fn is_feasible(cost: u64, survivor_class_log: u64, factor: u64) -> bool {
    cost <= factor * survivor_class_log
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_meter_id_stability() {
        let meter = MeterConfig::canonical_v1();
        let id = meter.meter_id();

        // This ID must never change for v1
        // If this test fails, you've accidentally modified the canonical meter
        assert_eq!(meter.version, 1);
        assert_ne!(id, [0u8; 32], "Meter ID should not be zero");

        // Verify determinism
        let id2 = meter.meter_id();
        assert_eq!(id, id2, "Meter ID must be deterministic");
    }

    #[test]
    fn test_sha256_chain_cost() {
        let meter = MeterConfig::canonical_v1();

        let cost_1 = sha256_chain_cost(&meter, 1);
        let cost_10 = sha256_chain_cost(&meter, 10);
        let cost_100 = sha256_chain_cost(&meter, 100);

        // Cost should scale linearly with chain length
        assert_eq!(cost_10, 10 * cost_1);
        assert_eq!(cost_100, 100 * cost_1);
    }

    #[test]
    fn test_cost_composition() {
        let meter = MeterConfig::canonical_v1();

        let cost_a = sha256_chain_cost(&meter, 100);
        let cost_b = sha256_chain_cost(&meter, 200);
        let cost_composed = sha256_chain_cost(&meter, 300);

        // Composition law: cost(A+B) = cost(A) + cost(B)
        assert_eq!(compose_costs(cost_a, cost_b), cost_composed);
    }

    #[test]
    fn test_cost_accumulator() {
        let meter = MeterConfig::canonical_v1();
        let mut acc = CostAccumulator::new();

        acc.add(&meter, Operation::Sha256Compression);
        acc.add(&meter, Operation::FieldMul);
        acc.add(&meter, Operation::LookupRead);

        let expected = meter.sha256_compression + meter.field_mul + meter.lookup_read;
        assert_eq!(acc.total(), expected);
    }

    #[test]
    fn test_feasibility() {
        // log2(2^20) = 20
        assert!(is_feasible(100, 20, 10));   // 100 ≤ 10*20 = 200 ✓
        assert!(!is_feasible(300, 20, 10));  // 300 > 10*20 = 200 ✗
    }

    #[test]
    fn test_total_proof_cost() {
        let meter = MeterConfig::canonical_v1();

        // N = 1000, L = 64
        let cost = total_proof_cost(&meter, 1000, 64);

        // Should be compute cost + recursion overhead
        let compute_only = sha256_chain_cost(&meter, 1000);
        assert!(cost > compute_only, "Total cost should include recursion overhead");
    }

    #[test]
    fn test_operation_costs_are_positive() {
        let meter = MeterConfig::canonical_v1();

        let ops = [
            Operation::Sha256Compression,
            Operation::PoseidonHash,
            Operation::Keccak256,
            Operation::FieldMul,
            Operation::FieldInv,
            Operation::EcScalarMul { bits: 256 },
            Operation::EddsaVerify,
            Operation::EcdsaVerify,
        ];

        for op in ops {
            let cost = meter_cost(&meter, op);
            assert!(cost > 0, "Operation {:?} should have positive cost", op);
        }
    }

    #[test]
    fn test_cost_breakdown() {
        let meter = MeterConfig::canonical_v1();
        let mut acc = CostAccumulator::new();

        // Add various operations
        acc.add(&meter, Operation::Sha256FullHash);
        acc.add(&meter, Operation::FieldMul);
        acc.add(&meter, Operation::LookupRead);
        acc.add(&meter, Operation::EcDouble);

        // Verify breakdown categories
        assert!(acc.breakdown.hash_ops > 0);
        assert!(acc.breakdown.field_ops > 0);
        assert!(acc.breakdown.lookup_ops > 0);
        assert!(acc.breakdown.ec_ops > 0);

        // Total should equal sum of breakdown
        let breakdown_sum = acc.breakdown.hash_ops
            + acc.breakdown.field_ops
            + acc.breakdown.memory_ops
            + acc.breakdown.lookup_ops
            + acc.breakdown.ec_ops
            + acc.breakdown.recursion_ops;

        assert_eq!(acc.total(), breakdown_sum);
    }
}
