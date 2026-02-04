//! Feasibility Predicates for Δ-Feasibility Verification
//!
//! This module implements endogenous feasibility checking, making
//! Δ-feasibility a Π-fixed invariant rather than an external check.
//!
//! # The Feasibility Predicate
//!
//! A transition τ is feasible with respect to survivor class W if:
//!
//! ```text
//! c_W(τ) ≤ k · log|W|
//! ```
//!
//! Where:
//! - c_W(τ) = max_{x ∈ W} meter(τ, x) is the worst-case cost
//! - k is the feasibility factor (pinned constant)
//! - |W| is the cardinality of the survivor class
//!
//! # Why This Matters
//!
//! Making feasibility endogenous means:
//! 1. No external audit needed to verify feasibility claims
//! 2. "Cheapness privilege" is mathematically impossible
//! 3. Cost bounds are cryptographically verified, not trusted

use crate::field::Fp;
use crate::meter::{MeterConfig, Operation, meter_cost};

/// Feasibility configuration with pinned constants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeasibilityConfig {
    /// Version of this feasibility configuration
    pub version: u32,

    /// Base feasibility factor k
    /// Transition is feasible if cost ≤ k * log|W|
    pub base_factor: u64,

    /// Minimum survivor class size (log2)
    /// Prevents division by zero and ensures meaningful bounds
    pub min_survivor_log: u64,

    /// Maximum allowed cost per step (absolute cap)
    pub max_step_cost: u64,

    /// Whether to enforce strict feasibility (reject if violated)
    pub strict_mode: bool,
}

impl FeasibilityConfig {
    /// Canonical feasibility configuration v1.
    pub fn canonical_v1() -> Self {
        FeasibilityConfig {
            version: 1,
            base_factor: 100,        // 100x the log bound
            min_survivor_log: 10,    // Minimum 2^10 = 1024 survivors
            max_step_cost: 1_000_000, // Absolute cap per step
            strict_mode: true,
        }
    }

    /// Lenient configuration for testing.
    pub fn lenient() -> Self {
        FeasibilityConfig {
            version: 0,
            base_factor: 10_000,
            min_survivor_log: 1,
            max_step_cost: u64::MAX,
            strict_mode: false,
        }
    }
}

/// Survivor class representation.
#[derive(Clone, Debug)]
pub struct SurvivorClass {
    /// Log2 of the cardinality (|W| = 2^log_cardinality)
    pub log_cardinality: u64,

    /// Description of the class (for debugging/audit)
    pub description: String,
}

impl SurvivorClass {
    /// Create a survivor class with given cardinality.
    pub fn new(log_cardinality: u64, description: &str) -> Self {
        SurvivorClass {
            log_cardinality,
            description: description.to_string(),
        }
    }

    /// The universal survivor class (all possible inputs).
    /// For 256-bit inputs, this is 2^256.
    pub fn universal_256() -> Self {
        SurvivorClass::new(256, "Universal 256-bit input space")
    }

    /// The SHA-256 output space (32 bytes = 256 bits).
    pub fn sha256_outputs() -> Self {
        SurvivorClass::new(256, "SHA-256 output space")
    }

    /// A constrained survivor class (e.g., valid signatures).
    pub fn constrained(log_size: u64, description: &str) -> Self {
        SurvivorClass::new(log_size, description)
    }
}

/// Result of a feasibility check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeasibilityResult {
    /// Transition is feasible
    Feasible {
        cost: u64,
        bound: u64,
        margin: u64,
    },

    /// Transition exceeds feasibility bound
    Infeasible {
        cost: u64,
        bound: u64,
        excess: u64,
    },

    /// Cost exceeds absolute maximum
    ExceedsAbsoluteMax {
        cost: u64,
        max: u64,
    },
}

impl FeasibilityResult {
    /// Is this result feasible?
    pub fn is_feasible(&self) -> bool {
        matches!(self, FeasibilityResult::Feasible { .. })
    }
}

/// Check feasibility of a transition cost.
///
/// Returns detailed result including bound and margin/excess.
pub fn check_feasibility(
    config: &FeasibilityConfig,
    cost: u64,
    survivor_class: &SurvivorClass,
) -> FeasibilityResult {
    // Check absolute maximum first
    if cost > config.max_step_cost {
        return FeasibilityResult::ExceedsAbsoluteMax {
            cost,
            max: config.max_step_cost,
        };
    }

    // Compute the feasibility bound
    let log_w = survivor_class.log_cardinality.max(config.min_survivor_log);
    let bound = config.base_factor * log_w;

    if cost <= bound {
        FeasibilityResult::Feasible {
            cost,
            bound,
            margin: bound - cost,
        }
    } else {
        FeasibilityResult::Infeasible {
            cost,
            bound,
            excess: cost - bound,
        }
    }
}

/// Check feasibility and return bool (for use in constraints).
pub fn is_feasible(
    config: &FeasibilityConfig,
    cost: u64,
    survivor_class: &SurvivorClass,
) -> bool {
    check_feasibility(config, cost, survivor_class).is_feasible()
}

/// Compute the feasibility bound for a survivor class.
pub fn feasibility_bound(config: &FeasibilityConfig, survivor_class: &SurvivorClass) -> u64 {
    let log_w = survivor_class.log_cardinality.max(config.min_survivor_log);
    config.base_factor * log_w
}

/// Compute worst-case cost for an operation.
///
/// For deterministic operations, worst-case = typical case.
/// For data-dependent operations, this returns the maximum.
pub fn worst_case_cost(meter: &MeterConfig, op: Operation) -> u64 {
    match op {
        // SHA-256 is data-independent (constant time)
        Operation::Sha256Compression => meter.sha256_compression,
        Operation::Sha256Schedule => meter.sha256_schedule,
        Operation::Sha256FullHash => meter_cost(meter, op),

        // Poseidon is data-independent
        Operation::PoseidonFullRound => meter.poseidon_full_round,
        Operation::PoseidonPartialRound => meter.poseidon_partial_round,
        Operation::PoseidonHash => meter_cost(meter, op),

        // Keccak is data-independent
        Operation::KeccakRound => meter.keccak_round,
        Operation::KeccakPermutation => meter_cost(meter, op),
        Operation::Keccak256 => meter_cost(meter, op),

        // Field operations are constant time in our implementation
        Operation::FieldAdd => meter.field_add,
        Operation::FieldMul => meter.field_mul,
        Operation::FieldInv => meter.field_inv,
        Operation::FieldExp { bits } => bits as u64 * meter.field_exp_bit,

        // EC operations - scalar mul depends on bit length
        Operation::EcScalarMul { bits } => bits as u64 * meter.ec_scalar_mul_bit,

        // All others are deterministic
        _ => meter_cost(meter, op),
    }
}

/// Verify that a cost claim is feasible for a given computation.
///
/// This is the core function used in proof verification to ensure
/// cost claims are within bounds.
pub fn verify_cost_feasibility(
    feasibility_config: &FeasibilityConfig,
    meter_config: &MeterConfig,
    claimed_cost: u64,
    operation: Operation,
    survivor_class: &SurvivorClass,
) -> Result<(), String> {
    // First, check that claimed cost matches expected cost
    let expected_cost = meter_cost(meter_config, operation);
    if claimed_cost != expected_cost {
        return Err(format!(
            "Cost mismatch: claimed {} but expected {} for {:?}",
            claimed_cost, expected_cost, operation
        ));
    }

    // Then check feasibility bound
    let result = check_feasibility(feasibility_config, claimed_cost, survivor_class);

    match result {
        FeasibilityResult::Feasible { .. } => Ok(()),
        FeasibilityResult::Infeasible { cost, bound, excess } => {
            Err(format!(
                "Infeasible: cost {} exceeds bound {} by {} for {:?}",
                cost, bound, excess, operation
            ))
        }
        FeasibilityResult::ExceedsAbsoluteMax { cost, max } => {
            Err(format!(
                "Exceeds absolute maximum: cost {} > max {} for {:?}",
                cost, max, operation
            ))
        }
    }
}

/// Cost constraint for AIR traces.
///
/// Represents the constraint: E_{t+1} - E_t - k_t = 0
pub struct CostConstraint {
    /// Column index for cost accumulator E_t
    pub acc_col: usize,
    /// Column index for step cost k_t
    pub step_cost_col: usize,
}

impl CostConstraint {
    /// Create a new cost constraint.
    pub fn new(acc_col: usize, step_cost_col: usize) -> Self {
        CostConstraint {
            acc_col,
            step_cost_col,
        }
    }

    /// Evaluate the constraint on adjacent rows.
    ///
    /// Returns zero if the constraint is satisfied.
    pub fn evaluate(&self, row: &[Fp], next_row: &[Fp]) -> Fp {
        let e_t = row[self.acc_col];
        let e_next = next_row[self.acc_col];
        let k_t = row[self.step_cost_col];

        // E_{t+1} - E_t - k_t should be 0
        e_next - e_t - k_t
    }
}

/// Boundary constraint for cost accumulator.
pub struct CostBoundaryConstraint {
    /// Column index for cost accumulator
    pub acc_col: usize,
    /// Expected initial cost (usually 0)
    pub initial_cost: Fp,
    /// Expected final cost
    pub final_cost: Fp,
}

impl CostBoundaryConstraint {
    /// Create boundary constraint for cost accumulator.
    pub fn new(acc_col: usize, initial_cost: u64, final_cost: u64) -> Self {
        CostBoundaryConstraint {
            acc_col,
            initial_cost: Fp::new(initial_cost),
            final_cost: Fp::new(final_cost),
        }
    }

    /// Check initial boundary.
    pub fn check_initial(&self, first_row: &[Fp]) -> Fp {
        first_row[self.acc_col] - self.initial_cost
    }

    /// Check final boundary.
    pub fn check_final(&self, last_row: &[Fp]) -> Fp {
        last_row[self.acc_col] - self.final_cost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feasibility_check() {
        let config = FeasibilityConfig::canonical_v1();
        let survivor = SurvivorClass::universal_256();

        // log|W| = 256, bound = 100 * 256 = 25600
        let bound = feasibility_bound(&config, &survivor);
        assert_eq!(bound, 25600);

        // Cost within bound
        let result = check_feasibility(&config, 1000, &survivor);
        assert!(result.is_feasible());

        // Cost exceeding bound
        let result = check_feasibility(&config, 30000, &survivor);
        assert!(!result.is_feasible());
    }

    #[test]
    fn test_worst_case_cost() {
        let meter = MeterConfig::canonical_v1();

        // SHA-256 is constant time
        let cost = worst_case_cost(&meter, Operation::Sha256Compression);
        assert_eq!(cost, meter.sha256_compression);

        // EC scalar mul depends on bits
        let cost_256 = worst_case_cost(&meter, Operation::EcScalarMul { bits: 256 });
        let cost_128 = worst_case_cost(&meter, Operation::EcScalarMul { bits: 128 });
        assert_eq!(cost_256, 2 * cost_128);
    }

    #[test]
    fn test_cost_constraint() {
        let constraint = CostConstraint::new(0, 1);

        // Satisfied constraint: E_next = E_t + k_t
        let row = vec![Fp::new(100), Fp::new(50)];  // E_t = 100, k_t = 50
        let next_row = vec![Fp::new(150), Fp::new(60)];  // E_next = 150

        let result = constraint.evaluate(&row, &next_row);
        assert_eq!(result, Fp::ZERO, "Constraint should be satisfied");

        // Violated constraint
        let bad_next = vec![Fp::new(200), Fp::new(60)];  // E_next = 200 (wrong!)
        let result = constraint.evaluate(&row, &bad_next);
        assert_ne!(result, Fp::ZERO, "Constraint should be violated");
    }

    #[test]
    fn test_boundary_constraint() {
        let boundary = CostBoundaryConstraint::new(0, 0, 1000);

        // Correct initial
        let first_row = vec![Fp::ZERO, Fp::new(10)];
        assert_eq!(boundary.check_initial(&first_row), Fp::ZERO);

        // Correct final
        let last_row = vec![Fp::new(1000), Fp::new(0)];
        assert_eq!(boundary.check_final(&last_row), Fp::ZERO);

        // Wrong final
        let wrong_last = vec![Fp::new(999), Fp::new(0)];
        assert_ne!(boundary.check_final(&wrong_last), Fp::ZERO);
    }

    #[test]
    fn test_verify_cost_feasibility() {
        let feas_config = FeasibilityConfig::canonical_v1();
        let meter_config = MeterConfig::canonical_v1();
        let survivor = SurvivorClass::universal_256();

        let sha_cost = meter_cost(&meter_config, Operation::Sha256Compression);

        // Correct cost should verify
        let result = verify_cost_feasibility(
            &feas_config,
            &meter_config,
            sha_cost,
            Operation::Sha256Compression,
            &survivor,
        );
        assert!(result.is_ok());

        // Wrong cost should fail
        let result = verify_cost_feasibility(
            &feas_config,
            &meter_config,
            sha_cost + 1,
            Operation::Sha256Compression,
            &survivor,
        );
        assert!(result.is_err());
    }
}
