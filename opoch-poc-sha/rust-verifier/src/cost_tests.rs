//! Security Tests for Proof-of-Cost-and-Computation
//!
//! These tests verify the critical security properties:
//!
//! 1. **Cost Binding**: Corrupting any cost field → proof rejects
//! 2. **Composition Law**: cost(A+B) = cost(A) + cost(B) exactly
//! 3. **Meter Determinism**: Same operation → same cost always
//! 4. **Feasibility Bounds**: Costs respect Δ-feasibility
//! 5. **No Cheapness Privilege**: Cannot claim lower cost without proof

#[cfg(test)]
mod cost_binding_tests {
    use crate::meter::{MeterConfig, CostAccumulator, CostBreakdown, Operation, meter_cost, sha256_chain_cost};
    use crate::feasibility::{FeasibilityConfig, SurvivorClass, check_feasibility, FeasibilityResult};
    use crate::cost_proof::{
        CostProofHeader, CostReceipt, verify_cost_claim, verify_cost_composition,
        aggregate_receipts,
    };

    /// Test 1: Cost binding - undercount rejection
    ///
    /// If a proof claims less cost than actually required,
    /// verification MUST fail.
    #[test]
    fn test_cost_binding_rejects_undercount() {
        let meter = MeterConfig::canonical_v1();
        let correct_cost = sha256_chain_cost(&meter, 1000);

        // Try to claim 1 unit less
        let claimed_cost = correct_cost - 1;

        // This should fail verification
        assert!(
            !verify_cost_claim(claimed_cost, 1000, 64, &meter),
            "SECURITY: Undercounting cost must be rejected!"
        );
    }

    /// Test 2: Cost binding - overcount rejection
    ///
    /// If a proof claims more cost than actually required,
    /// verification MUST fail. This prevents inflation attacks.
    #[test]
    fn test_cost_binding_rejects_overcount() {
        let meter = MeterConfig::canonical_v1();
        let correct_cost = sha256_chain_cost(&meter, 1000);

        // Try to claim 1 unit more
        let claimed_cost = correct_cost + 1;

        // This should fail verification
        assert!(
            !verify_cost_claim(claimed_cost, 1000, 64, &meter),
            "SECURITY: Overcounting cost must be rejected!"
        );
    }

    /// Test 3: Cost binding - exact match required
    ///
    /// Only the exact cost passes verification.
    #[test]
    fn test_cost_binding_exact_match() {
        let meter = MeterConfig::canonical_v1();

        for n in [100, 1000, 10000] {
            let correct_cost = sha256_chain_cost(&meter, n);

            // Exact match passes
            assert!(
                verify_cost_claim(correct_cost, n, 64, &meter),
                "Exact cost should verify for n={}", n
            );

            // Off by 1 fails
            assert!(!verify_cost_claim(correct_cost - 1, n, 64, &meter));
            assert!(!verify_cost_claim(correct_cost + 1, n, 64, &meter));
        }
    }

    /// Test 4: Cost binding - header corruption
    #[test]
    fn test_cost_header_corruption_detected() {
        let meter = MeterConfig::canonical_v1();
        let feasibility = FeasibilityConfig::canonical_v1();
        let cost = sha256_chain_cost(&meter, 1000);

        let header = CostProofHeader::new(
            1000,
            64,
            [1u8; 32],
            [2u8; 32],
            cost,
            CostBreakdown { hash_ops: cost, ..Default::default() },
            &meter,
            &feasibility,
        );

        // Original should verify
        assert!(header.verify());

        // Serialize, corrupt, deserialize
        let mut bytes = header.serialize();

        // Corrupt the cost field (bytes 85-92 in serialization)
        bytes[89] ^= 0xFF;

        let corrupted = CostProofHeader::deserialize(&bytes).unwrap();
        assert!(!corrupted.verify(), "Corrupted header must not verify");
    }
}

#[cfg(test)]
mod composition_tests {
    use crate::meter::{MeterConfig, sha256_chain_cost, compose_costs};
    use crate::cost_proof::{CostReceipt, verify_cost_composition, aggregate_receipts};

    /// Test 5: Composition law - exact additivity
    ///
    /// cost(A+B) = cost(A) + cost(B) exactly.
    /// No rounding, no approximation.
    #[test]
    fn test_composition_exact_additivity() {
        let meter = MeterConfig::canonical_v1();

        // Test various splits
        for (n_a, n_b) in [(100, 200), (500, 500), (1, 999), (333, 667)] {
            let cost_a = sha256_chain_cost(&meter, n_a);
            let cost_b = sha256_chain_cost(&meter, n_b);
            let cost_composed = sha256_chain_cost(&meter, n_a + n_b);

            assert_eq!(
                compose_costs(cost_a, cost_b),
                cost_composed,
                "Composition law violated for n_a={}, n_b={}", n_a, n_b
            );
        }
    }

    /// Test 6: Composition - receipt aggregation
    #[test]
    fn test_receipt_aggregation_preserves_cost() {
        let meter = MeterConfig::canonical_v1();

        let receipts: Vec<CostReceipt> = (0..10).map(|i| {
            CostReceipt {
                d0: [i as u8; 32],
                y: [(i + 1) as u8; 32],
                n: 100,
                total_cost: sha256_chain_cost(&meter, 100),
                meter_id: meter.meter_id(),
                proof_hash: [i as u8; 32],
                timestamp: 0,
            }
        }).collect();

        let aggregated = aggregate_receipts(&receipts);

        // Total cost must equal sum of individual costs
        let expected_cost: u64 = receipts.iter().map(|r| r.total_cost).sum();
        assert_eq!(aggregated.total_cost, expected_cost);

        // Total n must equal sum
        assert_eq!(aggregated.n, 1000);  // 10 * 100

        // Must equal cost of full chain
        let full_chain_cost = sha256_chain_cost(&meter, 1000);
        assert_eq!(aggregated.total_cost, full_chain_cost);
    }

    /// Test 7: Composition - cannot cheat lower cost
    #[test]
    fn test_composition_no_cheapness_cheat() {
        let meter = MeterConfig::canonical_v1();

        let receipt_a = CostReceipt {
            d0: [1u8; 32],
            y: [2u8; 32],
            n: 500,
            total_cost: sha256_chain_cost(&meter, 500),
            meter_id: meter.meter_id(),
            proof_hash: [1u8; 32],
            timestamp: 0,
        };

        let receipt_b = CostReceipt {
            d0: [2u8; 32],
            y: [3u8; 32],
            n: 500,
            total_cost: sha256_chain_cost(&meter, 500),
            meter_id: meter.meter_id(),
            proof_hash: [2u8; 32],
            timestamp: 0,
        };

        let correct_composed = receipt_a.total_cost + receipt_b.total_cost;

        // Trying to claim cheaper composed cost fails
        assert!(!verify_cost_composition(&receipt_a, &receipt_b, correct_composed - 1),
            "SECURITY: Cannot claim cheaper composed cost!");

        // Correct composed cost verifies
        assert!(verify_cost_composition(&receipt_a, &receipt_b, correct_composed));
    }
}

#[cfg(test)]
mod determinism_tests {
    use crate::meter::{MeterConfig, CostAccumulator, Operation, meter_cost, sha256_chain_cost};

    /// Test 8: Meter determinism - same input same cost
    #[test]
    fn test_meter_determinism() {
        let meter = MeterConfig::canonical_v1();

        // Same operation always gives same cost
        for _ in 0..100 {
            let cost1 = meter_cost(&meter, Operation::Sha256Compression);
            let cost2 = meter_cost(&meter, Operation::Sha256Compression);
            assert_eq!(cost1, cost2, "Meter must be deterministic");
        }
    }

    /// Test 9: Meter ID stability
    #[test]
    fn test_meter_id_stability() {
        let meter1 = MeterConfig::canonical_v1();
        let meter2 = MeterConfig::canonical_v1();

        // Same config gives same ID
        assert_eq!(meter1.meter_id(), meter2.meter_id());

        // Different config gives different ID
        let mut meter3 = MeterConfig::canonical_v1();
        meter3.sha256_compression += 1;
        assert_ne!(meter1.meter_id(), meter3.meter_id());
    }

    /// Test 10: Accumulator consistency
    #[test]
    fn test_accumulator_consistency() {
        let meter = MeterConfig::canonical_v1();

        let mut acc1 = CostAccumulator::new();
        let mut acc2 = CostAccumulator::new();

        // Same operations in same order
        acc1.add(&meter, Operation::Sha256Compression);
        acc1.add(&meter, Operation::FieldMul);
        acc1.add(&meter, Operation::LookupRead);

        acc2.add(&meter, Operation::Sha256Compression);
        acc2.add(&meter, Operation::FieldMul);
        acc2.add(&meter, Operation::LookupRead);

        assert_eq!(acc1.total(), acc2.total());
    }
}

#[cfg(test)]
mod feasibility_tests {
    use crate::meter::{MeterConfig, sha256_chain_cost};
    use crate::feasibility::{
        FeasibilityConfig, SurvivorClass, check_feasibility, FeasibilityResult,
        feasibility_bound, is_feasible,
    };

    /// Test 11: Feasibility bound computation
    #[test]
    fn test_feasibility_bound() {
        let config = FeasibilityConfig::canonical_v1();

        // Universal 256-bit space: bound = 100 * 256 = 25600
        let universal = SurvivorClass::universal_256();
        let bound = feasibility_bound(&config, &universal);
        assert_eq!(bound, 25600);

        // Smaller survivor class: bound = 100 * 128 = 12800
        let smaller = SurvivorClass::new(128, "Smaller class");
        let bound = feasibility_bound(&config, &smaller);
        assert_eq!(bound, 12800);
    }

    /// Test 12: Feasibility check
    #[test]
    fn test_feasibility_check() {
        let config = FeasibilityConfig::canonical_v1();
        let survivor = SurvivorClass::universal_256();
        let bound = feasibility_bound(&config, &survivor);

        // Within bound
        let result = check_feasibility(&config, bound - 1, &survivor);
        assert!(matches!(result, FeasibilityResult::Feasible { .. }));

        // At bound
        let result = check_feasibility(&config, bound, &survivor);
        assert!(matches!(result, FeasibilityResult::Feasible { .. }));

        // Exceeds bound
        let result = check_feasibility(&config, bound + 1, &survivor);
        assert!(matches!(result, FeasibilityResult::Infeasible { .. }));
    }

    /// Test 13: SHA-256 chain feasibility
    #[test]
    fn test_sha256_chain_feasibility() {
        let meter = MeterConfig::canonical_v1();
        let feas_config = FeasibilityConfig::canonical_v1();
        let survivor = SurvivorClass::universal_256();
        let bound = feasibility_bound(&feas_config, &survivor);

        // Check various chain lengths
        for n in [1, 10, 100] {
            let cost = sha256_chain_cost(&meter, n);

            // SHA-256 chains should be feasible for reasonable lengths
            // (this depends on pinned constants)
            if cost <= bound {
                assert!(is_feasible(&feas_config, cost, &survivor),
                    "SHA-256 chain of {} should be feasible", n);
            }
        }
    }
}

#[cfg(test)]
mod attack_resistance_tests {
    use crate::meter::{MeterConfig, sha256_chain_cost};
    use crate::cost_proof::{CostReceipt, verify_cost_claim};

    /// Test 14: Cannot claim cheaper via different meter
    #[test]
    fn test_no_meter_switching_attack() {
        let meter_v1 = MeterConfig::canonical_v1();

        // Create a "cheaper" meter
        let mut cheap_meter = MeterConfig::canonical_v1();
        cheap_meter.sha256_compression = 1;  // Artificially cheap

        let n = 1000;
        let honest_cost = sha256_chain_cost(&meter_v1, n);
        let cheap_cost = sha256_chain_cost(&cheap_meter, n);

        // Cheap cost is much lower
        assert!(cheap_cost < honest_cost);

        // But claiming cheap cost under honest meter fails
        assert!(
            !verify_cost_claim(cheap_cost, n, 64, &meter_v1),
            "SECURITY: Cannot use cheaper meter to reduce claimed cost!"
        );

        // Can only claim honest cost under honest meter
        assert!(verify_cost_claim(honest_cost, n, 64, &meter_v1));
    }

    /// Test 15: Receipt forgery detection
    #[test]
    fn test_receipt_forgery_detection() {
        let meter = MeterConfig::canonical_v1();
        let cost = sha256_chain_cost(&meter, 1000);

        let honest_receipt = CostReceipt {
            d0: [1u8; 32],
            y: [2u8; 32],
            n: 1000,
            total_cost: cost,
            meter_id: meter.meter_id(),
            proof_hash: [3u8; 32],
            timestamp: 12345,
        };

        // Forged receipt with wrong cost
        let mut forged = honest_receipt.clone();
        forged.total_cost = cost - 100;

        // Receipt IDs differ
        assert_ne!(honest_receipt.receipt_id(), forged.receipt_id());

        // Forged receipt fails cost verification
        assert!(!verify_cost_claim(forged.total_cost, forged.n, 64, &meter));
    }

    /// Test 16: Zero cost attack prevention
    #[test]
    fn test_zero_cost_attack_prevention() {
        let meter = MeterConfig::canonical_v1();

        // Cannot claim zero cost for any non-trivial computation
        for n in [1, 10, 100, 1000] {
            assert!(
                !verify_cost_claim(0, n, 64, &meter),
                "SECURITY: Cannot claim zero cost for n={}!", n
            );
        }
    }

    /// Test 17: Overflow attack prevention
    #[test]
    fn test_overflow_attack_prevention() {
        let meter = MeterConfig::canonical_v1();

        // Very large n should not overflow
        let large_n = u64::MAX / 10000;  // Still large but won't overflow
        let cost = sha256_chain_cost(&meter, 1000);

        // Verify cost computation doesn't panic
        let large_cost = sha256_chain_cost(&meter, large_n);
        assert!(large_cost > cost);
    }
}

#[cfg(test)]
mod edge_case_tests {
    use crate::meter::{MeterConfig, sha256_chain_cost, CostAccumulator, Operation};
    use crate::cost_proof::{verify_cost_claim, aggregate_receipts, CostReceipt};

    /// Test 18: Single step cost
    #[test]
    fn test_single_step_cost() {
        let meter = MeterConfig::canonical_v1();
        let cost = sha256_chain_cost(&meter, 1);

        assert!(cost > 0, "Single step must have positive cost");
        assert!(verify_cost_claim(cost, 1, 64, &meter));
    }

    /// Test 19: Empty accumulator
    #[test]
    fn test_empty_accumulator() {
        let acc = CostAccumulator::new();
        assert_eq!(acc.total(), 0);
    }

    /// Test 20: Breakdown sum equals total
    #[test]
    fn test_breakdown_consistency() {
        let meter = MeterConfig::canonical_v1();
        let mut acc = CostAccumulator::new();

        // Add various operations
        acc.add(&meter, Operation::Sha256FullHash);
        acc.add(&meter, Operation::PoseidonHash);
        acc.add(&meter, Operation::Keccak256);
        acc.add(&meter, Operation::FieldInv);
        acc.add(&meter, Operation::EcDouble);
        acc.add(&meter, Operation::LookupRead);
        acc.add(&meter, Operation::SegmentVerify);

        // Breakdown should sum to total
        let breakdown_sum = acc.breakdown.hash_ops
            + acc.breakdown.field_ops
            + acc.breakdown.memory_ops
            + acc.breakdown.lookup_ops
            + acc.breakdown.ec_ops
            + acc.breakdown.recursion_ops;

        assert_eq!(acc.total(), breakdown_sum);
    }

    /// Test 21: Single receipt aggregation
    #[test]
    fn test_single_receipt_aggregation() {
        let meter = MeterConfig::canonical_v1();

        let receipt = CostReceipt {
            d0: [1u8; 32],
            y: [2u8; 32],
            n: 1000,
            total_cost: sha256_chain_cost(&meter, 1000),
            meter_id: meter.meter_id(),
            proof_hash: [3u8; 32],
            timestamp: 0,
        };

        let aggregated = aggregate_receipts(&[receipt.clone()]);

        assert_eq!(aggregated.n, receipt.n);
        assert_eq!(aggregated.total_cost, receipt.total_cost);
    }
}
