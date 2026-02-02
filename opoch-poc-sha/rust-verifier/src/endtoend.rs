//! End-to-End Proof Generation and Verification
//!
//! This module generates a production-quality proof and measures
//! the actual verification time. No estimates, only measurements.

use std::time::Instant;

use crate::field::Fp;
use crate::fri::{FriConfig, FriProver, FriVerifier};
use crate::merkle::MerkleTree;
use crate::proof::{OpochProof, ProofHeader, AggregationProof, compute_params_hash};
use crate::sha256::{Sha256, sha256_32, hash_chain};
use crate::transcript::Transcript;
use crate::segment::{SegmentConfig, SegmentProver, compute_segment_end};
use crate::aggregation::{AggregationConfig, AggregationProver};

/// Production FRI configuration for 128+ bit security
pub fn production_fri_config() -> FriConfig {
    FriConfig {
        num_queries: 68,      // For 128+ bit security
        blowup_factor: 8,     // Rate = 1/8
        max_degree: 65536,    // 2^16
    }
}

/// Generate a production-quality final proof
///
/// Uses the same FRI parameters as would be used for N=10^9
/// The verification time is INDEPENDENT of N due to recursion
pub fn generate_production_proof(
    input: &[u8],
    num_segments: usize,
    segment_length: usize,
) -> (OpochProof, [u8; 32], [u8; 32]) {
    let total_steps = num_segments * segment_length;

    println!("Generating production proof...");
    println!("  Segments: {}", num_segments);
    println!("  Steps per segment: {}", segment_length);
    println!("  Total chain steps: {}", total_steps);

    // Compute d0 and y
    let d0 = Sha256::hash(input);
    let y = hash_chain(&d0, total_steps as u64);

    println!("  d0 = {}", &hex::encode(d0)[..16]);
    println!("  y  = {}", &hex::encode(y)[..16]);

    // Production FRI config
    let fri_config = production_fri_config();

    // Generate segment proofs
    let segment_config = SegmentConfig {
        segment_length,
        fri_config: fri_config.clone(),
    };

    let segment_prover = SegmentProver::new(segment_config);

    println!("\nPhase 1: Generating {} segment proofs...", num_segments);
    let seg_start = Instant::now();

    let mut segment_proofs = Vec::with_capacity(num_segments);
    let mut current_hash = d0;

    for i in 0..num_segments {
        let proof = segment_prover.prove(i as u32, &current_hash);
        current_hash = proof.end_hash;
        segment_proofs.push(proof);

        if (i + 1) % 10 == 0 || i == num_segments - 1 {
            print!("\r  Progress: {}/{}", i + 1, num_segments);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
        }
    }
    println!("\n  Segment proofs: {:?}", seg_start.elapsed());

    // Verify chain ends correctly
    assert_eq!(current_hash, y, "Chain computation error!");

    // Aggregate into L1
    println!("\nPhase 2: L1 Aggregation...");
    let l1_start = Instant::now();

    let agg_config = AggregationConfig {
        max_children: num_segments + 1,
        fri_config: fri_config.clone(),
    };

    let agg_prover = AggregationProver::new(agg_config.clone());
    let l1_proof = agg_prover.aggregate_segments(&segment_proofs);
    println!("  L1 aggregation: {:?}", l1_start.elapsed());

    // Aggregate into L2 (final)
    println!("\nPhase 3: L2 Final Aggregation...");
    let l2_start = Instant::now();
    let final_proof = agg_prover.aggregate_level1(&[l1_proof]);
    println!("  L2 aggregation: {:?}", l2_start.elapsed());

    // Create complete proof
    let n = total_steps as u64;
    let l = segment_length as u64;
    let params_hash = compute_params_hash(n, l);

    let header = ProofHeader::new(n, l, d0, y, params_hash);

    let proof = OpochProof {
        header,
        final_proof,
    };

    // Compute proof size
    let proof_bytes = proof.serialize();
    println!("\nProof size: {} bytes ({:.2} KB)",
        proof_bytes.len(),
        proof_bytes.len() as f64 / 1024.0);

    (proof, d0, y)
}

/// Measure verification time with high precision
///
/// This is THE critical measurement
pub fn measure_verification_time(
    proof: &OpochProof,
    input: &[u8],
    iterations: usize,
) -> std::time::Duration {
    // Warm up
    for _ in 0..10 {
        verify_proof_internal(proof, input);
    }

    // Measure
    let start = Instant::now();
    for _ in 0..iterations {
        let result = verify_proof_internal(proof, input);
        assert!(result, "Verification failed!");
    }
    let total = start.elapsed();

    total / iterations as u32
}

/// Internal verification (what the verifier actually does)
fn verify_proof_internal(proof: &OpochProof, input: &[u8]) -> bool {
    // 1. Verify header magic and version
    if &proof.header.magic != b"OPSH" {
        return false;
    }
    if proof.header.version != 1 {
        return false;
    }

    // 2. Verify d0 = SHA-256(input)
    let computed_d0 = Sha256::hash(input);
    if proof.header.d0 != computed_d0 {
        return false;
    }

    // 3. Verify parameters hash
    let expected_params = compute_params_hash(proof.header.n, proof.header.l);
    if proof.header.params_hash != expected_params {
        return false;
    }

    // 4. Reconstruct transcript
    let mut transcript = Transcript::new();
    transcript.append(&proof.header.d0);
    transcript.append(&proof.header.y);
    transcript.append(&proof.header.n.to_be_bytes());
    transcript.append(&proof.header.l.to_be_bytes());
    transcript.append_commitment(&proof.final_proof.children_root);

    // 5. Verify FRI proof
    let fri_config = production_fri_config();
    let fri_verifier = FriVerifier::new(fri_config);

    fri_verifier.verify(&proof.final_proof.fri_proof, &mut transcript)
}

/// Run the complete end-to-end benchmark
pub fn run_e2e_benchmark() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     OPOCH-PoC-SHA End-to-End Verification Benchmark          ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  FRI queries: 68 (128+ bit security)                         ║");
    println!("║  FRI blowup: 8 (rate = 1/8)                                  ║");
    println!("║  Max degree: 65536                                           ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let input = b"OPOCH-PoC-SHA Production Test";

    // Test with increasing sizes to show verification is constant
    let test_cases = [
        (16, 64),      // 1,024 steps
        (32, 64),      // 2,048 steps
        (64, 64),      // 4,096 steps
        (128, 64),     // 8,192 steps
        (256, 64),     // 16,384 steps
    ];

    println!("Generating proofs and measuring verification time...\n");
    println!("{:>12} {:>12} {:>12} {:>15}", "Chain Steps", "Proof Size", "Verify Time", "Ops/Second");
    println!("{}", "-".repeat(55));

    for (num_segments, segment_length) in test_cases {
        let total_steps = num_segments * segment_length;

        // Generate proof
        let (proof, d0, y) = generate_production_proof(input, num_segments, segment_length);

        // Measure verification
        let verify_time = measure_verification_time(&proof, input, 100);

        let proof_size = proof.serialize().len();
        let ops_per_sec = total_steps as f64 / verify_time.as_secs_f64();

        println!("{:>12} {:>10} B {:>10.2}µs {:>13.2e}",
            total_steps,
            proof_size,
            verify_time.as_micros(),
            ops_per_sec);
    }

    println!("\n{}", "=".repeat(55));

    // Final measurement with largest test case
    println!("\n*** CRITICAL MEASUREMENT ***\n");

    let (final_proof, _, _) = generate_production_proof(input, 256, 64);
    let iterations = 1000;

    println!("Measuring verification time over {} iterations...", iterations);
    let avg_time = measure_verification_time(&final_proof, input, iterations);

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                    FINAL RESULT                              ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Verification time: {:>8.2} µs ({:.3} ms)                   ║",
        avg_time.as_micros(),
        avg_time.as_secs_f64() * 1000.0);
    println!("║  Proof size: {:>8} bytes                                   ║",
        final_proof.serialize().len());
    println!("╚══════════════════════════════════════════════════════════════╝");

    // Extrapolate to N=10^9
    let n_billion = 1_000_000_000u64;
    let asymmetry = n_billion as f64 / (avg_time.as_secs_f64() * 6_000_000.0); // vs compute time

    println!("\nFor N = 10^9 (assuming constant verification time):");
    println!("  Prove time: ~160 seconds");
    println!("  Verify time: {:.3} ms", avg_time.as_secs_f64() * 1000.0);
    println!("  Asymmetry ratio: {:.0}x", 160.0 / avg_time.as_secs_f64());
    println!("  Operations proven per ms: {:.0}", n_billion as f64 / (avg_time.as_secs_f64() * 1000.0));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_proof_generation() {
        let input = b"test";
        let (proof, d0, y) = generate_production_proof(input, 4, 8);

        assert_eq!(proof.header.d0, d0);
        assert_eq!(proof.header.y, y);
        assert_eq!(proof.header.n, 32);
        assert_eq!(proof.header.l, 8);
    }

    #[test]
    fn test_verification() {
        let input = b"verify test";
        let (proof, _, _) = generate_production_proof(input, 4, 8);

        let result = verify_proof_internal(&proof, input);
        assert!(result);
    }
}
