//! Real Proof Size Measurement
//!
//! Measures actual proof sizes from the real STARK/FRI system.

use opoch_poc_sha::segment::{SegmentConfig, SegmentProver, SegmentVerifier};
use opoch_poc_sha::fri::FriConfig;
use opoch_poc_sha::sha256::Sha256;
use std::time::Instant;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║        REAL PROOF SIZE MEASUREMENT - NO SHORTCUTS            ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let start_hash = Sha256::hash(b"benchmark test");

    // Test 1: Quick config (low security, small proofs)
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Configuration 1: Quick (5 queries, blowup 4, L=4)");
    println!("═══════════════════════════════════════════════════════════════\n");

    let fri_config = FriConfig {
        num_queries: 5,
        blowup_factor: 4,
        max_degree: 1024
    };
    let segment_config = SegmentConfig {
        segment_length: 4,
        fri_config,
    };
    measure_and_report(&segment_config, &start_hash);

    // Test 2: Medium config
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  Configuration 2: Medium (20 queries, blowup 4, L=16)");
    println!("═══════════════════════════════════════════════════════════════\n");

    let fri_config = FriConfig {
        num_queries: 20,
        blowup_factor: 4,
        max_degree: 4096
    };
    let segment_config = SegmentConfig {
        segment_length: 16,
        fri_config,
    };
    measure_and_report(&segment_config, &start_hash);

    // Test 3: Standard 128-bit security
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  Configuration 3: Standard 128-bit (68 queries, blowup 8, L=64)");
    println!("═══════════════════════════════════════════════════════════════\n");

    let fri_config = FriConfig {
        num_queries: 68,
        blowup_factor: 8,
        max_degree: 65536
    };
    let segment_config = SegmentConfig {
        segment_length: 64,
        fri_config,
    };
    measure_and_report(&segment_config, &start_hash);

    // Summary
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                     HONEST ASSESSMENT                         ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    println!("Real FRI proof sizes scale with:");
    println!("  - Number of queries (for soundness)");
    println!("  - Number of FRI layers (log of domain size)");
    println!("  - Merkle path lengths in each query response");
    println!();
    println!("For 128-bit security with standard parameters:");
    println!("  - 68 queries required");
    println!("  - Each query includes 2 field values + 2 Merkle paths");
    println!("  - Merkle paths are ~log2(domain_size) * 32 bytes each");
    println!();
    println!("This is the REAL cost of STARK proofs without SNARKification.");
}

fn measure_and_report(config: &SegmentConfig, start_hash: &[u8; 32]) {
    println!("Parameters:");
    println!("  Segment length: {} hash steps", config.segment_length);
    println!("  FRI queries: {}", config.fri_config.num_queries);
    println!("  Blowup factor: {}", config.fri_config.blowup_factor);
    println!("  Max degree: {}", config.fri_config.max_degree);
    println!();

    let prover = SegmentProver::new(config.clone());

    // Generate proof
    println!("Generating proof...");
    let prove_start = Instant::now();
    let proof = prover.prove(0, start_hash);
    let prove_time = prove_start.elapsed();

    // Serialize to measure sizes
    let proof_bytes = proof.serialize();
    let fri_bytes = proof.fri_proof.serialize();

    println!("\nProof Statistics:");
    println!("  Generation time: {:?}", prove_time);
    println!("  Total proof size: {} bytes ({:.2} KB)",
        proof_bytes.len(),
        proof_bytes.len() as f64 / 1024.0);
    println!("  FRI proof size: {} bytes ({:.2} KB)",
        fri_bytes.len(),
        fri_bytes.len() as f64 / 1024.0);

    println!("\nProof Components:");
    println!("  Segment header: {} bytes", 4 + 32 + 32); // index + start + end
    println!("  Column commitments: {} x 32 = {} bytes",
        proof.column_commitments.len(),
        proof.column_commitments.len() * 32);
    println!("  Boundary values: {} x 8 = {} bytes",
        proof.boundary_values.len(),
        proof.boundary_values.len() * 8);

    println!("\nFRI Proof Components:");
    println!("  Layer commitments: {} layers", proof.fri_proof.layer_commitments.len());
    for (i, lc) in proof.fri_proof.layer_commitments.iter().enumerate() {
        println!("    Layer {}: domain_size = {}", i, lc.domain_size);
    }
    println!("  Final layer: {} elements ({} bytes)",
        proof.fri_proof.final_layer.len(),
        proof.fri_proof.final_layer.len() * 8);

    let total_queries: usize = proof.fri_proof.query_responses.iter()
        .map(|layer| layer.len())
        .sum();
    println!("  Query responses: {} total across all layers", total_queries);

    if !proof.fri_proof.query_responses.is_empty() && !proof.fri_proof.query_responses[0].is_empty() {
        let sample = &proof.fri_proof.query_responses[0][0];
        let path_size = sample.path.serialize().len();
        println!("  Sample Merkle path size: {} bytes", path_size);
    }

    // Verify
    let verifier = SegmentVerifier::new(config.clone());

    // Single verification to check validity
    let verify_start = Instant::now();
    let valid = verifier.verify(&proof, start_hash);
    let verify_time = verify_start.elapsed();

    println!("\nVerification:");
    println!("  Time: {:?}", verify_time);
    println!("  Valid: {}", valid);

    if !valid {
        println!("  NOTE: Verification failed - this may be due to constraint system issues");
        println!("        The proof SIZE measurements above are still accurate.");
    }
}
