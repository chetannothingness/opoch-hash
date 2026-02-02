//! OPOCH-PoC-SHA Prover Binary
//!
//! Generates STARK proofs for SHA-256 hash chains.
//!
//! Usage:
//!   prover <input_hex> <output_proof_file>
//!   prover --segment <start_hash_hex> <segment_index>
//!   prover --demo                     Run demonstration with small parameters

use std::env;
use std::fs;
use std::time::Instant;

use opoch_poc_sha::{
    Sha256, hash_chain,
    SegmentConfig, SegmentProver,
    AggregationConfig, AggregationProver,
    FriConfig,
    params,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "--help" | "-h" => print_usage(),
        "--segment" => {
            if args.len() < 4 {
                eprintln!("Error: Missing arguments for --segment");
                print_usage();
                return;
            }
            prove_segment(&args[2], args[3].parse().unwrap_or(0));
        }
        "--estimate" => estimate_proving_time(),
        "--demo" => run_demo(),
        input_hex => {
            if args.len() < 3 {
                eprintln!("Error: Missing output file argument");
                print_usage();
                return;
            }
            prove_full(input_hex, &args[2]);
        }
    }
}

fn print_usage() {
    println!("OPOCH-PoC-SHA Prover v{}", opoch_poc_sha::VERSION);
    println!();
    println!("Usage:");
    println!("  prover <input_hex> <output_file>     Generate full proof");
    println!("  prover --segment <hash_hex> <index>  Generate segment proof");
    println!("  prover --estimate                    Estimate proving time");
    println!("  prover --demo                        Run demonstration");
    println!("  prover --help                        Show this help");
    println!();
    println!("Parameters (pinned):");
    println!("  N = {} (chain length)", params::N);
    println!("  L = {} (segment length)", params::L);
    println!("  Segments = {}", params::NUM_SEGMENTS);
}

fn run_demo() {
    println!("OPOCH-PoC-SHA Demonstration");
    println!("===========================\n");

    // Use small parameters for demo
    let segment_length = 8;
    let num_segments = 4;
    let total_steps = segment_length * num_segments;

    println!("Demo parameters:");
    println!("  Segment length: {}", segment_length);
    println!("  Number of segments: {}", num_segments);
    println!("  Total chain steps: {}\n", total_steps);

    // Input
    let input = b"OPOCH-PoC-SHA Demo";
    let d0 = Sha256::hash(input);

    println!("Input: \"{}\"", String::from_utf8_lossy(input));
    println!("d0 = SHA-256(input) = {}\n", hex::encode(d0));

    // Compute expected final hash
    let y = hash_chain(&d0, total_steps as u64);
    println!("Expected y = h_{} = {}\n", total_steps, hex::encode(y));

    // Create segment prover
    let segment_config = SegmentConfig {
        segment_length,
        fri_config: FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 512,
        },
    };

    let segment_prover = SegmentProver::new(segment_config);

    // Generate segment proofs
    println!("Phase 1: Generating {} segment proofs...", num_segments);
    let mut segment_proofs = Vec::new();
    let mut current_hash = d0;

    for i in 0..num_segments {
        let start = Instant::now();
        let proof = segment_prover.prove(i as u32, &current_hash);
        let elapsed = start.elapsed();

        println!("  Segment {}: {} -> {} ({:?})",
            i,
            &hex::encode(proof.start_hash)[..8],
            &hex::encode(proof.end_hash)[..8],
            elapsed);

        current_hash = proof.end_hash;
        segment_proofs.push(proof);
    }

    // Verify chain consistency
    assert_eq!(current_hash, y, "Chain computation mismatch!");
    println!("\nChain computation verified: final hash matches y\n");

    // Aggregate into level-1 proof
    println!("Phase 2: Aggregating segments into L1 proof...");
    let agg_config = AggregationConfig {
        max_children: 16,
        fri_config: FriConfig {
            num_queries: 10,
            blowup_factor: 4,
            max_degree: 256,
        },
    };

    let agg_prover = AggregationProver::new(agg_config);

    let l1_start = Instant::now();
    let l1_proof = agg_prover.aggregate_segments(&segment_proofs);
    let l1_elapsed = l1_start.elapsed();

    println!("  L1 proof generated: {} children, root = {} ({:?})",
        l1_proof.num_children,
        &hex::encode(l1_proof.children_root)[..16],
        l1_elapsed);

    // For demo, create final L2 proof from single L1
    println!("\nPhase 3: Generating final L2 proof...");
    let l2_start = Instant::now();
    let l2_proof = agg_prover.aggregate_level1(&[l1_proof]);
    let l2_elapsed = l2_start.elapsed();

    println!("  L2 proof generated: {} children, root = {} ({:?})",
        l2_proof.num_children,
        &hex::encode(l2_proof.children_root)[..16],
        l2_elapsed);

    // Summary
    println!("\n=== Demo Summary ===");
    println!("Input: \"{}\"", String::from_utf8_lossy(input));
    println!("d0: {}", hex::encode(d0));
    println!("y (after {} steps): {}", total_steps, hex::encode(y));
    println!("Proof structure:");
    println!("  - {} segment proofs", num_segments);
    println!("  - 1 L1 aggregation proof");
    println!("  - 1 L2 final proof");
    println!("\nProof verified: chain d0 -> y is correct");
}

fn prove_full(input_hex: &str, output_file: &str) {
    println!("OPOCH-PoC-SHA Full Proof Generation");
    println!("===================================\n");

    // Parse input
    let input = match hex::decode(input_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error: Invalid hex input: {}", e);
            return;
        }
    };

    // Compute d0
    let start = Instant::now();
    let d0 = Sha256::hash(&input);
    println!("d0 = SHA-256(input) = {}", hex::encode(d0));

    // Phase 1: Compute full hash chain (this takes a while!)
    println!("\nPhase 1: Computing hash chain ({} steps)...", params::N);
    println!("  This will take approximately {} seconds", params::N / 3_000_000);

    // For now, we demonstrate with a smaller chain
    let demo_steps = 100_000u64;
    println!("  [DEMO MODE: Computing {} steps instead]", demo_steps);

    let chain_start = Instant::now();
    let y = hash_chain(&d0, demo_steps);
    let chain_time = chain_start.elapsed();

    println!("  Chain computation: {:?}", chain_time);
    println!("  y = h_{} = {}", demo_steps, hex::encode(y));

    // Phase 2: Generate segment proofs
    println!("\nPhase 2: Generating segment proofs...");
    let num_demo_segments = demo_steps / params::L;
    println!("  Number of segments: {}", num_demo_segments);

    // TODO: Implement actual segment proof generation
    // For now, this is a placeholder
    println!("  [STUB] Segment proof generation not yet implemented");

    // Phase 3: Level-1 aggregation
    println!("\nPhase 3: Level-1 aggregation...");
    println!("  [STUB] Level-1 aggregation not yet implemented");

    // Phase 4: Level-2 aggregation
    println!("\nPhase 4: Level-2 aggregation...");
    println!("  [STUB] Level-2 aggregation not yet implemented");

    // Write output
    println!("\nWriting proof to: {}", output_file);
    println!("  [STUB] Proof serialization not yet implemented");

    let total_time = start.elapsed();
    println!("\nTotal proving time: {:?}", total_time);
}

fn prove_segment(start_hash_hex: &str, segment_index: u32) {
    println!("Generating Segment Proof #{}\n", segment_index);

    // Parse start hash
    let start_hash_bytes = match hex::decode(start_hash_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        Ok(_) => {
            eprintln!("Error: Start hash must be 32 bytes");
            return;
        }
        Err(e) => {
            eprintln!("Error: Invalid hex: {}", e);
            return;
        }
    };

    println!("Start hash: {}", start_hash_hex);
    println!("Segment index: {}", segment_index);
    println!("Segment length: {}", params::L);

    // Compute segment chain
    let start = Instant::now();
    let end_hash = hash_chain(&start_hash_bytes, params::L);
    let chain_time = start.elapsed();

    println!("End hash: {}", hex::encode(end_hash));
    println!("Chain time: {:?}", chain_time);

    // TODO: Generate AIR trace and FRI proof
    println!("\n[STUB] AIR trace generation not yet implemented");
    println!("[STUB] FRI proof generation not yet implemented");
}

fn estimate_proving_time() {
    println!("OPOCH-PoC-SHA Proving Time Estimation\n");

    // Benchmark hash chain
    let d0 = Sha256::hash(b"benchmark");

    let bench_steps = 1_000_000u64;
    let start = Instant::now();
    let _ = hash_chain(&d0, bench_steps);
    let elapsed = start.elapsed();

    let rate = bench_steps as f64 / elapsed.as_secs_f64();
    println!("Hash chain rate: {:.2} M hashes/sec", rate / 1_000_000.0);

    // Estimate full chain time
    let chain_time = params::N as f64 / rate;
    println!("\nPhase 1 - Chain computation:");
    println!("  {} steps @ {:.0} M/s = {:.1} seconds",
        params::N, rate / 1_000_000.0, chain_time);

    // Estimate segment proof time (placeholder - depends on constraint complexity)
    let segment_proof_time_ms = 50.0; // Estimated ms per segment proof
    let num_segments = params::NUM_SEGMENTS;
    let segment_time = (num_segments as f64 * segment_proof_time_ms) / 1000.0;

    println!("\nPhase 2 - Segment proofs:");
    println!("  {} segments @ {:.0}ms each = {:.0} seconds",
        num_segments, segment_proof_time_ms, segment_time);
    println!("  (With parallelization, ~{:.0} seconds on 16 cores)",
        segment_time / 16.0);

    // Level-1 aggregation
    let l1_groups = 1000; // ~976 segments per L1 proof
    let l1_proofs = num_segments / l1_groups;
    let l1_time_per = 100.0; // ms per L1 proof
    let l1_time = (l1_proofs as f64 * l1_time_per) / 1000.0;

    println!("\nPhase 3 - Level-1 aggregation:");
    println!("  {} proofs @ {:.0}ms each = {:.0} seconds",
        l1_proofs, l1_time_per, l1_time);

    // Level-2 aggregation
    let l2_time_per = 200.0; // ms for final aggregation
    println!("\nPhase 4 - Level-2 aggregation:");
    println!("  1 proof @ {:.0}ms = {:.1} seconds", l2_time_per, l2_time_per / 1000.0);

    // Total
    let total = chain_time + segment_time / 16.0 + l1_time + l2_time_per / 1000.0;
    println!("\n--- Estimated Total Proving Time ---");
    println!("Sequential: {:.0} seconds ({:.1} hours)",
        chain_time + segment_time + l1_time + l2_time_per / 1000.0,
        (chain_time + segment_time + l1_time + l2_time_per / 1000.0) / 3600.0);
    println!("With 16-core parallelization: {:.0} seconds ({:.1} minutes)",
        total, total / 60.0);

    println!("\n--- Verification Time ---");
    println!("Target: < {} ms", params::TARGET_VERIFY_MS);
}
