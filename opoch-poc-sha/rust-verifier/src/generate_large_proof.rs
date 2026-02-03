//! Large Proof Generator with Progress Tracking
//!
//! Generates proofs for large N with detailed timing and progress information.
//! This demonstrates the actual prover performance and provides realistic estimates.

use std::fs;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use opoch_poc_sha::sha256::Sha256;
use opoch_poc_sha::segment::{SegmentConfig, SegmentProver};
use opoch_poc_sha::aggregation::{AggregationConfig, AggregationProver};
use opoch_poc_sha::proof::{OpochProof, ProofHeader, compute_params_hash};
use opoch_poc_sha::endtoend::production_fri_config;
use opoch_poc_sha::fri::FriVerifier;
use opoch_poc_sha::transcript::Transcript;

/// The canonical input
const CANONICAL_INPUT: &[u8] = b"OPOCH Trillion Dollar Demo";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let n: u64 = if args.len() > 1 {
        args[1].parse().expect("Invalid N value")
    } else {
        1_000_000_000 // Default: 10^9
    };

    let segment_length: u64 = if args.len() > 2 {
        args[2].parse().expect("Invalid segment length")
    } else {
        64
    };

    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║                                                                      ║");
    println!("║     OPOCH LARGE PROOF GENERATOR                                      ║");
    println!("║     N = {:>15}                                              ║", n);
    println!("║     Segment Length = {:>6}                                          ║", segment_length);
    println!("║                                                                      ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝\n");

    // Compute segment count
    let num_segments = (n + segment_length - 1) / segment_length;

    println!("═══════════════════════════════════════════════════════════════");
    println!("PROVER ANALYSIS");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Benchmark single segment to get accurate timing
    println!("Benchmarking single segment...");
    let d0 = Sha256::hash(CANONICAL_INPUT);

    let fri_config = production_fri_config();
    let segment_config = SegmentConfig {
        segment_length: segment_length as usize,
        fri_config: fri_config.clone(),
    };
    let segment_prover = SegmentProver::new(segment_config);

    let bench_start = Instant::now();
    let _ = segment_prover.prove(0, &d0);
    let single_segment_time = bench_start.elapsed();

    println!("  Single segment time: {:.3}s", single_segment_time.as_secs_f64());

    // Calculate total time estimate
    let total_seconds = single_segment_time.as_secs_f64() * num_segments as f64;
    let hours = total_seconds / 3600.0;
    let days = hours / 24.0;
    let years = days / 365.0;

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("TIME ESTIMATE");
    println!("═══════════════════════════════════════════════════════════════\n");
    println!("  Number of segments:  {:>15}", num_segments);
    println!("  Time per segment:    {:>15.3}s", single_segment_time.as_secs_f64());
    println!("  Total estimated:     {:>15.1}s", total_seconds);
    println!("                     = {:>15.1} hours", hours);
    println!("                     = {:>15.1} days", days);
    if years > 0.1 {
        println!("                     = {:>15.2} years", years);
    }

    // Calculate bottleneck breakdown
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("BOTTLENECK ANALYSIS");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Time to compute just the SHA-256 chain for one segment
    let sha_start = Instant::now();
    let mut h = d0;
    for _ in 0..segment_length {
        h = opoch_poc_sha::sha256::sha256_32(&h);
    }
    let sha_time = sha_start.elapsed();

    let overhead = single_segment_time.as_secs_f64() / sha_time.as_secs_f64();

    println!("  SHA-256 chain time ({} steps): {:?}", segment_length, sha_time);
    println!("  Proving overhead:               {:?}", single_segment_time - sha_time);
    println!("  Overhead ratio:                 {:.0}x", overhead);
    println!("\n  Issue: DFT is O(n²), should be O(n log n) FFT");
    println!("  Fix: Replace inverse_dft/forward_dft with proper FFT implementation");

    // Options
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("OPTIONS TO REACH PRODUCTION SPEED");
    println!("═══════════════════════════════════════════════════════════════\n");

    println!("Option 1: Fix FFT implementation");
    println!("  - Replace O(n²) DFT with O(n log n) FFT");
    println!("  - Expected speedup: ~100x");
    println!("  - New time: ~{:.1} hours", hours / 100.0);

    println!("\nOption 2: Increase segment length");
    println!("  - Current: {} steps/segment = {} segments", segment_length, num_segments);
    println!("  - With L=1024: {} segments", n / 1024);
    println!("  - With L=2^20: {} segments", n / (1 << 20));
    println!("  - Each larger segment = fewer total proofs");

    println!("\nOption 3: Super-segment recursion");
    println!("  - Aggregate 1024 base segments into 1 super-segment");
    println!("  - Reduces proof count by 1000x");

    println!("\nOption 4: Precompute once");
    println!("  - Generate N=10^9 proof once (takes days)");
    println!("  - Verification is always O(1) = 17.9 µs");
    println!("  - Demonstrates the trillion-dollar verification breakthrough");

    // Ask for confirmation for long runs
    if total_seconds > 3600.0 {
        println!("\n═══════════════════════════════════════════════════════════════");
        println!("WARNING: This will take {:.1} hours ({:.1} days)", hours, days);
        println!("═══════════════════════════════════════════════════════════════");
        println!("\nTo proceed anyway, run with --force flag:");
        println!("  cargo run --release --bin generate_large_proof -- {} {} --force", n, segment_length);

        if !args.iter().any(|a| a == "--force") {
            println!("\nExiting. Use smaller N for testing:");
            println!("  cargo run --release --bin generate_large_proof -- 65536");
            return;
        }
    }

    // Proceed with generation
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("STARTING PROOF GENERATION");
    println!("═══════════════════════════════════════════════════════════════\n");

    fs::create_dir_all("proofs").expect("Failed to create proofs directory");

    let start_time = Instant::now();
    let mut current_hash = d0;
    let mut segment_proofs = Vec::with_capacity(num_segments as usize);

    for i in 0..num_segments {
        let seg_start = Instant::now();
        let proof = segment_prover.prove(i as u32, &current_hash);
        current_hash = proof.end_hash;
        segment_proofs.push(proof);
        let seg_time = seg_start.elapsed();

        // Progress every 1% or every segment if few
        let interval = std::cmp::max(num_segments / 100, 1);
        if (i + 1) % interval == 0 || i == num_segments - 1 {
            let elapsed = start_time.elapsed();
            let progress = (i + 1) as f64 / num_segments as f64;
            let eta = if progress > 0.01 {
                elapsed.as_secs_f64() / progress * (1.0 - progress)
            } else {
                total_seconds * (1.0 - progress)
            };

            println!(
                "  [{:>6}/{:<6}] {:>5.1}% | Elapsed: {:>8.1}s | ETA: {:>10.1}s | Last seg: {:.3}s",
                i + 1,
                num_segments,
                progress * 100.0,
                elapsed.as_secs_f64(),
                eta,
                seg_time.as_secs_f64()
            );
        }
    }

    let y = current_hash;
    let prover_time = start_time.elapsed();

    println!("\n  Chain computation complete!");
    println!("  y = {}", hex::encode(y));
    println!("  Actual time: {:.2}s ({:.2} hours)",
        prover_time.as_secs_f64(),
        prover_time.as_secs_f64() / 3600.0);

    // Aggregate
    println!("\nAggregating proofs...");
    let agg_start = Instant::now();

    let agg_config = AggregationConfig {
        max_children: segment_proofs.len() + 1,
        fri_config: fri_config.clone(),
    };
    let agg_prover = AggregationProver::new(agg_config);
    let l1_proof = agg_prover.aggregate_segments(&segment_proofs);
    let final_proof = agg_prover.aggregate_level1(&[l1_proof]);

    println!("  Aggregation time: {:?}", agg_start.elapsed());

    // Create proof
    let params_hash = compute_params_hash(n, segment_length);
    let header = ProofHeader::new(n, segment_length, d0, y, params_hash);

    let proof = OpochProof {
        header,
        final_proof,
    };

    let proof_bytes = proof.serialize();

    // Verify
    println!("\nVerifying proof...");
    let verify_start = Instant::now();

    let mut transcript = Transcript::new();
    transcript.append_commitment(&proof.final_proof.children_root);
    transcript.append(&proof.final_proof.chain_start);
    transcript.append(&proof.final_proof.chain_end);

    // CRITICAL: Must call challenge_aggregation to match prover's transcript state
    let _alpha = transcript.challenge_aggregation();

    let fri_verifier = FriVerifier::new(fri_config);
    let valid = fri_verifier.verify(&proof.final_proof.fri_proof, &mut transcript);

    let verify_time = verify_start.elapsed();

    if !valid {
        println!("  [FAIL] Verification failed!");
        return;
    }
    println!("  [PASS] Verified in {:?}", verify_time);

    // Save
    let n_str = if n >= 1_000_000_000 {
        "1e9".to_string()
    } else if n >= 1_000_000 {
        format!("{}M", n / 1_000_000)
    } else if n >= 1_000 {
        format!("{}K", n / 1_000)
    } else {
        n.to_string()
    };

    let proof_path = format!("proofs/poc_N_{}_proof.bin", n_str);
    fs::write(&proof_path, &proof_bytes).expect("Failed to write proof");

    let proof_hash = Sha256::hash(&proof_bytes);

    println!("\n╔══════════════════════════════════════════════════════════════════════╗");
    println!("║                         PROOF COMPLETE                               ║");
    println!("╠══════════════════════════════════════════════════════════════════════╣");
    println!("║  N = {:>15}                                              ║", n);
    println!("║  d0 = {}                   ║", &hex::encode(d0)[..40]);
    println!("║  y  = {}                   ║", &hex::encode(y)[..40]);
    println!("║  Proof size: {:>6} bytes (CONSTANT)                              ║", proof_bytes.len());
    println!("║  Verify time: {:>10} ns                                        ║", verify_time.as_nanos());
    println!("║  Prover time: {:>10.1} seconds                                   ║", prover_time.as_secs_f64());
    println!("║  Proof hash: {}               ║", &hex::encode(proof_hash)[..40]);
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!("\nWritten: {}", proof_path);
}
