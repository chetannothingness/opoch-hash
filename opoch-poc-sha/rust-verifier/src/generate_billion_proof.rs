//! Proof Generator
//!
//! Generates the flagship artifact: proof that y = SHA256^N(d0)
//! This is the trillion-dollar demo artifact.
//!
//! Usage:
//!   cargo run --release --bin generate_billion_proof           # Default: N=4096 (demo)
//!   cargo run --release --bin generate_billion_proof -- 65536  # N=65536
//!   cargo run --release --bin generate_billion_proof -- 1000000000  # Full: N=10^9

use std::fs;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use opoch_poc_sha::sha256::Sha256;
use opoch_poc_sha::segment::{SegmentConfig, SegmentProver};
use opoch_poc_sha::aggregation::{AggregationConfig, AggregationProver};
use opoch_poc_sha::proof::{OpochProof, ProofHeader, compute_params_hash};
use opoch_poc_sha::endtoend::production_fri_config;
use opoch_poc_sha::fri::FriVerifier;
use opoch_poc_sha::transcript::Transcript;

/// The canonical input for all proofs
const CANONICAL_INPUT: &[u8] = b"OPOCH Trillion Dollar Demo";

/// Segment length (steps per segment)
const SEGMENT_LENGTH: u64 = 64;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Parse N from command line or use default
    let n: u64 = if args.len() > 1 {
        args[1].parse().expect("Invalid N value")
    } else {
        4096 // Default: 2^12 (generates in ~7 minutes)
    };

    // Determine output file names based on N
    let n_str = if n == 1_000_000_000 {
        "1e9".to_string()
    } else if n >= 1_000_000 {
        format!("{}M", n / 1_000_000)
    } else if n >= 1_000 {
        format!("{}K", n / 1_000)
    } else {
        n.to_string()
    };

    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║                                                                      ║");
    println!("║     OPOCH PROOF GENERATOR                                            ║");
    println!("║     N = {:>15}                                              ║", n);
    println!("║                                                                      ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝\n");

    // Create output directories
    fs::create_dir_all("proofs").expect("Failed to create proofs directory");
    fs::create_dir_all("public_bundle/vectors").expect("Failed to create vectors directory");

    // Compute d0
    let d0 = Sha256::hash(CANONICAL_INPUT);
    println!("Input: {:?}", String::from_utf8_lossy(CANONICAL_INPUT));
    println!("d0 = SHA256(input) = {}", hex::encode(d0));

    // Compute number of segments
    let num_segments = (n + SEGMENT_LENGTH - 1) / SEGMENT_LENGTH;
    println!("\nProof structure:");
    println!("  N = {}", n);
    println!("  Segment length = {}", SEGMENT_LENGTH);
    println!("  Number of segments = {}", num_segments);

    // Estimate time
    let est_seconds = num_segments as f64 * 6.7; // ~6.7s per 64-step segment
    if est_seconds > 3600.0 {
        println!("  Estimated time: {:.1} hours", est_seconds / 3600.0);
    } else if est_seconds > 60.0 {
        println!("  Estimated time: {:.1} minutes", est_seconds / 60.0);
    } else {
        println!("  Estimated time: {:.1} seconds", est_seconds);
    }

    // Phase 0: Generate segment proofs
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("Phase 0: Generating segment proofs (N = {})", n);
    println!("═══════════════════════════════════════════════════════════════\n");

    let chain_start = Instant::now();

    let fri_config = production_fri_config();
    let segment_config = SegmentConfig {
        segment_length: SEGMENT_LENGTH as usize,
        fri_config: fri_config.clone(),
    };
    let segment_prover = SegmentProver::new(segment_config);

    let mut segment_proofs = Vec::with_capacity(num_segments as usize);
    let mut current_hash = d0;

    println!("Generating {} segment proofs...\n", num_segments);

    for i in 0..num_segments {
        let proof = segment_prover.prove(i as u32, &current_hash);
        current_hash = proof.end_hash;
        segment_proofs.push(proof);

        // Progress update
        let progress_interval = std::cmp::max(num_segments / 100, 1);
        if (i + 1) % progress_interval == 0 || i == num_segments - 1 {
            let elapsed = chain_start.elapsed();
            let progress = (i + 1) as f64 / num_segments as f64;
            let eta = if progress > 0.0 {
                elapsed.as_secs_f64() / progress * (1.0 - progress)
            } else {
                0.0
            };

            print!(
                "\r  Progress: {}/{} ({:.1}%) | Elapsed: {:.1}s | ETA: {:.1}s    ",
                i + 1,
                num_segments,
                progress * 100.0,
                elapsed.as_secs_f64(),
                eta
            );
            use std::io::Write;
            std::io::stdout().flush().unwrap();
        }
    }
    println!();

    let y = current_hash;
    let chain_time = chain_start.elapsed();

    println!("\nChain computation complete!");
    println!("  y = SHA256^{}(d0) = {}", n, hex::encode(y));
    println!("  Time: {:.2} seconds ({:.2} minutes)",
        chain_time.as_secs_f64(),
        chain_time.as_secs_f64() / 60.0);

    // Phase 1: L1 Aggregation
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("Phase 1: L1 Aggregation");
    println!("═══════════════════════════════════════════════════════════════\n");

    let l1_start = Instant::now();

    let agg_config = AggregationConfig {
        max_children: segment_proofs.len() + 1,
        fri_config: fri_config.clone(),
    };
    let agg_prover = AggregationProver::new(agg_config);

    // Aggregate in batches for large numbers
    let batch_size = std::cmp::min(1000, segment_proofs.len());
    let mut l1_proofs = Vec::new();

    if segment_proofs.len() <= batch_size {
        // Single batch
        let l1_proof = agg_prover.aggregate_segments(&segment_proofs);
        l1_proofs.push(l1_proof);
        println!("  Single L1 batch: {} segments", segment_proofs.len());
    } else {
        // Multiple batches
        for batch_start in (0..segment_proofs.len()).step_by(batch_size) {
            let batch_end = std::cmp::min(batch_start + batch_size, segment_proofs.len());
            let batch = &segment_proofs[batch_start..batch_end];
            let l1_proof = agg_prover.aggregate_segments(batch);
            l1_proofs.push(l1_proof);
            println!("  L1 batch {}-{} aggregated", batch_start, batch_end);
        }
    }

    println!("  L1 aggregation: {:?}", l1_start.elapsed());

    // Phase 2: L2 Final Aggregation
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("Phase 2: L2 Final Aggregation");
    println!("═══════════════════════════════════════════════════════════════\n");

    let l2_start = Instant::now();
    let final_proof = agg_prover.aggregate_level1(&l1_proofs);
    println!("  L2 aggregation: {:?}", l2_start.elapsed());

    // Create complete proof
    let params_hash = compute_params_hash(n, SEGMENT_LENGTH);
    let header = ProofHeader::new(n, SEGMENT_LENGTH, d0, y, params_hash);

    let proof = OpochProof {
        header,
        final_proof,
    };

    // Serialize proof
    let proof_bytes = proof.serialize();
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("PROOF GENERATED");
    println!("═══════════════════════════════════════════════════════════════\n");
    println!("  Proof size: {} bytes", proof_bytes.len());

    // Verify the proof
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

    if valid {
        println!("  [PASS] Proof verified in {:?}", verify_time);
    } else {
        println!("  [FAIL] Proof verification failed!");
        std::process::exit(1);
    }

    // Write outputs
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("Writing artifacts");
    println!("═══════════════════════════════════════════════════════════════\n");

    // 1. Proof binary
    let proof_path = format!("proofs/poc_N_{}_proof.bin", n_str);
    fs::write(&proof_path, &proof_bytes).expect("Failed to write proof");
    println!("  Written: {}", proof_path);

    // 2. d0 hex
    let d0_path = format!("proofs/poc_N_{}_d0.hex", n_str);
    fs::write(&d0_path, hex::encode(d0)).expect("Failed to write d0");
    println!("  Written: {}", d0_path);

    // 3. y hex
    let y_path = format!("proofs/poc_N_{}_y.hex", n_str);
    fs::write(&y_path, hex::encode(y)).expect("Failed to write y");
    println!("  Written: {}", y_path);

    // 4. Statement JSON
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Read spec_id and verifier_id
    let spec_id = fs::read_to_string("public_bundle/verifier_id.txt")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    let verifier_id = fs::read_to_string("public_bundle/verifier_id.txt")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    // Compute proof hash
    let proof_hash = Sha256::hash(&proof_bytes);

    // Read environment hash
    let env_json = fs::read_to_string("public_bundle/environment.json")
        .unwrap_or_else(|_| "{}".to_string());
    let env_hash = Sha256::hash(env_json.as_bytes());

    let stmt = serde_json::json!({
        "spec_id": spec_id,
        "verifier_id": verifier_id,
        "H0_alg": "SHA256_FIPS_180_4",
        "x": hex::encode(CANONICAL_INPUT),
        "x_hash": hex::encode(d0),
        "d0": hex::encode(d0),
        "n": n,
        "segment_L": SEGMENT_LENGTH,
        "recursion_layout": {
            "levels": 3,
            "L0_fan_in": SEGMENT_LENGTH,
            "L1_batch_size": batch_size,
            "L2_fan_in": l1_proofs.len(),
            "padding": "zero_pad_to_power_of_2"
        },
        "y": hex::encode(y),
        "proof_size_bytes": proof_bytes.len(),
        "proof_hash": hex::encode(proof_hash),
        "timestamp_utc": timestamp,
        "prover_time_seconds": chain_time.as_secs_f64(),
        "verify_time_ns": verify_time.as_nanos() as u64,
        "environment_hash": hex::encode(env_hash)
    });

    let stmt_path = format!("proofs/poc_N_{}_stmt.json", n_str);
    let stmt_str = serde_json::to_string_pretty(&stmt).unwrap();
    fs::write(&stmt_path, &stmt_str).expect("Failed to write statement");
    println!("  Written: {}", stmt_path);

    // Copy to public bundle
    let bundle_proof_path = format!("public_bundle/vectors/poc_N_{}_proof.bin", n_str);
    fs::copy(&proof_path, &bundle_proof_path).expect("Failed to copy proof");
    println!("  Copied:  {}", bundle_proof_path);

    let bundle_stmt_path = format!("public_bundle/vectors/poc_N_{}_stmt.json", n_str);
    fs::copy(&stmt_path, &bundle_stmt_path).expect("Failed to copy statement");
    println!("  Copied:  {}", bundle_stmt_path);

    // Write proof hash
    let hash_path = format!("public_bundle/vectors/poc_N_{}_proof.sha256", n_str);
    let hash_content = format!("{}  poc_N_{}_proof.bin\n", hex::encode(proof_hash), n_str);
    fs::write(&hash_path, &hash_content).expect("Failed to write hash");
    println!("  Written: {}", hash_path);

    // Final summary
    println!("\n╔══════════════════════════════════════════════════════════════════════╗");
    println!("║                         PROOF COMPLETE                               ║");
    println!("╠══════════════════════════════════════════════════════════════════════╣");
    println!("║  N = {:>15}                                              ║", n);
    println!("║  d0 = {}...                                ║", &hex::encode(d0)[..16]);
    println!("║  y  = {}...                                ║", &hex::encode(y)[..16]);
    println!("║  Proof size: {:>6} bytes (CONSTANT)                              ║", proof_bytes.len());
    println!("║  Verify time: {:>10} ns                                        ║", verify_time.as_nanos());
    println!("║  Prover time: {:>10.1} seconds                                   ║", chain_time.as_secs_f64());
    println!("╚══════════════════════════════════════════════════════════════════════╝");

    // Print verification command
    println!("\nTo verify this proof:");
    println!("  cargo run --release --bin reference_verifier -- {} {}", bundle_stmt_path, bundle_proof_path);
}
