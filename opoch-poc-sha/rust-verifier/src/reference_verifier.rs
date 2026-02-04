//! Reference Verifier
//!
//! Standalone verifier that reads statement and proof from files and verifies.
//! This is the canonical verification tool for all proofs.

use std::fs;
use std::time::Instant;

use opoch_poc_sha::sha256::Sha256;
use opoch_poc_sha::proof::OpochProof;
use opoch_poc_sha::endtoend::production_fri_config;
use opoch_poc_sha::fri::FriVerifier;
use opoch_poc_sha::transcript::Transcript;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <stmt.json> <proof.bin>", args[0]);
        eprintln!("\nVerifies an OPOCH proof against its statement.");
        std::process::exit(1);
    }

    let stmt_path = &args[1];
    let proof_path = &args[2];

    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║                    OPOCH REFERENCE VERIFIER                          ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝\n");

    // Read statement
    println!("Loading statement: {}", stmt_path);
    let stmt_str = fs::read_to_string(stmt_path).expect("Failed to read statement file");
    let stmt: serde_json::Value = serde_json::from_str(&stmt_str).expect("Failed to parse statement");

    // Read proof
    println!("Loading proof: {}", proof_path);
    let proof_bytes = fs::read(proof_path).expect("Failed to read proof file");

    // Parse proof
    let proof = match OpochProof::deserialize(&proof_bytes) {
        Some(p) => p,
        None => {
            eprintln!("[FAIL] Invalid proof structure");
            std::process::exit(1);
        }
    };

    // Extract statement values
    let spec_id = stmt["spec_id"].as_str().unwrap_or("unknown");
    let d0_hex = stmt["d0"].as_str().expect("Missing d0 in statement");
    let y_hex = stmt["y"].as_str().expect("Missing y in statement");
    let n = stmt["n"].as_u64().expect("Missing n in statement");
    let proof_hash_expected = stmt["proof_hash"].as_str().unwrap_or("");

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("Statement:");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  spec_id:  {}", spec_id);
    println!("  d0:       {}", d0_hex);
    println!("  y:        {}", y_hex);
    println!("  n:        {}", n);
    println!("  expected: {}", proof_hash_expected);

    // Verify proof hash
    let proof_hash_actual = Sha256::hash(&proof_bytes);
    let proof_hash_actual_hex = hex::encode(proof_hash_actual);

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("Proof integrity:");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Size:     {} bytes", proof_bytes.len());
    println!("  Hash:     {}", proof_hash_actual_hex);

    if !proof_hash_expected.is_empty() && proof_hash_actual_hex != proof_hash_expected {
        eprintln!("[FAIL] Proof hash mismatch!");
        eprintln!("  Expected: {}", proof_hash_expected);
        eprintln!("  Actual:   {}", proof_hash_actual_hex);
        std::process::exit(1);
    }
    println!("  [PASS] Hash matches statement");

    // Parse d0 and y from statement
    let d0 = hex::decode(d0_hex).expect("Invalid d0 hex");
    let y = hex::decode(y_hex).expect("Invalid y hex");

    // Verify header bindings
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("Header verification:");
    println!("═══════════════════════════════════════════════════════════════");

    if proof.header.d0 != d0.as_slice() {
        eprintln!("[FAIL] d0 mismatch between proof header and statement");
        std::process::exit(1);
    }
    println!("  [PASS] d0 matches");

    if proof.header.y != y.as_slice() {
        eprintln!("[FAIL] y mismatch between proof header and statement");
        std::process::exit(1);
    }
    println!("  [PASS] y matches");

    if proof.header.n != n {
        eprintln!("[FAIL] n mismatch: proof says {}, statement says {}", proof.header.n, n);
        std::process::exit(1);
    }
    println!("  [PASS] n matches ({})", n);

    // Verify chain boundaries in final proof
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("Chain binding verification:");
    println!("═══════════════════════════════════════════════════════════════");

    if proof.final_proof.chain_start != proof.header.d0 {
        eprintln!("[FAIL] Final proof chain_start != d0");
        std::process::exit(1);
    }
    println!("  [PASS] chain_start == d0");

    if proof.final_proof.chain_end != proof.header.y {
        eprintln!("[FAIL] Final proof chain_end != y");
        std::process::exit(1);
    }
    println!("  [PASS] chain_end == y");

    // Verify FRI proof
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("FRI verification:");
    println!("═══════════════════════════════════════════════════════════════");

    let verify_start = Instant::now();

    let mut transcript = Transcript::new();
    transcript.append_commitment(&proof.final_proof.children_root);
    transcript.append(&proof.final_proof.chain_start);
    transcript.append(&proof.final_proof.chain_end);

    // CRITICAL: Must call challenge_aggregation to match prover's transcript state
    let _alpha = transcript.challenge_aggregation();

    let fri_config = production_fri_config();
    let fri_verifier = FriVerifier::new(fri_config);

    let valid = fri_verifier.verify(&proof.final_proof.fri_proof, &mut transcript);
    let verify_time = verify_start.elapsed();

    if !valid {
        eprintln!("[FAIL] FRI verification failed");
        std::process::exit(1);
    }
    println!("  [PASS] FRI proof valid");
    println!("  Time: {:?}", verify_time);

    // Final verdict
    println!("\n╔══════════════════════════════════════════════════════════════════════╗");
    println!("║                              PASS                                    ║");
    println!("╠══════════════════════════════════════════════════════════════════════╣");
    println!("║  Proof verified successfully.                                        ║");
    println!("║                                                                      ║");
    println!("║  spec_id:     {}   ║", &spec_id.get(..40).unwrap_or(spec_id));
    println!("║  y:           {}   ║", &y_hex.get(..40).unwrap_or(y_hex));
    println!("║  verify_time: {:>10?}                                          ║", verify_time);
    println!("╚══════════════════════════════════════════════════════════════════════╝");

    std::process::exit(0);
}
