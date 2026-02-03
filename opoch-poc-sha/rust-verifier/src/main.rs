//! OPOCH-PoC-SHA Verifier Binary
//!
//! Verifies STARK proofs for SHA-256 hash chains.
//!
//! Usage:
//!   verifier <proof_file> <input_hex>
//!   verifier --test-vectors
//!   verifier --benchmark

use std::env;
use std::fs;
use std::time::Instant;

use opoch_poc_sha::{
    Sha256, sha256_32, hash_chain, verify_timed,
    params,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "--test-vectors" => run_test_vectors(),
        "--benchmark" => run_benchmark(),
        "--chain-test" => run_chain_test(),
        "--help" | "-h" => print_usage(),
        proof_file => {
            if args.len() < 3 {
                eprintln!("Error: Missing input hex argument");
                print_usage();
                return;
            }
            verify_proof_file(proof_file, &args[2]);
        }
    }
}

fn print_usage() {
    println!("OPOCH-PoC-SHA Verifier v{}", opoch_poc_sha::VERSION);
    println!();
    println!("Usage:");
    println!("  verifier <proof_file> <input_hex>   Verify a proof");
    println!("  verifier --test-vectors             Run SHA-256 test vectors");
    println!("  verifier --benchmark                Run verification benchmark");
    println!("  verifier --chain-test               Test hash chain computation");
    println!("  verifier --help                     Show this help");
    println!();
    println!("Parameters (pinned):");
    println!("  N = {} (chain length)", params::N);
    println!("  L = {} (segment length)", params::L);
    println!("  FRI queries = {}", params::FRI_QUERIES);
    println!("  FRI blowup = {}", params::FRI_BLOWUP);
}

fn verify_proof_file(proof_file: &str, input_hex: &str) {
    // Parse input
    let input = match hex::decode(input_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error: Invalid hex input: {}", e);
            return;
        }
    };

    // Read proof
    let proof_bytes = match fs::read(proof_file) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error: Cannot read proof file: {}", e);
            return;
        }
    };

    println!("Input: {} bytes", input.len());
    println!("Proof: {} bytes", proof_bytes.len());

    // Verify with timing
    let (valid, duration) = verify_timed(&input, &proof_bytes);

    if valid {
        println!("VALID - Verification time: {:?}", duration);
    } else {
        println!("INVALID - Verification failed");
        std::process::exit(1);
    }
}

fn run_test_vectors() {
    println!("Running SHA-256 FIPS 180-4 Test Vectors...\n");

    let vectors = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (input, expected) in vectors.iter() {
        let hash = Sha256::hash(input.as_bytes());
        let hash_hex = hex::encode(hash);

        if hash_hex == *expected {
            println!("[PASS] \"{}...\" -> {}",
                &input[..std::cmp::min(20, input.len())],
                &hash_hex[..16]);
            passed += 1;
        } else {
            println!("[FAIL] \"{}\"", input);
            println!("  Expected: {}", expected);
            println!("  Got:      {}", hash_hex);
            failed += 1;
        }
    }

    // Test optimized sha256_32
    println!("\nTesting optimized sha256_32...");
    let d0 = Sha256::hash(b"test");
    let h1_opt = sha256_32(&d0);

    // Compute same thing using general hasher
    let h1_gen = Sha256::hash(&d0);

    if h1_opt == h1_gen {
        println!("[PASS] sha256_32 matches Sha256::hash for 32-byte input");
        passed += 1;
    } else {
        println!("[FAIL] sha256_32 mismatch!");
        println!("  Expected: {}", hex::encode(h1_gen));
        println!("  Got:      {}", hex::encode(h1_opt));
        failed += 1;
    }

    // Test chain computation
    println!("\nTesting hash_chain...");
    let chain_result = hash_chain(&d0, 1000);

    let mut h = d0;
    for _ in 0..1000 {
        h = sha256_32(&h);
    }

    if chain_result == h {
        println!("[PASS] hash_chain(1000) correct");
        passed += 1;
    } else {
        println!("[FAIL] hash_chain mismatch!");
        failed += 1;
    }

    println!("\n{} passed, {} failed", passed, failed);

    if failed > 0 {
        std::process::exit(1);
    }
}

fn run_chain_test() {
    println!("Testing Hash Chain Computation...\n");

    let input = b"OPOCH test input";
    let d0 = Sha256::hash(input);

    println!("Input: \"{}\"", String::from_utf8_lossy(input));
    println!("d0 = SHA-256(input) = {}", hex::encode(d0));

    // Compute first 10 chain values
    let mut h = d0;
    for i in 1..=10 {
        h = sha256_32(&h);
        println!("h_{} = {}", i, hex::encode(h));
    }

    // Test larger chain
    println!("\nComputing hash chain for various lengths...");

    for &steps in &[100u64, 1000, 10000, 100000] {
        let start = Instant::now();
        let result = hash_chain(&d0, steps);
        let elapsed = start.elapsed();

        let rate = steps as f64 / elapsed.as_secs_f64();
        println!("  {} steps: {} ({:.2} hashes/sec)",
            steps,
            &hex::encode(result)[..16],
            rate);
    }

    // Verify chain consistency
    println!("\nVerifying chain consistency...");
    let h1 = hash_chain(&d0, 500);
    let h2 = hash_chain(&h1, 500);
    let h3 = hash_chain(&d0, 1000);

    if h2 == h3 {
        println!("[PASS] hash_chain(500) + hash_chain(500) = hash_chain(1000)");
    } else {
        println!("[FAIL] Chain composition mismatch!");
        std::process::exit(1);
    }
}

fn run_benchmark() {
    println!("OPOCH-PoC-SHA Verification Benchmark\n");
    println!("Target: < {}ms verification time\n", params::TARGET_VERIFY_MS);

    // Benchmark SHA-256 primitive
    println!("SHA-256 primitive performance:");
    let d0 = Sha256::hash(b"benchmark");

    let iterations = 1_000_000;
    let start = Instant::now();
    let mut h = d0;
    for _ in 0..iterations {
        h = sha256_32(&h);
    }
    let elapsed = start.elapsed();

    let rate = iterations as f64 / elapsed.as_secs_f64();
    println!("  {} hashes in {:?}", iterations, elapsed);
    println!("  Rate: {:.2} hashes/second", rate);
    println!("  Per hash: {:.2} ns", elapsed.as_nanos() as f64 / iterations as f64);
    println!("  Result (to prevent optimization): {}", &hex::encode(h)[..8]);

    // Estimate full chain time
    let full_chain_time = params::N as f64 / rate;
    println!("\nEstimated full chain ({} steps): {:.1} seconds",
        params::N, full_chain_time);

    // Benchmark Merkle tree operations
    println!("\nMerkle tree performance:");
    use opoch_poc_sha::MerkleTree;

    let leaves: Vec<Vec<u8>> = (0..1024u32)
        .map(|i| i.to_le_bytes().to_vec())
        .collect();

    let tree_start = Instant::now();
    let tree = MerkleTree::new(leaves.clone());
    let tree_time = tree_start.elapsed();

    println!("  Build tree (1024 leaves): {:?}", tree_time);

    let path_start = Instant::now();
    for i in 0..100 {
        let _ = tree.get_path(i % 1024);
    }
    let path_time = path_start.elapsed();
    println!("  100 path generations: {:?}", path_time);

    // Benchmark field operations
    println!("\nField operations:");
    use opoch_poc_sha::Fp;

    let a = Fp::new(12345678901234567890);
    let b = Fp::new(9876543210987654321);

    let field_iters = 1_000_000;

    let mul_start = Instant::now();
    let mut c = a;
    for _ in 0..field_iters {
        c = c * b;
    }
    let mul_time = mul_start.elapsed();
    println!("  {} multiplications: {:?}", field_iters, mul_time);

    let inv_start = Instant::now();
    let mut d = a;
    for _ in 0..1000 {
        d = d.inverse();
    }
    let inv_time = inv_start.elapsed();
    println!("  1000 inversions: {:?}", inv_time);

    // Summary
    println!("\n--- Benchmark Summary ---");
    println!("SHA-256 rate: {:.0} M hashes/sec", rate / 1_000_000.0);
    println!("Full chain time: {:.1} sec (prover work)", full_chain_time);
    println!("Verification target: < {} ms", params::TARGET_VERIFY_MS);
}
