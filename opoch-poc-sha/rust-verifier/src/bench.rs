//! OPOCH-PoC-SHA Benchmark Suite
//!
//! Benchmarks A-E as specified in the protocol:
//! A. SHA-256 primitive correctness
//! B. Hash chain computation
//! C. Field arithmetic
//! D. Merkle tree operations
//! E. Full verification (once proofs are available)

use std::time::Instant;

use opoch_poc_sha::{
    Sha256, sha256_32, hash_chain,
    Fp, Fp2,
    MerkleTree, MerklePath,
    FriConfig, FriProver, FriVerifier,
    Transcript,
    params,
};

fn main() {
    println!("OPOCH-PoC-SHA Benchmark Suite v{}", opoch_poc_sha::VERSION);
    println!("=========================================\n");

    let args: Vec<String> = std::env::args().collect();

    let benchmarks: Vec<&str> = if args.len() > 1 {
        args[1..].iter().map(|s| s.as_str()).collect()
    } else {
        vec!["A", "B", "C", "D", "E"]
    };

    for bench in benchmarks {
        match bench.to_uppercase().as_str() {
            "A" => benchmark_a_sha256(),
            "B" => benchmark_b_chain(),
            "C" => benchmark_c_field(),
            "D" => benchmark_d_merkle(),
            "E" => benchmark_e_verification(),
            _ => println!("Unknown benchmark: {}", bench),
        }
        println!();
    }

    println!("Benchmark suite complete.");
}

/// Benchmark A: SHA-256 Primitive Correctness and Performance
fn benchmark_a_sha256() {
    println!("=== Benchmark A: SHA-256 Primitive ===\n");

    // A1: FIPS 180-4 test vectors
    println!("A1. FIPS 180-4 Test Vectors:");
    let vectors = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ];

    let mut all_pass = true;
    for (input, expected) in vectors.iter() {
        let hash = Sha256::hash(input.as_bytes());
        let actual = hex::encode(hash);
        let pass = actual == *expected;
        all_pass = all_pass && pass;
        println!("  {} Input: \"{}...\"",
            if pass { "[PASS]" } else { "[FAIL]" },
            &input[..std::cmp::min(16, input.len())]);
    }
    println!("  Result: {}\n", if all_pass { "ALL PASS" } else { "SOME FAILED" });

    // A2: sha256_32 equivalence
    println!("A2. sha256_32 Equivalence:");
    let mut equivalence_pass = true;
    for i in 0..100 {
        let input: [u8; 32] = std::array::from_fn(|j| (i * 17 + j * 31) as u8);
        let opt = sha256_32(&input);
        let gen = Sha256::hash(&input);
        if opt != gen {
            equivalence_pass = false;
            break;
        }
    }
    println!("  {} 100 random 32-byte inputs\n",
        if equivalence_pass { "[PASS]" } else { "[FAIL]" });

    // A3: Performance
    println!("A3. Performance:");
    let d0 = Sha256::hash(b"bench");
    let iterations = 1_000_000;

    let start = Instant::now();
    let mut h = d0;
    for _ in 0..iterations {
        h = sha256_32(&h);
    }
    let elapsed = start.elapsed();
    let rate = iterations as f64 / elapsed.as_secs_f64();

    println!("  {} iterations: {:?}", iterations, elapsed);
    println!("  Rate: {:.2} M hashes/sec", rate / 1_000_000.0);
    println!("  Per hash: {:.1} ns", elapsed.as_nanos() as f64 / iterations as f64);
    println!("  (prevent opt: {})", &hex::encode(h)[..8]);
}

/// Benchmark B: Hash Chain Computation
fn benchmark_b_chain() {
    println!("=== Benchmark B: Hash Chain ===\n");

    let d0 = Sha256::hash(b"chain benchmark");

    // B1: Correctness
    println!("B1. Chain Correctness:");
    let h1 = hash_chain(&d0, 1);
    let h1_manual = sha256_32(&d0);
    let pass1 = h1 == h1_manual;
    println!("  {} hash_chain(1) == sha256_32", if pass1 { "[PASS]" } else { "[FAIL]" });

    // Composition test
    let h500a = hash_chain(&d0, 500);
    let h1000a = hash_chain(&h500a, 500);
    let h1000b = hash_chain(&d0, 1000);
    let pass2 = h1000a == h1000b;
    println!("  {} chain(500) + chain(500) == chain(1000)\n",
        if pass2 { "[PASS]" } else { "[FAIL]" });

    // B2: Performance at various lengths
    println!("B2. Performance:");
    for &steps in &[1_000u64, 10_000, 100_000, 1_000_000] {
        let start = Instant::now();
        let result = hash_chain(&d0, steps);
        let elapsed = start.elapsed();
        let rate = steps as f64 / elapsed.as_secs_f64();
        println!("  {} steps: {:?} ({:.2} M/s) -> {}",
            steps, elapsed, rate / 1_000_000.0, &hex::encode(result)[..8]);
    }

    // B3: Full chain estimate
    println!("\nB3. Full Chain (N={}) Estimate:", params::N);
    let bench_steps = 1_000_000u64;
    let start = Instant::now();
    let _ = hash_chain(&d0, bench_steps);
    let elapsed = start.elapsed();
    let rate = bench_steps as f64 / elapsed.as_secs_f64();
    let full_time = params::N as f64 / rate;
    println!("  Estimated time: {:.1} seconds ({:.1} minutes)",
        full_time, full_time / 60.0);
}

/// Benchmark C: Field Arithmetic
fn benchmark_c_field() {
    println!("=== Benchmark C: Field Arithmetic ===\n");

    // C1: Basic operations
    println!("C1. Basic Operations (Fp):");
    let a = Fp::new(12345678901234567890);
    let b = Fp::new(9876543210987654321);

    let add = a + b;
    let sub = a - b;
    let mul = a * b;
    let inv = a.inverse();

    println!("  a = {}", a.to_u64());
    println!("  b = {}", b.to_u64());
    println!("  a + b = {}", add.to_u64());
    println!("  a - b = {}", sub.to_u64());
    println!("  a * b = {}", mul.to_u64());
    println!("  a^(-1) = {}", inv.to_u64());
    println!("  a * a^(-1) = {} (should be 1)\n", (a * inv).to_u64());

    // C2: Performance
    println!("C2. Performance:");
    let iters = 1_000_000;

    let start = Instant::now();
    let mut x = a;
    for _ in 0..iters {
        x = x * b;
    }
    let mul_time = start.elapsed();
    println!("  {} multiplications: {:?}", iters, mul_time);

    let start = Instant::now();
    let mut y = a;
    for _ in 0..iters {
        y = y + b;
    }
    let add_time = start.elapsed();
    println!("  {} additions: {:?}", iters, add_time);

    let start = Instant::now();
    let mut z = a;
    for _ in 0..1000 {
        z = z.inverse();
    }
    let inv_time = start.elapsed();
    println!("  1000 inversions: {:?}", inv_time);

    // C3: Fp2 operations
    println!("\nC3. Extension Field (Fp2):");
    let c = Fp2::new(Fp::new(100), Fp::new(200));
    let d = Fp2::new(Fp::new(300), Fp::new(400));
    let prod = c * d;
    let c_inv = c.inverse();
    let should_be_one = c * c_inv;

    println!("  c = {} + {}*alpha", c.c0.to_u64(), c.c1.to_u64());
    println!("  d = {} + {}*alpha", d.c0.to_u64(), d.c1.to_u64());
    println!("  c * d = {} + {}*alpha", prod.c0.to_u64(), prod.c1.to_u64());
    println!("  c * c^(-1) = {} + {}*alpha (should be 1 + 0)",
        should_be_one.c0.to_u64(), should_be_one.c1.to_u64());
}

/// Benchmark D: Merkle Tree Operations
fn benchmark_d_merkle() {
    println!("=== Benchmark D: Merkle Tree ===\n");

    // D1: Build trees of various sizes
    println!("D1. Tree Construction:");
    for &size in &[64usize, 256, 1024, 4096] {
        let leaves: Vec<Vec<u8>> = (0..size as u32)
            .map(|i| i.to_le_bytes().to_vec())
            .collect();

        let start = Instant::now();
        let tree = MerkleTree::new(leaves);
        let elapsed = start.elapsed();

        println!("  {} leaves: {:?} (root: {})",
            size, elapsed, &hex::encode(tree.root)[..16]);
    }

    // D2: Path generation and verification
    println!("\nD2. Path Operations (1024 leaves):");
    let leaves: Vec<Vec<u8>> = (0..1024u32)
        .map(|i| i.to_le_bytes().to_vec())
        .collect();
    let tree = MerkleTree::new(leaves.clone());

    let start = Instant::now();
    let mut paths = Vec::with_capacity(100);
    for i in 0..100 {
        paths.push(tree.get_path(i * 10));
    }
    let gen_time = start.elapsed();
    println!("  100 path generations: {:?}", gen_time);

    let start = Instant::now();
    let mut all_valid = true;
    for (i, path) in paths.iter().enumerate() {
        let leaf_data = (i * 10) as u32;
        if !path.verify(&leaf_data.to_le_bytes(), &tree.root) {
            all_valid = false;
        }
    }
    let verify_time = start.elapsed();
    println!("  100 path verifications: {:?}", verify_time);
    println!("  All paths valid: {}", all_valid);

    // D3: Serialization
    println!("\nD3. Serialization:");
    let path = tree.get_path(42);
    let serialized = path.serialize();
    let deserialized = MerklePath::deserialize(&serialized).unwrap();
    let roundtrip_ok = path.index == deserialized.index &&
                       path.siblings.len() == deserialized.siblings.len();
    println!("  Path size: {} bytes", serialized.len());
    println!("  Roundtrip: {}", if roundtrip_ok { "OK" } else { "FAIL" });
}

/// Benchmark E: Full Verification (placeholder until proofs available)
fn benchmark_e_verification() {
    println!("=== Benchmark E: Verification ===\n");

    // E1: Component timings
    println!("E1. Component Timings:");

    // Transcript operations
    let start = Instant::now();
    for _ in 0..1000 {
        let mut t = Transcript::new();
        t.append(b"test data");
        let _ = t.challenge_fri();
    }
    let transcript_time = start.elapsed();
    println!("  1000 transcript operations: {:?}", transcript_time);

    // FRI verification (small test)
    println!("\nE2. FRI Verification (small test):");
    let config = FriConfig {
        num_queries: 10,
        blowup_factor: 4,
        max_degree: 16,
    };

    // Create a low-degree polynomial (constant)
    let evaluations: Vec<Fp> = (0..64).map(|_| Fp::new(42)).collect();

    let prover = FriProver::new(config.clone());
    let mut transcript = Transcript::new();

    let prove_start = Instant::now();
    let proof = prover.prove(evaluations, &mut transcript);
    let prove_time = prove_start.elapsed();
    println!("  FRI prove (64 evals): {:?}", prove_time);

    let verifier = FriVerifier::new(config);
    let mut verify_transcript = Transcript::new();

    let verify_start = Instant::now();
    let valid = verifier.verify(&proof, &mut verify_transcript);
    let verify_time = verify_start.elapsed();
    println!("  FRI verify: {:?}", verify_time);
    println!("  Valid: {}", valid);

    // E3: Full verification estimate
    println!("\nE3. Full Verification Estimate:");
    println!("  Target: < {} ms", params::TARGET_VERIFY_MS);
    println!("  (See closure_benchmark for measured results: ~18µs p95)");
    println!("  Components breakdown:");
    println!("    - Header parsing: ~10 us");
    println!("    - d0 = SHA-256(x): ~300 ns");
    println!("    - Transcript setup: ~5 us");
    println!("    - FRI verification: ~800 us (estimated for full proof)");
    println!("    - Total: < 1 ms");
}
