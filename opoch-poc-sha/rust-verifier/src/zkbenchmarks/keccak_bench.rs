//! Keccak Benchmark for zkbenchmarks.com
//!
//! This module implements the Keccak-256 benchmark matching the
//! zkbenchmarks.com specification.

use std::time::{Duration, Instant};
use super::adapter::{OpochZkVM, ProgramId, ZkVMStats};
use crate::keccak::keccak256;

/// Keccak benchmark runner
pub struct KeccakBenchmark {
    zkvm: OpochZkVM,
}

impl KeccakBenchmark {
    /// Create new benchmark
    pub fn new() -> Self {
        KeccakBenchmark {
            zkvm: OpochZkVM::new(),
        }
    }

    /// Run benchmark for a single input
    pub fn run(&self, input: &[u8]) -> KeccakResult {
        let start = Instant::now();
        let result = self.zkvm.prove(ProgramId::Keccak, input);
        let total_time = start.elapsed();

        match result {
            Ok((proof, output, stats)) => {
                // Verify
                let verify_start = Instant::now();
                let valid = self.zkvm.verify(ProgramId::Keccak, input, &output, &proof)
                    .unwrap_or(false);
                let verify_time = verify_start.elapsed();

                // Verify output matches expected
                let expected = keccak256(input);
                let output_matches = output.len() == 32 &&
                    output.iter().zip(expected.iter()).all(|(a, b)| a == b);

                KeccakResult {
                    input_size: input.len(),
                    output: output.try_into().unwrap_or([0u8; 32]),
                    prove_time: Duration::from_secs_f64(stats.prove_time_secs),
                    verify_time,
                    proof_size: stats.proof_size_bytes,
                    total_time,
                    valid: valid && output_matches,
                }
            }
            Err(_) => {
                KeccakResult {
                    input_size: input.len(),
                    output: [0u8; 32],
                    prove_time: total_time,
                    verify_time: Duration::ZERO,
                    proof_size: 0,
                    total_time,
                    valid: false,
                }
            }
        }
    }

    /// Run benchmark suite with standard input sizes
    pub fn run_suite(&self) -> Vec<KeccakResult> {
        let inputs: Vec<Vec<u8>> = vec![
            vec![0u8; 32],      // 32 bytes (1 block)
            vec![0u8; 136],     // 136 bytes (1 block boundary)
            vec![0u8; 1024],    // 1 KB
            vec![0u8; 10240],   // 10 KB
            vec![0u8; 102400],  // 100 KB
        ];

        inputs.iter().map(|input| self.run(input)).collect()
    }

    /// Run with zkbenchmarks.com standard vectors
    pub fn run_zkbenchmarks_vectors(&self) -> Vec<KeccakResult> {
        // Standard test vectors from zkbenchmarks.com
        let vectors = vec![
            // Empty input
            vec![],
            // "abc"
            b"abc".to_vec(),
            // 64 bytes
            vec![0xAAu8; 64],
            // 136 bytes (rate boundary)
            vec![0x55u8; 136],
            // 1000 bytes
            (0..1000).map(|i| (i % 256) as u8).collect(),
        ];

        vectors.iter().map(|input| self.run(input)).collect()
    }
}

impl Default for KeccakBenchmark {
    fn default() -> Self {
        Self::new()
    }
}

/// Result from a Keccak benchmark run
#[derive(Debug, Clone)]
pub struct KeccakResult {
    /// Input size in bytes
    pub input_size: usize,
    /// Keccak-256 output
    pub output: [u8; 32],
    /// Time to generate proof
    pub prove_time: Duration,
    /// Time to verify proof
    pub verify_time: Duration,
    /// Proof size in bytes
    pub proof_size: usize,
    /// Total benchmark time
    pub total_time: Duration,
    /// Whether verification passed
    pub valid: bool,
}

impl KeccakResult {
    /// Format as CSV row
    pub fn to_csv_row(&self) -> String {
        format!(
            "keccak,opoch,{},{:.6},{},{:.6},{}",
            self.input_size,
            self.prove_time.as_secs_f64(),
            self.proof_size,
            self.verify_time.as_secs_f64() * 1_000_000.0,
            if self.valid { "PASS" } else { "FAIL" }
        )
    }

    /// Format as display string
    pub fn to_display(&self) -> String {
        format!(
            "keccak256({} bytes) = {}... | prove: {:.3}s | verify: {:.1}µs | proof: {} bytes | {}",
            self.input_size,
            hex::encode(&self.output[..8]),
            self.prove_time.as_secs_f64(),
            self.verify_time.as_nanos() as f64 / 1000.0,
            self.proof_size,
            if self.valid { "PASS" } else { "FAIL" }
        )
    }
}

/// Run the full Keccak benchmark and print results
pub fn run_keccak_benchmark() {
    println!("\n╔═══════════════════════════════════════════════════════════════════╗");
    println!("║           KECCAK BENCHMARK (zkbenchmarks.com format)              ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!("║  Matching SP1/Risc0/Pico benchmark methodology                    ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝\n");

    let bench = KeccakBenchmark::new();

    println!("CSV Header: program,prover,input_size,prove_time_s,proof_size_bytes,verify_time_us,status\n");

    // Standard input sizes
    let sizes: Vec<usize> = vec![32, 64, 136, 1024, 10240];

    for size in sizes {
        let input = vec![0xABu8; size];
        let result = bench.run(&input);
        println!("{}", result.to_csv_row());
        println!("  -> {}", result.to_display());
    }

    println!("\n═══════════════════════════════════════════════════════════════════");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak_benchmark() {
        let bench = KeccakBenchmark::new();
        let input = b"test input";
        let result = bench.run(input);

        assert!(result.valid);
        assert_eq!(result.output, keccak256(input));
        assert!(result.proof_size < 500);
    }

    #[test]
    fn test_keccak_empty() {
        let bench = KeccakBenchmark::new();
        let result = bench.run(&[]);

        assert!(result.valid);
        // Empty keccak256 = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        assert_eq!(
            hex::encode(&result.output),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn test_keccak_abc() {
        let bench = KeccakBenchmark::new();
        let result = bench.run(b"abc");

        assert!(result.valid);
        // keccak256("abc") = 0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
        assert_eq!(
            hex::encode(&result.output),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }
}
