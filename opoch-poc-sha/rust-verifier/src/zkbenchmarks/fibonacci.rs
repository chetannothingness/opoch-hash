//! Fibonacci Benchmark for zkbenchmarks.com
//!
//! This module implements the Fibonacci benchmark matching the
//! zkbenchmarks.com specification:
//!
//! - Input: N (number of iterations)
//! - Output: fib(N) as u128
//! - Trace: iterative computation (a, b) -> (b, a+b)

use std::time::{Duration, Instant};
use super::adapter::{OpochZkVM, ProgramId, ZkVMStats};

/// Fibonacci benchmark runner
pub struct FibonacciBenchmark {
    zkvm: OpochZkVM,
}

impl FibonacciBenchmark {
    /// Create new benchmark
    pub fn new() -> Self {
        FibonacciBenchmark {
            zkvm: OpochZkVM::new(),
        }
    }

    /// Run benchmark for a single N value
    pub fn run(&self, n: u64) -> FibonacciResult {
        let input = n.to_le_bytes();

        let start = Instant::now();
        let result = self.zkvm.prove(ProgramId::Fibonacci, &input);
        let total_time = start.elapsed();

        match result {
            Ok((proof, output, stats)) => {
                // Parse output
                let fib_result = if output.len() >= 16 {
                    u128::from_le_bytes(output[..16].try_into().unwrap())
                } else if output.len() >= 8 {
                    u64::from_le_bytes(output[..8].try_into().unwrap()) as u128
                } else {
                    0
                };

                // Verify
                let verify_start = Instant::now();
                let valid = self.zkvm.verify(ProgramId::Fibonacci, &input, &output, &proof)
                    .unwrap_or(false);
                let verify_time = verify_start.elapsed();

                FibonacciResult {
                    n,
                    fib_n: fib_result,
                    prove_time: Duration::from_secs_f64(stats.prove_time_secs),
                    verify_time,
                    proof_size: stats.proof_size_bytes,
                    total_time,
                    valid,
                }
            }
            Err(e) => {
                FibonacciResult {
                    n,
                    fib_n: 0,
                    prove_time: total_time,
                    verify_time: Duration::ZERO,
                    proof_size: 0,
                    total_time,
                    valid: false,
                }
            }
        }
    }

    /// Run benchmark suite with standard N values from zkbenchmarks.com
    pub fn run_suite(&self) -> Vec<FibonacciResult> {
        // Standard N values from zkbenchmarks.com
        let ns = vec![100, 1000, 10_000, 100_000, 1_000_000, 10_000_000];

        ns.iter().map(|&n| self.run(n)).collect()
    }

    /// Run with custom N values
    pub fn run_custom(&self, ns: &[u64]) -> Vec<FibonacciResult> {
        ns.iter().map(|&n| self.run(n)).collect()
    }
}

impl Default for FibonacciBenchmark {
    fn default() -> Self {
        Self::new()
    }
}

/// Result from a Fibonacci benchmark run
#[derive(Debug, Clone)]
pub struct FibonacciResult {
    /// Input N
    pub n: u64,
    /// Computed fib(N)
    pub fib_n: u128,
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

impl FibonacciResult {
    /// Format as CSV row
    pub fn to_csv_row(&self) -> String {
        format!(
            "fibonacci,opoch,{},{:.6},{},{:.6},{}",
            self.n,
            self.prove_time.as_secs_f64(),
            self.proof_size,
            self.verify_time.as_secs_f64() * 1_000_000.0, // µs
            if self.valid { "PASS" } else { "FAIL" }
        )
    }

    /// Format as display string
    pub fn to_display(&self) -> String {
        format!(
            "fib({}) = {} | prove: {:.3}s | verify: {:.1}µs | proof: {} bytes | {}",
            self.n,
            self.fib_n,
            self.prove_time.as_secs_f64(),
            self.verify_time.as_nanos() as f64 / 1000.0,
            self.proof_size,
            if self.valid { "PASS" } else { "FAIL" }
        )
    }
}

/// Run the full Fibonacci benchmark and print results
pub fn run_fibonacci_benchmark() {
    println!("\n╔═══════════════════════════════════════════════════════════════════╗");
    println!("║           FIBONACCI BENCHMARK (zkbenchmarks.com format)           ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!("║  Matching SP1/Risc0/Pico benchmark methodology                    ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝\n");

    let bench = FibonacciBenchmark::new();

    println!("CSV Header: program,prover,N,prove_time_s,proof_size_bytes,verify_time_us,status\n");

    // Standard zkbenchmarks.com N values
    let ns = vec![100, 1_000, 10_000, 100_000, 1_000_000];

    for n in ns {
        let result = bench.run(n);
        println!("{}", result.to_csv_row());
        println!("  -> {}", result.to_display());
    }

    println!("\n═══════════════════════════════════════════════════════════════════");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fibonacci_benchmark() {
        let bench = FibonacciBenchmark::new();
        let result = bench.run(100);

        assert!(result.valid);
        assert_eq!(result.fib_n, 354224848179261915075); // fib(100)
        assert!(result.proof_size < 500);
        assert!(result.verify_time.as_micros() < 1000);
    }

    #[test]
    fn test_fibonacci_suite() {
        let bench = FibonacciBenchmark::new();
        let results = bench.run_custom(&[10, 100, 1000]);

        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.valid);
        }
    }
}
