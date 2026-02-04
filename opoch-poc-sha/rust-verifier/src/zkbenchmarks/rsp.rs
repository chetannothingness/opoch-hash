//! RSP (Reth Succinct Processor) Benchmark for zkbenchmarks.com
//!
//! This module implements a simplified RSP benchmark that simulates
//! Ethereum block execution validation.

use std::time::{Duration, Instant};
use super::adapter::{OpochZkVM, ProgramId, ZkVMStats};
use crate::sha256::Sha256;

/// RSP benchmark runner
pub struct RspBenchmark {
    zkvm: OpochZkVM,
}

impl RspBenchmark {
    /// Create new benchmark
    pub fn new() -> Self {
        RspBenchmark {
            zkvm: OpochZkVM::new(),
        }
    }

    /// Run benchmark for a single block
    pub fn run(&self, block_data: &[u8]) -> RspResult {
        let start = Instant::now();
        let result = self.zkvm.prove(ProgramId::Rsp, block_data);
        let total_time = start.elapsed();

        match result {
            Ok((proof, output, stats)) => {
                // Verify
                let verify_start = Instant::now();
                let valid = self.zkvm.verify(ProgramId::Rsp, block_data, &output, &proof)
                    .unwrap_or(false);
                let verify_time = verify_start.elapsed();

                // Parse state root from output
                let state_root = if output.len() >= 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&output[..32]);
                    arr
                } else {
                    [0u8; 32]
                };

                RspResult {
                    block_size: block_data.len(),
                    state_root,
                    prove_time: Duration::from_secs_f64(stats.prove_time_secs),
                    verify_time,
                    proof_size: stats.proof_size_bytes,
                    total_time,
                    valid,
                }
            }
            Err(_) => {
                RspResult {
                    block_size: block_data.len(),
                    state_root: [0u8; 32],
                    prove_time: total_time,
                    verify_time: Duration::ZERO,
                    proof_size: 0,
                    total_time,
                    valid: false,
                }
            }
        }
    }

    /// Run benchmark suite with simulated blocks
    pub fn run_suite(&self) -> Vec<RspResult> {
        // Simulate different block sizes
        let block_sizes: Vec<usize> = vec![
            1024,      // ~1 KB (tiny block)
            10240,     // ~10 KB (small block)
            102400,    // ~100 KB (medium block)
            1048576,   // ~1 MB (large block)
        ];

        block_sizes.iter().map(|&size| {
            let block_data = generate_mock_block(size);
            self.run(&block_data)
        }).collect()
    }

    /// Run with specific block numbers (using mock data)
    pub fn run_blocks(&self, block_numbers: &[u64]) -> Vec<RspResult> {
        block_numbers.iter().map(|&block_num| {
            let block_data = generate_mock_block_by_number(block_num);
            self.run(&block_data)
        }).collect()
    }
}

impl Default for RspBenchmark {
    fn default() -> Self {
        Self::new()
    }
}

/// Result from an RSP benchmark run
#[derive(Debug, Clone)]
pub struct RspResult {
    /// Block data size in bytes
    pub block_size: usize,
    /// Computed state root
    pub state_root: [u8; 32],
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

impl RspResult {
    /// Format as CSV row
    pub fn to_csv_row(&self) -> String {
        format!(
            "rsp,opoch,{},{:.6},{},{:.6},{}",
            self.block_size,
            self.prove_time.as_secs_f64(),
            self.proof_size,
            self.verify_time.as_secs_f64() * 1_000_000.0,
            if self.valid { "PASS" } else { "FAIL" }
        )
    }

    /// Format as display string
    pub fn to_display(&self) -> String {
        format!(
            "rsp({} bytes) -> state_root={}... | prove: {:.3}s | verify: {:.1}µs | proof: {} bytes | {}",
            self.block_size,
            hex::encode(&self.state_root[..8]),
            self.prove_time.as_secs_f64(),
            self.verify_time.as_nanos() as f64 / 1000.0,
            self.proof_size,
            if self.valid { "PASS" } else { "FAIL" }
        )
    }
}

/// Generate mock block data of specified size
fn generate_mock_block(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);

    // Block header (simplified)
    let header = MockBlockHeader {
        parent_hash: Sha256::hash(b"parent"),
        timestamp: 1700000000,
        number: 19000000,
        gas_limit: 30_000_000,
        gas_used: 15_000_000,
    };

    data.extend_from_slice(&header.serialize());

    // Fill remaining with mock transaction data
    while data.len() < size {
        let tx_data = generate_mock_transaction(data.len() as u64);
        data.extend_from_slice(&tx_data);
    }

    data.truncate(size);
    data
}

/// Generate mock block by block number
fn generate_mock_block_by_number(block_num: u64) -> Vec<u8> {
    // Block size varies by number (simulate different block types)
    let base_size = 10240; // 10 KB base
    let extra = ((block_num % 100) as usize) * 1024; // 0-99 KB extra
    generate_mock_block(base_size + extra)
}

/// Mock block header
struct MockBlockHeader {
    parent_hash: [u8; 32],
    timestamp: u64,
    number: u64,
    gas_limit: u64,
    gas_used: u64,
}

impl MockBlockHeader {
    fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(80);
        data.extend_from_slice(&self.parent_hash);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.number.to_le_bytes());
        data.extend_from_slice(&self.gas_limit.to_le_bytes());
        data.extend_from_slice(&self.gas_used.to_le_bytes());
        data
    }
}

/// Generate mock transaction data
fn generate_mock_transaction(seed: u64) -> Vec<u8> {
    // Simplified transaction: 100-200 bytes
    let size = 100 + (seed % 100) as usize;
    let mut data = vec![0u8; size];

    // Fill with deterministic data based on seed
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = ((seed + i as u64) % 256) as u8;
    }

    data
}

/// Run the full RSP benchmark and print results
pub fn run_rsp_benchmark() {
    println!("\n╔═══════════════════════════════════════════════════════════════════╗");
    println!("║           RSP BENCHMARK (zkbenchmarks.com format)                 ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!("║  Simulating Ethereum block execution validation                   ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝\n");

    let bench = RspBenchmark::new();

    println!("CSV Header: program,prover,block_size,prove_time_s,proof_size_bytes,verify_time_us,status\n");

    let results = bench.run_suite();

    for result in results {
        println!("{}", result.to_csv_row());
        println!("  -> {}", result.to_display());
    }

    println!("\n═══════════════════════════════════════════════════════════════════");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsp_benchmark() {
        let bench = RspBenchmark::new();
        let block = generate_mock_block(1024);
        let result = bench.run(&block);

        assert!(result.valid);
        assert!(result.proof_size < 500);
    }

    #[test]
    fn test_mock_block_generation() {
        let block = generate_mock_block(10240);
        assert_eq!(block.len(), 10240);

        // Block should start with header
        assert!(block.len() >= 80);
    }
}
