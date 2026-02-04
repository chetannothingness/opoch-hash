//! OPOCH zkbenchmarks.com Integration
//!
//! This module implements OPOCH as a zkVM backend for the standardized
//! zkbenchmarks.com benchmark suite, enabling direct comparison with
//! SP1, Risc0, Pico, and other zkVMs.
//!
//! ## Interface
//!
//! The standard zkVM interface:
//! - `prove(program_id, input_bytes) -> (proof_bytes, output_bytes, stats)`
//! - `verify(program_id, input_bytes, output_bytes, proof_bytes) -> bool`
//!
//! ## Programs Supported
//!
//! - **Fibonacci**: Iterative computation of fib(N)
//! - **Keccak**: keccak256 over benchmark input vectors
//! - **RSP**: Ethereum block execution validation
//!
//! ## Metrics Collected
//!
//! - Proof size (bytes)
//! - Verifier time (µs)
//! - Prover time (s)
//! - Peak memory (MB)

pub mod adapter;
pub mod fibonacci;
pub mod keccak_bench;
pub mod rsp;
pub mod harness;
pub mod results;

pub use adapter::{OpochZkVM, ZkVMStats, ProgramId};
pub use fibonacci::FibonacciBenchmark;
pub use keccak_bench::KeccakBenchmark;
pub use harness::{run_zkbenchmarks, BenchmarkConfig};
pub use results::{BenchmarkResult, BenchmarkReport, generate_csv, generate_plots_data};
