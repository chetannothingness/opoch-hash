//! Benchmark Results and Report Generation
//!
//! This module handles result collection, CSV generation, and
//! report generation in zkbenchmarks.com format.

use serde::{Serialize, Deserialize};
use super::fibonacci::FibonacciResult;
use super::keccak_bench::KeccakResult;
use super::rsp::RspResult;

/// Unified benchmark result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Program name (fibonacci, keccak, rsp)
    pub program: String,
    /// Prover name (opoch)
    pub prover: String,
    /// Input size (N for fib, bytes for keccak/rsp)
    pub input_size: u64,
    /// Prove time in seconds
    pub prove_time_secs: f64,
    /// Proof size in bytes
    pub proof_size_bytes: usize,
    /// Verify time in microseconds
    pub verify_time_us: f64,
    /// Whether benchmark passed
    pub passed: bool,
}

impl BenchmarkResult {
    /// Create from Fibonacci result
    pub fn from_fibonacci(r: &FibonacciResult) -> Self {
        BenchmarkResult {
            program: "fibonacci".to_string(),
            prover: "opoch".to_string(),
            input_size: r.n,
            prove_time_secs: r.prove_time.as_secs_f64(),
            proof_size_bytes: r.proof_size,
            verify_time_us: r.verify_time.as_nanos() as f64 / 1000.0,
            passed: r.valid,
        }
    }

    /// Create from Keccak result
    pub fn from_keccak(r: &KeccakResult) -> Self {
        BenchmarkResult {
            program: "keccak".to_string(),
            prover: "opoch".to_string(),
            input_size: r.input_size as u64,
            prove_time_secs: r.prove_time.as_secs_f64(),
            proof_size_bytes: r.proof_size,
            verify_time_us: r.verify_time.as_nanos() as f64 / 1000.0,
            passed: r.valid,
        }
    }

    /// Create from RSP result
    pub fn from_rsp(r: &RspResult) -> Self {
        BenchmarkResult {
            program: "rsp".to_string(),
            prover: "opoch".to_string(),
            input_size: r.block_size as u64,
            prove_time_secs: r.prove_time.as_secs_f64(),
            proof_size_bytes: r.proof_size,
            verify_time_us: r.verify_time.as_nanos() as f64 / 1000.0,
            passed: r.valid,
        }
    }

    /// Format as CSV row
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{:.6},{},{:.2},{}",
            self.program,
            self.prover,
            self.input_size,
            self.prove_time_secs,
            self.proof_size_bytes,
            self.verify_time_us,
            if self.passed { "PASS" } else { "FAIL" }
        )
    }
}

/// Complete benchmark report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Prover name
    pub prover: String,
    /// Version
    pub version: String,
    /// Timestamp
    pub timestamp: String,
    /// Total benchmark time
    pub total_time_secs: f64,
    /// All results
    pub results: Vec<BenchmarkResult>,
}

impl BenchmarkReport {
    /// Generate summary statistics
    pub fn summary(&self) -> ReportSummary {
        let mut summary = ReportSummary::default();

        for r in &self.results {
            summary.total_benchmarks += 1;
            if r.passed {
                summary.passed += 1;
            } else {
                summary.failed += 1;
            }

            summary.total_prove_time += r.prove_time_secs;
            summary.avg_proof_size += r.proof_size_bytes as f64;
            summary.avg_verify_time += r.verify_time_us;
        }

        if summary.total_benchmarks > 0 {
            let n = summary.total_benchmarks as f64;
            summary.avg_proof_size /= n;
            summary.avg_verify_time /= n;
        }

        summary
    }
}

/// Summary statistics for a report
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_benchmarks: u32,
    pub passed: u32,
    pub failed: u32,
    pub total_prove_time: f64,
    pub avg_proof_size: f64,
    pub avg_verify_time: f64,
}

/// Generate CSV output for a specific program
pub fn generate_csv(program: &str, results: &[BenchmarkResult]) -> String {
    let mut csv = String::new();

    // Header
    csv.push_str("program,prover,input_size,prove_time_s,proof_size_bytes,verify_time_us,status\n");

    // Rows
    for r in results.iter().filter(|r| r.program == program) {
        csv.push_str(&r.to_csv_row());
        csv.push('\n');
    }

    csv
}

/// Generate combined CSV with all results
pub fn generate_combined_csv(results: &[BenchmarkResult]) -> String {
    let mut csv = String::new();

    csv.push_str("program,prover,input_size,prove_time_s,proof_size_bytes,verify_time_us,status\n");

    for r in results {
        csv.push_str(&r.to_csv_row());
        csv.push('\n');
    }

    csv
}

/// Generate markdown report
pub fn generate_markdown_report(report: &BenchmarkReport) -> String {
    let summary = report.summary();
    let mut md = String::new();

    md.push_str("# OPOCH zkbenchmarks.com Results\n\n");
    md.push_str(&format!("**Version**: {}\n", report.version));
    md.push_str(&format!("**Timestamp**: {}\n", report.timestamp));
    md.push_str(&format!("**Total Time**: {:.2}s\n\n", report.total_time_secs));

    md.push_str("## Summary\n\n");
    md.push_str(&format!("- Total Benchmarks: {}\n", summary.total_benchmarks));
    md.push_str(&format!("- Passed: {}\n", summary.passed));
    md.push_str(&format!("- Failed: {}\n", summary.failed));
    md.push_str(&format!("- Average Proof Size: {:.0} bytes\n", summary.avg_proof_size));
    md.push_str(&format!("- Average Verify Time: {:.1} µs\n\n", summary.avg_verify_time));

    md.push_str("## Fibonacci Results\n\n");
    md.push_str("| N | Prove Time (s) | Proof Size (bytes) | Verify Time (µs) | Status |\n");
    md.push_str("|---|---------------|-------------------|-----------------|--------|\n");
    for r in report.results.iter().filter(|r| r.program == "fibonacci") {
        md.push_str(&format!(
            "| {} | {:.3} | {} | {:.1} | {} |\n",
            r.input_size, r.prove_time_secs, r.proof_size_bytes,
            r.verify_time_us, if r.passed { "PASS" } else { "FAIL" }
        ));
    }

    md.push_str("\n## Keccak Results\n\n");
    md.push_str("| Input Size | Prove Time (s) | Proof Size (bytes) | Verify Time (µs) | Status |\n");
    md.push_str("|------------|---------------|-------------------|-----------------|--------|\n");
    for r in report.results.iter().filter(|r| r.program == "keccak") {
        md.push_str(&format!(
            "| {} | {:.3} | {} | {:.1} | {} |\n",
            r.input_size, r.prove_time_secs, r.proof_size_bytes,
            r.verify_time_us, if r.passed { "PASS" } else { "FAIL" }
        ));
    }

    md.push_str("\n## RSP Results\n\n");
    md.push_str("| Block Size | Prove Time (s) | Proof Size (bytes) | Verify Time (µs) | Status |\n");
    md.push_str("|------------|---------------|-------------------|-----------------|--------|\n");
    for r in report.results.iter().filter(|r| r.program == "rsp") {
        md.push_str(&format!(
            "| {} | {:.3} | {} | {:.1} | {} |\n",
            r.input_size, r.prove_time_secs, r.proof_size_bytes,
            r.verify_time_us, if r.passed { "PASS" } else { "FAIL" }
        ));
    }

    md.push_str("\n## Comparison with Other zkVMs\n\n");
    md.push_str("| Prover | Avg Proof Size | Avg Verify Time | Notes |\n");
    md.push_str("|--------|---------------|-----------------|-------|\n");
    md.push_str(&format!(
        "| **OPOCH** | **{:.0} bytes** | **{:.1} µs** | Constant-size proofs |\n",
        summary.avg_proof_size, summary.avg_verify_time
    ));
    md.push_str("| SP1 | ~40-50 KB | ~5-15 ms | STARK + Groth16 |\n");
    md.push_str("| Risc0 | ~200-250 KB | ~2-5 ms | STARK |\n");
    md.push_str("| Pico | ~40-50 KB | ~5-10 ms | STARK + SNARK |\n");

    md.push_str("\n---\n");
    md.push_str("*Generated by OPOCH zkbenchmarks integration*\n");

    md
}

/// Generate plots data (for external plotting tools)
pub fn generate_plots_data(report: &BenchmarkReport) -> PlotsData {
    PlotsData {
        fibonacci: report.results.iter()
            .filter(|r| r.program == "fibonacci")
            .map(|r| PlotPoint {
                x: r.input_size as f64,
                prove_time: r.prove_time_secs,
                proof_size: r.proof_size_bytes as f64,
                verify_time: r.verify_time_us,
            })
            .collect(),
        keccak: report.results.iter()
            .filter(|r| r.program == "keccak")
            .map(|r| PlotPoint {
                x: r.input_size as f64,
                prove_time: r.prove_time_secs,
                proof_size: r.proof_size_bytes as f64,
                verify_time: r.verify_time_us,
            })
            .collect(),
        rsp: report.results.iter()
            .filter(|r| r.program == "rsp")
            .map(|r| PlotPoint {
                x: r.input_size as f64,
                prove_time: r.prove_time_secs,
                proof_size: r.proof_size_bytes as f64,
                verify_time: r.verify_time_us,
            })
            .collect(),
    }
}

/// Data for generating plots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlotsData {
    pub fibonacci: Vec<PlotPoint>,
    pub keccak: Vec<PlotPoint>,
    pub rsp: Vec<PlotPoint>,
}

/// Single plot point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlotPoint {
    pub x: f64,
    pub prove_time: f64,
    pub proof_size: f64,
    pub verify_time: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_csv_generation() {
        let results = vec![
            BenchmarkResult {
                program: "fibonacci".to_string(),
                prover: "opoch".to_string(),
                input_size: 100,
                prove_time_secs: 0.001,
                proof_size_bytes: 300,
                verify_time_us: 150.0,
                passed: true,
            },
            BenchmarkResult {
                program: "fibonacci".to_string(),
                prover: "opoch".to_string(),
                input_size: 1000,
                prove_time_secs: 0.01,
                proof_size_bytes: 300,
                verify_time_us: 155.0,
                passed: true,
            },
        ];

        let csv = generate_csv("fibonacci", &results);
        assert!(csv.contains("fibonacci,opoch,100"));
        assert!(csv.contains("fibonacci,opoch,1000"));
    }

    #[test]
    fn test_report_summary() {
        let report = BenchmarkReport {
            prover: "opoch".to_string(),
            version: "1.0.0".to_string(),
            timestamp: "test".to_string(),
            total_time_secs: 1.0,
            results: vec![
                BenchmarkResult {
                    program: "fibonacci".to_string(),
                    prover: "opoch".to_string(),
                    input_size: 100,
                    prove_time_secs: 0.001,
                    proof_size_bytes: 300,
                    verify_time_us: 150.0,
                    passed: true,
                },
            ],
        };

        let summary = report.summary();
        assert_eq!(summary.total_benchmarks, 1);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.avg_proof_size, 300.0);
    }
}
