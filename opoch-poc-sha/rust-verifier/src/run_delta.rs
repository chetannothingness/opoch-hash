//! Delta Benchmark Runner
//!
//! Runs the complete v0 vs v1 comparison suite and generates reports.
//!
//! Usage:
//!   cargo run --release --bin run_delta

use opoch_poc_sha::delta_benchmarks::run_delta_benchmarks;
use std::fs;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     OPOCH-PoC-SHA Delta Benchmark Suite                      ║");
    println!("║     Proving the partition-lattice addition changed everything║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // Run all benchmarks
    let report = run_delta_benchmarks();

    // Generate JSON report
    let json = serde_json::to_string_pretty(&report).unwrap();

    // Create output directory
    fs::create_dir_all("out").ok();

    // Write report
    fs::write("out/delta_report.json", &json).expect("Failed to write report");
    println!("\nGenerated: out/delta_report.json");

    // Generate markdown summary
    let md = generate_markdown_summary(&report);
    fs::write("out/delta_report.md", &md).expect("Failed to write markdown");
    println!("Generated: out/delta_report.md");

    // Print headline numbers
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                    HEADLINE NUMBERS                          ║");
    println!("╠══════════════════════════════════════════════════════════════╣");

    // 1. Semantic slack collapse
    for b in &report.benchmarks {
        if b.name.contains("Factorial Collapse") {
            let raw = b.delta.extra.get("raw_distinct").copied().unwrap_or(0.0);
            let serpi = b.delta.extra.get("serpi_distinct").copied().unwrap_or(1.0);
            let ratio = b.delta.extra.get("collapse_ratio").copied().unwrap_or(1.0);
            println!("║  {}: {}x collapse ({} -> {})", b.name, ratio as u64, raw as u64, serpi as u64);
        }
    }

    // 2. Coequalization
    for b in &report.benchmarks {
        if b.name.contains("Coequalization") {
            let discarded = b.v1_result.extra.get("tests_discarded").copied().unwrap_or(0.0);
            let savings = b.v1_result.extra.get("savings_percent").copied().unwrap_or(0.0);
            println!("║  Coequalization: {:.1}% savings ({} tests discarded)", savings, discarded as u64);
        }
    }

    // 3. Throughput
    for b in &report.benchmarks {
        if b.name.contains("Throughput") {
            println!("║  Throughput: v0={:.0} ops/s, v1={:.0} ops/s",
                b.v0_result.ops_per_sec, b.v1_result.ops_per_sec);
            println!("║  Latency p95: v0={:.1}us, v1={:.1}us",
                b.v0_result.p95_us, b.v1_result.p95_us);
        }
    }

    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  VERDICT: {}", if report.summary.all_pass { "ALL BENCHMARKS PASS" } else { "SOME FAILED" });
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // Exit with appropriate code
    if !report.summary.all_pass {
        std::process::exit(1);
    }
}

fn generate_markdown_summary(report: &opoch_poc_sha::delta_benchmarks::DeltaReport) -> String {
    let mut md = String::new();

    md.push_str("# Delta Benchmark Report\n\n");
    md.push_str(&format!("Generated: {}\n", report.timestamp));
    md.push_str(&format!("Seed: {}\n\n", report.seed));

    md.push_str("## Summary\n\n");
    md.push_str(&format!("- Total Benchmarks: {}\n", report.summary.total_benchmarks));
    md.push_str(&format!("- Passed: {}\n", report.summary.passed));
    md.push_str(&format!("- Failed: {}\n", report.summary.failed));
    md.push_str(&format!("- Semantic Slack Collapsed: {}\n", report.summary.semantic_slack_collapsed));
    md.push_str(&format!("- Coequalization Active: {}\n", report.summary.coequalization_active));
    md.push_str(&format!("- Compression Active: {}\n", report.summary.compression_active));
    md.push_str(&format!("- **All Pass: {}**\n\n", report.summary.all_pass));

    md.push_str("## Benchmark Results\n\n");
    md.push_str("| Benchmark | Status | Notes |\n");
    md.push_str("|-----------|--------|-------|\n");

    for b in &report.benchmarks {
        let status = if b.pass { "PASS" } else { "FAIL" };
        md.push_str(&format!("| {} | {} | {} |\n", b.name, status, b.notes));
    }

    md.push_str("\n## Headline Charts\n\n");

    md.push_str("### 1. Semantic Slack Collapse\n\n");
    md.push_str("| n (fields) | Raw Hash (distinct) | SerΠ (distinct) | Collapse Ratio |\n");
    md.push_str("|------------|--------------------|-----------------|-----------------|\n");
    for b in &report.benchmarks {
        if b.name.contains("Factorial Collapse") {
            let raw = b.delta.extra.get("raw_distinct").copied().unwrap_or(0.0);
            let serpi = b.delta.extra.get("serpi_distinct").copied().unwrap_or(1.0);
            let ratio = b.delta.extra.get("collapse_ratio").copied().unwrap_or(1.0);
            let n = b.name.split("n=").last().unwrap_or("?").trim_end_matches(')');
            md.push_str(&format!("| {} | {} | {} | {}x |\n", n, raw as u64, serpi as u64, ratio as u64));
        }
    }

    md.push_str("\n### 2. Partition-Lattice Compression Gain\n\n");
    for b in &report.benchmarks {
        if b.name.contains("Coequalization") {
            let discarded = b.v1_result.extra.get("tests_discarded").copied().unwrap_or(0.0);
            let savings = b.v1_result.extra.get("savings_percent").copied().unwrap_or(0.0);
            md.push_str(&format!("- **Coequalization Rate**: {:.1}% ({} redundant tests discarded)\n",
                savings, discarded as u64));
        }
    }

    md.push_str("\n### 3. End-to-End Performance\n\n");
    md.push_str("| Metric | v0 | v1 | Delta |\n");
    md.push_str("|--------|----|----|-------|\n");
    for b in &report.benchmarks {
        if b.name.contains("Throughput") {
            md.push_str(&format!("| Ops/sec | {:.0} | {:.0} | {:.1}% |\n",
                b.v0_result.ops_per_sec, b.v1_result.ops_per_sec,
                b.delta.throughput_improvement));
            md.push_str(&format!("| p95 latency (us) | {:.1} | {:.1} | {:.1}% |\n",
                b.v0_result.p95_us, b.v1_result.p95_us,
                b.delta.latency_reduction_p95));
        }
    }

    md.push_str("\n---\n");
    md.push_str("*Generated by OPOCH-PoC-SHA Delta Benchmark Suite*\n");

    md
}
