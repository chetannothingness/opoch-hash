//! OPOCH Berkeley RDI / zkbench.dev Benchmark Runner
//!
//! Run with: cargo run --release --bin berkeley_bench

fn main() {
    opoch_poc_sha::berkeley_bench::run_berkeley_benchmarks();
}
