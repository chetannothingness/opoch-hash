//! Security Analysis Binary
//!
//! Runs soundness and sequentiality analysis.

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "soundness" => {
                opoch_poc_sha::soundness::print_soundness_analysis();
                opoch_poc_sha::soundness::demonstrate_fake_attempt();
            }
            "sequentiality" => {
                opoch_poc_sha::sequentiality::analyze_sequentiality();
                opoch_poc_sha::sequentiality::demonstrate_segment_parallelism();
            }
            _ => print_usage(),
        }
    } else {
        // Run both
        opoch_poc_sha::soundness::print_soundness_analysis();
        println!("\n\n");
        opoch_poc_sha::soundness::demonstrate_fake_attempt();
        println!("\n\n");
        opoch_poc_sha::sequentiality::analyze_sequentiality();
        println!("\n");
        opoch_poc_sha::sequentiality::demonstrate_segment_parallelism();
    }
}

fn print_usage() {
    println!("OPOCH-PoC-SHA Security Analysis\n");
    println!("Usage:");
    println!("  analysis              Run all analyses");
    println!("  analysis soundness    Run soundness analysis only");
    println!("  analysis sequentiality Run sequentiality analysis only");
}
