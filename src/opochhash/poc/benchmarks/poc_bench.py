"""
PoC_Hash Benchmark Orchestrator

Runs all 8 benchmarks and generates comprehensive report.

Benchmarks:
1. Asymmetry - Prover/Verifier cost ratio
2. Soundness - Cryptographic soundness bounds
3. ProofSize - Proof size scaling
4. Overhead - Prover overhead vs plain work
5. Recursion - Recursive proof aggregation
6. Memory - Memory-hardness validation
7. Switching - Zero switching cost
8. Compatibility - Backward compatibility
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import json
import time
from datetime import datetime

from .base import BenchmarkResult, BenchmarkStatus, BenchmarkSuite
from .runner_asymmetry import AsymmetryBenchmark
from .runner_soundness import SoundnessBenchmark
from .runner_proof_size import ProofSizeBenchmark, RecursionProofSizeBenchmark
from .runner_overhead import OverheadBenchmark, ProofGenerationBreakdown
from .runner_recursion import RecursionBenchmark, RecursionScalingBenchmark
from .runner_memory import MemoryHardnessBenchmark, SequentialityBenchmark, TimingBenchmark
from .runner_switching import SwitchingCostBenchmark, BackwardCompatibilityBenchmark, MigrationBenchmark
from .runner_compatibility import (
    APICompatibilityBenchmark,
    FormatCompatibilityBenchmark,
    IntegrationBenchmark,
    DeterminismBenchmark
)
from ..params import PoCParams
from ..poc_hash import ProofTier


@dataclass
class BenchmarkReport:
    """Complete benchmark report."""
    timestamp: str
    total_duration_ms: float
    all_passed: bool
    pass_count: int
    total_count: int
    suites: Dict[str, Dict[str, Any]]
    summary: Dict[str, Any]
    params: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'total_duration_ms': round(self.total_duration_ms, 2),
            'all_passed': self.all_passed,
            'pass_count': self.pass_count,
            'total_count': self.total_count,
            'suites': self.suites,
            'summary': self.summary,
            'params': self.params
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save(self, path: str):
        """Save report to file."""
        with open(path, 'w') as f:
            f.write(self.to_json())

    def print_summary(self):
        """Print human-readable summary."""
        print("\n" + "=" * 60)
        print("PoC_Hash Benchmark Report")
        print("=" * 60)
        print(f"Timestamp: {self.timestamp}")
        print(f"Duration: {self.total_duration_ms:.2f} ms")
        print(f"Result: {'ALL PASSED' if self.all_passed else 'SOME FAILED'}")
        print(f"Score: {self.pass_count}/{self.total_count}")
        print("-" * 60)

        for suite_name, suite_data in self.suites.items():
            status = "✓" if suite_data['all_passed'] else "✗"
            print(f"\n{status} {suite_name}: {suite_data['passed']}/{suite_data['total']}")
            for result in suite_data['results']:
                r_status = "✓" if result['status'] == 'PASS' else "✗"
                print(f"    {r_status} {result['name']}: {result['actual']}")

        print("\n" + "=" * 60)
        print("Summary:")
        for key, value in self.summary.items():
            print(f"  {key}: {value}")
        print("=" * 60)


def run_all_benchmarks(
    params: Optional[PoCParams] = None,
    tier: ProofTier = ProofTier.Q,
    verbose: bool = True,
    W_values: List[int] = None
) -> BenchmarkReport:
    """
    Run all 8 PoC_Hash benchmarks.

    Args:
        params: Parameters to use (default creates test params)
        tier: Proof tier to test
        verbose: Print progress
        W_values: W values to test (default: [100, 500, 1000])

    Returns:
        Complete benchmark report
    """
    if params is None:
        params = PoCParams(W=1000, memory_bytes=1024 * 1024)

    if W_values is None:
        W_values = [100, 500, 1000]

    start_time = time.perf_counter()
    timestamp = datetime.now().isoformat()

    if verbose:
        print("\n" + "=" * 60)
        print("Running PoC_Hash Benchmarks")
        print("=" * 60)

    # Build suites
    suites = {}

    # Suite 1: Asymmetry
    if verbose:
        print("\n[1/8] Running Asymmetry benchmarks...")
    asymmetry_suite = BenchmarkSuite(
        name="Asymmetry",
        benchmarks=[AsymmetryBenchmark(W_values, tier)]
    )
    asymmetry_suite.run_all(verbose)
    suites['asymmetry'] = asymmetry_suite.to_dict()

    # Suite 2: Soundness
    if verbose:
        print("\n[2/8] Running Soundness benchmarks...")
    soundness_suite = BenchmarkSuite(
        name="Soundness",
        benchmarks=[SoundnessBenchmark(params=params)]
    )
    soundness_suite.run_all(verbose)
    suites['soundness'] = soundness_suite.to_dict()

    # Suite 3: Proof Size
    if verbose:
        print("\n[3/8] Running Proof Size benchmarks...")
    proof_size_suite = BenchmarkSuite(
        name="ProofSize",
        benchmarks=[
            ProofSizeBenchmark(W_values, tier),
            RecursionProofSizeBenchmark()
        ]
    )
    proof_size_suite.run_all(verbose)
    suites['proof_size'] = proof_size_suite.to_dict()

    # Suite 4: Overhead
    if verbose:
        print("\n[4/8] Running Overhead benchmarks...")
    overhead_suite = BenchmarkSuite(
        name="Overhead",
        benchmarks=[
            OverheadBenchmark(W_values, tier),
            ProofGenerationBreakdown(W=500, tier=tier)
        ]
    )
    overhead_suite.run_all(verbose)
    suites['overhead'] = overhead_suite.to_dict()

    # Suite 5: Recursion
    if verbose:
        print("\n[5/8] Running Recursion benchmarks...")
    recursion_suite = BenchmarkSuite(
        name="Recursion",
        benchmarks=[
            RecursionBenchmark(W=500, max_chunk_size=100),
            RecursionScalingBenchmark()
        ]
    )
    recursion_suite.run_all(verbose)
    suites['recursion'] = recursion_suite.to_dict()

    # Suite 6: Memory Hardness
    if verbose:
        print("\n[6/8] Running Memory benchmarks...")
    memory_suite = BenchmarkSuite(
        name="Memory",
        benchmarks=[
            MemoryHardnessBenchmark(W=500),
            SequentialityBenchmark(W=200),
            TimingBenchmark([100, 200, 500])
        ]
    )
    memory_suite.run_all(verbose)
    suites['memory'] = memory_suite.to_dict()

    # Suite 7: Switching Cost
    if verbose:
        print("\n[7/8] Running Switching Cost benchmarks...")
    switching_suite = BenchmarkSuite(
        name="SwitchingCost",
        benchmarks=[
            SwitchingCostBenchmark(),
            BackwardCompatibilityBenchmark(),
            MigrationBenchmark()
        ]
    )
    switching_suite.run_all(verbose)
    suites['switching'] = switching_suite.to_dict()

    # Suite 8: Compatibility
    if verbose:
        print("\n[8/8] Running Compatibility benchmarks...")
    compatibility_suite = BenchmarkSuite(
        name="Compatibility",
        benchmarks=[
            APICompatibilityBenchmark(),
            FormatCompatibilityBenchmark(),
            IntegrationBenchmark(),
            DeterminismBenchmark()
        ]
    )
    compatibility_suite.run_all(verbose)
    suites['compatibility'] = compatibility_suite.to_dict()

    # Compute totals
    total_duration = (time.perf_counter() - start_time) * 1000

    all_results = []
    for suite_data in suites.values():
        all_results.extend(suite_data['results'])

    pass_count = sum(1 for r in all_results if r['status'] == 'PASS')
    total_count = len(all_results)
    all_passed = pass_count == total_count

    # Generate summary
    summary = {
        'asymmetry': suites['asymmetry']['all_passed'],
        'soundness': suites['soundness']['all_passed'],
        'proof_size': suites['proof_size']['all_passed'],
        'overhead': suites['overhead']['all_passed'],
        'recursion': suites['recursion']['all_passed'],
        'memory': suites['memory']['all_passed'],
        'switching': suites['switching']['all_passed'],
        'compatibility': suites['compatibility']['all_passed'],
        'compliance_score': f"{pass_count}/{total_count} ({100*pass_count//total_count}%)"
    }

    report = BenchmarkReport(
        timestamp=timestamp,
        total_duration_ms=total_duration,
        all_passed=all_passed,
        pass_count=pass_count,
        total_count=total_count,
        suites=suites,
        summary=summary,
        params={
            'W': params.W,
            'memory_bytes': params.memory_bytes,
            'security_bits': params.security_bits,
            'tier': tier.value
        }
    )

    if verbose:
        report.print_summary()

    return report


def run_quick_benchmarks(verbose: bool = True) -> BenchmarkReport:
    """Run quick benchmarks with minimal settings."""
    params = PoCParams(W=100, memory_bytes=256 * 1024)  # 256KB
    return run_all_benchmarks(params, ProofTier.Q, verbose, W_values=[50, 100])


def run_full_benchmarks(verbose: bool = True) -> BenchmarkReport:
    """Run full benchmarks with production-like settings."""
    params = PoCParams(W=10000, memory_bytes=16 * 1024 * 1024)  # 16MB
    return run_all_benchmarks(params, ProofTier.Q, verbose, W_values=[1000, 5000, 10000])


# =============================================================================
# Soundness Report Generator
# =============================================================================

def generate_soundness_report(params: PoCParams = None) -> Dict[str, Any]:
    """
    Generate detailed soundness analysis report.

    This is the soundness.json output required by the spec.
    """
    if params is None:
        params = PoCParams()

    from .runner_soundness import DetailedSoundnessAnalysis

    analysis = DetailedSoundnessAnalysis(params)
    report = analysis.analyze()

    return {
        'params': {
            'W': params.W,
            'security_bits': params.security_bits,
            'blowup_factor': params.blowup_factor,
            'fri_queries': params.fri_queries,
            'fri_rate': params.fri_rate
        },
        'analysis': report,
        'conclusion': {
            'target_security': f"{params.security_bits} bits",
            'achieved_security': f"{report['combined']['achieved_bits']} bits",
            'meets_requirement': report['combined']['meets_target'],
            'forgery_probability': f"< 2^-{report['combined']['achieved_bits']}"
        }
    }


def save_soundness_report(path: str, params: PoCParams = None):
    """Save soundness report to JSON file."""
    report = generate_soundness_report(params)
    with open(path, 'w') as f:
        json.dump(report, f, indent=2)


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    """Run benchmarks from command line."""
    import argparse

    parser = argparse.ArgumentParser(description='PoC_Hash Benchmark Suite')
    parser.add_argument('--quick', action='store_true', help='Run quick benchmarks')
    parser.add_argument('--full', action='store_true', help='Run full benchmarks')
    parser.add_argument('--output', '-o', type=str, help='Output JSON file')
    parser.add_argument('--soundness', type=str, help='Output soundness.json file')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')

    args = parser.parse_args()

    verbose = not args.quiet

    if args.quick:
        report = run_quick_benchmarks(verbose)
    elif args.full:
        report = run_full_benchmarks(verbose)
    else:
        report = run_all_benchmarks(verbose=verbose)

    if args.output:
        report.save(args.output)
        print(f"\nReport saved to: {args.output}")

    if args.soundness:
        save_soundness_report(args.soundness)
        print(f"Soundness report saved to: {args.soundness}")

    # Exit code based on results
    return 0 if report.all_passed else 1


if __name__ == '__main__':
    exit(main())
