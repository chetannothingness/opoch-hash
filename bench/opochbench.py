#!/usr/bin/env python3
"""
OpochBench: Complete Benchmark Suite for OpochHash

Proves OpochHash end-to-end:
    meaning → Π-fixed tape → tree sponge mix → receipts

Shows why it dominates every commonly used hashing setup on all industry-relevant
axes (correctness, determinism, mode safety, streaming/parallel throughput),
while also being competitive on mixer-only cpb/throughput.

Usage:
    opochbench serpi_conformance   [--output DIR]
    opochbench mixer_microbench    [--output DIR] [--include-large]
    opochbench end2end             [--output DIR]
    opochbench dominance_proofs    [--output DIR] [--max-keys N]
    opochbench all                 [--output DIR]
    opochbench report              [--output DIR]
"""

from __future__ import annotations
import argparse
import json
import hashlib
import time
import os
import sys
from pathlib import Path
from typing import Dict, Any, List

# Add paths
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent))

from runners.serpi_conformance import SerPiConformanceRunner
from runners.mixer_microbench import MixerMicrobenchRunner
from runners.end2end_bench import End2EndBenchRunner
from runners.dominance_proofs import DominanceProofsRunner
from runners.pareto_frontier import ParetoFrontierRunner


class OpochBench:
    """Main benchmark orchestrator."""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.receipts_dir = self.output_dir / 'receipts'
        self.receipts_dir.mkdir(exist_ok=True)

    def run_serpi_conformance(self) -> Dict[str, Any]:
        """Run Ser_Π conformance tests."""
        print("=" * 60)
        print("RUNNER 1: Ser_Π Conformance Tests")
        print("=" * 60)

        runner = SerPiConformanceRunner(self.output_dir)
        report = runner.run()

        print(f"\nResults: {report.passed}/{report.total_tests} passed")
        print(f"Duration: {report.duration_ms:.2f} ms")
        print(f"Vectors hash: {report.vectors_hash[:16]}...")

        if report.failed > 0:
            print("\n⚠️  FAILURES DETECTED:")
            for test in report.tests:
                if not test.passed:
                    print(f"  - {test.test_name}: {test.details}")

        return report.to_dict()

    def run_mixer_microbench(self, include_large: bool = False) -> Dict[str, Any]:
        """Run mixer microbenchmarks."""
        print("\n" + "=" * 60)
        print("RUNNER 2: Mixer Microbenchmarks")
        print("=" * 60)

        runner = MixerMicrobenchRunner(self.output_dir, include_large=include_large)
        report = runner.run()

        print(f"\nMixers tested: {', '.join(report.summary.get('mixers_tested', []))}")
        print(f"Duration: {report.duration_ms:.2f} ms")

        if 'throughput_4kb' in report.summary:
            print("\nThroughput at 4KB:")
            for name, throughput in report.summary['throughput_4kb'].items():
                print(f"  {name:20s}: {throughput}")

        return report.to_dict()

    def run_end2end(self) -> Dict[str, Any]:
        """Run end-to-end benchmarks."""
        print("\n" + "=" * 60)
        print("RUNNER 3: End-to-End Object Hash Benchmarks")
        print("=" * 60)

        runner = End2EndBenchRunner(self.output_dir)
        report = runner.run()

        print(f"\nDuration: {report.duration_ms:.2f} ms")
        print("\nObject category results:")
        for result in report.object_results:
            print(f"  {result.category:10s}: {result.median_latency_us:8.2f} µs, "
                  f"{result.throughput_ops:8.0f} ops/s")

        return report.to_dict()

    def run_dominance_proofs(self, max_keys: int = 10) -> Dict[str, Any]:
        """Run dominance proof tests."""
        print("\n" + "=" * 60)
        print("RUNNER 4: Semantic Dominance Proofs")
        print("=" * 60)

        runner = DominanceProofsRunner(self.output_dir, max_keys=max_keys)
        report = runner.run()

        print(f"\nDuration: {report.duration_ms:.2f} ms")

        # Factorial dominance
        print("\nFactorial Slack Collapse (R(n) = baseline_distinct / opoch_distinct):")
        for result in report.factorial_results:
            print(f"  n={result.n_keys}: R(n) = {result.dominance_ratio:.1f}x "
                  f"({result.baseline_distinct_digests} vs {result.opoch_distinct_digests})")

        # Mode confusion
        print("\nMode Confusion Prevention:")
        for result in report.mode_confusion_results:
            print(f"  {result.test_name}: {result.prevention_rate:.0f}% prevented")

        # Schema evolution
        print("\nSchema Evolution Protection:")
        for result in report.schema_evolution_results:
            status = "✓" if result.opoch_collisions == 0 else "✗"
            print(f"  {result.test_name}: {status} ({result.collisions_prevented} prevented)")

        print(f"\nVerdict: {report.summary.get('verdict', 'UNKNOWN')}")

        return report.to_dict()

    def run_pareto_frontier(self) -> Dict[str, Any]:
        """Run Pareto frontier certification."""
        print("\n" + "=" * 60)
        print("RUNNER 5: Pareto Frontier Certificate")
        print("=" * 60)

        runner = ParetoFrontierRunner(self.output_dir)
        report = runner.run()

        print(f"\nOptimal τ: {report.optimal_tau} bytes")
        print(f"Duration: {report.duration_ms:.2f} ms")

        print("\nτ Sweep Results:")
        for result in report.tau_sweep_results:
            print(f"  τ={result.tau:4d}: 64B={result.latency_64b_us:5.2f}µs, "
                  f"4KB={result.throughput_4kb_mbs:6.2f}MB/s, score={result.pareto_score:.2f}")

        print("\nRegime Analysis:")
        for analysis in report.regime_analysis:
            print(f"  {analysis.size_bytes:6d}B: {analysis.optimal_mode:5s} "
                  f"({analysis.speedup_vs_wrong_mode:.1f}x better)")

        cert = report.pareto_certificate
        print(f"\nPareto Certificate:")
        print(f"  Verdict: {cert.get('verdict', 'UNKNOWN')}")
        print(f"  Crossover: {cert.get('crossover_size', 'N/A')} bytes")

        return report.to_dict()

    def run_all(self, max_keys: int = 10, include_large: bool = False) -> Dict[str, Any]:
        """Run all benchmarks."""
        start_time = time.perf_counter()

        results = {
            'serpi_conformance': self.run_serpi_conformance(),
            'mixer_microbench': self.run_mixer_microbench(include_large),
            'end2end': self.run_end2end(),
            'dominance_proofs': self.run_dominance_proofs(max_keys),
            'pareto_frontier': self.run_pareto_frontier(),
        }

        elapsed = (time.perf_counter() - start_time) * 1000

        # Generate consolidated report
        consolidated = self._generate_consolidated_report(results, elapsed)

        # Generate receipts
        self._generate_receipts(consolidated)

        return consolidated

    def _generate_consolidated_report(
        self,
        results: Dict[str, Any],
        total_duration_ms: float
    ) -> Dict[str, Any]:
        """Generate consolidated benchmark report."""
        report = {
            'opochbench_version': '1.0.0',
            'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            'total_duration_ms': total_duration_ms,
            'results': results,
            'verdict': self._compute_verdict(results),
        }

        # Write consolidated report
        report_path = self.output_dir / 'report.json'
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        print("\n" + "=" * 60)
        print("CONSOLIDATED REPORT")
        print("=" * 60)
        print(f"Written to: {report_path}")
        print(f"Total duration: {total_duration_ms:.2f} ms")

        return report

    def _compute_verdict(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Compute overall verdict."""
        serpi = results.get('serpi_conformance', {})
        dominance = results.get('dominance_proofs', {})

        serpi_passed = serpi.get('passed', 0) == serpi.get('total_tests', 0)
        dominance_verdict = dominance.get('summary', {}).get('verdict', 'UNKNOWN')

        return {
            'serpi_conformance': 'PASS' if serpi_passed else 'FAIL',
            'dominance': dominance_verdict,
            'overall': 'STRICT_DOMINANCE' if serpi_passed and dominance_verdict == 'STRICT_DOMINANCE' else 'INCOMPLETE',
        }

    def _generate_receipts(self, report: Dict[str, Any]):
        """Generate hash chain receipts for reproducibility."""
        # Receipt 1: Report hash
        report_json = json.dumps(report, sort_keys=True, indent=2)
        report_hash = hashlib.sha256(report_json.encode()).hexdigest()

        receipt = {
            'type': 'opochbench_receipt',
            'version': '1.0.0',
            'timestamp': report['timestamp'],
            'report_hash': report_hash,
            'verdict': report['verdict'],
        }

        receipt_path = self.receipts_dir / 'receipt.json'
        with open(receipt_path, 'w') as f:
            json.dump(receipt, f, indent=2)

        # Generate replay script
        replay_path = self.receipts_dir / 'replay.sh'
        with open(replay_path, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("# OpochBench Replay Script\n")
            f.write(f"# Original run: {report['timestamp']}\n")
            f.write(f"# Report hash: {report_hash}\n\n")
            f.write("cd \"$(dirname \"$0\")/..\"\n")
            f.write("python opochbench.py all\n")

        os.chmod(replay_path, 0o755)

        print(f"\nReceipts written to: {self.receipts_dir}")
        print(f"Report hash: {report_hash[:32]}...")


def main():
    parser = argparse.ArgumentParser(
        description='OpochBench: Complete Benchmark Suite for OpochHash',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    opochbench all                    # Run all benchmarks
    opochbench serpi_conformance      # Run only conformance tests
    opochbench dominance_proofs       # Run only dominance proofs
    opochbench mixer_microbench       # Run only mixer benchmarks
        """
    )

    parser.add_argument(
        'command',
        choices=['serpi_conformance', 'mixer_microbench', 'end2end',
                 'dominance_proofs', 'pareto_frontier', 'all', 'quick'],
        help='Benchmark command to run'
    )

    parser.add_argument(
        '--output', '-o',
        type=Path,
        default=Path('./bench_output'),
        help='Output directory for results'
    )

    parser.add_argument(
        '--max-keys',
        type=int,
        default=10,
        help='Maximum keys for factorial tests (default: 10)'
    )

    parser.add_argument(
        '--include-large',
        action='store_true',
        help='Include large message benchmarks (1MB, 64MB)'
    )

    args = parser.parse_args()

    bench = OpochBench(args.output)

    if args.command == 'serpi_conformance':
        bench.run_serpi_conformance()
    elif args.command == 'mixer_microbench':
        bench.run_mixer_microbench(args.include_large)
    elif args.command == 'end2end':
        bench.run_end2end()
    elif args.command == 'dominance_proofs':
        bench.run_dominance_proofs(args.max_keys)
    elif args.command == 'pareto_frontier':
        bench.run_pareto_frontier()
    elif args.command == 'all':
        bench.run_all(args.max_keys, args.include_large)
    elif args.command == 'quick':
        # Quick demo of all runners
        from runners.mixer_microbench import run_quick_benchmark
        from runners.end2end_bench import run_quick_end2end
        from runners.dominance_proofs import run_quick_dominance
        from runners.pareto_frontier import run_quick_pareto

        run_quick_benchmark()
        run_quick_end2end()
        run_quick_dominance()
        run_quick_pareto()


if __name__ == '__main__':
    main()
