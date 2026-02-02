"""
Benchmark 4: Prover Overhead

Target: Prover overhead < 10x vs plain sequential work

Tests:
- Measure time for plain work (no proof)
- Measure time for work + proof generation
- Calculate overhead ratio
"""

from dataclasses import dataclass
from typing import List, Dict, Any
import time

from .base import Benchmark, BenchmarkResult, BenchmarkStatus
from ..params import PoCParams
from ..poc_hash import poc_hash, ProofTier
from ..work import compute_full_work, legacy_digest


@dataclass
class OverheadMeasurement:
    """Single overhead measurement."""
    W: int
    plain_work_ms: float
    proof_gen_ms: float
    total_ms: float
    overhead_ratio: float


class OverheadBenchmark(Benchmark):
    """
    Benchmark 4: Prover Overhead

    Requirement: Overhead < 10x vs plain work
    """

    name = "overhead"
    description = "Prover overhead vs plain work"

    def __init__(
        self,
        W_values: List[int] = None,
        tier: ProofTier = ProofTier.Q,
        max_overhead: float = 10.0
    ):
        self.W_values = W_values or [100, 500, 1000]
        self.tier = tier
        self.max_overhead = max_overhead

    def run(self) -> BenchmarkResult:
        measurements = []
        test_input = b"overhead benchmark input"

        for W in self.W_values:
            params = PoCParams(W=W, memory_bytes=1024 * 1024)

            # Measure plain work (no proof)
            plain_start = time.perf_counter()
            trace, _ = compute_full_work(test_input, params)
            plain_end = time.perf_counter()
            plain_ms = (plain_end - plain_start) * 1000

            # Measure full proof generation
            total_start = time.perf_counter()
            result = poc_hash(test_input, params, self.tier)
            total_end = time.perf_counter()
            total_ms = (total_end - total_start) * 1000

            # Proof generation time
            proof_ms = result.proof.proof_time_ms

            # Overhead ratio
            overhead = total_ms / max(plain_ms, 0.001)

            measurements.append(OverheadMeasurement(
                W=W,
                plain_work_ms=plain_ms,
                proof_gen_ms=proof_ms,
                total_ms=total_ms,
                overhead_ratio=overhead
            ))

        # Analyze
        max_observed_overhead = max(m.overhead_ratio for m in measurements)
        avg_overhead = sum(m.overhead_ratio for m in measurements) / len(measurements)

        passed = max_observed_overhead <= self.max_overhead

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if passed else BenchmarkStatus.FAIL,
            target=f"Overhead < {self.max_overhead}x",
            actual=f"Max overhead: {max_observed_overhead:.2f}x, Avg: {avg_overhead:.2f}x",
            details={
                'measurements': [
                    {
                        'W': m.W,
                        'plain_ms': round(m.plain_work_ms, 2),
                        'proof_ms': round(m.proof_gen_ms, 2),
                        'total_ms': round(m.total_ms, 2),
                        'overhead': round(m.overhead_ratio, 2)
                    }
                    for m in measurements
                ],
                'max_overhead': max_observed_overhead,
                'avg_overhead': avg_overhead
            }
        )


class ProofGenerationBreakdown(Benchmark):
    """
    Detailed breakdown of proof generation time.
    """

    name = "proof_breakdown"
    description = "Proof generation time breakdown"

    def __init__(self, W: int = 1000, tier: ProofTier = ProofTier.Q):
        self.W = W
        self.tier = tier

    def run(self) -> BenchmarkResult:
        test_input = b"breakdown benchmark"
        params = PoCParams(W=self.W, memory_bytes=1024 * 1024)

        # Measure components
        breakdown = {}

        # 1. Legacy digest
        start = time.perf_counter()
        d0 = legacy_digest(test_input, params.legacy_hash)
        breakdown['legacy_digest_ms'] = (time.perf_counter() - start) * 1000

        # 2. Work execution
        start = time.perf_counter()
        trace, memory_accesses = compute_full_work(test_input, params)
        breakdown['work_execution_ms'] = (time.perf_counter() - start) * 1000

        # 3. Full proof
        start = time.perf_counter()
        result = poc_hash(test_input, params, self.tier)
        breakdown['total_ms'] = (time.perf_counter() - start) * 1000

        # Calculated
        breakdown['proof_only_ms'] = result.proof.proof_time_ms

        # Percentages
        total = breakdown['total_ms']
        breakdown['work_pct'] = round(100 * breakdown['work_execution_ms'] / total, 1)
        breakdown['proof_pct'] = round(100 * breakdown['proof_only_ms'] / total, 1)

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS,
            target="Breakdown analysis",
            actual=f"Work: {breakdown['work_pct']}%, Proof: {breakdown['proof_pct']}%",
            details=breakdown
        )


def run_overhead_benchmark(
    W_values: List[int] = None,
    tier: ProofTier = ProofTier.Q,
    verbose: bool = True
) -> BenchmarkResult:
    """Run overhead benchmark."""
    bench = OverheadBenchmark(W_values, tier)
    result = bench.timed_run()

    if verbose:
        print(f"\n=== Overhead Benchmark ===")
        print(f"Status: {result.status.value}")
        print(f"Target: {result.target}")
        print(f"Actual: {result.actual}")
        if 'measurements' in result.details:
            print("\nMeasurements:")
            for m in result.details['measurements']:
                print(f"  W={m['W']:>5}: Plain={m['plain_ms']:>8.2f}ms, "
                      f"Total={m['total_ms']:>8.2f}ms, Overhead={m['overhead']:.2f}x")

    return result
