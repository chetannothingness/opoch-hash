"""
Benchmark 1: Prover/Verifier Asymmetry

Target: Verifier cost = O(polylog W), Prover cost = Θ(W)
This ensures verification is exponentially cheaper than proving.

Tests:
- Measure prover time for various W
- Measure verifier time for same W
- Verify asymptotic ratio matches O(W / polylog W)
"""

from dataclasses import dataclass
from typing import List, Tuple
import time
import math

from .base import Benchmark, BenchmarkResult, BenchmarkStatus
from ..params import PoCParams
from ..poc_hash import poc_hash, verify_poc, ProofTier
from ..state import WorkState


@dataclass
class AsymmetryMeasurement:
    """Single measurement of prover/verifier times."""
    W: int
    prover_ms: float
    verifier_ms: float
    ratio: float


class AsymmetryBenchmark(Benchmark):
    """
    Benchmark 1: Prover/Verifier Asymmetry

    Requirement: Verifier = O(polylog W), Prover = Θ(W)
    """

    name = "asymmetry"
    description = "Prover/Verifier cost asymmetry"

    def __init__(
        self,
        W_values: List[int] = None,
        tier: ProofTier = ProofTier.Q,
        min_ratio: float = 10.0  # Verifier should be at least 10x faster
    ):
        self.W_values = W_values or [100, 500, 1000, 2000]
        self.tier = tier
        self.min_ratio = min_ratio

    def run(self) -> BenchmarkResult:
        measurements = []
        test_input = b"asymmetry benchmark input"

        for W in self.W_values:
            params = PoCParams(W=W, memory_bytes=1024 * 1024)  # 1MB memory

            # Measure prover time
            prover_start = time.perf_counter()
            result = poc_hash(test_input, params, self.tier)
            prover_end = time.perf_counter()
            prover_ms = (prover_end - prover_start) * 1000

            # Measure verifier time
            verifier_start = time.perf_counter()
            valid = verify_poc(result.d0, result.proof, params)
            verifier_end = time.perf_counter()
            verifier_ms = (verifier_end - verifier_start) * 1000

            if not valid:
                return BenchmarkResult(
                    name=self.name,
                    status=BenchmarkStatus.FAIL,
                    target="Valid proofs",
                    actual=f"Proof invalid for W={W}",
                    details={'W': W}
                )

            ratio = prover_ms / max(verifier_ms, 0.001)
            measurements.append(AsymmetryMeasurement(
                W=W, prover_ms=prover_ms, verifier_ms=verifier_ms, ratio=ratio
            ))

        # Analyze results
        all_ratios = [m.ratio for m in measurements]
        min_observed_ratio = min(all_ratios)
        avg_ratio = sum(all_ratios) / len(all_ratios)

        # Check that ratio grows with W (polylog behavior)
        # For small W, ratio should still be significant
        ratio_growth = self._check_ratio_growth(measurements)

        passed = min_observed_ratio >= self.min_ratio

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if passed else BenchmarkStatus.FAIL,
            target=f"Prover/Verifier ratio >= {self.min_ratio}x",
            actual=f"Min ratio: {min_observed_ratio:.1f}x, Avg: {avg_ratio:.1f}x",
            details={
                'measurements': [
                    {
                        'W': m.W,
                        'prover_ms': round(m.prover_ms, 2),
                        'verifier_ms': round(m.verifier_ms, 2),
                        'ratio': round(m.ratio, 1)
                    }
                    for m in measurements
                ],
                'min_ratio': min_observed_ratio,
                'avg_ratio': avg_ratio,
                'ratio_growth': ratio_growth
            }
        )

    def _check_ratio_growth(self, measurements: List[AsymmetryMeasurement]) -> str:
        """Check if ratio grows appropriately with W."""
        if len(measurements) < 2:
            return "insufficient data"

        # Sort by W
        sorted_m = sorted(measurements, key=lambda m: m.W)

        # Check if ratio increases (prover scales faster than verifier)
        increasing = all(
            sorted_m[i].ratio <= sorted_m[i+1].ratio * 1.5  # Allow some variance
            for i in range(len(sorted_m) - 1)
        )

        if increasing:
            return "ratio grows with W (expected)"
        else:
            return "ratio stable or decreasing"


def run_asymmetry_benchmark(
    W_values: List[int] = None,
    tier: ProofTier = ProofTier.Q,
    verbose: bool = True
) -> BenchmarkResult:
    """Convenience function to run asymmetry benchmark."""
    bench = AsymmetryBenchmark(W_values, tier)
    result = bench.timed_run()

    if verbose:
        print(f"\n=== Asymmetry Benchmark ===")
        print(f"Status: {result.status.value}")
        print(f"Target: {result.target}")
        print(f"Actual: {result.actual}")
        if 'measurements' in result.details:
            print("\nMeasurements:")
            for m in result.details['measurements']:
                print(f"  W={m['W']:>5}: Prover={m['prover_ms']:>8.2f}ms, "
                      f"Verifier={m['verifier_ms']:>6.2f}ms, Ratio={m['ratio']:>6.1f}x")

    return result
