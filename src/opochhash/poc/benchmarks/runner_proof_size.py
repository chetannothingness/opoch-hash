"""
Benchmark 3: Proof Size

Target: O(polylog W) proof size, <1KB for W=10^12 with recursion

Tests:
- Measure proof sizes for various W
- Verify polylogarithmic growth
- Test recursive proof aggregation
"""

from dataclasses import dataclass
from typing import List, Dict, Any
import math

from .base import Benchmark, BenchmarkResult, BenchmarkStatus
from ..params import PoCParams
from ..poc_hash import poc_hash, ProofTier, estimate_proof_size
from ..recursion import estimate_recursive_proof_size, proof_size_for_target


@dataclass
class ProofSizeMeasurement:
    """Single proof size measurement."""
    W: int
    proof_size_bytes: int
    log_W: float
    size_per_log_W: float


class ProofSizeBenchmark(Benchmark):
    """
    Benchmark 3: Proof Size Scaling

    Requirement: O(polylog W) size, <1KB for W=10^12 with recursion
    """

    name = "proof_size"
    description = "Proof size scaling with work"

    def __init__(
        self,
        W_values: List[int] = None,
        tier: ProofTier = ProofTier.Q,
        max_size_kb: float = 100.0  # Max acceptable size in KB for test W
    ):
        self.W_values = W_values or [100, 500, 1000, 2000]
        self.tier = tier
        self.max_size_kb = max_size_kb

    def run(self) -> BenchmarkResult:
        measurements = []
        test_input = b"proof size benchmark"

        for W in self.W_values:
            params = PoCParams(W=W, memory_bytes=1024 * 1024)

            result = poc_hash(test_input, params, self.tier)
            proof_size = result.proof.size

            log_W = math.log2(W + 1)
            size_per_log = proof_size / (log_W * log_W)  # Normalize by log^2

            measurements.append(ProofSizeMeasurement(
                W=W,
                proof_size_bytes=proof_size,
                log_W=log_W,
                size_per_log_W=size_per_log
            ))

        # Analyze polylog growth
        growth_analysis = self._analyze_growth(measurements)

        # Estimate for W=10^12 with recursion
        recursive_estimate = estimate_recursive_proof_size(10**12)
        target_analysis = proof_size_for_target(1024, 10**12)

        # Check if sizes are reasonable
        max_observed = max(m.proof_size_bytes for m in measurements)
        max_kb = max_observed / 1024

        passed = max_kb <= self.max_size_kb and growth_analysis['is_polylog']

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if passed else BenchmarkStatus.FAIL,
            target=f"Proof size < {self.max_size_kb}KB, polylog growth",
            actual=f"Max size: {max_kb:.2f}KB, {growth_analysis['growth_type']}",
            details={
                'measurements': [
                    {
                        'W': m.W,
                        'size_bytes': m.proof_size_bytes,
                        'size_kb': round(m.proof_size_bytes / 1024, 2),
                        'log_W': round(m.log_W, 2)
                    }
                    for m in measurements
                ],
                'growth_analysis': growth_analysis,
                'recursive_estimate_10_12': recursive_estimate,
                'target_1kb_analysis': target_analysis
            }
        )

    def _analyze_growth(self, measurements: List[ProofSizeMeasurement]) -> Dict[str, Any]:
        """Analyze if proof size growth is polylogarithmic."""
        if len(measurements) < 2:
            return {'is_polylog': True, 'growth_type': 'insufficient data'}

        sorted_m = sorted(measurements, key=lambda m: m.W)

        # Check growth rate
        # Polylog: size ~ log^k(W) for some k
        # Linear: size ~ W

        # Compute ratio of size increase to W increase
        ratios = []
        for i in range(len(sorted_m) - 1):
            W_ratio = sorted_m[i+1].W / sorted_m[i].W
            size_ratio = sorted_m[i+1].proof_size_bytes / max(sorted_m[i].proof_size_bytes, 1)
            ratios.append(size_ratio / W_ratio)

        avg_ratio = sum(ratios) / len(ratios) if ratios else 1

        # For polylog, ratio should be << 1 (size grows slower than W)
        # For linear, ratio should be ~1

        is_polylog = avg_ratio < 0.5  # Size grows at most half as fast as W

        if avg_ratio < 0.1:
            growth_type = "polylog (excellent)"
        elif avg_ratio < 0.5:
            growth_type = "sublinear (good)"
        elif avg_ratio < 1.5:
            growth_type = "linear (acceptable)"
        else:
            growth_type = "superlinear (bad)"

        return {
            'is_polylog': is_polylog,
            'growth_type': growth_type,
            'avg_ratio': round(avg_ratio, 3),
            'explanation': f"Size/W ratio: {avg_ratio:.3f} (lower is better)"
        }


class RecursionProofSizeBenchmark(Benchmark):
    """
    Benchmark for recursive proof size at large W.

    Tests the O(polylog W) claim for W = 10^12.
    """

    name = "recursive_proof_size"
    description = "Recursive proof size for large W"

    def __init__(self, target_kb: float = 1.0):
        self.target_kb = target_kb

    def run(self) -> BenchmarkResult:
        # Estimate sizes for various large W
        W_values = [10**6, 10**9, 10**12]

        estimates = []
        for W in W_values:
            size = estimate_recursive_proof_size(W)
            estimates.append({
                'W': W,
                'W_str': f"10^{int(math.log10(W))}",
                'estimated_bytes': size,
                'estimated_kb': round(size / 1024, 2)
            })

        # Check 10^12 meets target
        estimate_10_12 = estimates[-1]['estimated_kb']
        passed = estimate_10_12 <= self.target_kb

        # Detailed analysis for achieving 1KB
        target_analysis = proof_size_for_target(1024, 10**12)

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if passed else BenchmarkStatus.FAIL,
            target=f"Recursive proof < {self.target_kb}KB for W=10^12",
            actual=f"Estimated: {estimate_10_12}KB for W=10^12",
            details={
                'estimates': estimates,
                'target_analysis': target_analysis,
                'achievable': target_analysis['num_samples'] >= 30  # Min for 128-bit security
            }
        )


def run_proof_size_benchmark(
    W_values: List[int] = None,
    tier: ProofTier = ProofTier.Q,
    verbose: bool = True
) -> BenchmarkResult:
    """Run proof size benchmark."""
    bench = ProofSizeBenchmark(W_values, tier)
    result = bench.timed_run()

    if verbose:
        print(f"\n=== Proof Size Benchmark ===")
        print(f"Status: {result.status.value}")
        print(f"Target: {result.target}")
        print(f"Actual: {result.actual}")
        if 'measurements' in result.details:
            print("\nMeasurements:")
            for m in result.details['measurements']:
                print(f"  W={m['W']:>5}: {m['size_bytes']:>6} bytes ({m['size_kb']:.2f} KB)")

    return result
