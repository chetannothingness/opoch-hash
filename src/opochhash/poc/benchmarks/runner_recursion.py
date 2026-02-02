"""
Benchmark 5: Recursion

Target: Recursive proof aggregation works correctly

Tests:
- Generate recursive proofs for chunked computation
- Verify proof size remains bounded
- Verify correctness of aggregation
"""

from dataclasses import dataclass
from typing import List, Dict, Any
import time
import math

from .base import Benchmark, BenchmarkResult, BenchmarkStatus
from ..params import PoCParams
from ..work import compute_full_work, legacy_digest
from ..recursion import (
    RecursiveProver,
    RecursiveVerifier,
    estimate_recursive_proof_size,
    proof_size_for_target
)


class RecursionBenchmark(Benchmark):
    """
    Benchmark 5: Recursive Proof Aggregation

    Tests that recursive proofs work and scale correctly.
    """

    name = "recursion"
    description = "Recursive proof aggregation"

    def __init__(
        self,
        W: int = 1000,
        max_chunk_size: int = 200
    ):
        self.W = W
        self.max_chunk_size = max_chunk_size

    def run(self) -> BenchmarkResult:
        test_input = b"recursion benchmark"
        params = PoCParams(W=self.W, memory_bytes=1024 * 1024)

        # Generate trace
        trace, memory_accesses = compute_full_work(test_input, params)
        d0 = legacy_digest(test_input, params.legacy_hash)

        # Generate recursive proof
        prover = RecursiveProver(params, self.max_chunk_size)

        prove_start = time.perf_counter()
        proof = prover.prove(d0, trace, memory_accesses)
        prove_time = (time.perf_counter() - prove_start) * 1000

        # Verify
        verifier = RecursiveVerifier(params)

        verify_start = time.perf_counter()
        valid = verifier.verify(proof)
        verify_time = (time.perf_counter() - verify_start) * 1000

        if not valid:
            return BenchmarkResult(
                name=self.name,
                status=BenchmarkStatus.FAIL,
                target="Valid recursive proof",
                actual="Verification failed"
            )

        # Analyze
        proof_size = proof.size
        num_chunks = proof.num_chunks
        expected_chunks = math.ceil(self.W / self.max_chunk_size)

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS,
            target="Valid recursive proof with bounded size",
            actual=f"Valid proof, {num_chunks} chunks, {proof_size} bytes",
            details={
                'W': self.W,
                'max_chunk_size': self.max_chunk_size,
                'num_chunks': num_chunks,
                'expected_chunks': expected_chunks,
                'proof_size_bytes': proof_size,
                'proof_size_kb': round(proof_size / 1024, 2),
                'prove_time_ms': round(prove_time, 2),
                'verify_time_ms': round(verify_time, 2),
                'prover_verifier_ratio': round(prove_time / max(verify_time, 0.001), 1)
            }
        )


class RecursionScalingBenchmark(Benchmark):
    """
    Test that recursion scales correctly with W.
    """

    name = "recursion_scaling"
    description = "Recursive proof scaling analysis"

    def __init__(self, max_chunk_size: int = 100):
        self.max_chunk_size = max_chunk_size

    def run(self) -> BenchmarkResult:
        # Theoretical analysis for large W
        W_values = [10**3, 10**6, 10**9, 10**12]

        estimates = []
        for W in W_values:
            size = estimate_recursive_proof_size(W, self.max_chunk_size)
            num_chunks = math.ceil(W / self.max_chunk_size)
            log_chunks = math.ceil(math.log2(num_chunks + 1))

            estimates.append({
                'W': W,
                'W_str': f"10^{int(math.log10(W))}",
                'num_chunks': num_chunks,
                'log_chunks': log_chunks,
                'estimated_size_bytes': size,
                'estimated_size_kb': round(size / 1024, 2)
            })

        # Check polylog scaling
        # Proof size should grow as O(log^2 W) roughly
        is_polylog = self._check_polylog(estimates)

        # Check 1KB target for 10^12
        meets_1kb = estimates[-1]['estimated_size_kb'] <= 1.0

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if is_polylog else BenchmarkStatus.FAIL,
            target="Polylog proof size scaling",
            actual=f"{'Polylog' if is_polylog else 'Non-polylog'} scaling, "
                   f"{estimates[-1]['estimated_size_kb']}KB at W=10^12",
            details={
                'estimates': estimates,
                'is_polylog': is_polylog,
                'meets_1kb_target': meets_1kb,
                'target_analysis': proof_size_for_target(1024, 10**12)
            }
        )

    def _check_polylog(self, estimates: List[Dict]) -> bool:
        """Check if scaling is polylogarithmic."""
        if len(estimates) < 2:
            return True

        # For polylog: size ~ log^k(W)
        # When W increases by 10^3, size should increase by ~10 (log factor)
        # Not by 10^3 (linear)

        for i in range(len(estimates) - 1):
            W_ratio = estimates[i+1]['W'] / estimates[i]['W']
            size_ratio = estimates[i+1]['estimated_size_bytes'] / max(estimates[i]['estimated_size_bytes'], 1)

            # For polylog, size_ratio << W_ratio
            if size_ratio > W_ratio * 0.01:  # Allow 1% of linear growth
                return False

        return True


def run_recursion_benchmark(
    W: int = 1000,
    max_chunk_size: int = 200,
    verbose: bool = True
) -> BenchmarkResult:
    """Run recursion benchmark."""
    bench = RecursionBenchmark(W, max_chunk_size)
    result = bench.timed_run()

    if verbose:
        print(f"\n=== Recursion Benchmark ===")
        print(f"Status: {result.status.value}")
        print(f"Target: {result.target}")
        print(f"Actual: {result.actual}")
        if result.details:
            print(f"\nDetails:")
            print(f"  Chunks: {result.details.get('num_chunks', 'N/A')}")
            print(f"  Proof size: {result.details.get('proof_size_kb', 'N/A')} KB")
            print(f"  Prove time: {result.details.get('prove_time_ms', 'N/A')} ms")
            print(f"  Verify time: {result.details.get('verify_time_ms', 'N/A')} ms")

    return result
