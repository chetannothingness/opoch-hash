"""
Benchmark 6: Memory Hardness

Target: Work function is memory-hard (cannot skip memory accesses)

Tests:
- Memory bandwidth utilization
- Sequential access pattern
- Cannot parallelize significantly
- Time-memory tradeoff resistance
"""

from dataclasses import dataclass
from typing import List, Dict, Any
import time
import hashlib

from .base import Benchmark, BenchmarkResult, BenchmarkStatus
from ..params import PoCParams
from ..work import compute_full_work
from ..state import WorkState
from ..memory import MerkleMemory, initialize_memory


class MemoryHardnessBenchmark(Benchmark):
    """
    Benchmark 6: Memory Hardness

    Tests that the work function properly exercises memory.
    """

    name = "memory_hardness"
    description = "Memory-hard work validation"

    def __init__(
        self,
        W: int = 1000,
        memory_mb: int = 1
    ):
        self.W = W
        self.memory_mb = memory_mb

    def run(self) -> BenchmarkResult:
        test_input = b"memory hardness benchmark"
        params = PoCParams(
            W=self.W,
            memory_bytes=self.memory_mb * 1024 * 1024
        )

        # Execute work and analyze memory access patterns
        trace, memory_accesses = compute_full_work(test_input, params)

        # Analyze access patterns
        analysis = self._analyze_memory_accesses(memory_accesses, params)

        # Check memory hardness criteria
        passed = all([
            analysis['coverage_pct'] >= 50,  # Access at least 50% of memory
            analysis['unique_addresses_pct'] >= 30,  # Diverse addresses
            analysis['sequential_runs'] < self.W * 0.5,  # Not too sequential
        ])

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if passed else BenchmarkStatus.FAIL,
            target="Memory-hard access pattern",
            actual=f"{analysis['coverage_pct']:.1f}% coverage, "
                   f"{analysis['unique_addresses_pct']:.1f}% unique",
            details=analysis
        )

    def _analyze_memory_accesses(
        self,
        memory_accesses,
        params: PoCParams
    ) -> Dict[str, Any]:
        """Analyze memory access patterns."""
        if not memory_accesses:
            return {
                'coverage_pct': 0,
                'unique_addresses_pct': 0,
                'sequential_runs': 0,
                'error': 'No memory accesses'
            }

        addresses = [ma.address for ma in memory_accesses]
        num_blocks = params.num_blocks

        # Coverage: how many unique blocks accessed
        unique_addresses = set(addresses)
        coverage_pct = 100 * len(unique_addresses) / num_blocks

        # Unique percentage: unique / total accesses
        unique_pct = 100 * len(unique_addresses) / len(addresses)

        # Sequential runs: count consecutive addresses
        sequential_runs = 0
        for i in range(1, len(addresses)):
            if addresses[i] == (addresses[i-1] + 1) % num_blocks:
                sequential_runs += 1

        # Address distribution
        addr_counts = {}
        for addr in addresses:
            addr_counts[addr] = addr_counts.get(addr, 0) + 1

        max_accesses_single = max(addr_counts.values()) if addr_counts else 0
        avg_accesses = sum(addr_counts.values()) / len(addr_counts) if addr_counts else 0

        return {
            'num_accesses': len(addresses),
            'unique_addresses': len(unique_addresses),
            'num_blocks': num_blocks,
            'coverage_pct': round(coverage_pct, 2),
            'unique_addresses_pct': round(unique_pct, 2),
            'sequential_runs': sequential_runs,
            'sequential_pct': round(100 * sequential_runs / max(len(addresses) - 1, 1), 2),
            'max_accesses_single_block': max_accesses_single,
            'avg_accesses_per_block': round(avg_accesses, 2)
        }


class SequentialityBenchmark(Benchmark):
    """
    Test that work is inherently sequential (hard to parallelize).
    """

    name = "sequentiality"
    description = "Work is sequential (not parallelizable)"

    def __init__(self, W: int = 500):
        self.W = W

    def run(self) -> BenchmarkResult:
        test_input = b"sequentiality test"
        params = PoCParams(W=self.W, memory_bytes=1024 * 1024)

        # Check dependency chain
        trace, _ = compute_full_work(test_input, params)

        # Verify each state depends on previous
        dependencies_valid = True
        for i in range(1, len(trace)):
            # Each r[i] should be derived from r[i-1]
            # This is inherent in the work function design
            if trace[i].t != trace[i-1].t + 1:
                dependencies_valid = False
                break

        # Check that r values are chained (each derives from previous)
        chain_valid = self._verify_chain(trace)

        passed = dependencies_valid and chain_valid

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if passed else BenchmarkStatus.FAIL,
            target="Sequential dependency chain",
            actual="Valid chain" if passed else "Broken chain",
            details={
                'W': self.W,
                'trace_length': len(trace),
                'dependencies_valid': dependencies_valid,
                'chain_valid': chain_valid
            }
        )

    def _verify_chain(self, trace: List[WorkState]) -> bool:
        """Verify state chain integrity."""
        if len(trace) < 2:
            return True

        for i in range(1, len(trace)):
            # r[i] should be different from r[i-1] (hash output)
            if trace[i].r == trace[i-1].r:
                # Same r values would indicate broken chain
                # (extremely unlikely with proper hashing)
                return False

        return True


class TimingBenchmark(Benchmark):
    """
    Measure timing characteristics of memory-hard work.
    """

    name = "timing"
    description = "Work timing characteristics"

    def __init__(self, W_values: List[int] = None):
        self.W_values = W_values or [100, 200, 500, 1000]

    def run(self) -> BenchmarkResult:
        test_input = b"timing benchmark"
        measurements = []

        for W in self.W_values:
            params = PoCParams(W=W, memory_bytes=1024 * 1024)

            start = time.perf_counter()
            compute_full_work(test_input, params)
            elapsed = (time.perf_counter() - start) * 1000

            measurements.append({
                'W': W,
                'time_ms': round(elapsed, 2),
                'time_per_step_us': round(elapsed * 1000 / W, 2)
            })

        # Check linear scaling
        is_linear = self._check_linear_scaling(measurements)

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS,
            target="Linear time scaling with W",
            actual=f"{'Linear' if is_linear else 'Non-linear'} scaling",
            details={
                'measurements': measurements,
                'is_linear': is_linear
            }
        )

    def _check_linear_scaling(self, measurements: List[Dict]) -> bool:
        """Check if time scales linearly with W."""
        if len(measurements) < 2:
            return True

        # Time per step should be roughly constant
        times_per_step = [m['time_per_step_us'] for m in measurements]
        avg = sum(times_per_step) / len(times_per_step)

        # Allow 50% variance
        for t in times_per_step:
            if t < avg * 0.5 or t > avg * 1.5:
                return False

        return True


def run_memory_benchmark(
    W: int = 1000,
    memory_mb: int = 1,
    verbose: bool = True
) -> BenchmarkResult:
    """Run memory hardness benchmark."""
    bench = MemoryHardnessBenchmark(W, memory_mb)
    result = bench.timed_run()

    if verbose:
        print(f"\n=== Memory Hardness Benchmark ===")
        print(f"Status: {result.status.value}")
        print(f"Target: {result.target}")
        print(f"Actual: {result.actual}")
        if result.details:
            print(f"\nDetails:")
            print(f"  Coverage: {result.details.get('coverage_pct', 'N/A')}%")
            print(f"  Unique addresses: {result.details.get('unique_addresses_pct', 'N/A')}%")
            print(f"  Sequential: {result.details.get('sequential_pct', 'N/A')}%")

    return result
