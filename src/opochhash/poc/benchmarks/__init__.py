"""
PoC_Hash Benchmarks

8 benchmarks to validate all requirements:
1. Asymmetry: Prover/Verifier cost ratio
2. Soundness: Forgery probability bounds
3. ProofSize: Proof size scaling
4. Overhead: Prover overhead vs plain work
5. Recursion: Recursive proof aggregation
6. Memory: Memory-hardness validation
7. Switching: Zero switching cost
8. Compatibility: Backward compatibility
"""

from .runner_asymmetry import AsymmetryBenchmark
from .runner_soundness import SoundnessBenchmark
from .runner_proof_size import ProofSizeBenchmark
from .runner_overhead import OverheadBenchmark
from .runner_recursion import RecursionBenchmark
from .runner_memory import MemoryHardnessBenchmark as MemoryBenchmark
from .runner_switching import SwitchingCostBenchmark as SwitchingBenchmark
from .runner_compatibility import APICompatibilityBenchmark as CompatibilityBenchmark
from .poc_bench import run_all_benchmarks, BenchmarkReport

__all__ = [
    'AsymmetryBenchmark',
    'SoundnessBenchmark',
    'ProofSizeBenchmark',
    'OverheadBenchmark',
    'RecursionBenchmark',
    'MemoryBenchmark',
    'SwitchingBenchmark',
    'CompatibilityBenchmark',
    'run_all_benchmarks',
    'BenchmarkReport',
]
