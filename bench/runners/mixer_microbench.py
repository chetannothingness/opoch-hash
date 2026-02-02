"""
Runner 2: Mixer Microbenchmarks

Goal: Compare Mix cores on standard input sizes and report cpb/throughput/scaling.

Compares:
- OpochHash TreeSponge (native SHAKE256)
- SHA-256
- SHA-512/256
- SHA3-256
- SHAKE256 (direct)
- BLAKE2b
- BLAKE3 (if available)

Metrics:
- Cycles per byte (cpb) - approximated via timing
- Throughput (MB/s)
- Latency (µs) for small messages
- Parallel scaling efficiency
"""

from __future__ import annotations
import json
import time
import hashlib
import os
import platform
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Callable
from concurrent.futures import ThreadPoolExecutor
import statistics

sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from opochhash.mixer_fast import FastTreeSpongeMixer, get_best_mixer


# Standard message sizes (bytes)
STANDARD_SIZES = [0, 1, 7, 8, 16, 31, 32, 64, 128, 576, 1024, 1536, 4096]
LARGE_SIZES = [1024 * 1024, 64 * 1024 * 1024]  # 1MB, 64MB

# Thread counts for scaling tests
THREAD_COUNTS = [1, 2, 4, 8]


@dataclass
class MixerResult:
    """Result for a single mixer at a single size."""
    mixer_name: str
    message_size: int
    iterations: int
    total_time_ms: float
    median_latency_us: float
    p95_latency_us: float
    throughput_mbs: float
    approx_cpb: float  # Approximate cycles per byte


@dataclass
class ScalingResult:
    """Result for parallel scaling test."""
    mixer_name: str
    message_size: int
    threads: int
    throughput_mbs: float
    scaling_efficiency: float  # throughput(n) / (n * throughput(1))


@dataclass
class MixerBenchReport:
    """Full mixer benchmark report."""
    timestamp: str
    environment: Dict[str, Any]
    single_thread_results: List[MixerResult]
    scaling_results: List[ScalingResult]
    summary: Dict[str, Any]
    duration_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'environment': self.environment,
            'single_thread_results': [asdict(r) for r in self.single_thread_results],
            'scaling_results': [asdict(r) for r in self.scaling_results],
            'summary': self.summary,
            'duration_ms': self.duration_ms,
        }


class MixerMicrobenchRunner:
    """
    Mixer microbenchmark runner.

    Measures raw mixer performance against industry standards.
    """

    # Approximate CPU frequency for cpb estimation (will be measured)
    CPU_FREQ_GHZ = 3.0  # Default, will try to detect

    def __init__(self, output_dir: Path, include_large: bool = False):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.include_large = include_large
        self.results: List[MixerResult] = []
        self.scaling_results: List[ScalingResult] = []

        # Try to detect CPU frequency
        self._detect_cpu_freq()

    def _detect_cpu_freq(self):
        """Attempt to detect CPU frequency."""
        try:
            if platform.system() == 'Darwin':
                import subprocess
                result = subprocess.run(
                    ['sysctl', '-n', 'hw.cpufrequency'],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    freq_hz = int(result.stdout.strip())
                    self.CPU_FREQ_GHZ = freq_hz / 1e9
        except Exception:
            pass

    def _get_environment(self) -> Dict[str, Any]:
        """Collect environment information."""
        return {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'cpu': platform.processor(),
            'cpu_count': os.cpu_count(),
            'estimated_cpu_freq_ghz': self.CPU_FREQ_GHZ,
        }

    def _get_mixers(self) -> Dict[str, Callable[[bytes], bytes]]:
        """Get all mixer implementations to benchmark."""
        mixers = {}

        # OpochHash fast mixer
        opoch_mixer = get_best_mixer()
        mixers['opoch_treesponge'] = opoch_mixer.mix

        # SHA-256
        mixers['sha256'] = lambda d: hashlib.sha256(d).digest()

        # SHA-512/256
        if hasattr(hashlib, 'sha512'):
            mixers['sha512_256'] = lambda d: hashlib.sha512(d).digest()[:32]

        # SHA3-256
        if hasattr(hashlib, 'sha3_256'):
            mixers['sha3_256'] = lambda d: hashlib.sha3_256(d).digest()

        # SHAKE256 (XOF, 32 bytes output)
        if hasattr(hashlib, 'shake_256'):
            mixers['shake256'] = lambda d: hashlib.shake_256(d).digest(32)

        # BLAKE2b
        if hasattr(hashlib, 'blake2b'):
            mixers['blake2b'] = lambda d: hashlib.blake2b(d, digest_size=32).digest()

        # BLAKE3 (if available)
        try:
            import blake3
            mixers['blake3'] = lambda d: blake3.blake3(d).digest()
        except ImportError:
            pass

        return mixers

    def run(self) -> MixerBenchReport:
        """Run all benchmarks."""
        start_time = time.perf_counter()

        mixers = self._get_mixers()
        sizes = STANDARD_SIZES + (LARGE_SIZES if self.include_large else [])

        # Single-thread benchmarks
        for size in sizes:
            data = os.urandom(size) if size > 0 else b''

            for name, mixer_fn in mixers.items():
                result = self._benchmark_mixer(name, mixer_fn, data, size)
                self.results.append(result)

        # Parallel scaling benchmarks (only for OpochHash and large sizes)
        if self.include_large:
            self._run_scaling_benchmarks()

        elapsed = (time.perf_counter() - start_time) * 1000

        # Generate summary
        summary = self._generate_summary()

        report = MixerBenchReport(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            environment=self._get_environment(),
            single_thread_results=self.results,
            scaling_results=self.scaling_results,
            summary=summary,
            duration_ms=elapsed,
        )

        # Write report
        report_path = self.output_dir / 'mixer_microbench.json'
        with open(report_path, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)

        return report

    def _benchmark_mixer(
        self,
        name: str,
        mixer_fn: Callable[[bytes], bytes],
        data: bytes,
        size: int
    ) -> MixerResult:
        """Benchmark a single mixer at a single size."""
        # Determine iteration count based on size
        if size == 0:
            iterations = 100000
        elif size < 64:
            iterations = 50000
        elif size < 1024:
            iterations = 10000
        elif size < 65536:
            iterations = 1000
        elif size < 1024 * 1024:
            iterations = 100
        else:
            iterations = 10

        # Warmup
        for _ in range(min(100, iterations // 10)):
            mixer_fn(data)

        # Collect latencies
        latencies = []
        start_total = time.perf_counter()

        for _ in range(iterations):
            start = time.perf_counter()
            mixer_fn(data)
            end = time.perf_counter()
            latencies.append((end - start) * 1e6)  # Convert to µs

        end_total = time.perf_counter()
        total_time_ms = (end_total - start_total) * 1000

        # Calculate metrics
        median_latency = statistics.median(latencies)
        p95_latency = sorted(latencies)[int(0.95 * len(latencies))]

        # Throughput
        total_bytes = size * iterations
        total_seconds = total_time_ms / 1000
        throughput_mbs = (total_bytes / total_seconds) / (1024 * 1024) if total_seconds > 0 else 0

        # Approximate cycles per byte
        if size > 0:
            cycles_per_call = median_latency * 1e-6 * self.CPU_FREQ_GHZ * 1e9
            approx_cpb = cycles_per_call / size
        else:
            approx_cpb = 0

        return MixerResult(
            mixer_name=name,
            message_size=size,
            iterations=iterations,
            total_time_ms=total_time_ms,
            median_latency_us=median_latency,
            p95_latency_us=p95_latency,
            throughput_mbs=throughput_mbs,
            approx_cpb=approx_cpb,
        )

    def _run_scaling_benchmarks(self):
        """Run parallel scaling benchmarks."""
        from opochhash.mixer_fast import ParallelFastTreeSpongeMixer

        size = 1024 * 1024  # 1MB
        data = os.urandom(size)

        baseline_throughput = None

        for threads in THREAD_COUNTS:
            if threads > os.cpu_count():
                continue

            mixer = ParallelFastTreeSpongeMixer(max_workers=threads)

            # Benchmark
            iterations = 10
            start = time.perf_counter()
            for _ in range(iterations):
                mixer.mix(data)
            elapsed = time.perf_counter() - start

            throughput = (size * iterations) / elapsed / (1024 * 1024)

            if threads == 1:
                baseline_throughput = throughput
                efficiency = 1.0
            else:
                efficiency = throughput / (threads * baseline_throughput) if baseline_throughput else 0

            self.scaling_results.append(ScalingResult(
                mixer_name='opoch_treesponge_parallel',
                message_size=size,
                threads=threads,
                throughput_mbs=throughput,
                scaling_efficiency=efficiency,
            ))

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics."""
        summary = {
            'mixers_tested': list(set(r.mixer_name for r in self.results)),
            'sizes_tested': list(set(r.message_size for r in self.results)),
        }

        # Best throughput per mixer (at 4KB)
        size_4k_results = [r for r in self.results if r.message_size == 4096]
        if size_4k_results:
            summary['throughput_4kb'] = {
                r.mixer_name: f"{r.throughput_mbs:.2f} MB/s"
                for r in sorted(size_4k_results, key=lambda x: -x.throughput_mbs)
            }

        # Latency comparison at 64 bytes
        size_64_results = [r for r in self.results if r.message_size == 64]
        if size_64_results:
            summary['latency_64b'] = {
                r.mixer_name: f"{r.median_latency_us:.2f} µs"
                for r in sorted(size_64_results, key=lambda x: x.median_latency_us)
            }

        return summary


def run_quick_benchmark():
    """Quick benchmark for immediate results."""
    print("=== Quick Mixer Benchmark ===\n")

    mixers = {
        'opoch_treesponge': get_best_mixer().mix,
        'sha256': lambda d: hashlib.sha256(d).digest(),
        'sha3_256': lambda d: hashlib.sha3_256(d).digest(),
        'shake256': lambda d: hashlib.shake_256(d).digest(32),
    }

    if hasattr(hashlib, 'blake2b'):
        mixers['blake2b'] = lambda d: hashlib.blake2b(d, digest_size=32).digest()

    sizes = [64, 1024, 4096]

    for size in sizes:
        print(f"--- {size} bytes ---")
        data = os.urandom(size)
        iterations = 10000 if size < 1024 else 1000

        for name, fn in mixers.items():
            # Warmup
            for _ in range(100):
                fn(data)

            start = time.perf_counter()
            for _ in range(iterations):
                fn(data)
            elapsed = time.perf_counter() - start

            latency_us = (elapsed / iterations) * 1e6
            throughput = (size * iterations) / elapsed / (1024 * 1024)

            print(f"  {name:20s}: {latency_us:8.2f} µs, {throughput:8.2f} MB/s")
        print()


if __name__ == '__main__':
    run_quick_benchmark()
