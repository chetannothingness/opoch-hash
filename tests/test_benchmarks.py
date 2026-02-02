"""
Benchmark Tests for OpochHash

Section 6C: Performance

Mixer-only benchmarks measure only Mix. The decisive advantage is that
you don't lose performance to glue bugs and you gain parallel throughput
on long messages.

These benchmarks compare:
1. Pure mixer performance vs SHA-256/SHA-3
2. Full OpochHash (Ser_Π + Mix) overhead
3. Parallel speedup on large inputs
"""

import pytest
import time
import hashlib
from typing import Callable, Tuple
import os

from opochhash.mixer import TreeSpongeMixer, ParallelTreeSpongeMixer
from opochhash.opochhash import OpochHash, to_semantic
from opochhash.types import SBytes, SString, SInt, SList, SMap


# =============================================================================
# BENCHMARK UTILITIES
# =============================================================================

def benchmark(func: Callable, iterations: int = 1000) -> Tuple[float, float]:
    """
    Benchmark a function.
    Returns (total_time, time_per_iteration) in seconds.
    """
    start = time.perf_counter()
    for _ in range(iterations):
        func()
    end = time.perf_counter()

    total = end - start
    per_iter = total / iterations
    return total, per_iter


def format_rate(bytes_per_second: float) -> str:
    """Format throughput as human-readable string."""
    if bytes_per_second >= 1e9:
        return f"{bytes_per_second / 1e9:.2f} GB/s"
    elif bytes_per_second >= 1e6:
        return f"{bytes_per_second / 1e6:.2f} MB/s"
    elif bytes_per_second >= 1e3:
        return f"{bytes_per_second / 1e3:.2f} KB/s"
    else:
        return f"{bytes_per_second:.2f} B/s"


# =============================================================================
# MIXER BENCHMARKS
# =============================================================================

class TestMixerBenchmarks:
    """
    Benchmark the tree sponge mixer against standard hash functions.
    """

    @pytest.mark.parametrize("size", [64, 256, 1024, 4096, 16384, 65536])
    def test_mixer_throughput(self, size: int):
        """Measure mixer throughput at various input sizes."""
        mixer = TreeSpongeMixer()
        data = os.urandom(size)

        # Determine iterations based on size
        iterations = max(100, 100000 // size)

        _, per_iter = benchmark(lambda: mixer.mix(data), iterations)

        throughput = size / per_iter
        print(f"\nMixer throughput at {size} bytes: {format_rate(throughput)}")
        print(f"  Latency: {per_iter * 1e6:.2f} µs")

    @pytest.mark.parametrize("size", [64, 256, 1024, 4096, 16384, 65536])
    def test_sha256_comparison(self, size: int):
        """Compare against SHA-256 (baseline)."""
        mixer = TreeSpongeMixer()
        data = os.urandom(size)

        iterations = max(100, 100000 // size)

        # OpochHash mixer
        _, mixer_time = benchmark(lambda: mixer.mix(data), iterations)

        # SHA-256
        _, sha256_time = benchmark(lambda: hashlib.sha256(data).digest(), iterations)

        mixer_throughput = size / mixer_time
        sha256_throughput = size / sha256_time

        print(f"\n{size} bytes comparison:")
        print(f"  OpochHash Mixer: {format_rate(mixer_throughput)} ({mixer_time * 1e6:.2f} µs)")
        print(f"  SHA-256:         {format_rate(sha256_throughput)} ({sha256_time * 1e6:.2f} µs)")
        print(f"  Ratio:           {sha256_time / mixer_time:.2f}x")

    @pytest.mark.parametrize("size", [1024, 4096, 16384])
    def test_sha3_comparison(self, size: int):
        """Compare against SHA-3 (Keccak family baseline)."""
        mixer = TreeSpongeMixer()
        data = os.urandom(size)

        iterations = max(100, 50000 // size)

        # OpochHash mixer
        _, mixer_time = benchmark(lambda: mixer.mix(data), iterations)

        # SHA3-256
        _, sha3_time = benchmark(lambda: hashlib.sha3_256(data).digest(), iterations)

        mixer_throughput = size / mixer_time
        sha3_throughput = size / sha3_time

        print(f"\n{size} bytes SHA-3 comparison:")
        print(f"  OpochHash Mixer: {format_rate(mixer_throughput)} ({mixer_time * 1e6:.2f} µs)")
        print(f"  SHA3-256:        {format_rate(sha3_throughput)} ({sha3_time * 1e6:.2f} µs)")
        print(f"  Ratio:           {sha3_time / mixer_time:.2f}x")


# =============================================================================
# FULL OPOCHHASH BENCHMARKS
# =============================================================================

class TestOpochHashBenchmarks:
    """
    Benchmark the complete OpochHash (Ser_Π + Mix).
    """

    def test_primitive_hashing(self):
        """Benchmark hashing primitive types."""
        hasher = OpochHash()

        primitives = [
            SInt(42),
            SString("Hello, World!"),
            SBytes(b"binary data" * 10),
        ]

        for obj in primitives:
            _, per_iter = benchmark(lambda o=obj: hasher.hash(o), 10000)
            print(f"\n{type(obj).__name__}: {per_iter * 1e6:.2f} µs")

    def test_collection_hashing(self):
        """Benchmark hashing collections of various sizes."""
        hasher = OpochHash()

        for size in [10, 100, 1000]:
            list_obj = SList([SInt(i) for i in range(size)])

            iterations = max(100, 10000 // size)
            _, per_iter = benchmark(lambda o=list_obj: hasher.hash(o), iterations)

            print(f"\nList[{size}]: {per_iter * 1e6:.2f} µs ({size / per_iter:.0f} elements/s)")

    def test_nested_structure_hashing(self):
        """Benchmark hashing nested structures."""
        hasher = OpochHash()

        # Typical API response structure
        api_response = SMap({
            SString('status'): SString('success'),
            SString('data'): SList([
                SMap({
                    SString('id'): SInt(i),
                    SString('name'): SString(f'Item {i}'),
                    SString('values'): SList([SInt(j) for j in range(10)]),
                })
                for i in range(100)
            ])
        })

        _, per_iter = benchmark(lambda: hasher.hash(api_response), 100)
        print(f"\nComplex nested structure: {per_iter * 1e3:.2f} ms")

    def test_serialization_vs_mixing_breakdown(self):
        """Break down time spent in serialization vs mixing."""
        from opochhash.serializer import SerPi

        hasher = OpochHash()

        # Medium complexity object
        obj = SList([SInt(i) for i in range(1000)])

        # Measure serialization
        _, ser_time = benchmark(lambda: SerPi.serialize(obj), 1000)

        # Measure mixing (with pre-serialized tape)
        tape = SerPi.serialize(obj).to_bytes()
        _, mix_time = benchmark(lambda: hasher.mixer.mix(tape), 1000)

        # Measure total
        _, total_time = benchmark(lambda: hasher.hash(obj), 1000)

        print(f"\nBreakdown for List[1000]:")
        print(f"  Serialization: {ser_time * 1e6:.2f} µs ({ser_time / total_time * 100:.1f}%)")
        print(f"  Mixing:        {mix_time * 1e6:.2f} µs ({mix_time / total_time * 100:.1f}%)")
        print(f"  Total:         {total_time * 1e6:.2f} µs")


# =============================================================================
# PARALLEL BENCHMARKS
# =============================================================================

class TestParallelBenchmarks:
    """
    Benchmark parallel tree hashing.
    """

    @pytest.mark.parametrize("size_mb", [1, 10])
    def test_parallel_speedup(self, size_mb: int):
        """Measure parallel speedup on large inputs."""
        size = size_mb * 1024 * 1024
        data = os.urandom(size)

        # Serial mixer
        serial_mixer = TreeSpongeMixer()
        iterations = max(1, 10 // size_mb)
        _, serial_time = benchmark(lambda: serial_mixer.mix(data), iterations)

        # Parallel mixer
        parallel_mixer = ParallelTreeSpongeMixer(max_workers=4)
        _, parallel_time = benchmark(lambda: parallel_mixer.mix(data), iterations)

        serial_throughput = size / serial_time
        parallel_throughput = size / parallel_time

        print(f"\n{size_mb} MB parallel benchmark:")
        print(f"  Serial:   {format_rate(serial_throughput)} ({serial_time:.3f} s)")
        print(f"  Parallel: {format_rate(parallel_throughput)} ({parallel_time:.3f} s)")
        print(f"  Speedup:  {serial_time / parallel_time:.2f}x")


# =============================================================================
# XOF AND KEYED MODE BENCHMARKS
# =============================================================================

class TestModeBenchmarks:
    """
    Benchmark different operation modes.
    """

    def test_xof_throughput(self):
        """Benchmark XOF (extendable output) mode."""
        mixer = TreeSpongeMixer()
        data = os.urandom(1024)

        for output_len in [32, 64, 128, 256, 1024]:
            _, per_iter = benchmark(
                lambda ol=output_len: mixer.mix_xof(data, ol),
                1000
            )
            print(f"\nXOF {output_len} bytes: {per_iter * 1e6:.2f} µs")

    def test_mac_throughput(self):
        """Benchmark keyed (MAC) mode."""
        mixer = TreeSpongeMixer()
        key = os.urandom(32)

        for data_len in [64, 256, 1024, 4096]:
            data = os.urandom(data_len)
            _, per_iter = benchmark(
                lambda d=data: mixer.mix_keyed(d, key),
                1000
            )
            throughput = data_len / per_iter
            print(f"\nMAC {data_len} bytes: {per_iter * 1e6:.2f} µs ({format_rate(throughput)})")


# =============================================================================
# REAL-WORLD SCENARIO BENCHMARKS
# =============================================================================

class TestRealWorldBenchmarks:
    """
    Benchmark real-world usage scenarios.
    """

    def test_json_like_document_hashing(self):
        """Benchmark hashing JSON-like documents."""
        hasher = OpochHash()

        # Simulate a typical JSON API response
        doc = {
            'id': 12345,
            'timestamp': 1699999999,
            'user': {
                'name': 'Alice Smith',
                'email': 'alice@example.com',
                'roles': ['admin', 'user'],
            },
            'data': [
                {'key': f'item_{i}', 'value': i * 1.5}
                for i in range(50)
            ]
        }

        semantic_doc = to_semantic(doc)

        _, per_iter = benchmark(lambda: hasher.hash(semantic_doc), 1000)
        print(f"\nJSON-like document hashing: {per_iter * 1e6:.2f} µs")

    def test_content_addressable_storage(self):
        """
        Benchmark for content-addressable storage use case.
        Many small objects (typical file chunks).
        """
        hasher = OpochHash()

        # Typical 4KB chunks
        chunks = [SBytes(os.urandom(4096)) for _ in range(100)]

        start = time.perf_counter()
        for chunk in chunks:
            hasher.hash(chunk)
        end = time.perf_counter()

        per_chunk = (end - start) / len(chunks)
        throughput = 4096 / per_chunk

        print(f"\nContent-addressable storage (4KB chunks):")
        print(f"  Per chunk: {per_chunk * 1e6:.2f} µs")
        print(f"  Throughput: {format_rate(throughput)}")

    def test_merkle_tree_building(self):
        """
        Benchmark for Merkle tree use case.
        Hash many leaf nodes, then internal nodes.
        """
        hasher = OpochHash()

        # 1000 leaf hashes
        leaves = [SBytes(os.urandom(32)) for _ in range(1000)]

        start = time.perf_counter()
        leaf_hashes = [hasher.hash(leaf) for leaf in leaves]

        # Build tree (simplified: just hash pairs)
        level = leaf_hashes
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    combined = SBytes(level[i] + level[i + 1])
                    next_level.append(hasher.hash(combined))
                else:
                    next_level.append(level[i])
            level = next_level

        end = time.perf_counter()

        print(f"\nMerkle tree (1000 leaves): {(end - start) * 1e3:.2f} ms")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
