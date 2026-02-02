"""
Runner 3: End-to-End Object Hash Benchmark

Goal: Measure the real pipeline:
    object → Ser_Π → TreeSpongeMixer → digest + receipts

Metrics:
- End-to-end latency per object (median/p95)
- Throughput (objects/sec)
- CPU time split (serialization vs mixing vs receipt)
- Receipt size overhead
"""

from __future__ import annotations
import json
import time
import hashlib
import os
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import statistics

sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from opochhash import (
    SerPi, OpochHashFast,
    SNull, SBool, SInt, SFloat, SBytes, SString,
    SList, SSet, SMap, SStruct, SOptional,
    SchemaId, SemanticObject
)


@dataclass
class ObjectBenchResult:
    """Result for a category of objects."""
    category: str
    object_count: int
    avg_tape_size: float
    median_latency_us: float
    p95_latency_us: float
    throughput_ops: float  # objects per second
    serialization_pct: float
    mixing_pct: float
    receipt_pct: float


@dataclass
class ModeBenchResult:
    """Result for different hash modes."""
    mode: str  # HASH, XOF, KEYED
    median_latency_us: float
    throughput_ops: float


@dataclass
class End2EndReport:
    """Full end-to-end benchmark report."""
    timestamp: str
    object_results: List[ObjectBenchResult]
    mode_results: List[ModeBenchResult]
    receipt_stats: Dict[str, Any]
    duration_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'object_results': [asdict(r) for r in self.object_results],
            'mode_results': [asdict(r) for r in self.mode_results],
            'receipt_stats': self.receipt_stats,
            'duration_ms': self.duration_ms,
        }


class End2EndBenchRunner:
    """
    End-to-end benchmark runner.

    Measures the complete OpochHash pipeline including:
    - Semantic object construction
    - Ser_Π serialization
    - Tree sponge mixing
    - Receipt generation
    """

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.hasher = OpochHashFast()

    def run(self) -> End2EndReport:
        """Run all end-to-end benchmarks."""
        start_time = time.perf_counter()

        object_results = []
        mode_results = []

        # Generate test corpora
        small_objects = self._generate_small_objects(1000)
        medium_objects = self._generate_medium_objects(500)
        large_objects = self._generate_large_objects(100)

        # Benchmark each category
        object_results.append(self._benchmark_category("small", small_objects))
        object_results.append(self._benchmark_category("medium", medium_objects))
        object_results.append(self._benchmark_category("large", large_objects))

        # Benchmark different modes
        test_obj = medium_objects[0]
        mode_results.append(self._benchmark_mode("HASH", test_obj))
        mode_results.append(self._benchmark_mode("XOF", test_obj))
        mode_results.append(self._benchmark_mode("KEYED", test_obj))

        # Receipt statistics
        receipt_stats = self._measure_receipt_overhead(medium_objects[:100])

        elapsed = (time.perf_counter() - start_time) * 1000

        report = End2EndReport(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            object_results=object_results,
            mode_results=mode_results,
            receipt_stats=receipt_stats,
            duration_ms=elapsed,
        )

        # Write report
        report_path = self.output_dir / 'end2end_bench.json'
        with open(report_path, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)

        return report

    def _generate_small_objects(self, count: int) -> List[SemanticObject]:
        """Generate small objects (< 100 bytes tape)."""
        return [
            SStruct(
                SchemaId('bench', 'SmallEvent', 1),
                {
                    'id': SInt(i),
                    'type': SString('event'),
                    'value': SFloat(i * 0.1),
                }
            )
            for i in range(count)
        ]

    def _generate_medium_objects(self, count: int) -> List[SemanticObject]:
        """Generate medium objects (100-1000 bytes tape)."""
        return [
            SStruct(
                SchemaId('bench', 'MediumEvent', 1),
                {
                    'id': SInt(i),
                    'type': SString('transaction'),
                    'data': SMap({
                        SString(f'field{j}'): SInt(j * i)
                        for j in range(10)
                    }),
                    'tags': SList([SString(f'tag{j}') for j in range(5)]),
                    'metadata': SOptional(SString(f'meta_{i}')),
                }
            )
            for i in range(count)
        ]

    def _generate_large_objects(self, count: int) -> List[SemanticObject]:
        """Generate large objects (> 1000 bytes tape)."""
        return [
            SStruct(
                SchemaId('bench', 'LargeEvent', 1),
                {
                    'id': SInt(i),
                    'type': SString('batch'),
                    'records': SList([
                        SMap({
                            SString('key'): SString(f'record_{i}_{j}'),
                            SString('value'): SInt(j),
                            SString('data'): SBytes(os.urandom(50)),
                        })
                        for j in range(20)
                    ]),
                    'summary': SMap({
                        SString(f'stat{k}'): SFloat(k * 1.5)
                        for k in range(10)
                    }),
                }
            )
            for i in range(count)
        ]

    def _benchmark_category(
        self,
        category: str,
        objects: List[SemanticObject]
    ) -> ObjectBenchResult:
        """Benchmark a category of objects."""
        # Measure tape sizes
        tape_sizes = []
        for obj in objects[:100]:  # Sample
            tape = SerPi.serialize(obj)
            tape_sizes.append(len(tape.to_bytes()))

        avg_tape_size = statistics.mean(tape_sizes)

        # Warmup
        for obj in objects[:10]:
            self.hasher.hash(obj)

        # Measure latencies with breakdown
        latencies = []
        ser_times = []
        mix_times = []

        for obj in objects:
            # Serialization
            start_ser = time.perf_counter()
            tape = SerPi.serialize(obj)
            tape_bytes = tape.to_bytes()
            end_ser = time.perf_counter()

            # Mixing
            start_mix = time.perf_counter()
            digest = self.hasher.mixer.mix(tape_bytes)
            end_mix = time.perf_counter()

            ser_time = (end_ser - start_ser) * 1e6
            mix_time = (end_mix - start_mix) * 1e6
            total_time = ser_time + mix_time

            latencies.append(total_time)
            ser_times.append(ser_time)
            mix_times.append(mix_time)

        median_latency = statistics.median(latencies)
        p95_latency = sorted(latencies)[int(0.95 * len(latencies))]
        throughput = len(objects) / (sum(latencies) / 1e6)

        avg_ser = statistics.mean(ser_times)
        avg_mix = statistics.mean(mix_times)
        total_avg = avg_ser + avg_mix

        return ObjectBenchResult(
            category=category,
            object_count=len(objects),
            avg_tape_size=avg_tape_size,
            median_latency_us=median_latency,
            p95_latency_us=p95_latency,
            throughput_ops=throughput,
            serialization_pct=(avg_ser / total_avg) * 100 if total_avg > 0 else 0,
            mixing_pct=(avg_mix / total_avg) * 100 if total_avg > 0 else 0,
            receipt_pct=0,  # Calculated separately
        )

    def _benchmark_mode(
        self,
        mode: str,
        obj: SemanticObject
    ) -> ModeBenchResult:
        """Benchmark a specific hash mode."""
        iterations = 1000
        key = b'benchmark_key_32bytes_exactly!!'  # 32 bytes

        # Warmup
        for _ in range(100):
            if mode == "HASH":
                self.hasher.hash(obj)
            elif mode == "XOF":
                self.hasher.xof(obj, 64)
            elif mode == "KEYED":
                self.hasher.mac(obj, key)

        # Benchmark
        latencies = []
        for _ in range(iterations):
            start = time.perf_counter()
            if mode == "HASH":
                self.hasher.hash(obj)
            elif mode == "XOF":
                self.hasher.xof(obj, 64)
            elif mode == "KEYED":
                self.hasher.mac(obj, key)
            end = time.perf_counter()
            latencies.append((end - start) * 1e6)

        median_latency = statistics.median(latencies)
        throughput = iterations / (sum(latencies) / 1e6)

        return ModeBenchResult(
            mode=mode,
            median_latency_us=median_latency,
            throughput_ops=throughput,
        )

    def _measure_receipt_overhead(
        self,
        objects: List[SemanticObject]
    ) -> Dict[str, Any]:
        """Measure receipt generation overhead."""
        receipts = []
        receipt_times = []

        for obj in objects:
            # Hash and create receipt
            start = time.perf_counter()
            digest = self.hasher.hash(obj)
            tape = SerPi.serialize(obj)

            receipt = {
                'digest': digest.hex(),
                'tape_hash': hashlib.sha256(tape.to_bytes()).hexdigest(),
                'tape_len': len(tape.to_bytes()),
                'timestamp': time.time(),
            }
            receipt_json = json.dumps(receipt, sort_keys=True)
            end = time.perf_counter()

            receipts.append(receipt_json)
            receipt_times.append((end - start) * 1e6)

        avg_receipt_size = statistics.mean(len(r) for r in receipts)
        avg_receipt_time = statistics.mean(receipt_times)

        return {
            'avg_receipt_size_bytes': avg_receipt_size,
            'avg_receipt_time_us': avg_receipt_time,
            'sample_receipt': json.loads(receipts[0]),
        }


def run_quick_end2end():
    """Quick end-to-end test."""
    print("=== Quick End-to-End Benchmark ===\n")

    hasher = OpochHashFast()

    # Test objects
    small = SStruct(
        SchemaId('test', 'Small', 1),
        {'id': SInt(1), 'name': SString('test')}
    )

    medium = SMap({
        SString(f'key{i}'): SInt(i)
        for i in range(50)
    })

    large = SList([
        SMap({SString('data'): SBytes(os.urandom(100))})
        for _ in range(100)
    ])

    for name, obj in [('small', small), ('medium', medium), ('large', large)]:
        tape = SerPi.serialize(obj)
        tape_size = len(tape.to_bytes())

        # Benchmark
        iterations = 1000
        start = time.perf_counter()
        for _ in range(iterations):
            hasher.hash(obj)
        elapsed = time.perf_counter() - start

        latency_us = (elapsed / iterations) * 1e6
        throughput = iterations / elapsed

        print(f"{name:10s}: tape={tape_size:5d}B, latency={latency_us:8.2f}µs, {throughput:8.0f} ops/s")


if __name__ == '__main__':
    run_quick_end2end()
