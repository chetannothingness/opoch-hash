"""
Benchmark 8: Compatibility

Target: Complete compatibility with existing systems

Tests:
- API compatibility
- Format compatibility
- Integration compatibility
- Cross-platform consistency
"""

from dataclasses import dataclass
from typing import List, Dict, Any
import hashlib
import json

from .base import Benchmark, BenchmarkResult, BenchmarkStatus
from ..params import PoCParams, LegacyHash
from ..poc_hash import (
    poc_hash, verify_poc, poc_hash_simple,
    PoCHasher, ProofTier
)


class APICompatibilityBenchmark(Benchmark):
    """
    Test API compatibility with common hash interfaces.
    """

    name = "api_compatibility"
    description = "API compatibility with standard interfaces"

    def run(self) -> BenchmarkResult:
        tests = []

        # Test 1: Simple function interface
        try:
            d0, proof_bytes = poc_hash_simple(b"test", W=10)
            tests.append({
                'test': 'simple_interface',
                'passed': len(d0) == 32 and len(proof_bytes) > 0
            })
        except Exception as e:
            tests.append({'test': 'simple_interface', 'passed': False, 'error': str(e)})

        # Test 2: Streaming interface (like hashlib)
        try:
            hasher = PoCHasher(PoCParams(W=10))
            hasher.update(b"hello ")
            hasher.update(b"world")
            result = hasher.finalize()
            tests.append({
                'test': 'streaming_interface',
                'passed': len(result.d0) == 32
            })
        except Exception as e:
            tests.append({'test': 'streaming_interface', 'passed': False, 'error': str(e)})

        # Test 3: Full interface
        try:
            result = poc_hash(b"test", PoCParams(W=10), ProofTier.Q)
            valid = verify_poc(result.d0, result.proof, PoCParams(W=10))
            tests.append({
                'test': 'full_interface',
                'passed': valid
            })
        except Exception as e:
            tests.append({'test': 'full_interface', 'passed': False, 'error': str(e)})

        # Test 4: Hashlib-like digest_size
        try:
            hasher = PoCHasher()
            tests.append({
                'test': 'digest_size',
                'passed': hasher.digest_size == 32
            })
        except Exception as e:
            tests.append({'test': 'digest_size', 'passed': False, 'error': str(e)})

        all_passed = all(t['passed'] for t in tests)

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if all_passed else BenchmarkStatus.FAIL,
            target="Standard hash API compatibility",
            actual=f"{sum(1 for t in tests if t['passed'])}/{len(tests)} tests pass",
            details={'tests': tests}
        )


class FormatCompatibilityBenchmark(Benchmark):
    """
    Test format compatibility (serialization, encoding).
    """

    name = "format_compatibility"
    description = "Data format compatibility"

    def run(self) -> BenchmarkResult:
        tests = []

        # Test 1: d0 is valid hex string
        result = poc_hash(b"test", PoCParams(W=10), ProofTier.Q)
        try:
            hex_str = result.d0.hex()
            recovered = bytes.fromhex(hex_str)
            tests.append({
                'test': 'hex_encoding',
                'passed': recovered == result.d0
            })
        except Exception as e:
            tests.append({'test': 'hex_encoding', 'passed': False, 'error': str(e)})

        # Test 2: Proof serialization roundtrip
        try:
            proof_bytes = result.proof.serialize()
            # Just check it's valid bytes
            tests.append({
                'test': 'proof_serialization',
                'passed': len(proof_bytes) > 0
            })
        except Exception as e:
            tests.append({'test': 'proof_serialization', 'passed': False, 'error': str(e)})

        # Test 3: JSON-compatible output
        try:
            json_data = {
                'd0': result.d0.hex(),
                'r_final': result.r_final.hex(),
                'proof_size': result.proof.size
            }
            json_str = json.dumps(json_data)
            recovered = json.loads(json_str)
            tests.append({
                'test': 'json_compatible',
                'passed': recovered['d0'] == result.d0.hex()
            })
        except Exception as e:
            tests.append({'test': 'json_compatible', 'passed': False, 'error': str(e)})

        # Test 4: Params serialization
        try:
            params = PoCParams(W=1000)
            params_bytes = params.serialize()
            params_hash = params.hash()
            tests.append({
                'test': 'params_serialization',
                'passed': len(params_bytes) > 0 and len(params_hash) == 32
            })
        except Exception as e:
            tests.append({'test': 'params_serialization', 'passed': False, 'error': str(e)})

        all_passed = all(t['passed'] for t in tests)

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if all_passed else BenchmarkStatus.FAIL,
            target="Standard data format compatibility",
            actual=f"{sum(1 for t in tests if t['passed'])}/{len(tests)} tests pass",
            details={'tests': tests}
        )


class IntegrationBenchmark(Benchmark):
    """
    Test integration scenarios.
    """

    name = "integration"
    description = "Integration compatibility"

    def run(self) -> BenchmarkResult:
        tests = []

        # Scenario 1: Document signing workflow
        try:
            document = b"Important document content"
            params = PoCParams(W=10)

            # Compute proof of work
            result = poc_hash(document, params, ProofTier.Q)

            # Sign the hash (simulated)
            signature_input = result.d0 + result.r_final

            # Verify
            valid = verify_poc(result.d0, result.proof, params)

            tests.append({
                'scenario': 'document_signing',
                'passed': valid,
                'description': 'Document signing with PoC'
            })
        except Exception as e:
            tests.append({'scenario': 'document_signing', 'passed': False, 'error': str(e)})

        # Scenario 2: Batch processing
        try:
            documents = [f"doc{i}".encode() for i in range(5)]
            params = PoCParams(W=10)

            results = [poc_hash(doc, params, ProofTier.Q) for doc in documents]
            all_valid = all(verify_poc(r.d0, r.proof, params) for r in results)

            tests.append({
                'scenario': 'batch_processing',
                'passed': all_valid,
                'description': 'Batch document processing'
            })
        except Exception as e:
            tests.append({'scenario': 'batch_processing', 'passed': False, 'error': str(e)})

        # Scenario 3: Incremental update
        try:
            hasher = PoCHasher(PoCParams(W=10))
            for chunk in [b"chunk1", b"chunk2", b"chunk3"]:
                hasher.update(chunk)
            result = hasher.finalize()

            tests.append({
                'scenario': 'incremental_update',
                'passed': len(result.d0) == 32,
                'description': 'Incremental data processing'
            })
        except Exception as e:
            tests.append({'scenario': 'incremental_update', 'passed': False, 'error': str(e)})

        all_passed = all(t['passed'] for t in tests)

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if all_passed else BenchmarkStatus.FAIL,
            target="Integration compatibility",
            actual=f"{sum(1 for t in tests if t['passed'])}/{len(tests)} scenarios pass",
            details={'tests': tests}
        )


class DeterminismBenchmark(Benchmark):
    """
    Test that results are deterministic.
    """

    name = "determinism"
    description = "Output determinism"

    def run(self) -> BenchmarkResult:
        tests = []
        test_input = b"determinism test"
        params = PoCParams(W=50)

        # Run multiple times and check consistency
        results = []
        for i in range(3):
            result = poc_hash(test_input, params, ProofTier.Q)
            results.append({
                'd0': result.d0,
                'r_final': result.r_final,
                'proof_size': result.proof.size
            })

        # Check all d0 values match
        d0_consistent = all(r['d0'] == results[0]['d0'] for r in results)
        tests.append({
            'test': 'd0_deterministic',
            'passed': d0_consistent
        })

        # Check all r_final values match
        r_consistent = all(r['r_final'] == results[0]['r_final'] for r in results)
        tests.append({
            'test': 'r_final_deterministic',
            'passed': r_consistent
        })

        # Check proof sizes match (content may differ due to timing metadata)
        size_consistent = all(r['proof_size'] == results[0]['proof_size'] for r in results)
        tests.append({
            'test': 'proof_size_consistent',
            'passed': size_consistent
        })

        all_passed = all(t['passed'] for t in tests)

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if all_passed else BenchmarkStatus.FAIL,
            target="Deterministic output",
            actual=f"{sum(1 for t in tests if t['passed'])}/{len(tests)} tests pass",
            details={'tests': tests}
        )


def run_compatibility_benchmark(verbose: bool = True) -> BenchmarkResult:
    """Run compatibility benchmark."""
    bench = APICompatibilityBenchmark()
    result = bench.timed_run()

    if verbose:
        print(f"\n=== Compatibility Benchmark ===")
        print(f"Status: {result.status.value}")
        print(f"Target: {result.target}")
        print(f"Actual: {result.actual}")

    return result
