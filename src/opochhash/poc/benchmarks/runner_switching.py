"""
Benchmark 7: Zero Switching Cost

Target: Legacy digest d₀ is identical to what legacy systems produce

Tests:
- d₀ matches legacy hash output exactly
- No changes required to existing verification code
- Proof is completely optional for backward compatibility
"""

from dataclasses import dataclass
from typing import List, Dict, Any
import hashlib

from .base import Benchmark, BenchmarkResult, BenchmarkStatus
from ..params import PoCParams, LegacyHash
from ..poc_hash import poc_hash, ProofTier
from ..work import legacy_digest


class SwitchingCostBenchmark(Benchmark):
    """
    Benchmark 7: Zero Switching Cost

    Verifies that d₀ is byte-identical to legacy hash output.
    """

    name = "switching_cost"
    description = "Zero switching cost verification"

    def __init__(self, test_vectors: List[bytes] = None):
        self.test_vectors = test_vectors or [
            b"",
            b"hello",
            b"hello world",
            b"The quick brown fox jumps over the lazy dog",
            bytes(range(256)),
            b"x" * 10000,
        ]

    def run(self) -> BenchmarkResult:
        # Test each legacy hash type
        results = []

        for legacy_hash in [LegacyHash.SHA256, LegacyHash.SHAKE256]:
            params = PoCParams(W=10, legacy_hash=legacy_hash)  # Small W for speed

            for test_input in self.test_vectors:
                # Compute via PoC_Hash
                poc_result = poc_hash(test_input, params, ProofTier.Q)
                d0_poc = poc_result.d0

                # Compute via legacy method directly
                d0_legacy = self._compute_legacy(test_input, legacy_hash)

                match = d0_poc == d0_legacy
                results.append({
                    'input_len': len(test_input),
                    'legacy_hash': legacy_hash.value,
                    'match': match,
                    'd0_poc': d0_poc.hex()[:16] + '...',
                    'd0_legacy': d0_legacy.hex()[:16] + '...'
                })

                if not match:
                    return BenchmarkResult(
                        name=self.name,
                        status=BenchmarkStatus.FAIL,
                        target="d₀ matches legacy hash exactly",
                        actual=f"Mismatch for input len={len(test_input)}, hash={legacy_hash.value}",
                        details={'results': results}
                    )

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS,
            target="d₀ matches legacy hash exactly",
            actual=f"All {len(results)} test cases match",
            details={
                'test_count': len(results),
                'results': results[:5]  # First 5 for brevity
            }
        )

    def _compute_legacy(self, data: bytes, legacy_hash: LegacyHash) -> bytes:
        """Compute legacy hash directly."""
        if legacy_hash == LegacyHash.SHA256:
            return hashlib.sha256(data).digest()
        elif legacy_hash == LegacyHash.SHAKE256:
            return hashlib.shake_256(data).digest(32)
        else:
            raise ValueError(f"Unknown legacy hash: {legacy_hash}")


class BackwardCompatibilityBenchmark(Benchmark):
    """
    Verify backward compatibility scenarios.
    """

    name = "backward_compatibility"
    description = "Backward compatibility with legacy systems"

    def run(self) -> BenchmarkResult:
        scenarios = []

        # Scenario 1: Legacy system ignores proof
        test_input = b"backward compat test"
        params = PoCParams(W=10)
        result = poc_hash(test_input, params, ProofTier.Q)

        # Legacy system only sees d0
        d0 = result.d0
        legacy_expected = hashlib.shake_256(test_input).digest(32)

        scenario1_pass = d0 == legacy_expected
        scenarios.append({
            'name': 'legacy_ignores_proof',
            'passed': scenario1_pass,
            'description': 'Legacy system can use d₀ and ignore proof'
        })

        # Scenario 2: Proof is optional
        # Can compute d0 without computing full proof
        d0_only = legacy_digest(test_input, params.legacy_hash)
        scenario2_pass = d0_only == d0

        scenarios.append({
            'name': 'proof_optional',
            'passed': scenario2_pass,
            'description': 'd₀ can be computed without proof generation'
        })

        # Scenario 3: New system can verify old digests
        # Old system produced d0, new system can verify it came from input
        old_d0 = hashlib.shake_256(test_input).digest(32)
        new_d0 = legacy_digest(test_input, LegacyHash.SHAKE256)
        scenario3_pass = old_d0 == new_d0

        scenarios.append({
            'name': 'verify_old_digests',
            'passed': scenario3_pass,
            'description': 'New system can verify old digests'
        })

        all_passed = all(s['passed'] for s in scenarios)

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if all_passed else BenchmarkStatus.FAIL,
            target="Full backward compatibility",
            actual=f"{sum(1 for s in scenarios if s['passed'])}/{len(scenarios)} scenarios pass",
            details={'scenarios': scenarios}
        )


class MigrationBenchmark(Benchmark):
    """
    Test migration scenarios from legacy to PoC_Hash.
    """

    name = "migration"
    description = "Legacy to PoC_Hash migration"

    def run(self) -> BenchmarkResult:
        """Test migration scenarios."""
        migration_steps = []

        # Step 1: System produces legacy hashes
        test_inputs = [b"doc1", b"doc2", b"doc3"]
        legacy_hashes = [hashlib.shake_256(inp).digest(32) for inp in test_inputs]

        migration_steps.append({
            'step': 1,
            'description': 'Legacy system produces hashes',
            'count': len(legacy_hashes)
        })

        # Step 2: New system produces same hashes + proofs
        params = PoCParams(W=10)
        new_results = [poc_hash(inp, params, ProofTier.Q) for inp in test_inputs]
        new_hashes = [r.d0 for r in new_results]

        # Verify compatibility
        compatible = all(l == n for l, n in zip(legacy_hashes, new_hashes))

        migration_steps.append({
            'step': 2,
            'description': 'New system produces compatible hashes',
            'compatible': compatible
        })

        # Step 3: Legacy verifiers continue working
        # (They just ignore the proof)
        legacy_verification = all(
            hashlib.shake_256(inp).digest(32) == r.d0
            for inp, r in zip(test_inputs, new_results)
        )

        migration_steps.append({
            'step': 3,
            'description': 'Legacy verifiers still work',
            'working': legacy_verification
        })

        passed = compatible and legacy_verification

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if passed else BenchmarkStatus.FAIL,
            target="Seamless migration",
            actual="Migration successful" if passed else "Migration issues",
            details={'steps': migration_steps}
        )


def run_switching_benchmark(verbose: bool = True) -> BenchmarkResult:
    """Run switching cost benchmark."""
    bench = SwitchingCostBenchmark()
    result = bench.timed_run()

    if verbose:
        print(f"\n=== Zero Switching Cost Benchmark ===")
        print(f"Status: {result.status.value}")
        print(f"Target: {result.target}")
        print(f"Actual: {result.actual}")

    return result
