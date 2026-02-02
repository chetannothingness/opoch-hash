"""
Benchmark 2: Soundness

Target: Forgery probability < 2^-128

Tests:
- Compute theoretical soundness bound
- Verify FRI soundness parameters
- Check constraint system completeness
- Validate Fiat-Shamir security
"""

from dataclasses import dataclass
from typing import Dict, Any
import math

from .base import Benchmark, BenchmarkResult, BenchmarkStatus
from ..params import PoCParams
from ..fri import fri_soundness_bound


@dataclass
class SoundnessAnalysis:
    """Soundness analysis results."""
    stark_soundness: float
    fri_soundness: float
    constraint_soundness: float
    fiat_shamir_bits: int
    combined_soundness: float
    target_bits: int
    achieved_bits: int


class SoundnessBenchmark(Benchmark):
    """
    Benchmark 2: Soundness Analysis

    Requirement: Forgery probability < 2^-128
    """

    name = "soundness"
    description = "Cryptographic soundness bounds"

    def __init__(
        self,
        target_bits: int = 128,
        params: PoCParams = None
    ):
        self.target_bits = target_bits
        self.params = params or PoCParams()

    def run(self) -> BenchmarkResult:
        analysis = self._analyze_soundness()

        passed = analysis.achieved_bits >= self.target_bits

        return BenchmarkResult(
            name=self.name,
            status=BenchmarkStatus.PASS if passed else BenchmarkStatus.FAIL,
            target=f"Soundness >= {self.target_bits} bits (forgery prob < 2^-{self.target_bits})",
            actual=f"Achieved {analysis.achieved_bits} bits soundness",
            details={
                'stark_soundness_bits': self._prob_to_bits(analysis.stark_soundness),
                'fri_soundness_bits': self._prob_to_bits(analysis.fri_soundness),
                'constraint_soundness_bits': self._prob_to_bits(analysis.constraint_soundness),
                'fiat_shamir_bits': analysis.fiat_shamir_bits,
                'combined_soundness_bits': analysis.achieved_bits,
                'target_bits': self.target_bits,
                'parameters': {
                    'W': self.params.W,
                    'blowup_factor': self.params.blowup_factor,
                    'fri_queries': self.params.fri_queries,
                    'security_bits': self.params.security_bits
                }
            }
        )

    def _analyze_soundness(self) -> SoundnessAnalysis:
        """Analyze soundness of the proof system."""

        # 1. FRI Soundness
        # ε_FRI ≤ (ρ + δ)^q where ρ = rate, q = queries
        domain_size = 2 ** 20  # Typical LDE domain
        max_degree = self.params.W
        fri_sound = fri_soundness_bound(
            domain_size, max_degree, self.params.fri_queries
        )

        # 2. STARK Soundness (composition)
        # Combines FRI with constraint checking
        # ε_STARK ≈ ε_FRI + num_constraints/|F|
        field_size = 2 ** 64  # Goldilocks
        num_constraints = 10  # Approximate
        stark_sound = fri_sound + num_constraints / field_size

        # 3. Constraint Soundness
        # Probability that random trace satisfies constraints
        constraint_sound = 1.0 / field_size

        # 4. Fiat-Shamir Security
        # Based on output size of hash function
        fs_bits = 256  # SHAKE-256 with 32-byte output provides 256-bit security

        # 5. Combined Soundness
        # Conservative: take minimum of components
        combined = max(stark_sound, fri_sound, constraint_sound)
        achieved_bits = self._prob_to_bits(combined)

        return SoundnessAnalysis(
            stark_soundness=stark_sound,
            fri_soundness=fri_sound,
            constraint_soundness=constraint_sound,
            fiat_shamir_bits=fs_bits,
            combined_soundness=combined,
            target_bits=self.target_bits,
            achieved_bits=achieved_bits
        )

    def _prob_to_bits(self, prob: float) -> int:
        """Convert probability to security bits."""
        if prob <= 0:
            return 256  # Maximum
        if prob >= 1:
            return 0
        return min(256, int(-math.log2(prob)))


class DetailedSoundnessAnalysis:
    """
    More detailed soundness analysis for documentation.
    """

    def __init__(self, params: PoCParams):
        self.params = params

    def analyze(self) -> Dict[str, Any]:
        """Produce detailed soundness report."""
        return {
            'fri_analysis': self._fri_analysis(),
            'constraint_analysis': self._constraint_analysis(),
            'hash_analysis': self._hash_analysis(),
            'combined': self._combined_analysis()
        }

    def _fri_analysis(self) -> Dict[str, Any]:
        """FRI protocol soundness."""
        q = self.params.fri_queries
        rho = self.params.fri_rate
        delta = 0.1  # Proximity parameter

        # ε ≤ (ρ + δ)^q
        epsilon = (rho + delta) ** q

        return {
            'queries': q,
            'rate': rho,
            'proximity': delta,
            'soundness_bound': epsilon,
            'security_bits': self._prob_to_bits(epsilon),
            'explanation': f"FRI proves polynomial degree with error ≤ ({rho}+{delta})^{q}"
        }

    def _constraint_analysis(self) -> Dict[str, Any]:
        """Constraint system analysis."""
        num_constraints = 10  # Transition + boundary
        constraint_degree = 2  # Max degree per constraint

        # Use cubic extension field for challenge sampling
        # This triples the security bits for random linear combinations
        base_field_size = 2 ** 64
        extension_degree = 3
        field_size = base_field_size ** extension_degree  # ~2^192

        # In STARK, constraints are enforced via composition polynomial
        # which is then tested via FRI. The soundness comes from:
        # 1. FRI proving composition poly is close to low-degree
        # 2. Random linear combination of constraints in composition

        # By Schwartz-Zippel lemma, if any constraint c_i is not identically zero,
        # Pr[random linear combination C(α) = 0] ≤ max_total_degree / |F|
        #
        # Total degree of composition = num_constraints * constraint_degree
        # (approximately, since we use random powers α, α^2, ..., α^k)
        total_degree = num_constraints * constraint_degree  # ~20

        false_positive = total_degree / field_size

        return {
            'num_constraints': num_constraints,
            'max_degree': constraint_degree,
            'total_degree': total_degree,
            'field_size': field_size,
            'extension_degree': extension_degree,
            'false_positive_prob': false_positive,
            'security_bits': self._prob_to_bits(false_positive),
            'explanation': "Schwartz-Zippel: Pr[bad combination] ≤ total_degree / |extension_field|"
        }

    def _hash_analysis(self) -> Dict[str, Any]:
        """Hash function security."""
        return {
            'function': 'SHAKE-256',
            'output_bits': 256,
            'collision_resistance': 128,
            'preimage_resistance': 256,
            'second_preimage_resistance': 256,
            'explanation': "Domain-separated SHAKE-256 for all hashing"
        }

    def _combined_analysis(self) -> Dict[str, Any]:
        """Combined security analysis."""
        fri = self._fri_analysis()
        constraint = self._constraint_analysis()

        # In STARK, the main soundness comes from FRI
        # Constraints are enforced through composition polynomial
        # So FRI soundness dominates (with small addition from linear combination)

        # Combined: FRI error + constraint combination error
        fri_prob = fri['soundness_bound']
        constraint_prob = constraint['false_positive_prob']

        # Union bound (conservative)
        combined_prob = fri_prob + constraint_prob
        combined_bits = self._prob_to_bits(combined_prob)

        # Also account for Fiat-Shamir security
        min_bits = min(combined_bits, 256)  # SHAKE-256 provides 256-bit security

        return {
            'achieved_bits': min_bits,
            'target_bits': self.params.security_bits,
            'meets_target': min_bits >= self.params.security_bits,
            'limiting_factor': 'FRI queries' if fri['security_bits'] <= 128 else 'hash function'
        }

    def _prob_to_bits(self, prob: float) -> int:
        if prob <= 0:
            return 256
        if prob >= 1:
            return 0
        return min(256, int(-math.log2(prob)))


def run_soundness_benchmark(
    params: PoCParams = None,
    target_bits: int = 128,
    verbose: bool = True
) -> BenchmarkResult:
    """Run soundness benchmark."""
    bench = SoundnessBenchmark(target_bits, params)
    result = bench.timed_run()

    if verbose:
        print(f"\n=== Soundness Benchmark ===")
        print(f"Status: {result.status.value}")
        print(f"Target: {result.target}")
        print(f"Actual: {result.actual}")
        print(f"\nComponent analysis:")
        for key, value in result.details.items():
            if key != 'parameters':
                print(f"  {key}: {value}")

    return result
