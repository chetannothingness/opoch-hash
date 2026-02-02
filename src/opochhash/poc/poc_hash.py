"""
PoC_Hash: Main API

PoC_Hash(x; θ) → (d₀, π)

This is the unified interface that:
1. Produces legacy digest d₀ (zero switching cost)
2. Generates proof π that work was performed correctly
3. Supports two proof tiers: S (STARK) and Q (Quick)

Properties:
- Backward compatible: d₀ works with legacy systems unchanged
- Verifiable: Anyone can verify π without replaying work
- Configurable: Security/performance tradeoffs via params
"""

from dataclasses import dataclass
from typing import Tuple, List, Optional, Union
from enum import Enum
import time

from .params import PoCParams
from .state import WorkState, MemoryAccess
from .memory import MerkleMemory, initialize_memory
from .work import (
    compute_seed,
    legacy_digest,
    work_step,
    compute_full_work,
    verify_step
)
from .tier_q import TierQProof, TierQProver, TierQVerifier, prove_tier_q, verify_tier_q
from .tier_s import STARKProof, STARKProver, STARKVerifier, prove_tier_s, verify_tier_s
from .tags import PoCTag, tag_bytes


class ProofTier(Enum):
    """Proof tier selection."""
    S = "S"  # STARK - O(polylog W) verification
    Q = "Q"  # Quick - O(k log W) verification


@dataclass
class PoCProof:
    """
    Unified proof container for PoC_Hash.

    Contains either a STARK proof (Tier S) or Quick proof (Tier Q).
    """
    tier: ProofTier
    stark_proof: Optional[STARKProof] = None
    quick_proof: Optional[TierQProof] = None

    # Timing metadata
    work_time_ms: float = 0.0
    proof_time_ms: float = 0.0

    def serialize(self) -> bytes:
        """Serialize proof."""
        parts = [
            tag_bytes(PoCTag.PROOF_TIER_S if self.tier == ProofTier.S else PoCTag.PROOF_TIER_Q),
            self.tier.value.encode('utf-8'),
        ]

        if self.tier == ProofTier.S and self.stark_proof:
            proof_bytes = self.stark_proof.serialize()
        elif self.tier == ProofTier.Q and self.quick_proof:
            proof_bytes = self.quick_proof.serialize()
        else:
            proof_bytes = b''

        parts.append(len(proof_bytes).to_bytes(4, 'big'))
        parts.append(proof_bytes)

        return b''.join(parts)

    @property
    def size(self) -> int:
        """Proof size in bytes."""
        return len(self.serialize())

    @property
    def r_final(self) -> bytes:
        """Get final register value."""
        if self.tier == ProofTier.S and self.stark_proof:
            return self.stark_proof.r_final
        elif self.tier == ProofTier.Q and self.quick_proof:
            return self.quick_proof.r_final
        return b''

    @property
    def d0(self) -> bytes:
        """Get legacy digest."""
        if self.tier == ProofTier.S and self.stark_proof:
            return self.stark_proof.d0
        elif self.tier == ProofTier.Q and self.quick_proof:
            return self.quick_proof.d0
        return b''


@dataclass
class PoCResult:
    """
    Complete result from PoC_Hash computation.
    """
    # Legacy digest - use this with existing systems
    d0: bytes

    # Proof of correct computation
    proof: PoCProof

    # Work output (can differ from d0)
    r_final: bytes

    # Execution trace (optional, for debugging)
    trace: Optional[List[WorkState]] = None
    memory_accesses: Optional[List[MemoryAccess]] = None


def poc_hash(
    input_data: bytes,
    params: Optional[PoCParams] = None,
    tier: Union[ProofTier, str] = ProofTier.S,
    keep_trace: bool = False
) -> PoCResult:
    """
    PoC_Hash(x; θ) → (d₀, π)

    Compute memory-hard work with proof generation.

    Args:
        input_data: Input to hash
        params: PoC parameters (uses default if None)
        tier: Proof tier - 'S' for STARK, 'Q' for Quick
        keep_trace: If True, include trace in result (for debugging)

    Returns:
        PoCResult containing:
        - d0: Legacy digest (backward compatible)
        - proof: Proof of correct computation
        - r_final: Final register value
        - trace/memory_accesses: Optional execution trace

    Example:
        >>> result = poc_hash(b"hello world")
        >>> d0 = result.d0  # Use with legacy systems
        >>> proof = result.proof  # Verify computation
    """
    # Default parameters
    if params is None:
        params = PoCParams()

    # Normalize tier
    if isinstance(tier, str):
        tier = ProofTier(tier.upper())

    # 1. Compute legacy digest (zero switching cost)
    d0 = legacy_digest(input_data, params.legacy_hash)

    # 2. Execute memory-hard work
    work_start = time.perf_counter()

    trace, memory_accesses = compute_full_work(input_data, params)

    work_end = time.perf_counter()
    work_time_ms = (work_end - work_start) * 1000

    r_final = trace[-1].r

    # 3. Generate proof
    proof_start = time.perf_counter()

    if tier == ProofTier.S:
        stark_proof = prove_tier_s(input_data, params, trace, memory_accesses)
        proof = PoCProof(
            tier=ProofTier.S,
            stark_proof=stark_proof,
            work_time_ms=work_time_ms
        )
    else:
        quick_proof = prove_tier_q(input_data, params, trace, memory_accesses)
        proof = PoCProof(
            tier=ProofTier.Q,
            quick_proof=quick_proof,
            work_time_ms=work_time_ms
        )

    proof_end = time.perf_counter()
    proof.proof_time_ms = (proof_end - proof_start) * 1000

    # 4. Build result
    return PoCResult(
        d0=d0,
        proof=proof,
        r_final=r_final,
        trace=trace if keep_trace else None,
        memory_accesses=memory_accesses if keep_trace else None
    )


def verify_poc(
    d0: bytes,
    proof: PoCProof,
    params: Optional[PoCParams] = None
) -> bool:
    """
    Verify PoC_Hash proof.

    This does NOT replay the work - it verifies the proof cryptographically.

    Args:
        d0: Expected legacy digest
        proof: Proof to verify
        params: PoC parameters (must match prover's params)

    Returns:
        True if proof is valid

    Verification cost:
    - Tier S: O(polylog W)
    - Tier Q: O(k log W)
    """
    if params is None:
        params = PoCParams()

    # Check d0 matches proof
    if proof.d0 != d0:
        return False

    # Verify based on tier
    if proof.tier == ProofTier.S and proof.stark_proof:
        return verify_tier_s(proof.stark_proof, params)
    elif proof.tier == ProofTier.Q and proof.quick_proof:
        return verify_tier_q(proof.quick_proof, params)

    return False


def poc_hash_simple(input_data: bytes, W: int = 10000) -> Tuple[bytes, bytes]:
    """
    Simplified interface returning (d0, proof_bytes).

    For quick testing with minimal configuration.
    """
    params = PoCParams(W=W)
    result = poc_hash(input_data, params, tier=ProofTier.Q)
    return result.d0, result.proof.serialize()


# =============================================================================
# Batch Operations
# =============================================================================

def poc_hash_batch(
    inputs: List[bytes],
    params: Optional[PoCParams] = None,
    tier: Union[ProofTier, str] = ProofTier.Q
) -> List[PoCResult]:
    """
    Compute PoC_Hash for multiple inputs.

    Each computation is independent (no batching optimization yet).
    Future: Could batch FRI queries across proofs.
    """
    results = []
    for input_data in inputs:
        result = poc_hash(input_data, params, tier)
        results.append(result)
    return results


def verify_poc_batch(
    items: List[Tuple[bytes, PoCProof]],
    params: Optional[PoCParams] = None
) -> List[bool]:
    """
    Verify multiple proofs.

    Returns list of verification results.
    """
    results = []
    for d0, proof in items:
        results.append(verify_poc(d0, proof, params))
    return results


# =============================================================================
# Streaming Interface
# =============================================================================

class PoCHasher:
    """
    Streaming hasher interface for PoC_Hash.

    Accumulates input data, then computes hash + proof on finalize.

    Example:
        >>> hasher = PoCHasher()
        >>> hasher.update(b"hello ")
        >>> hasher.update(b"world")
        >>> result = hasher.finalize()
    """

    def __init__(
        self,
        params: Optional[PoCParams] = None,
        tier: Union[ProofTier, str] = ProofTier.S
    ):
        self.params = params or PoCParams()
        self.tier = tier if isinstance(tier, ProofTier) else ProofTier(tier.upper())
        self._buffer = bytearray()
        self._finalized = False

    def update(self, data: bytes) -> 'PoCHasher':
        """Add data to hash."""
        if self._finalized:
            raise RuntimeError("Cannot update finalized hasher")
        self._buffer.extend(data)
        return self

    def finalize(self, keep_trace: bool = False) -> PoCResult:
        """Compute final hash and proof."""
        if self._finalized:
            raise RuntimeError("Already finalized")
        self._finalized = True
        return poc_hash(bytes(self._buffer), self.params, self.tier, keep_trace)

    def copy(self) -> 'PoCHasher':
        """Create copy of hasher state."""
        if self._finalized:
            raise RuntimeError("Cannot copy finalized hasher")
        new = PoCHasher(self.params, self.tier)
        new._buffer = bytearray(self._buffer)
        return new

    @property
    def digest_size(self) -> int:
        """Size of d0 digest."""
        return 32  # SHAKE-256 with 32 bytes


# =============================================================================
# Utility Functions
# =============================================================================

def estimate_proof_size(W: int, tier: ProofTier = ProofTier.S) -> int:
    """
    Estimate proof size in bytes for given work amount.

    Tier S: O(log^2 W) - grows slowly
    Tier Q: O(k log W) - grows with security parameter
    """
    if tier == ProofTier.S:
        import math
        # STARK: ~log^2(W) * constant
        log_w = max(1, math.log2(W + 1))
        return int(log_w * log_w * 100)  # ~100 bytes per log^2 term
    else:
        # Quick: k samples * (state + merkle proof)
        k = min(1000, max(100, W // 1000))  # Adaptive sampling
        import math
        log_w = max(1, math.log2(W + 1))
        return int(k * (64 + 32 * log_w))  # state + proof per sample


def soundness_bound(
    params: PoCParams,
    tier: ProofTier = ProofTier.S
) -> float:
    """
    Compute soundness bound (probability of accepting invalid proof).

    Target: < 2^-128
    """
    if tier == ProofTier.S:
        return params.stark_soundness_bound()
    else:
        # Tier Q: (1 - 1/W)^k
        import math
        k = min(1000, max(100, params.W // 1000))
        return (1 - 1/params.W) ** k if params.W > 0 else 1.0


def verification_cost(
    params: PoCParams,
    tier: ProofTier = ProofTier.S
) -> str:
    """
    Describe verification cost.
    """
    if tier == ProofTier.S:
        return f"O(polylog {params.W}) - approximately {params.fri_queries * 20} field operations"
    else:
        k = min(1000, max(100, params.W // 1000))
        import math
        log_w = max(1, int(math.log2(params.W + 1)))
        return f"O({k} * log {params.W}) - approximately {k * log_w} hash operations"
