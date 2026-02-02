"""
PoC (Proof of Computation) Module

Memory-hard hash function with succinct proofs.

Main API:
    poc_hash(input_data, params, tier) -> PoCResult
    verify_poc(d0, proof, params) -> bool

Proof Tiers:
    S - STARK: O(polylog W) verification, ~log^2(W) proof size
    Q - Quick: O(k log W) verification, spot-check based

Example:
    >>> from opochhash.poc import poc_hash, verify_poc
    >>> result = poc_hash(b"hello world")
    >>> d0 = result.d0  # Legacy digest (backward compatible)
    >>> assert verify_poc(d0, result.proof)
"""

# Main API
from .poc_hash import (
    poc_hash,
    verify_poc,
    poc_hash_simple,
    poc_hash_batch,
    verify_poc_batch,
    PoCHasher,
    PoCResult,
    PoCProof,
    ProofTier,
    estimate_proof_size,
    soundness_bound,
    verification_cost,
)

# Parameters
from .params import PoCParams

# Domain separation
from .tags import PoCTag, tag_bytes

# Field arithmetic
from .field import FieldElement, GOLDILOCKS_PRIME, batch_inverse

# State types
from .state import WorkState, MemoryAccess, TransitionWitness

# Memory operations
from .memory import MerkleMemory, initialize_memory, verify_memory_transition

# Work function
from .work import (
    compute_seed,
    legacy_digest,
    work_step,
    compute_full_work,
    verify_step,
    compute_address,
    compute_step_register,
)

# Polynomial operations
from .poly import (
    Polynomial,
    fft,
    ifft,
    low_degree_extend,
    get_domain,
)

# FRI protocol
from .fri import (
    FRIProver,
    FRIVerifier,
    FRIProof,
    MerkleTreeFRI,
    Transcript,
)

# Constraints
from .constraints import (
    WorkAIR,
    ExecutionTrace,
    TraceColumn,
    BoundaryConstraint,
    TransitionConstraint,
    bytes_to_field_elements,
    field_elements_to_bytes,
)

# Tier S (STARK)
from .tier_s import (
    STARKProver,
    STARKVerifier,
    STARKProof,
    prove_tier_s,
    verify_tier_s,
)

# Tier Q (Quick)
from .tier_q import (
    TierQProver,
    TierQVerifier,
    TierQProof,
    prove_tier_q,
    verify_tier_q,
)

__all__ = [
    # Main API
    'poc_hash',
    'verify_poc',
    'poc_hash_simple',
    'poc_hash_batch',
    'verify_poc_batch',
    'PoCHasher',
    'PoCResult',
    'PoCProof',
    'ProofTier',
    'estimate_proof_size',
    'soundness_bound',
    'verification_cost',

    # Parameters
    'PoCParams',

    # Tags
    'PoCTag',
    'tag_bytes',

    # Field
    'FieldElement',
    'GOLDILOCKS_PRIME',
    'batch_inverse',

    # State
    'WorkState',
    'MemoryAccess',
    'TransitionWitness',

    # Memory
    'MerkleMemory',
    'initialize_memory',
    'verify_memory_transition',

    # Work
    'compute_seed',
    'legacy_digest',
    'work_step',
    'compute_full_work',
    'verify_step',
    'compute_address',
    'compute_step_register',

    # Polynomial
    'Polynomial',
    'fft',
    'ifft',
    'low_degree_extend',
    'get_domain',

    # FRI
    'FRIProver',
    'FRIVerifier',
    'FRIProof',
    'MerkleTreeFRI',
    'Transcript',

    # Constraints
    'WorkAIR',
    'ExecutionTrace',
    'TraceColumn',
    'BoundaryConstraint',
    'TransitionConstraint',
    'bytes_to_field_elements',
    'field_elements_to_bytes',

    # Tier S
    'STARKProver',
    'STARKVerifier',
    'STARKProof',
    'prove_tier_s',
    'verify_tier_s',

    # Tier Q
    'TierQProver',
    'TierQVerifier',
    'TierQProof',
    'prove_tier_q',
    'verify_tier_q',
]

# Version
__version__ = '0.1.0'
