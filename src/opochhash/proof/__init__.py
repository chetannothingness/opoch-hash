"""
OpochHash Proof of Computation

A Π-clean, deterministic, mechanically verifiable proof of computation stack.

Three levels:
- Level 0 (Receipted Replay): O(T) verification, perfect integrity
- Level 1 (Spot-Check): O(k log T) verification, probabilistic soundness
- Level 2 (STARK-style): O(polylog T) verification (framework)

All built on OpochHash's semantic hashing foundation.
"""

from .tags import ProofTag, tag_bytes
from .merkle import (
    MerkleTree,
    MerkleProof,
    leaf_hash,
    node_hash,
    root_hash,
    build_trace_tree,
    verify_transition,
)
from .kernel import (
    MachineState,
    Program,
    ComputationClaim,
    execute,
    execute_with_serialized_trace,
)
from .level0 import (
    Level0Proof,
    Level0Prover,
    Level0Verifier,
    Level0VerificationResult,
    prove_level0,
    verify_level0,
    compute_receipt_chain,
)
from .level1 import (
    Statement,
    TransitionProof,
    Level1Proof,
    Level1Prover,
    Level1Verifier,
    Level1VerificationResult,
    prove_level1,
    verify_level1,
    derive_challenges,
)
from .vm import (
    Opcode,
    Instruction,
    StackVM,
    program_factorial,
    program_fibonacci,
    program_add,
    program_multiply,
)

__all__ = [
    # Tags
    'ProofTag',
    'tag_bytes',

    # Merkle
    'MerkleTree',
    'MerkleProof',
    'leaf_hash',
    'node_hash',
    'root_hash',
    'build_trace_tree',
    'verify_transition',

    # Kernel
    'MachineState',
    'Program',
    'ComputationClaim',
    'execute',
    'execute_with_serialized_trace',

    # Level 0
    'Level0Proof',
    'Level0Prover',
    'Level0Verifier',
    'Level0VerificationResult',
    'prove_level0',
    'verify_level0',
    'compute_receipt_chain',

    # Level 1
    'Statement',
    'TransitionProof',
    'Level1Proof',
    'Level1Prover',
    'Level1Verifier',
    'Level1VerificationResult',
    'prove_level1',
    'verify_level1',
    'derive_challenges',

    # VM
    'Opcode',
    'Instruction',
    'StackVM',
    'program_factorial',
    'program_fibonacci',
    'program_add',
    'program_multiply',
]
