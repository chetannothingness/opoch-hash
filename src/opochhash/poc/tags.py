"""
Domain Tags for Proof of Computation

All tags are domain-separated to prevent cross-protocol collisions.
These tags are PINNED - changing them breaks compatibility.
"""

from enum import IntEnum


class PoCTag(IntEnum):
    """Domain separation tags for proof of computation."""

    # Work function
    SEED = 0x70         # Initial seed derivation
    INIT = 0x71         # Memory initialization
    STEP = 0x72         # Sequential work step
    WRITE = 0x73        # Memory write
    ADDR = 0x74         # Address derivation

    # Memory proofs
    MEM_LEAF = 0x75     # Memory Merkle leaf
    MEM_NODE = 0x76     # Memory Merkle node
    MEM_ROOT = 0x77     # Memory Merkle root

    # Trace commitments
    TRACE_LEAF = 0x78   # Trace Merkle leaf
    TRACE_NODE = 0x79   # Trace Merkle node
    TRACE_ROOT = 0x7A   # Trace Merkle root

    # STARK
    CONSTRAINT = 0x80   # Constraint polynomial
    COMPOSITION = 0x81  # Composition polynomial
    FRI_LAYER = 0x82    # FRI layer commitment
    FRI_QUERY = 0x83    # FRI query

    # Challenges (Fiat-Shamir)
    CHAL_COMP = 0x90    # Composition challenge
    CHAL_FRI = 0x91     # FRI folding challenge
    CHAL_QUERY = 0x92   # Query indices challenge

    # Proof structure
    PROOF_HEADER = 0xA0  # Proof header
    PROOF_TIER_S = 0xA1  # STARK proof
    PROOF_TIER_Q = 0xA2  # Quick proof
    PROOF_AGG = 0xA3     # Aggregated proof

    # Parameters
    PARAMS = 0xB0        # Parameter serialization


def tag_bytes(tag: PoCTag) -> bytes:
    """Convert tag to canonical bytes (2 bytes, big-endian)."""
    return tag.to_bytes(2, 'big')
