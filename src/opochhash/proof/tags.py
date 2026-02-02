"""
Domain Tags for Proof of Computation

All tags are domain-separated to prevent cross-protocol collisions.
"""

from enum import IntEnum


class ProofTag(IntEnum):
    """Domain separation tags for proof of computation."""

    # Receipt chain
    STEP = 0x10        # State transition in receipt chain

    # Merkle tree
    LEAF = 0x20        # Merkle leaf node
    NODE = 0x21        # Merkle internal node
    ROOT = 0x22        # Merkle root finalization

    # Challenges
    CHAL = 0x30        # Challenge seed derivation
    CHAL_INDEX = 0x31  # Challenge index derivation

    # Memory proofs (RAM model)
    MEMREAD = 0x40     # Memory read proof
    MEMWRITE = 0x41    # Memory write proof
    MEMROOT = 0x42     # Memory Merkle root

    # STARK-style (Level 2)
    POLY = 0x50        # Polynomial commitment
    FRI = 0x51         # FRI layer commitment
    EVAL = 0x52        # Evaluation proof

    # Computation
    INIT = 0x60        # Initial state
    FINAL = 0x61       # Final state
    PROGRAM = 0x62     # Program hash
    INPUT = 0x63       # Input hash
    OUTPUT = 0x64      # Output hash


def tag_bytes(tag: ProofTag) -> bytes:
    """Convert tag to canonical bytes."""
    return tag.to_bytes(2, 'big')
