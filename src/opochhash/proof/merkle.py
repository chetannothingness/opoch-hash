"""
Merkle Tree for Proof of Computation

Domain-separated, binary Merkle tree using OpochHash.
Supports:
- Building trees from leaf data
- Generating authentication paths (proofs)
- Verifying inclusion proofs
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple
import hashlib

from .tags import ProofTag, tag_bytes


def _hash(tag: ProofTag, *parts: bytes) -> bytes:
    """Domain-separated hash using SHAKE256."""
    h = hashlib.shake_256()
    h.update(tag_bytes(tag))
    for part in parts:
        h.update(len(part).to_bytes(8, 'big'))
        h.update(part)
    return h.digest(32)


def leaf_hash(index: int, data: bytes) -> bytes:
    """Hash a leaf node: H(LEAF ‖ index ‖ data)"""
    return _hash(ProofTag.LEAF, index.to_bytes(8, 'big'), data)


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash an internal node: H(NODE ‖ left ‖ right)"""
    return _hash(ProofTag.NODE, left, right)


def root_hash(h: bytes) -> bytes:
    """Finalize a root: H(ROOT ‖ h)"""
    return _hash(ProofTag.ROOT, h)


@dataclass
class MerkleProof:
    """Authentication path for Merkle tree inclusion."""
    index: int
    leaf_data: bytes
    siblings: List[Tuple[bytes, bool]]  # (sibling_hash, is_right)

    def verify(self, root: bytes) -> bool:
        """Verify this proof against a root."""
        current = leaf_hash(self.index, self.leaf_data)

        for sibling, is_right in self.siblings:
            if is_right:
                current = node_hash(current, sibling)
            else:
                current = node_hash(sibling, current)

        return root_hash(current) == root

    def serialize(self) -> bytes:
        """Serialize proof to bytes."""
        parts = [
            self.index.to_bytes(8, 'big'),
            len(self.leaf_data).to_bytes(4, 'big'),
            self.leaf_data,
            len(self.siblings).to_bytes(4, 'big'),
        ]
        for sibling, is_right in self.siblings:
            parts.append(sibling)
            parts.append(bytes([1 if is_right else 0]))
        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'MerkleProof':
        """Deserialize proof from bytes."""
        offset = 0

        index = int.from_bytes(data[offset:offset+8], 'big')
        offset += 8

        leaf_len = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        leaf_data = data[offset:offset+leaf_len]
        offset += leaf_len

        num_siblings = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4

        siblings = []
        for _ in range(num_siblings):
            sibling = data[offset:offset+32]
            offset += 32
            is_right = data[offset] == 1
            offset += 1
            siblings.append((sibling, is_right))

        return cls(index=index, leaf_data=leaf_data, siblings=siblings)


class MerkleTree:
    """
    Binary Merkle tree with domain-separated hashing.

    Properties:
    - Deterministic construction
    - O(log n) proof generation
    - O(log n) verification
    """

    def __init__(self, leaves: List[bytes]):
        """
        Build a Merkle tree from leaf data.

        Args:
            leaves: List of leaf data (will be hashed with indices)
        """
        if not leaves:
            raise ValueError("Cannot build empty Merkle tree")

        self.leaf_count = len(leaves)
        self.leaves = leaves

        # Hash leaves with their indices
        self.leaf_hashes = [
            leaf_hash(i, data) for i, data in enumerate(leaves)
        ]

        # Build tree bottom-up
        self.layers: List[List[bytes]] = [self.leaf_hashes]
        self._build_tree()

        # Finalize root
        self.root = root_hash(self.layers[-1][0])

    def _build_tree(self):
        """Build internal layers of the tree."""
        current_layer = self.leaf_hashes

        while len(current_layer) > 1:
            next_layer = []

            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                # If odd number of nodes, duplicate the last one
                right = current_layer[i + 1] if i + 1 < len(current_layer) else left
                next_layer.append(node_hash(left, right))

            self.layers.append(next_layer)
            current_layer = next_layer

    def get_proof(self, index: int) -> MerkleProof:
        """
        Generate authentication path for leaf at index.

        Args:
            index: Leaf index (0-based)

        Returns:
            MerkleProof that can verify inclusion
        """
        if index < 0 or index >= self.leaf_count:
            raise IndexError(f"Index {index} out of range [0, {self.leaf_count})")

        siblings = []
        current_index = index

        for layer in self.layers[:-1]:  # Exclude root layer
            # Determine sibling index
            if current_index % 2 == 0:
                # Current is left child, sibling is right
                sibling_index = current_index + 1
                is_right = True
            else:
                # Current is right child, sibling is left
                sibling_index = current_index - 1
                is_right = False

            # Handle case where sibling doesn't exist (odd layer)
            if sibling_index < len(layer):
                sibling_hash = layer[sibling_index]
            else:
                sibling_hash = layer[current_index]  # Duplicate

            siblings.append((sibling_hash, is_right))

            # Move to parent index
            current_index //= 2

        return MerkleProof(
            index=index,
            leaf_data=self.leaves[index],
            siblings=siblings
        )

    def verify_proof(self, proof: MerkleProof) -> bool:
        """Verify an inclusion proof against this tree's root."""
        return proof.verify(self.root)


def build_trace_tree(states: List[bytes]) -> MerkleTree:
    """
    Build a Merkle tree over an execution trace.

    Args:
        states: List of serialized states s_0, s_1, ..., s_T

    Returns:
        MerkleTree with root R committing to entire trace
    """
    return MerkleTree(states)


def verify_transition(
    root: bytes,
    proof_t: MerkleProof,
    proof_t1: MerkleProof,
    step_fn,
    program: bytes
) -> bool:
    """
    Verify a single transition in the trace.

    Args:
        root: Merkle root of trace
        proof_t: Proof for state at time t
        proof_t1: Proof for state at time t+1
        step_fn: Function (program, state) -> next_state
        program: Program bytecode

    Returns:
        True if transition is valid
    """
    # Verify both proofs
    if not proof_t.verify(root):
        return False
    if not proof_t1.verify(root):
        return False

    # Verify indices are consecutive
    if proof_t1.index != proof_t.index + 1:
        return False

    # Verify transition
    computed_next = step_fn(program, proof_t.leaf_data)
    return computed_next == proof_t1.leaf_data
