"""
Merkle Memory Model for Proof of Computation

Memory is represented as a Merkle tree where:
- Leaves are memory blocks
- Each read/write has an authentication path
- Updates produce a new root efficiently

This enables:
- O(log n) proof for any memory access
- O(log n) update for any write
- Constant-time address computation
"""

from dataclasses import dataclass
from typing import List, Tuple, Optional
import hashlib

from .tags import PoCTag, tag_bytes


def _hash(tag: PoCTag, *parts: bytes) -> bytes:
    """Domain-separated hash using SHAKE256."""
    h = hashlib.shake_256()
    h.update(tag_bytes(tag))
    for part in parts:
        h.update(len(part).to_bytes(4, 'big'))
        h.update(part)
    return h.digest(32)


def memory_leaf_hash(index: int, data: bytes) -> bytes:
    """
    Hash a memory block as a Merkle leaf.

    leaf_hash(index, data) = H(MEM_LEAF || index || data)
    """
    return _hash(PoCTag.MEM_LEAF, index.to_bytes(8, 'big'), data)


def memory_node_hash(left: bytes, right: bytes) -> bytes:
    """
    Hash two children to produce parent node.

    node_hash(left, right) = H(MEM_NODE || left || right)
    """
    return _hash(PoCTag.MEM_NODE, left, right)


def memory_root_hash(h: bytes) -> bytes:
    """
    Finalize a Merkle root.

    root_hash(h) = H(MEM_ROOT || h)
    """
    return _hash(PoCTag.MEM_ROOT, h)


@dataclass
class MemoryProof:
    """
    Merkle proof for a memory access.

    Contains the authentication path from leaf to root.
    """
    index: int
    """Block index."""

    value: bytes
    """Block value."""

    siblings: List[Tuple[bytes, bool]]
    """(sibling_hash, is_right) pairs from leaf to root."""

    def verify(self, root: bytes) -> bool:
        """
        Verify this proof against a Merkle root.

        Returns True if the proof is valid.
        """
        current = memory_leaf_hash(self.index, self.value)

        for sibling, is_right in self.siblings:
            if is_right:
                current = memory_node_hash(current, sibling)
            else:
                current = memory_node_hash(sibling, current)

        return memory_root_hash(current) == root

    def serialize(self) -> bytes:
        """Serialize proof for storage/transmission."""
        parts = [
            self.index.to_bytes(8, 'big'),
            len(self.value).to_bytes(4, 'big'),
            self.value,
            len(self.siblings).to_bytes(4, 'big'),
        ]
        for sibling, is_right in self.siblings:
            parts.append(sibling)
            parts.append(bytes([1 if is_right else 0]))
        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'MemoryProof':
        """Deserialize from bytes."""
        offset = 0

        index = int.from_bytes(data[offset:offset+8], 'big')
        offset += 8

        value_len = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        value = data[offset:offset+value_len]
        offset += value_len

        num_siblings = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4

        siblings = []
        for _ in range(num_siblings):
            sibling = data[offset:offset+32]
            offset += 32
            is_right = data[offset] == 1
            offset += 1
            siblings.append((sibling, is_right))

        return cls(index=index, value=value, siblings=siblings)


class MerkleMemory:
    """
    Merkle-committed memory array.

    Supports:
    - O(1) read with O(log n) proof
    - O(log n) update with new root
    - Efficient batch initialization

    The tree is a complete binary tree. If num_blocks is not a power of 2,
    we pad to the next power of 2 with zero blocks.
    """

    def __init__(self, blocks: List[bytes], block_size: int = 64):
        """
        Initialize memory with given blocks.

        Args:
            blocks: List of memory blocks
            block_size: Size of each block in bytes
        """
        self.block_size = block_size
        self.num_blocks = len(blocks)

        # Pad to power of 2
        self.tree_size = 1
        while self.tree_size < self.num_blocks:
            self.tree_size *= 2

        # Store blocks (copy to avoid mutation issues)
        self.blocks = [b[:] for b in blocks]
        # Pad with zeros
        while len(self.blocks) < self.tree_size:
            self.blocks.append(b'\x00' * block_size)

        # Build Merkle tree
        self._build_tree()

    def _build_tree(self):
        """Build Merkle tree from blocks."""
        # Compute leaf hashes
        self.leaves = [
            memory_leaf_hash(i, block)
            for i, block in enumerate(self.blocks)
        ]

        # Build tree layers bottom-up
        self.layers: List[List[bytes]] = [self.leaves]

        current = self.leaves
        while len(current) > 1:
            next_layer = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                next_layer.append(memory_node_hash(left, right))
            self.layers.append(next_layer)
            current = next_layer

        # Finalize root
        self.root = memory_root_hash(self.layers[-1][0])

    def read(self, index: int) -> Tuple[bytes, MemoryProof]:
        """
        Read a block and generate proof.

        Args:
            index: Block index

        Returns:
            (block_value, proof)
        """
        if index < 0 or index >= self.num_blocks:
            raise IndexError(f"Index {index} out of range [0, {self.num_blocks})")

        value = self.blocks[index]
        proof = self._get_proof(index, value)
        return value, proof

    def _get_proof(self, index: int, value: bytes) -> MemoryProof:
        """Generate Merkle proof for a leaf."""
        siblings = []
        current_index = index

        for layer in self.layers[:-1]:  # Exclude root layer
            # Determine sibling
            if current_index % 2 == 0:
                # Current is left child
                sibling_index = current_index + 1
                is_right = True
            else:
                # Current is right child
                sibling_index = current_index - 1
                is_right = False

            if sibling_index < len(layer):
                sibling_hash = layer[sibling_index]
            else:
                sibling_hash = layer[current_index]  # Duplicate for odd

            siblings.append((sibling_hash, is_right))
            current_index //= 2

        return MemoryProof(index=index, value=value, siblings=siblings)

    def write(self, index: int, new_value: bytes) -> Tuple[bytes, MemoryProof, MemoryProof]:
        """
        Write a block and update the tree.

        Args:
            index: Block index
            new_value: New block value

        Returns:
            (new_root, old_proof, new_proof)
            - new_root: Updated Merkle root
            - old_proof: Proof for old value
            - new_proof: Proof for new value under new root
        """
        if index < 0 or index >= self.num_blocks:
            raise IndexError(f"Index {index} out of range [0, {self.num_blocks})")

        if len(new_value) != self.block_size:
            new_value = new_value[:self.block_size].ljust(self.block_size, b'\x00')

        # Get old proof before update
        old_value = self.blocks[index]
        old_proof = self._get_proof(index, old_value)

        # Update block
        self.blocks[index] = new_value

        # Update leaf hash
        new_leaf_hash = memory_leaf_hash(index, new_value)
        self.layers[0][index] = new_leaf_hash

        # Update path to root
        current_index = index
        for layer_idx in range(len(self.layers) - 1):
            parent_index = current_index // 2
            left_idx = parent_index * 2
            right_idx = left_idx + 1

            left = self.layers[layer_idx][left_idx]
            if right_idx < len(self.layers[layer_idx]):
                right = self.layers[layer_idx][right_idx]
            else:
                right = left

            self.layers[layer_idx + 1][parent_index] = memory_node_hash(left, right)
            current_index = parent_index

        # Update root
        self.root = memory_root_hash(self.layers[-1][0])

        # Get new proof
        new_proof = self._get_proof(index, new_value)

        return self.root, old_proof, new_proof

    def get_root(self) -> bytes:
        """Get current Merkle root."""
        return self.root

    def verify_proof(self, proof: MemoryProof) -> bool:
        """Verify a proof against current root."""
        return proof.verify(self.root)


def initialize_memory(
    seed: bytes,
    num_blocks: int,
    block_size: int = 64
) -> Tuple[MerkleMemory, bytes]:
    """
    Initialize memory array from seed.

    Each block is:
        A[j] = H(INIT || seed || j)

    This is parallelizable across all blocks.

    Args:
        seed: Initial seed (r₀)
        num_blocks: Number of blocks
        block_size: Size of each block

    Returns:
        (memory, root)
    """
    blocks = []
    for j in range(num_blocks):
        block = _hash(PoCTag.INIT, seed, j.to_bytes(8, 'big'))
        # Extend or truncate to block_size
        if len(block) < block_size:
            block = block * (block_size // len(block) + 1)
        blocks.append(block[:block_size])

    memory = MerkleMemory(blocks, block_size)
    return memory, memory.get_root()


def verify_memory_transition(
    old_root: bytes,
    new_root: bytes,
    index: int,
    old_value: bytes,
    new_value: bytes,
    old_proof: MemoryProof,
    new_proof: MemoryProof
) -> bool:
    """
    Verify that a memory transition is valid.

    Checks:
    1. old_proof is valid under old_root
    2. new_proof is valid under new_root
    3. Only the specified index changed

    Args:
        old_root: Merkle root before write
        new_root: Merkle root after write
        index: Block index that was written
        old_value: Value before write
        new_value: Value after write
        old_proof: Proof for old value
        new_proof: Proof for new value

    Returns:
        True if transition is valid
    """
    # Verify old proof
    if not old_proof.verify(old_root):
        return False

    # Verify new proof
    if not new_proof.verify(new_root):
        return False

    # Verify indices match
    if old_proof.index != index or new_proof.index != index:
        return False

    # Verify values match
    if old_proof.value != old_value or new_proof.value != new_value:
        return False

    return True
