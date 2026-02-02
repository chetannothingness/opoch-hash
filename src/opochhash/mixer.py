"""
The Mixer: Domain-Separated Tree Sponge

Section 4: The forced best execution model

The mixer's job: make distinct tapes look like ideal random outputs,
up to the counting limits.

Structure:
- Sponge (capacity controls security, supports XOF)
- Tree (parallelism on large inputs, streaming)
- Tags (domain separation prevents mode confusion)
"""

from __future__ import annotations
import struct
import hashlib
from typing import List, Optional, Tuple
from dataclasses import dataclass
from enum import IntEnum
from abc import ABC, abstractmethod
import math

from .types import MixerTag


# =============================================================================
# SPONGE CONSTRUCTION
# =============================================================================

class SpongePermutation(ABC):
    """
    Abstract permutation for sponge construction.
    The permutation is the cryptographic core.
    """

    @property
    @abstractmethod
    def state_size(self) -> int:
        """Total state size in bytes."""
        pass

    @property
    @abstractmethod
    def rate(self) -> int:
        """Rate (absorb/squeeze size) in bytes."""
        pass

    @property
    @abstractmethod
    def capacity(self) -> int:
        """Capacity (security parameter) in bytes."""
        pass

    @abstractmethod
    def permute(self, state: bytearray) -> None:
        """Apply the permutation in-place."""
        pass


class Keccak1600Permutation(SpongePermutation):
    """
    Keccak-f[1600] permutation (used in SHA-3/SHAKE).

    State: 1600 bits = 200 bytes
    This is the gold standard permutation with extensive cryptanalysis.
    """

    # Keccak round constants
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]

    # Rotation offsets
    ROTATIONS = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ]

    def __init__(self, capacity_bits: int = 512):
        """
        Initialize with specified capacity.

        Common configurations:
        - capacity=512: 256-bit security (like SHA3-256)
        - capacity=256: 128-bit security (like SHA3-128)
        - capacity=1024: Maximum security
        """
        self._capacity_bits = capacity_bits
        self._rate_bits = 1600 - capacity_bits

    @property
    def state_size(self) -> int:
        return 200  # 1600 bits

    @property
    def rate(self) -> int:
        return self._rate_bits // 8

    @property
    def capacity(self) -> int:
        return self._capacity_bits // 8

    def permute(self, state: bytearray) -> None:
        """Apply Keccak-f[1600] permutation."""
        # Convert to 5x5 array of 64-bit lanes
        lanes = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                offset = 8 * (x + 5 * y)
                lanes[x][y] = int.from_bytes(state[offset:offset+8], 'little')

        # 24 rounds
        for rc in self.RC:
            # θ (theta)
            C = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4]
                 for x in range(5)]
            D = [C[(x - 1) % 5] ^ self._rot64(C[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    lanes[x][y] ^= D[x]

            # ρ (rho) and π (pi)
            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    B[y][(2 * x + 3 * y) % 5] = self._rot64(
                        lanes[x][y], self.ROTATIONS[x][y]
                    )

            # χ (chi)
            for x in range(5):
                for y in range(5):
                    lanes[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

            # ι (iota)
            lanes[0][0] ^= rc

        # Convert back to bytes
        for x in range(5):
            for y in range(5):
                offset = 8 * (x + 5 * y)
                state[offset:offset+8] = lanes[x][y].to_bytes(8, 'little')

    @staticmethod
    def _rot64(x: int, n: int) -> int:
        """64-bit rotation."""
        return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


class Sponge:
    """
    Sponge construction with domain separation.

    Operations:
    - absorb(): Input data into the sponge
    - squeeze(): Extract output from the sponge
    - finalize(): Get fixed-length digest
    """

    def __init__(
        self,
        permutation: SpongePermutation,
        domain_tag: MixerTag
    ):
        self.perm = permutation
        self.state = bytearray(permutation.state_size)
        self.absorbed = 0
        self.squeezing = False

        # Domain separation: XOR tag into first byte of capacity
        self.state[permutation.rate] ^= domain_tag

    def absorb(self, data: bytes) -> 'Sponge':
        """Absorb data into the sponge."""
        if self.squeezing:
            raise RuntimeError("Cannot absorb after squeezing")

        rate = self.perm.rate
        offset = self.absorbed % rate

        for byte in data:
            self.state[offset] ^= byte
            offset += 1
            if offset == rate:
                self.perm.permute(self.state)
                offset = 0

        self.absorbed += len(data)
        return self

    def _finalize_absorb(self) -> None:
        """Finalize absorption phase with padding."""
        if self.squeezing:
            return

        rate = self.perm.rate
        offset = self.absorbed % rate

        # Pad10*1 padding
        self.state[offset] ^= 0x06  # Domain separator for sponge mode
        self.state[rate - 1] ^= 0x80  # Final bit

        self.perm.permute(self.state)
        self.squeezing = True

    def squeeze(self, length: int) -> bytes:
        """Squeeze output from the sponge (XOF mode)."""
        self._finalize_absorb()

        rate = self.perm.rate
        output = bytearray()
        offset = 0

        while len(output) < length:
            if offset == rate:
                self.perm.permute(self.state)
                offset = 0
            output.append(self.state[offset])
            offset += 1

        return bytes(output[:length])

    def finalize(self, length: int = 32) -> bytes:
        """Get fixed-length digest."""
        return self.squeeze(length)


# =============================================================================
# TREE SPONGE MIXER
# =============================================================================

@dataclass
class TreeNode:
    """Node in the hash tree."""
    hash: bytes
    is_leaf: bool


class TreeSpongeMixer:
    """
    Domain-separated tree sponge mixer.

    Section 4 construction:
    - Leaf: h_i = Sponge(LEAF ‖ i ‖ M_i)
    - Parent: h_p = Sponge(PARENT ‖ h_L ‖ h_R)
    - Root: digest = Sponge(ROOT ‖ h_root)
    - XOF: stream = SpongeStream(ROOT_XOF ‖ h_root)
    - Keyed: digest = Sponge(KEYED ‖ K ‖ ROLE_TAG ‖ TAPE)

    Properties:
    - Domain separation prevents mode confusion
    - Tree structure enables parallelism
    - Single primitive covers all modes
    """

    DEFAULT_CHUNK_SIZE = 4096  # Bytes per leaf
    DEFAULT_HASH_SIZE = 32    # Output size in bytes
    DEFAULT_CAPACITY = 512    # Bits of capacity (256-bit security)

    def __init__(
        self,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        hash_size: int = DEFAULT_HASH_SIZE,
        capacity_bits: int = DEFAULT_CAPACITY
    ):
        self.chunk_size = chunk_size
        self.hash_size = hash_size
        self.capacity_bits = capacity_bits

    def _make_sponge(self, tag: MixerTag) -> Sponge:
        """Create a new sponge with the given domain tag."""
        perm = Keccak1600Permutation(self.capacity_bits)
        return Sponge(perm, tag)

    def _hash_leaf(self, index: int, data: bytes) -> bytes:
        """
        Hash a leaf node.
        h_i = Sponge(LEAF ‖ i ‖ M_i)
        """
        sponge = self._make_sponge(MixerTag.LEAF)
        sponge.absorb(struct.pack('>Q', index))  # 64-bit index
        sponge.absorb(data)
        return sponge.finalize(self.hash_size)

    def _hash_parent(self, left: bytes, right: bytes) -> bytes:
        """
        Hash a parent node.
        h_p = Sponge(PARENT ‖ h_L ‖ h_R)
        """
        sponge = self._make_sponge(MixerTag.PARENT)
        sponge.absorb(left)
        sponge.absorb(right)
        return sponge.finalize(self.hash_size)

    def _hash_root(self, tree_root: bytes, xof: bool = False) -> Sponge:
        """
        Create root sponge.
        digest = Sponge(ROOT ‖ h_root) or
        XOF = SpongeStream(ROOT_XOF ‖ h_root)
        """
        tag = MixerTag.ROOT_XOF if xof else MixerTag.ROOT
        sponge = self._make_sponge(tag)
        sponge.absorb(tree_root)
        return sponge

    def mix(self, tape: bytes) -> bytes:
        """
        Mix the tape to produce a fixed-length digest.

        This is the main hash function.
        """
        if len(tape) == 0:
            # Empty input: single leaf with empty data
            leaf_hash = self._hash_leaf(0, b'')
            return self._hash_root(leaf_hash).finalize(self.hash_size)

        # Build leaf layer
        leaves: List[bytes] = []
        for i in range(0, len(tape), self.chunk_size):
            chunk = tape[i:i + self.chunk_size]
            leaves.append(self._hash_leaf(i // self.chunk_size, chunk))

        # Build tree bottom-up
        tree_root = self._build_tree(leaves)

        # Finalize at root
        return self._hash_root(tree_root).finalize(self.hash_size)

    def mix_xof(self, tape: bytes, length: int) -> bytes:
        """
        Mix the tape to produce extendable output (XOF mode).
        """
        if len(tape) == 0:
            leaf_hash = self._hash_leaf(0, b'')
            return self._hash_root(leaf_hash, xof=True).squeeze(length)

        leaves: List[bytes] = []
        for i in range(0, len(tape), self.chunk_size):
            chunk = tape[i:i + self.chunk_size]
            leaves.append(self._hash_leaf(i // self.chunk_size, chunk))

        tree_root = self._build_tree(leaves)
        return self._hash_root(tree_root, xof=True).squeeze(length)

    def mix_keyed(
        self,
        tape: bytes,
        key: bytes,
        role: bytes = b'MAC'
    ) -> bytes:
        """
        Keyed mixing (MAC/KDF/PRF mode).
        digest = Sponge(KEYED ‖ K ‖ ROLE_TAG ‖ TAPE)

        The key is absorbed first, providing prefix-MAC security.
        Role tag separates different keyed applications.
        """
        sponge = self._make_sponge(MixerTag.KEYED)

        # Key with length prefix (prevents length extension)
        sponge.absorb(struct.pack('>I', len(key)))
        sponge.absorb(key)

        # Role tag with length prefix
        sponge.absorb(struct.pack('>I', len(role)))
        sponge.absorb(role)

        # For large tapes, use tree structure
        if len(tape) > self.chunk_size:
            # Tree hash the tape, then absorb tree root
            leaves: List[bytes] = []
            for i in range(0, len(tape), self.chunk_size):
                chunk = tape[i:i + self.chunk_size]
                leaves.append(self._hash_leaf(i // self.chunk_size, chunk))
            tree_root = self._build_tree(leaves)
            sponge.absorb(tree_root)
        else:
            # Small tape: absorb directly
            sponge.absorb(tape)

        return sponge.finalize(self.hash_size)

    def _build_tree(self, leaves: List[bytes]) -> bytes:
        """
        Build a Merkle tree from leaves and return the root.

        Uses a complete binary tree structure.
        If odd number of nodes, the last one is promoted.
        """
        if len(leaves) == 0:
            return self._hash_leaf(0, b'')

        if len(leaves) == 1:
            return leaves[0]

        # Build tree level by level
        current_level = leaves
        while len(current_level) > 1:
            next_level: List[bytes] = []
            i = 0
            while i < len(current_level):
                if i + 1 < len(current_level):
                    # Pair exists
                    parent = self._hash_parent(
                        current_level[i],
                        current_level[i + 1]
                    )
                    next_level.append(parent)
                    i += 2
                else:
                    # Odd node: promote to next level
                    next_level.append(current_level[i])
                    i += 1
            current_level = next_level

        return current_level[0]

    def mix_streaming(self, chunks: List[bytes]) -> bytes:
        """
        Mix with streaming input (for very large data).

        Each chunk is hashed as a leaf, then tree is built.
        This allows processing data that doesn't fit in memory.
        """
        leaves: List[bytes] = []
        for i, chunk in enumerate(chunks):
            leaves.append(self._hash_leaf(i, chunk))

        if len(leaves) == 0:
            leaves.append(self._hash_leaf(0, b''))

        tree_root = self._build_tree(leaves)
        return self._hash_root(tree_root).finalize(self.hash_size)


# =============================================================================
# PARALLEL MIXER (for large inputs)
# =============================================================================

class ParallelTreeSpongeMixer(TreeSpongeMixer):
    """
    Parallel version of the tree sponge mixer.

    Uses thread pool for leaf hashing on large inputs.
    The tree structure naturally supports parallelism.
    """

    def __init__(
        self,
        chunk_size: int = TreeSpongeMixer.DEFAULT_CHUNK_SIZE,
        hash_size: int = TreeSpongeMixer.DEFAULT_HASH_SIZE,
        capacity_bits: int = TreeSpongeMixer.DEFAULT_CAPACITY,
        max_workers: Optional[int] = None
    ):
        super().__init__(chunk_size, hash_size, capacity_bits)
        self.max_workers = max_workers

    def mix(self, tape: bytes) -> bytes:
        """
        Mix with parallel leaf hashing.
        """
        if len(tape) <= self.chunk_size:
            # Small input: no parallelism needed
            return super().mix(tape)

        from concurrent.futures import ThreadPoolExecutor

        # Prepare chunks
        chunks = []
        for i in range(0, len(tape), self.chunk_size):
            chunks.append((i // self.chunk_size, tape[i:i + self.chunk_size]))

        # Parallel leaf hashing
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            leaves = list(executor.map(
                lambda x: self._hash_leaf(x[0], x[1]),
                chunks
            ))

        # Build tree (sequential, but fast)
        tree_root = self._build_tree(leaves)
        return self._hash_root(tree_root).finalize(self.hash_size)
