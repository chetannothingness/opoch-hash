"""
Fast Mixer Implementation

This module provides an optimized mixer using native cryptographic libraries.
Falls back to pure Python implementation if native libraries unavailable.

The pure Python implementation (mixer.py) serves as:
1. Reference implementation for correctness
2. Fallback when native libraries unavailable
3. Test oracle for verifying fast implementations

Production deployments should use this fast implementation.
"""

from __future__ import annotations
import struct
import hashlib
from typing import List, Optional

from .types import MixerTag


# =============================================================================
# TRY NATIVE IMPLEMENTATIONS
# =============================================================================

_HAS_NATIVE_SHAKE = hasattr(hashlib, 'shake_256')


class FastSponge:
    """
    Fast sponge using native SHAKE256 (Keccak-based XOF).

    SHAKE256 is part of SHA-3 family and provides:
    - 256-bit security level
    - Extendable output (XOF)
    - Native C implementation in hashlib

    We use domain separation by prefixing the tag to input.
    """

    def __init__(self, domain_tag: MixerTag):
        if not _HAS_NATIVE_SHAKE:
            raise RuntimeError("Native SHAKE256 not available")
        self._hasher = hashlib.shake_256()
        # Domain separation: absorb tag first
        self._hasher.update(bytes([domain_tag]))
        self._finalized = False

    def absorb(self, data: bytes) -> 'FastSponge':
        if self._finalized:
            raise RuntimeError("Cannot absorb after squeezing")
        self._hasher.update(data)
        return self

    def squeeze(self, length: int) -> bytes:
        self._finalized = True
        return self._hasher.digest(length)

    def finalize(self, length: int = 32) -> bytes:
        return self.squeeze(length)


class FastTreeSpongeMixer:
    """
    High-performance tree sponge mixer using native SHAKE256.

    Same interface as TreeSpongeMixer but uses native implementations.
    Falls back to pure Python if native libs unavailable.
    """

    DEFAULT_CHUNK_SIZE = 4096
    DEFAULT_HASH_SIZE = 32

    def __init__(
        self,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        hash_size: int = DEFAULT_HASH_SIZE,
    ):
        self.chunk_size = chunk_size
        self.hash_size = hash_size

        if not _HAS_NATIVE_SHAKE:
            # Fall back to pure Python
            from .mixer import TreeSpongeMixer
            self._fallback = TreeSpongeMixer(chunk_size, hash_size)
        else:
            self._fallback = None

    def _shake_hash(self, tag: MixerTag, *inputs: bytes) -> bytes:
        """Hash with domain separation using SHAKE256."""
        h = hashlib.shake_256()
        h.update(bytes([tag]))
        for inp in inputs:
            h.update(inp)
        return h.digest(self.hash_size)

    def _hash_leaf(self, index: int, data: bytes) -> bytes:
        """Hash a leaf node with index."""
        return self._shake_hash(
            MixerTag.LEAF,
            struct.pack('>Q', index),
            data
        )

    def _hash_parent(self, left: bytes, right: bytes) -> bytes:
        """Hash a parent node."""
        return self._shake_hash(MixerTag.PARENT, left, right)

    def _hash_root(self, tree_root: bytes) -> bytes:
        """Hash the root."""
        return self._shake_hash(MixerTag.ROOT, tree_root)

    def _build_tree(self, leaves: List[bytes]) -> bytes:
        """Build tree from leaves."""
        if len(leaves) == 0:
            return self._hash_leaf(0, b'')
        if len(leaves) == 1:
            return leaves[0]

        current = leaves
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    next_level.append(self._hash_parent(current[i], current[i + 1]))
                else:
                    next_level.append(current[i])
            current = next_level
        return current[0]

    def mix(self, tape: bytes) -> bytes:
        """Mix tape to produce fixed-length digest."""
        if self._fallback:
            return self._fallback.mix(tape)

        if len(tape) == 0:
            leaf = self._hash_leaf(0, b'')
            return self._hash_root(leaf)

        # Build leaves
        leaves = []
        for i in range(0, len(tape), self.chunk_size):
            chunk = tape[i:i + self.chunk_size]
            leaves.append(self._hash_leaf(i // self.chunk_size, chunk))

        tree_root = self._build_tree(leaves)
        return self._hash_root(tree_root)

    def mix_xof(self, tape: bytes, length: int) -> bytes:
        """Mix with extendable output."""
        if self._fallback:
            return self._fallback.mix_xof(tape, length)

        if len(tape) == 0:
            leaf = self._hash_leaf(0, b'')
            h = hashlib.shake_256()
            h.update(bytes([MixerTag.ROOT_XOF]))
            h.update(leaf)
            return h.digest(length)

        leaves = []
        for i in range(0, len(tape), self.chunk_size):
            chunk = tape[i:i + self.chunk_size]
            leaves.append(self._hash_leaf(i // self.chunk_size, chunk))

        tree_root = self._build_tree(leaves)

        h = hashlib.shake_256()
        h.update(bytes([MixerTag.ROOT_XOF]))
        h.update(tree_root)
        return h.digest(length)

    def mix_keyed(
        self,
        tape: bytes,
        key: bytes,
        role: bytes = b'MAC'
    ) -> bytes:
        """Keyed mixing (MAC mode)."""
        if self._fallback:
            return self._fallback.mix_keyed(tape, key, role)

        h = hashlib.shake_256()
        h.update(bytes([MixerTag.KEYED]))

        # Key with length prefix
        h.update(struct.pack('>I', len(key)))
        h.update(key)

        # Role with length prefix
        h.update(struct.pack('>I', len(role)))
        h.update(role)

        # For large tapes, tree hash first
        if len(tape) > self.chunk_size:
            leaves = []
            for i in range(0, len(tape), self.chunk_size):
                chunk = tape[i:i + self.chunk_size]
                leaves.append(self._hash_leaf(i // self.chunk_size, chunk))
            tree_root = self._build_tree(leaves)
            h.update(tree_root)
        else:
            h.update(tape)

        return h.digest(self.hash_size)


# =============================================================================
# PARALLEL FAST MIXER
# =============================================================================

class ParallelFastTreeSpongeMixer(FastTreeSpongeMixer):
    """
    Parallel version using thread pool for leaf hashing.
    """

    def __init__(
        self,
        chunk_size: int = FastTreeSpongeMixer.DEFAULT_CHUNK_SIZE,
        hash_size: int = FastTreeSpongeMixer.DEFAULT_HASH_SIZE,
        max_workers: Optional[int] = None
    ):
        super().__init__(chunk_size, hash_size)
        self.max_workers = max_workers

    def mix(self, tape: bytes) -> bytes:
        """Parallel tree hashing for large inputs."""
        if self._fallback:
            from .mixer import ParallelTreeSpongeMixer
            return ParallelTreeSpongeMixer(
                self.chunk_size,
                self.hash_size,
                max_workers=self.max_workers
            ).mix(tape)

        if len(tape) <= self.chunk_size:
            return super().mix(tape)

        from concurrent.futures import ThreadPoolExecutor

        chunks = []
        for i in range(0, len(tape), self.chunk_size):
            chunks.append((i // self.chunk_size, tape[i:i + self.chunk_size]))

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            leaves = list(executor.map(
                lambda x: self._hash_leaf(x[0], x[1]),
                chunks
            ))

        tree_root = self._build_tree(leaves)
        return self._hash_root(tree_root)


# =============================================================================
# AUTO-SELECT BEST AVAILABLE
# =============================================================================

def get_best_mixer(
    chunk_size: int = 4096,
    hash_size: int = 32,
    parallel: bool = False,
    max_workers: Optional[int] = None
):
    """
    Get the best available mixer implementation.

    Returns FastTreeSpongeMixer if native SHAKE256 available,
    otherwise returns pure Python TreeSpongeMixer.
    """
    if _HAS_NATIVE_SHAKE:
        if parallel:
            return ParallelFastTreeSpongeMixer(chunk_size, hash_size, max_workers)
        return FastTreeSpongeMixer(chunk_size, hash_size)
    else:
        from .mixer import TreeSpongeMixer, ParallelTreeSpongeMixer
        if parallel:
            return ParallelTreeSpongeMixer(chunk_size, hash_size, max_workers=max_workers)
        return TreeSpongeMixer(chunk_size, hash_size)
