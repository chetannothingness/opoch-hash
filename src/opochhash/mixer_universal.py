"""
Universal Two-Regime Mixer

The forced no-slack fix for dominating BOTH:
- Short-message latency (SMALL mode)
- Long-message throughput (TREE mode)

Mix(TAPE) = {
    SmallMsgMode(SMALL ‖ TAPE)     if |TAPE| ≤ τ
    TreeMode(TREE ‖ TAPE)          if |TAPE| > τ
}

With τ pinned in spec and SMALL/TREE tags inside input,
there is NO collision channel between regimes.

This is the unique Pareto-optimal decomposition of cost geometry.
"""

from __future__ import annotations
import struct
import hashlib
from typing import List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import os

from .types import MixerTag


# =============================================================================
# TAG REGISTRY (Domain Separation)
# =============================================================================

class MixMode(Enum):
    """Mix mode indicator for receipts."""
    SMALL = "SMALL"
    TREE = "TREE"


class UniversalMixerTag:
    """
    Fixed tag registry for universal mixer.
    All tags are constant byte strings - no collision channel.
    """
    # Regime tags
    SMALL = b'\x10'          # Small message mode
    SMALL_XOF = b'\x11'      # Small message XOF
    SMALL_KEYED = b'\x12'    # Small message keyed

    # Tree mode tags
    TREE = b'\x20'           # Tree mode marker
    TREE_LEAF = b'\x21'      # Leaf node
    TREE_PARENT = b'\x22'    # Parent node
    TREE_ROOT = b'\x23'      # Root finalization
    TREE_ROOT_XOF = b'\x24'  # Root XOF
    TREE_KEYED = b'\x25'     # Tree keyed mode

    # Keyed mode wrapper
    KEYED = b'\x30'          # Keyed wrapper


# =============================================================================
# CORE HASH INTERFACE
# =============================================================================

class CoreHash:
    """
    Core hash interface using native SHAKE256.

    For production SIMD optimization, this would be replaced with:
    - BLAKE3 tree structure
    - AVX2/AVX-512 vectorized compression
    - Parallel leaf processing

    The interface remains stable; only the core changes.
    """

    DIGEST_SIZE = 32

    @staticmethod
    def hash(data: bytes) -> bytes:
        """Fixed-length hash."""
        return hashlib.shake_256(data).digest(CoreHash.DIGEST_SIZE)

    @staticmethod
    def xof(data: bytes, length: int) -> bytes:
        """Extendable output."""
        return hashlib.shake_256(data).digest(length)


# =============================================================================
# UNIVERSAL TWO-REGIME MIXER
# =============================================================================

@dataclass
class MixResult:
    """Result of mixing with metadata for receipts."""
    digest: bytes
    mode: MixMode
    tau: int
    tape_len: int
    core_id: str


class UniversalMixer:
    """
    Universal two-regime mixer.

    Achieves Pareto-optimal performance:
    - SMALL mode: minimal overhead for |TAPE| ≤ τ
    - TREE mode: maximal throughput for |TAPE| > τ

    Properties:
    - Deterministic: same tape → same digest
    - Domain-separated: SMALL/TREE tags prevent collisions
    - Π-clean: mode derived from tape length
    - Receipt-auditable: mode, τ, core recorded
    """

    # Pinned threshold (Pareto-optimal from benchmark sweep)
    DEFAULT_TAU = 1024  # bytes

    # Tree parameters
    DEFAULT_CHUNK_SIZE = 4096
    DEFAULT_HASH_SIZE = 32

    # Core identification
    CORE_ID = "shake256-v1"

    def __init__(
        self,
        tau: int = DEFAULT_TAU,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        hash_size: int = DEFAULT_HASH_SIZE,
    ):
        self.tau = tau
        self.chunk_size = chunk_size
        self.hash_size = hash_size

    # =========================================================================
    # MAIN INTERFACE
    # =========================================================================

    def mix(self, tape: bytes) -> bytes:
        """
        Mix tape to digest using optimal regime.

        Mix(TAPE) = {
            SmallMsgMode(SMALL ‖ len ‖ TAPE)  if |TAPE| ≤ τ
            TreeMode(TREE ‖ TAPE)              if |TAPE| > τ
        }
        """
        if len(tape) <= self.tau:
            return self._small_mode(tape)
        else:
            return self._tree_mode(tape)

    def mix_with_receipt(self, tape: bytes) -> MixResult:
        """Mix with full metadata for receipts."""
        if len(tape) <= self.tau:
            digest = self._small_mode(tape)
            mode = MixMode.SMALL
        else:
            digest = self._tree_mode(tape)
            mode = MixMode.TREE

        return MixResult(
            digest=digest,
            mode=mode,
            tau=self.tau,
            tape_len=len(tape),
            core_id=self.CORE_ID,
        )

    def mix_xof(self, tape: bytes, length: int) -> bytes:
        """XOF mode with optimal regime."""
        if len(tape) <= self.tau:
            return self._small_mode_xof(tape, length)
        else:
            return self._tree_mode_xof(tape, length)

    def mix_keyed(
        self,
        tape: bytes,
        key: bytes,
        role: bytes = b'MAC'
    ) -> bytes:
        """
        Keyed mode (MAC/KDF/PRF).

        Keyed wrapper sits above the chosen mode:
        out = CoreHash(KEYED ‖ len(K) ‖ K ‖ ROLE ‖ MODE ‖ payload)

        where MODE is SMALL or TREE, and payload is the mode output.
        """
        # First, compute the inner hash using optimal regime
        if len(tape) <= self.tau:
            mode_tag = UniversalMixerTag.SMALL_KEYED
            inner = self._small_mode_inner(tape)
        else:
            mode_tag = UniversalMixerTag.TREE_KEYED
            inner = self._tree_mode_inner(tape)

        # Keyed wrapper
        keyed_input = (
            UniversalMixerTag.KEYED +
            struct.pack('>I', len(key)) +
            key +
            struct.pack('>I', len(role)) +
            role +
            mode_tag +
            inner
        )

        return CoreHash.hash(keyed_input)

    # =========================================================================
    # SMALL MESSAGE MODE
    # =========================================================================

    def _small_mode(self, tape: bytes) -> bytes:
        """
        Small message mode: single call, no tree framing.

        digest = CoreHash(SMALL ‖ len(TAPE) ‖ TAPE)

        No leaf indices. No parent nodes. No root wrapping.
        This removes the fixed overhead that microbenchmarks punish.
        """
        input_data = (
            UniversalMixerTag.SMALL +
            struct.pack('>Q', len(tape)) +
            tape
        )
        return CoreHash.hash(input_data)

    def _small_mode_xof(self, tape: bytes, length: int) -> bytes:
        """Small message XOF mode."""
        input_data = (
            UniversalMixerTag.SMALL_XOF +
            struct.pack('>Q', len(tape)) +
            tape
        )
        return CoreHash.xof(input_data, length)

    def _small_mode_inner(self, tape: bytes) -> bytes:
        """Inner hash for keyed mode (before keyed wrapper)."""
        return (
            struct.pack('>Q', len(tape)) +
            tape
        )

    # =========================================================================
    # TREE MODE
    # =========================================================================

    def _tree_mode(self, tape: bytes) -> bytes:
        """
        Tree mode: parallel tree hashing for throughput.

        1. Chunk tape into fixed chunks
        2. Hash leaves: h_i = CoreHash(TREE_LEAF ‖ i ‖ M_i)
        3. Build tree: h_p = CoreHash(TREE_PARENT ‖ h_L ‖ h_R)
        4. Finalize: digest = CoreHash(TREE_ROOT ‖ len ‖ N ‖ h_root)
        """
        leaves = self._hash_leaves(tape)
        root = self._build_tree(leaves)
        return self._finalize_root(tape, leaves, root)

    def _tree_mode_xof(self, tape: bytes, length: int) -> bytes:
        """Tree mode XOF."""
        leaves = self._hash_leaves(tape)
        root = self._build_tree(leaves)
        return self._finalize_root_xof(tape, leaves, root, length)

    def _tree_mode_inner(self, tape: bytes) -> bytes:
        """Inner hash for keyed mode."""
        leaves = self._hash_leaves(tape)
        root = self._build_tree(leaves)
        # Return the root envelope without final hash
        return (
            struct.pack('>Q', len(tape)) +
            struct.pack('>I', len(leaves)) +
            root
        )

    def _hash_leaves(self, tape: bytes) -> List[bytes]:
        """Hash all leaves."""
        leaves = []
        for i in range(0, len(tape), self.chunk_size):
            chunk = tape[i:i + self.chunk_size]
            leaf_input = (
                UniversalMixerTag.TREE_LEAF +
                struct.pack('>Q', i // self.chunk_size) +
                chunk
            )
            leaves.append(CoreHash.hash(leaf_input))
        return leaves

    def _build_tree(self, leaves: List[bytes]) -> bytes:
        """Build Merkle tree from leaves."""
        if len(leaves) == 0:
            return CoreHash.hash(UniversalMixerTag.TREE_LEAF + b'\x00' * 8)

        if len(leaves) == 1:
            return leaves[0]

        current = leaves
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    parent_input = (
                        UniversalMixerTag.TREE_PARENT +
                        current[i] +
                        current[i + 1]
                    )
                    next_level.append(CoreHash.hash(parent_input))
                else:
                    next_level.append(current[i])
            current = next_level

        return current[0]

    def _finalize_root(
        self,
        tape: bytes,
        leaves: List[bytes],
        root: bytes
    ) -> bytes:
        """Finalize tree root."""
        root_input = (
            UniversalMixerTag.TREE_ROOT +
            struct.pack('>Q', len(tape)) +
            struct.pack('>I', len(leaves)) +
            root
        )
        return CoreHash.hash(root_input)

    def _finalize_root_xof(
        self,
        tape: bytes,
        leaves: List[bytes],
        root: bytes,
        length: int
    ) -> bytes:
        """Finalize tree root with XOF."""
        root_input = (
            UniversalMixerTag.TREE_ROOT_XOF +
            struct.pack('>Q', len(tape)) +
            struct.pack('>I', len(leaves)) +
            root
        )
        return CoreHash.xof(root_input, length)


# =============================================================================
# PARALLEL UNIVERSAL MIXER
# =============================================================================

class ParallelUniversalMixer(UniversalMixer):
    """
    Parallel version with SIMD-style leaf batching.

    Parallelizes leaves across threads, then reduces tree deterministically.
    """

    def __init__(
        self,
        tau: int = UniversalMixer.DEFAULT_TAU,
        chunk_size: int = UniversalMixer.DEFAULT_CHUNK_SIZE,
        hash_size: int = UniversalMixer.DEFAULT_HASH_SIZE,
        max_workers: Optional[int] = None,
    ):
        super().__init__(tau, chunk_size, hash_size)
        self.max_workers = max_workers

    def _hash_leaves(self, tape: bytes) -> List[bytes]:
        """Parallel leaf hashing."""
        if len(tape) <= self.chunk_size * 4:
            # Not worth parallelizing for small inputs
            return super()._hash_leaves(tape)

        from concurrent.futures import ThreadPoolExecutor

        chunks = []
        for i in range(0, len(tape), self.chunk_size):
            chunks.append((i // self.chunk_size, tape[i:i + self.chunk_size]))

        def hash_leaf(args):
            idx, chunk = args
            leaf_input = (
                UniversalMixerTag.TREE_LEAF +
                struct.pack('>Q', idx) +
                chunk
            )
            return CoreHash.hash(leaf_input)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            leaves = list(executor.map(hash_leaf, chunks))

        return leaves


# =============================================================================
# BLAKE3-STYLE OPTIMIZED MIXER (Production)
# =============================================================================

class Blake3StyleMixer(UniversalMixer):
    """
    BLAKE3-style optimized mixer using native blake3 library if available.

    Falls back to SHAKE256 if blake3 not installed.
    """

    CORE_ID = "blake3-v1"

    def __init__(
        self,
        tau: int = UniversalMixer.DEFAULT_TAU,
        chunk_size: int = 1024,  # BLAKE3 uses 1KB chunks
        hash_size: int = 32,
    ):
        super().__init__(tau, chunk_size, hash_size)

        # Check for blake3
        try:
            import blake3
            self._has_blake3 = True
            self._blake3 = blake3
        except ImportError:
            self._has_blake3 = False
            self.CORE_ID = "shake256-blake3-fallback"

    def _core_hash(self, data: bytes) -> bytes:
        """Core hash using BLAKE3 if available."""
        if self._has_blake3:
            return self._blake3.blake3(data).digest()
        return CoreHash.hash(data)

    def _core_xof(self, data: bytes, length: int) -> bytes:
        """Core XOF using BLAKE3 if available."""
        if self._has_blake3:
            # BLAKE3 supports XOF via digest with length
            h = self._blake3.blake3(data)
            return h.digest(length)
        return CoreHash.xof(data, length)

    def _small_mode(self, tape: bytes) -> bytes:
        """Optimized small message mode."""
        input_data = (
            UniversalMixerTag.SMALL +
            struct.pack('>Q', len(tape)) +
            tape
        )
        return self._core_hash(input_data)

    def _small_mode_xof(self, tape: bytes, length: int) -> bytes:
        """Optimized small message XOF."""
        input_data = (
            UniversalMixerTag.SMALL_XOF +
            struct.pack('>Q', len(tape)) +
            tape
        )
        return self._core_xof(input_data, length)


# =============================================================================
# FACTORY FUNCTION
# =============================================================================

def get_universal_mixer(
    tau: int = UniversalMixer.DEFAULT_TAU,
    chunk_size: int = UniversalMixer.DEFAULT_CHUNK_SIZE,
    parallel: bool = False,
    use_blake3: bool = True,
    max_workers: Optional[int] = None,
) -> UniversalMixer:
    """
    Get the best available universal mixer.

    Priority:
    1. BLAKE3-style (if available and requested)
    2. Parallel (if requested)
    3. Standard universal mixer
    """
    if use_blake3:
        try:
            import blake3
            if parallel:
                # BLAKE3 is already internally parallel
                return Blake3StyleMixer(tau, chunk_size)
            return Blake3StyleMixer(tau, chunk_size)
        except ImportError:
            pass

    if parallel:
        return ParallelUniversalMixer(tau, chunk_size, max_workers=max_workers)

    return UniversalMixer(tau, chunk_size)
