"""
OpochHash Fast Implementation

Production-ready OpochHash using native cryptographic libraries.
Same mathematical guarantees, optimized performance.
"""

from __future__ import annotations
from typing import Optional, Any

from .types import SemanticObject, SchemaId
from .serializer import SerPi
from .mixer_fast import get_best_mixer, FastTreeSpongeMixer


class OpochHashFast:
    """
    Production OpochHash implementation.

    Uses native SHAKE256 for mixer when available.
    Same API as OpochHash, optimized for performance.
    """

    DEFAULT_HASH_SIZE = 32
    DEFAULT_CONTEXT = 0x0000

    def __init__(
        self,
        hash_size: int = DEFAULT_HASH_SIZE,
        chunk_size: int = 4096,
        parallel: bool = False,
        max_workers: Optional[int] = None
    ):
        self.hash_size = hash_size
        self.chunk_size = chunk_size
        self.mixer = get_best_mixer(chunk_size, hash_size, parallel, max_workers)

    def hash(
        self,
        obj: SemanticObject,
        context: int = DEFAULT_CONTEXT
    ) -> bytes:
        """Hash a semantic object."""
        tape = SerPi.serialize(obj, context_tag=context)
        return self.mixer.mix(tape.to_bytes())

    def xof(
        self,
        obj: SemanticObject,
        length: int,
        context: int = DEFAULT_CONTEXT
    ) -> bytes:
        """Hash with extendable output."""
        tape = SerPi.serialize(obj, context_tag=context)
        return self.mixer.mix_xof(tape.to_bytes(), length)

    def mac(
        self,
        obj: SemanticObject,
        key: bytes,
        role: bytes = b'MAC',
        context: int = DEFAULT_CONTEXT
    ) -> bytes:
        """Keyed hashing (MAC mode)."""
        tape = SerPi.serialize(obj, context_tag=context)
        return self.mixer.mix_keyed(tape.to_bytes(), key, role)


# Default fast instance
_fast_hasher = OpochHashFast()


def opoch_hash_fast(
    obj: SemanticObject,
    context: int = OpochHashFast.DEFAULT_CONTEXT
) -> bytes:
    """Fast hash with default settings."""
    return _fast_hasher.hash(obj, context)


def opoch_xof_fast(
    obj: SemanticObject,
    length: int,
    context: int = OpochHashFast.DEFAULT_CONTEXT
) -> bytes:
    """Fast XOF with default settings."""
    return _fast_hasher.xof(obj, length, context)


def opoch_mac_fast(
    obj: SemanticObject,
    key: bytes,
    role: bytes = b'MAC',
    context: int = OpochHashFast.DEFAULT_CONTEXT
) -> bytes:
    """Fast MAC with default settings."""
    return _fast_hasher.mac(obj, key, role, context)
