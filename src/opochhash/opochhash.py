"""
OpochHash: The Complete Construction

Section 5 & 7: OpochHash = TreeSpongeMixer ∘ Ser_Π

This is the complete "hashing from nothingness" resolution:
- First compile meaning to a Π-fixed tape (no slack)
- Then mix with a canonical, domain-separated tree sponge
- With explicit accountability for every collision cause
- And security bounded exactly by the irreducible counting limits

Collision Localization Theorem:
If OpochHash(o) = OpochHash(o'), exactly one holds:
1. o ~ o' (same meaning), or
2. Ser_Π violated injectivity (serialization bug), or
3. Mix collided on distinct tapes (cryptographic collision), or
4. Output truncation caused collision (birthday at truncated length)
"""

from __future__ import annotations
from typing import Optional, Union, Any, Dict, List
from dataclasses import dataclass

from .types import (
    SemanticObject, TypeTag, SchemaId,
    SNull, SBool, SInt, SFloat, SBytes, SString,
    SList, SSet, SMap, SStruct, SOptional
)
from .serializer import SerPi, CanonicalTape
from .mixer import TreeSpongeMixer, ParallelTreeSpongeMixer


# =============================================================================
# OPOCHHASH MAIN CLASS
# =============================================================================

class OpochHash:
    """
    OpochHash = TreeSpongeMixer ∘ Ser_Π

    The complete semantic hashing construction with:
    - Meaning canonicalization (Ser_Π layer)
    - Domain-separated tree sponge mixing (mixer layer)
    - Explicit collision accountability
    - Optimal security bounds

    Usage:
        # Hash a semantic object
        digest = OpochHash.hash(my_object)

        # Hash with custom context (protocol separation)
        digest = OpochHash.hash(my_object, context=0x0001)

        # XOF mode (extendable output)
        key_material = OpochHash.xof(my_object, length=64)

        # Keyed mode (MAC/PRF)
        mac = OpochHash.mac(my_object, key=my_key)
    """

    DEFAULT_HASH_SIZE = 32  # 256 bits
    DEFAULT_CONTEXT = 0x0000

    def __init__(
        self,
        hash_size: int = DEFAULT_HASH_SIZE,
        chunk_size: int = 4096,
        capacity_bits: int = 512,
        parallel: bool = False,
        max_workers: Optional[int] = None
    ):
        """
        Initialize OpochHash with configuration.

        Args:
            hash_size: Output size in bytes (default 32 = 256 bits)
            chunk_size: Chunk size for tree hashing (default 4096)
            capacity_bits: Sponge capacity in bits (default 512 = 256-bit security)
            parallel: Enable parallel tree hashing for large inputs
            max_workers: Max threads for parallel mode (None = auto)
        """
        self.hash_size = hash_size
        self.chunk_size = chunk_size
        self.capacity_bits = capacity_bits

        if parallel:
            self.mixer = ParallelTreeSpongeMixer(
                chunk_size=chunk_size,
                hash_size=hash_size,
                capacity_bits=capacity_bits,
                max_workers=max_workers
            )
        else:
            self.mixer = TreeSpongeMixer(
                chunk_size=chunk_size,
                hash_size=hash_size,
                capacity_bits=capacity_bits
            )

    def hash(
        self,
        obj: SemanticObject,
        context: int = DEFAULT_CONTEXT
    ) -> bytes:
        """
        Hash a semantic object.

        OpochHash(o) = Mix(Ser_Π(o))

        Args:
            obj: The semantic object to hash
            context: Protocol/application context tag for domain separation

        Returns:
            The hash digest (hash_size bytes)
        """
        # Step 1: Ser_Π - serialize to canonical tape
        tape = SerPi.serialize(obj, context_tag=context)

        # Step 2: Mix - apply tree sponge mixer
        return self.mixer.mix(tape.to_bytes())

    def xof(
        self,
        obj: SemanticObject,
        length: int,
        context: int = DEFAULT_CONTEXT
    ) -> bytes:
        """
        Hash with extendable output (XOF mode).

        Useful for key derivation and generating arbitrary-length output.

        Args:
            obj: The semantic object to hash
            length: Desired output length in bytes
            context: Protocol/application context tag

        Returns:
            XOF output (length bytes)
        """
        tape = SerPi.serialize(obj, context_tag=context)
        return self.mixer.mix_xof(tape.to_bytes(), length)

    def mac(
        self,
        obj: SemanticObject,
        key: bytes,
        role: bytes = b'MAC',
        context: int = DEFAULT_CONTEXT
    ) -> bytes:
        """
        Keyed hashing (MAC mode).

        Args:
            obj: The semantic object to authenticate
            key: The secret key
            role: Role tag (MAC, KDF, PRF, etc.)
            context: Protocol/application context tag

        Returns:
            The MAC (hash_size bytes)
        """
        tape = SerPi.serialize(obj, context_tag=context)
        return self.mixer.mix_keyed(tape.to_bytes(), key, role)

    def kdf(
        self,
        obj: SemanticObject,
        key: bytes,
        length: int,
        context: int = DEFAULT_CONTEXT
    ) -> bytes:
        """
        Key derivation function mode.

        Args:
            obj: The semantic object (context/info)
            key: The input key material
            length: Desired output length in bytes
            context: Protocol/application context tag

        Returns:
            Derived key material (length bytes)
        """
        # For KDF, we use the keyed mode followed by XOF
        tape = SerPi.serialize(obj, context_tag=context)
        tape_bytes = tape.to_bytes()

        # First, compute the intermediate keyed hash
        from .mixer import MixerTag, Sponge, Keccak1600Permutation
        perm = Keccak1600Permutation(self.capacity_bits)
        sponge = Sponge(perm, MixerTag.KDF)

        # Absorb key
        import struct
        sponge.absorb(struct.pack('>I', len(key)))
        sponge.absorb(key)

        # Absorb tape
        sponge.absorb(tape_bytes)

        # Squeeze to desired length
        return sponge.squeeze(length)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

# Default global instance
_default_hasher = OpochHash()


def opoch_hash(
    obj: SemanticObject,
    context: int = OpochHash.DEFAULT_CONTEXT
) -> bytes:
    """Hash a semantic object with default settings."""
    return _default_hasher.hash(obj, context)


def opoch_xof(
    obj: SemanticObject,
    length: int,
    context: int = OpochHash.DEFAULT_CONTEXT
) -> bytes:
    """Hash with XOF mode using default settings."""
    return _default_hasher.xof(obj, length, context)


def opoch_mac(
    obj: SemanticObject,
    key: bytes,
    role: bytes = b'MAC',
    context: int = OpochHash.DEFAULT_CONTEXT
) -> bytes:
    """MAC a semantic object with default settings."""
    return _default_hasher.mac(obj, key, role, context)


# =============================================================================
# PYTHON OBJECT CONVERSION
# =============================================================================

def to_semantic(obj: Any, schema: Optional[SchemaId] = None) -> SemanticObject:
    """
    Convert a Python object to a SemanticObject.

    This is a convenience function for common Python types.
    For custom types, create SemanticObject subclasses directly.
    """
    if obj is None:
        return SNull()

    if isinstance(obj, bool):
        return SBool(obj)

    if isinstance(obj, int):
        return SInt(obj)

    if isinstance(obj, float):
        return SFloat(obj)

    if isinstance(obj, bytes):
        return SBytes(obj)

    if isinstance(obj, str):
        return SString(obj)

    if isinstance(obj, list):
        return SList([to_semantic(e) for e in obj])

    if isinstance(obj, set):
        return SSet({to_semantic(e) for e in obj})

    if isinstance(obj, dict):
        # Check if it's a struct (string keys) or a map
        if all(isinstance(k, str) for k in obj.keys()):
            if schema is not None:
                return SStruct(
                    schema=schema,
                    fields={k: to_semantic(v) for k, v in obj.items()}
                )
            # Without schema, treat as map
            return SMap({
                to_semantic(k): to_semantic(v)
                for k, v in obj.items()
            })
        return SMap({
            to_semantic(k): to_semantic(v)
            for k, v in obj.items()
        })

    if isinstance(obj, tuple):
        return SList([to_semantic(e) for e in obj])

    if isinstance(obj, SemanticObject):
        return obj

    raise TypeError(f"Cannot convert {type(obj)} to SemanticObject")


def hash_python(
    obj: Any,
    context: int = OpochHash.DEFAULT_CONTEXT,
    schema: Optional[SchemaId] = None
) -> bytes:
    """
    Hash a Python object directly.

    Converts to SemanticObject first, then hashes.
    """
    semantic = to_semantic(obj, schema)
    return opoch_hash(semantic, context)


# =============================================================================
# COLLISION ACCOUNTABILITY (Section 5)
# =============================================================================

@dataclass
class CollisionAnalysis:
    """
    Analysis of a potential collision.

    Per the Collision Localization Theorem, if OpochHash(o) = OpochHash(o'),
    exactly one of these holds:
    1. Same meaning (o ~ o')
    2. Serialization bug (Ser_Π violated injectivity)
    3. Cryptographic collision (Mix collided)
    4. Truncation collision (at shorter output length)
    """
    same_meaning: bool
    serialization_matches: bool
    raw_collision: bool
    truncation_issue: bool
    explanation: str


def analyze_collision(
    obj1: SemanticObject,
    obj2: SemanticObject,
    hash1: bytes,
    hash2: bytes
) -> CollisionAnalysis:
    """
    Analyze a collision between two objects.

    This implements the accountability guarantee from Section 5:
    every collision is attributable to exactly one cause.
    """
    # Check semantic equality
    same_meaning = obj1.semantic_eq(obj2)

    # Check serialization
    tape1 = SerPi.serialize(obj1).to_bytes()
    tape2 = SerPi.serialize(obj2).to_bytes()
    serialization_matches = (tape1 == tape2)

    # Check if hashes match
    hash_matches = (hash1 == hash2)

    if hash_matches:
        if same_meaning:
            return CollisionAnalysis(
                same_meaning=True,
                serialization_matches=True,
                raw_collision=False,
                truncation_issue=False,
                explanation="Objects have same meaning (o ~ o'). This is expected behavior."
            )

        if serialization_matches:
            return CollisionAnalysis(
                same_meaning=False,
                serialization_matches=True,
                raw_collision=False,
                truncation_issue=False,
                explanation="SERIALIZATION BUG: Different meanings produced same tape. "
                           "Check Ser_Π injectivity on meaning classes."
            )

        # Different tapes, same hash -> cryptographic collision or truncation
        return CollisionAnalysis(
            same_meaning=False,
            serialization_matches=False,
            raw_collision=True,
            truncation_issue=(len(hash1) < 32),
            explanation="MIXER COLLISION: Different tapes produced same hash. "
                       "This is either a cryptographic collision (very rare) "
                       "or truncation issue (if using short output)."
        )

    # No collision
    return CollisionAnalysis(
        same_meaning=same_meaning,
        serialization_matches=serialization_matches,
        raw_collision=False,
        truncation_issue=False,
        explanation="No collision: hashes differ."
    )
