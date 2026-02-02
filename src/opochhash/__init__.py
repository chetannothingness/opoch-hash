"""
OpochHash: Semantic Hashing from First Principles

OpochHash = TreeSpongeMixer ∘ Ser_Π

A complete "hashing from nothingness" resolution:
- Compile meaning to Π-fixed tape (no slack)
- Mix with canonical, domain-separated tree sponge (no mode/framing ambiguity)
- Explicit accountability for every collision cause
- Security bounded exactly by irreducible counting limits

Usage:
    from opochhash import opoch_hash, SInt, SString, SMap

    # Hash semantic objects
    digest = opoch_hash(SInt(42))
    digest = opoch_hash(SString("hello"))
    digest = opoch_hash(SMap({SString("key"): SInt(1)}))

    # Hash Python objects directly
    from opochhash import hash_python
    digest = hash_python({"name": "Alice", "age": 30})

    # For production performance, use the fast implementation
    from opochhash import OpochHashFast, opoch_hash_fast
    digest = opoch_hash_fast(SInt(42))
"""

# Types
from .types import (
    SemanticObject,
    TypeTag,
    SchemaId,
    MixerTag,
    SNull,
    SBool,
    SInt,
    SFloat,
    SBytes,
    SString,
    SList,
    SSet,
    SMap,
    SStruct,
    SOptional,
)

# Serialization
from .serializer import SerPi, SerPiDeserializer, CanonicalTape

# Mixers
from .mixer import TreeSpongeMixer, ParallelTreeSpongeMixer, Sponge
from .mixer_fast import FastTreeSpongeMixer, ParallelFastTreeSpongeMixer, get_best_mixer

# Main API (reference implementation)
from .opochhash import (
    OpochHash,
    opoch_hash,
    opoch_xof,
    opoch_mac,
    to_semantic,
    hash_python,
    analyze_collision,
    CollisionAnalysis,
)

# Fast API (production implementation)
from .opochhash_fast import (
    OpochHashFast,
    opoch_hash_fast,
    opoch_xof_fast,
    opoch_mac_fast,
)

__version__ = "0.1.0"

__all__ = [
    # Version
    "__version__",
    # Types
    "SemanticObject",
    "TypeTag",
    "SchemaId",
    "MixerTag",
    "SNull",
    "SBool",
    "SInt",
    "SFloat",
    "SBytes",
    "SString",
    "SList",
    "SSet",
    "SMap",
    "SStruct",
    "SOptional",
    # Serialization
    "SerPi",
    "SerPiDeserializer",
    "CanonicalTape",
    # Mixers
    "TreeSpongeMixer",
    "ParallelTreeSpongeMixer",
    "FastTreeSpongeMixer",
    "ParallelFastTreeSpongeMixer",
    "Sponge",
    "get_best_mixer",
    # Reference API
    "OpochHash",
    "opoch_hash",
    "opoch_xof",
    "opoch_mac",
    "to_semantic",
    "hash_python",
    "analyze_collision",
    "CollisionAnalysis",
    # Fast API
    "OpochHashFast",
    "opoch_hash_fast",
    "opoch_xof_fast",
    "opoch_mac_fast",
]
