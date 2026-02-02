"""
Type System and Tag Registry for OpochHash

Section 0-2 of the theory: Admissibility gate and semantic quotient Π
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from abc import ABC, abstractmethod
import struct
import math


# =============================================================================
# TAG REGISTRY (Domain Separation)
# =============================================================================

class TypeTag(IntEnum):
    """
    Minimal tag registry for domain separation.
    Every semantic object type gets a unique tag.
    Tags are 2 bytes, allowing 65536 types.
    """
    # Primitives (0x00XX)
    NULL = 0x0000
    BOOL = 0x0001
    INT = 0x0002
    FLOAT = 0x0003
    BYTES = 0x0004
    STRING = 0x0005

    # Collections (0x01XX)
    LIST = 0x0100
    SET = 0x0101
    MAP = 0x0102
    TUPLE = 0x0103

    # Structured (0x02XX)
    STRUCT = 0x0200
    ENUM = 0x0201
    UNION = 0x0202
    OPTIONAL = 0x0203

    # Semantic types (0x03XX)
    TIMESTAMP = 0x0300
    UUID = 0x0301
    URI = 0x0302
    DECIMAL = 0x0303

    # Domain-specific (0x04XX+)
    CUSTOM = 0x0400


class MixerTag(IntEnum):
    """
    Tags for the tree sponge mixer (Section 4).
    Prevents mode confusion between different operations.
    """
    LEAF = 0x00
    PARENT = 0x01
    ROOT = 0x02
    ROOT_XOF = 0x03
    KEYED = 0x04
    MAC = 0x05
    KDF = 0x06
    PRF = 0x07


@dataclass(frozen=True)
class SchemaId:
    """
    Schema identifier for structured types.
    Includes namespace, name, and version for evolution support.
    """
    namespace: str
    name: str
    version: int

    def to_bytes(self) -> bytes:
        """Canonical byte representation."""
        ns_bytes = self.namespace.encode('utf-8')
        name_bytes = self.name.encode('utf-8')
        return (
            struct.pack('>H', len(ns_bytes)) + ns_bytes +
            struct.pack('>H', len(name_bytes)) + name_bytes +
            struct.pack('>I', self.version)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Tuple['SchemaId', bytes]:
        """Parse from bytes, return (schema_id, remaining)."""
        ns_len = struct.unpack('>H', data[:2])[0]
        namespace = data[2:2+ns_len].decode('utf-8')
        offset = 2 + ns_len

        name_len = struct.unpack('>H', data[offset:offset+2])[0]
        name = data[offset+2:offset+2+name_len].decode('utf-8')
        offset += 2 + name_len

        version = struct.unpack('>I', data[offset:offset+4])[0]
        return cls(namespace, name, version), data[offset+4:]


# =============================================================================
# SEMANTIC EQUIVALENCE (The Π quotient)
# =============================================================================

class SemanticObject(ABC):
    """
    Base class for all semantic objects.

    Section 2: A hash that fingerprints meaning must satisfy:
    - No minted distinctions: o ~ o' ⟹ Hash(o) = Hash(o')
    - No minted collisions: o ≁ o' ⟹ ser_Π(o) ≠ ser_Π(o')

    Subclasses must implement:
    - canonical_form(): Return the Π-canonical representation
    - semantic_eq(): Define when two objects have same meaning
    """

    @abstractmethod
    def canonical_form(self) -> 'SemanticObject':
        """
        Return the canonical representative of this object's equivalence class.
        This is the Π projection.
        """
        pass

    @abstractmethod
    def semantic_eq(self, other: 'SemanticObject') -> bool:
        """
        Return True iff self ~ other (same meaning).
        Must be reflexive, symmetric, transitive.
        """
        pass

    @abstractmethod
    def type_tag(self) -> TypeTag:
        """Return the type tag for domain separation."""
        pass

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemanticObject):
            return False
        return self.semantic_eq(other)

    def __hash__(self) -> int:
        # Use canonical form for hashing
        return hash(self.canonical_form()._structural_hash())

    @abstractmethod
    def _structural_hash(self) -> Tuple:
        """Return a hashable tuple for structural comparison."""
        pass


# =============================================================================
# PRIMITIVE SEMANTIC TYPES
# =============================================================================

@dataclass(frozen=True)
class SNull(SemanticObject):
    """Semantic null/none value."""

    def canonical_form(self) -> 'SNull':
        return self

    def semantic_eq(self, other: SemanticObject) -> bool:
        return isinstance(other, SNull)

    def type_tag(self) -> TypeTag:
        return TypeTag.NULL

    def _structural_hash(self) -> Tuple:
        return (TypeTag.NULL,)


@dataclass(frozen=True)
class SBool(SemanticObject):
    """Semantic boolean."""
    value: bool

    def canonical_form(self) -> 'SBool':
        return self

    def semantic_eq(self, other: SemanticObject) -> bool:
        return isinstance(other, SBool) and self.value == other.value

    def type_tag(self) -> TypeTag:
        return TypeTag.BOOL

    def _structural_hash(self) -> Tuple:
        return (TypeTag.BOOL, self.value)


@dataclass(frozen=True)
class SInt(SemanticObject):
    """
    Semantic integer (arbitrary precision).
    Canonical form: no leading zeros in representation.
    """
    value: int

    def canonical_form(self) -> 'SInt':
        return self  # Python ints are already canonical

    def semantic_eq(self, other: SemanticObject) -> bool:
        return isinstance(other, SInt) and self.value == other.value

    def type_tag(self) -> TypeTag:
        return TypeTag.INT

    def _structural_hash(self) -> Tuple:
        return (TypeTag.INT, self.value)


@dataclass(frozen=True)
class SFloat(SemanticObject):
    """
    Semantic floating-point number.

    Canonical rules (Section 3):
    - NaN → single canonical NaN (no payload preservation)
    - -0.0 → +0.0
    - Infinity preserved with sign
    """
    value: float

    def canonical_form(self) -> 'SFloat':
        if math.isnan(self.value):
            return SFloat(float('nan'))  # Canonical NaN
        if self.value == 0.0:
            return SFloat(0.0)  # Canonical zero (positive)
        return self

    def semantic_eq(self, other: SemanticObject) -> bool:
        if not isinstance(other, SFloat):
            return False
        # NaN equals NaN for semantic purposes
        if math.isnan(self.value) and math.isnan(other.value):
            return True
        # -0.0 equals +0.0
        if self.value == 0.0 and other.value == 0.0:
            return True
        return self.value == other.value

    def type_tag(self) -> TypeTag:
        return TypeTag.FLOAT

    def _structural_hash(self) -> Tuple:
        cf = self.canonical_form()
        if math.isnan(cf.value):
            return (TypeTag.FLOAT, "NaN")
        return (TypeTag.FLOAT, cf.value)


@dataclass(frozen=True)
class SBytes(SemanticObject):
    """Semantic byte sequence."""
    value: bytes

    def canonical_form(self) -> 'SBytes':
        return self

    def semantic_eq(self, other: SemanticObject) -> bool:
        return isinstance(other, SBytes) and self.value == other.value

    def type_tag(self) -> TypeTag:
        return TypeTag.BYTES

    def _structural_hash(self) -> Tuple:
        return (TypeTag.BYTES, self.value)


@dataclass(frozen=True)
class SString(SemanticObject):
    """
    Semantic string.

    Canonical rules (Section 3):
    - NFC normalization
    - No leading/trailing whitespace (configurable)
    - Consistent line endings
    """
    value: str
    normalize_whitespace: bool = False

    def canonical_form(self) -> 'SString':
        import unicodedata
        normalized = unicodedata.normalize('NFC', self.value)
        if self.normalize_whitespace:
            # Normalize line endings to \n
            normalized = normalized.replace('\r\n', '\n').replace('\r', '\n')
            # Strip leading/trailing whitespace
            normalized = normalized.strip()
        return SString(normalized, self.normalize_whitespace)

    def semantic_eq(self, other: SemanticObject) -> bool:
        if not isinstance(other, SString):
            return False
        return self.canonical_form().value == other.canonical_form().value

    def type_tag(self) -> TypeTag:
        return TypeTag.STRING

    def _structural_hash(self) -> Tuple:
        return (TypeTag.STRING, self.canonical_form().value)


# =============================================================================
# COLLECTION SEMANTIC TYPES
# =============================================================================

@dataclass
class SList(SemanticObject):
    """
    Semantic list (ordered sequence).
    Order matters for semantic equality.
    """
    elements: List[SemanticObject] = field(default_factory=list)

    def canonical_form(self) -> 'SList':
        return SList([e.canonical_form() for e in self.elements])

    def semantic_eq(self, other: SemanticObject) -> bool:
        if not isinstance(other, SList):
            return False
        if len(self.elements) != len(other.elements):
            return False
        return all(a.semantic_eq(b) for a, b in zip(self.elements, other.elements))

    def type_tag(self) -> TypeTag:
        return TypeTag.LIST

    def _structural_hash(self) -> Tuple:
        cf = self.canonical_form()
        return (TypeTag.LIST, tuple(e._structural_hash() for e in cf.elements))


@dataclass
class SSet(SemanticObject):
    """
    Semantic set (unordered, unique elements).
    Canonical form: sorted by canonical serialization.
    """
    elements: Set[SemanticObject] = field(default_factory=set)

    def canonical_form(self) -> 'SSet':
        return SSet({e.canonical_form() for e in self.elements})

    def semantic_eq(self, other: SemanticObject) -> bool:
        if not isinstance(other, SSet):
            return False
        if len(self.elements) != len(other.elements):
            return False
        # Check that every element in self has a semantic match in other
        other_canonical = [e.canonical_form() for e in other.elements]
        for e in self.elements:
            ec = e.canonical_form()
            if not any(ec.semantic_eq(oc) for oc in other_canonical):
                return False
        return True

    def type_tag(self) -> TypeTag:
        return TypeTag.SET

    def _structural_hash(self) -> Tuple:
        cf = self.canonical_form()
        # Sort by structural hash for determinism
        sorted_hashes = sorted(e._structural_hash() for e in cf.elements)
        return (TypeTag.SET, tuple(sorted_hashes))


@dataclass
class SMap(SemanticObject):
    """
    Semantic map (key-value pairs).
    Canonical form: sorted by canonical key serialization.
    """
    entries: Dict[SemanticObject, SemanticObject] = field(default_factory=dict)

    def canonical_form(self) -> 'SMap':
        return SMap({
            k.canonical_form(): v.canonical_form()
            for k, v in self.entries.items()
        })

    def semantic_eq(self, other: SemanticObject) -> bool:
        if not isinstance(other, SMap):
            return False
        if len(self.entries) != len(other.entries):
            return False
        self_cf = self.canonical_form()
        other_cf = other.canonical_form()
        # Compare canonical forms
        for k, v in self_cf.entries.items():
            found = False
            for ok, ov in other_cf.entries.items():
                if k.semantic_eq(ok) and v.semantic_eq(ov):
                    found = True
                    break
            if not found:
                return False
        return True

    def type_tag(self) -> TypeTag:
        return TypeTag.MAP

    def _structural_hash(self) -> Tuple:
        cf = self.canonical_form()
        # Sort by key hash for determinism
        sorted_pairs = sorted(
            (k._structural_hash(), v._structural_hash())
            for k, v in cf.entries.items()
        )
        return (TypeTag.MAP, tuple(sorted_pairs))


# =============================================================================
# STRUCTURED SEMANTIC TYPES
# =============================================================================

@dataclass
class SStruct(SemanticObject):
    """
    Semantic struct (named fields with schema).

    Schema ID enables version evolution and cross-language compatibility.
    """
    schema: SchemaId
    fields: Dict[str, SemanticObject] = field(default_factory=dict)

    def canonical_form(self) -> 'SStruct':
        return SStruct(
            schema=self.schema,
            fields={k: v.canonical_form() for k, v in self.fields.items()}
        )

    def semantic_eq(self, other: SemanticObject) -> bool:
        if not isinstance(other, SStruct):
            return False
        if self.schema != other.schema:
            return False
        if set(self.fields.keys()) != set(other.fields.keys()):
            return False
        return all(
            self.fields[k].semantic_eq(other.fields[k])
            for k in self.fields
        )

    def type_tag(self) -> TypeTag:
        return TypeTag.STRUCT

    def _structural_hash(self) -> Tuple:
        cf = self.canonical_form()
        sorted_fields = sorted(
            (k, v._structural_hash())
            for k, v in cf.fields.items()
        )
        return (TypeTag.STRUCT, self.schema, tuple(sorted_fields))


@dataclass
class SOptional(SemanticObject):
    """
    Semantic optional (present or absent).

    This handles the trit-native "absent/default/indifferent" case from Section 3:
    - None = absent
    - Some(value) = present
    """
    value: Optional[SemanticObject] = None

    def canonical_form(self) -> 'SOptional':
        if self.value is None:
            return SOptional(None)
        return SOptional(self.value.canonical_form())

    def semantic_eq(self, other: SemanticObject) -> bool:
        if not isinstance(other, SOptional):
            return False
        if self.value is None and other.value is None:
            return True
        if self.value is None or other.value is None:
            return False
        return self.value.semantic_eq(other.value)

    def type_tag(self) -> TypeTag:
        return TypeTag.OPTIONAL

    def _structural_hash(self) -> Tuple:
        if self.value is None:
            return (TypeTag.OPTIONAL, None)
        return (TypeTag.OPTIONAL, self.value.canonical_form()._structural_hash())
