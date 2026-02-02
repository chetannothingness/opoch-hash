"""
Ser_Π: The Π-Fixed Serialization Layer

Section 3: Canonical tape normal form

TAPE = TYPE_TAG ‖ VERSION ‖ SCHEMA_ID ‖ LEN-PREFIXED_FIELDS ‖
       CANONICAL_ORDER ‖ CANONICAL_NUMERIC_RULES ‖
       CANONICAL_TEXT_RULES ‖ CONTEXT_TAGS

Properties (forced):
1. Quotient respect: o ~ o' ⟹ Ser_Π(o) = Ser_Π(o')
2. Injective on meaning classes: o ≁ o' ⟹ Ser_Π(o) ≠ Ser_Π(o')
3. Domain separation: Type/version/schema/context are part of the tape
"""

from __future__ import annotations
import struct
import math
from typing import List, Tuple, Optional
from dataclasses import dataclass

from .types import (
    SemanticObject, TypeTag, SchemaId,
    SNull, SBool, SInt, SFloat, SBytes, SString,
    SList, SSet, SMap, SStruct, SOptional
)


# =============================================================================
# CANONICAL TAPE STRUCTURE
# =============================================================================

@dataclass
class CanonicalTape:
    """
    The canonical tape produced by Ser_Π.

    Structure:
    - MAGIC (4 bytes): Identifies OpochHash format
    - VERSION (2 bytes): Serialization format version
    - CONTEXT_TAG (2 bytes): Protocol/application context
    - PAYLOAD: The serialized semantic object
    """
    MAGIC = b'OPCH'
    FORMAT_VERSION = 1

    context_tag: int
    payload: bytes

    def to_bytes(self) -> bytes:
        """Produce the final tape."""
        return (
            self.MAGIC +
            struct.pack('>H', self.FORMAT_VERSION) +
            struct.pack('>H', self.context_tag) +
            self.payload
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> 'CanonicalTape':
        """Parse a canonical tape."""
        if data[:4] != cls.MAGIC:
            raise ValueError("Invalid OpochHash tape magic")
        version = struct.unpack('>H', data[4:6])[0]
        if version != cls.FORMAT_VERSION:
            raise ValueError(f"Unsupported format version: {version}")
        context_tag = struct.unpack('>H', data[6:8])[0]
        payload = data[8:]
        return cls(context_tag=context_tag, payload=payload)


# =============================================================================
# Ser_Π IMPLEMENTATION
# =============================================================================

class SerPi:
    """
    The Π-fixed serialization function.

    Ser_Π: O → Σ^(<∞)

    Guarantees:
    - Deterministic: same semantic object → same bytes
    - Quotient respect: o ~ o' ⟹ Ser_Π(o) = Ser_Π(o')
    - Injective on meaning classes: o ≁ o' ⟹ Ser_Π(o) ≠ Ser_Π(o')
    - Domain separated: type tags prevent cross-type collisions
    """

    DEFAULT_CONTEXT = 0x0000  # Default application context

    @classmethod
    def serialize(
        cls,
        obj: SemanticObject,
        context_tag: int = DEFAULT_CONTEXT
    ) -> CanonicalTape:
        """
        Serialize a semantic object to canonical tape.

        1. Canonicalize the object (apply Π projection)
        2. Serialize to bytes with TLV encoding
        3. Wrap in canonical tape format
        """
        # Step 1: Canonicalize
        canonical = obj.canonical_form()

        # Step 2: Serialize with TLV
        payload = cls._serialize_object(canonical)

        # Step 3: Wrap
        return CanonicalTape(context_tag=context_tag, payload=payload)

    @classmethod
    def _serialize_object(cls, obj: SemanticObject) -> bytes:
        """
        Serialize a canonical semantic object to TLV bytes.

        TLV Format:
        - Type (2 bytes): TypeTag
        - Length (4 bytes): Payload length (big-endian)
        - Value: Type-specific encoding
        """
        type_tag = obj.type_tag()
        value_bytes = cls._serialize_value(obj)

        return (
            struct.pack('>H', type_tag) +
            struct.pack('>I', len(value_bytes)) +
            value_bytes
        )

    @classmethod
    def _serialize_value(cls, obj: SemanticObject) -> bytes:
        """Serialize the value portion based on type."""

        if isinstance(obj, SNull):
            return b''

        elif isinstance(obj, SBool):
            return b'\x01' if obj.value else b'\x00'

        elif isinstance(obj, SInt):
            return cls._serialize_int(obj.value)

        elif isinstance(obj, SFloat):
            return cls._serialize_float(obj.value)

        elif isinstance(obj, SBytes):
            return obj.value

        elif isinstance(obj, SString):
            return obj.value.encode('utf-8')

        elif isinstance(obj, SList):
            return cls._serialize_list(obj)

        elif isinstance(obj, SSet):
            return cls._serialize_set(obj)

        elif isinstance(obj, SMap):
            return cls._serialize_map(obj)

        elif isinstance(obj, SStruct):
            return cls._serialize_struct(obj)

        elif isinstance(obj, SOptional):
            return cls._serialize_optional(obj)

        else:
            raise TypeError(f"Unknown semantic type: {type(obj)}")

    @classmethod
    def _serialize_int(cls, value: int) -> bytes:
        """
        Canonical integer serialization.

        Format:
        - Sign byte (0x00 = non-negative, 0x01 = negative)
        - Length (2 bytes): Number of magnitude bytes
        - Magnitude: Big-endian, minimal (no leading zeros)
        """
        if value == 0:
            return b'\x00\x00\x00'  # sign=0, len=0

        sign = 0x01 if value < 0 else 0x00
        magnitude = abs(value)

        # Convert to bytes, minimal representation
        byte_length = (magnitude.bit_length() + 7) // 8
        mag_bytes = magnitude.to_bytes(byte_length, 'big')

        return (
            bytes([sign]) +
            struct.pack('>H', len(mag_bytes)) +
            mag_bytes
        )

    @classmethod
    def _serialize_float(cls, value: float) -> bytes:
        """
        Canonical float serialization.

        Rules (Section 3):
        - NaN → canonical NaN representation (0x7FF8000000000000)
        - -0.0 → +0.0
        - Otherwise: IEEE 754 double, big-endian

        This ensures all semantically equal floats serialize identically.
        """
        if math.isnan(value):
            # Canonical NaN: quiet NaN with zero payload
            return b'\x7f\xf8\x00\x00\x00\x00\x00\x00'

        if value == 0.0:
            # Canonical zero: positive zero
            return b'\x00\x00\x00\x00\x00\x00\x00\x00'

        # Standard IEEE 754 big-endian
        return struct.pack('>d', value)

    @classmethod
    def _serialize_list(cls, obj: SList) -> bytes:
        """
        Serialize list: count followed by elements in order.
        Order is preserved (semantic for lists).
        """
        parts = [struct.pack('>I', len(obj.elements))]
        for elem in obj.elements:
            parts.append(cls._serialize_object(elem))
        return b''.join(parts)

    @classmethod
    def _serialize_set(cls, obj: SSet) -> bytes:
        """
        Serialize set: count followed by elements in CANONICAL ORDER.

        Canonical order: sort by serialized bytes (lexicographic).
        This ensures set{a,b} and set{b,a} serialize identically.
        """
        # Serialize each element
        serialized = [cls._serialize_object(e) for e in obj.elements]

        # Sort by bytes for canonical order
        serialized.sort()

        parts = [struct.pack('>I', len(serialized))]
        parts.extend(serialized)
        return b''.join(parts)

    @classmethod
    def _serialize_map(cls, obj: SMap) -> bytes:
        """
        Serialize map: count followed by key-value pairs in CANONICAL ORDER.

        Canonical order: sort by serialized key bytes (lexicographic).
        This ensures {a:1, b:2} and {b:2, a:1} serialize identically.
        """
        # Serialize each key-value pair
        pairs: List[Tuple[bytes, bytes]] = []
        for k, v in obj.entries.items():
            k_bytes = cls._serialize_object(k)
            v_bytes = cls._serialize_object(v)
            pairs.append((k_bytes, v_bytes))

        # Sort by key bytes for canonical order
        pairs.sort(key=lambda p: p[0])

        parts = [struct.pack('>I', len(pairs))]
        for k_bytes, v_bytes in pairs:
            parts.append(k_bytes)
            parts.append(v_bytes)
        return b''.join(parts)

    @classmethod
    def _serialize_struct(cls, obj: SStruct) -> bytes:
        """
        Serialize struct: schema ID followed by fields in CANONICAL ORDER.

        Fields are sorted by field name (UTF-8 lexicographic).
        """
        parts = [obj.schema.to_bytes()]

        # Sort fields by name
        sorted_fields = sorted(obj.fields.items(), key=lambda x: x[0])

        parts.append(struct.pack('>I', len(sorted_fields)))
        for name, value in sorted_fields:
            name_bytes = name.encode('utf-8')
            parts.append(struct.pack('>H', len(name_bytes)))
            parts.append(name_bytes)
            parts.append(cls._serialize_object(value))

        return b''.join(parts)

    @classmethod
    def _serialize_optional(cls, obj: SOptional) -> bytes:
        """
        Serialize optional: presence flag followed by value if present.

        This handles the trit-native "absent" state:
        - 0x00 = absent (None)
        - 0x01 = present (followed by value)
        """
        if obj.value is None:
            return b'\x00'
        return b'\x01' + cls._serialize_object(obj.value)


# =============================================================================
# DESERIALIZATION (for verification)
# =============================================================================

class SerPiDeserializer:
    """
    Deserialize canonical tapes back to semantic objects.
    Used for verification and round-trip testing.
    """

    @classmethod
    def deserialize(cls, tape: CanonicalTape) -> SemanticObject:
        """Deserialize a canonical tape to a semantic object."""
        obj, remaining = cls._deserialize_object(tape.payload)
        if remaining:
            raise ValueError(f"Trailing bytes in tape: {len(remaining)}")
        return obj

    @classmethod
    def _deserialize_object(cls, data: bytes) -> Tuple[SemanticObject, bytes]:
        """Deserialize a TLV-encoded object."""
        if len(data) < 6:
            raise ValueError("Truncated TLV header")

        type_tag = struct.unpack('>H', data[:2])[0]
        length = struct.unpack('>I', data[2:6])[0]

        if len(data) < 6 + length:
            raise ValueError("Truncated TLV value")

        value_bytes = data[6:6+length]
        remaining = data[6+length:]

        obj = cls._deserialize_value(TypeTag(type_tag), value_bytes)
        return obj, remaining

    @classmethod
    def _deserialize_value(cls, type_tag: TypeTag, data: bytes) -> SemanticObject:
        """Deserialize value based on type tag."""

        if type_tag == TypeTag.NULL:
            return SNull()

        elif type_tag == TypeTag.BOOL:
            return SBool(data[0] != 0)

        elif type_tag == TypeTag.INT:
            return SInt(cls._deserialize_int(data))

        elif type_tag == TypeTag.FLOAT:
            return SFloat(cls._deserialize_float(data))

        elif type_tag == TypeTag.BYTES:
            return SBytes(data)

        elif type_tag == TypeTag.STRING:
            return SString(data.decode('utf-8'))

        elif type_tag == TypeTag.LIST:
            return cls._deserialize_list(data)

        elif type_tag == TypeTag.SET:
            return cls._deserialize_set(data)

        elif type_tag == TypeTag.MAP:
            return cls._deserialize_map(data)

        elif type_tag == TypeTag.STRUCT:
            return cls._deserialize_struct(data)

        elif type_tag == TypeTag.OPTIONAL:
            return cls._deserialize_optional(data)

        else:
            raise ValueError(f"Unknown type tag: {type_tag}")

    @classmethod
    def _deserialize_int(cls, data: bytes) -> int:
        """Deserialize canonical integer."""
        sign = data[0]
        length = struct.unpack('>H', data[1:3])[0]

        if length == 0:
            return 0

        magnitude = int.from_bytes(data[3:3+length], 'big')
        return -magnitude if sign else magnitude

    @classmethod
    def _deserialize_float(cls, data: bytes) -> float:
        """Deserialize canonical float."""
        # Check for canonical NaN
        if data == b'\x7f\xf8\x00\x00\x00\x00\x00\x00':
            return float('nan')
        return struct.unpack('>d', data)[0]

    @classmethod
    def _deserialize_list(cls, data: bytes) -> SList:
        """Deserialize list."""
        count = struct.unpack('>I', data[:4])[0]
        remaining = data[4:]
        elements = []
        for _ in range(count):
            elem, remaining = cls._deserialize_object(remaining)
            elements.append(elem)
        return SList(elements)

    @classmethod
    def _deserialize_set(cls, data: bytes) -> SSet:
        """Deserialize set."""
        count = struct.unpack('>I', data[:4])[0]
        remaining = data[4:]
        elements = set()
        for _ in range(count):
            elem, remaining = cls._deserialize_object(remaining)
            elements.add(elem)
        return SSet(elements)

    @classmethod
    def _deserialize_map(cls, data: bytes) -> SMap:
        """Deserialize map."""
        count = struct.unpack('>I', data[:4])[0]
        remaining = data[4:]
        entries = {}
        for _ in range(count):
            key, remaining = cls._deserialize_object(remaining)
            value, remaining = cls._deserialize_object(remaining)
            entries[key] = value
        return SMap(entries)

    @classmethod
    def _deserialize_struct(cls, data: bytes) -> SStruct:
        """Deserialize struct."""
        schema, remaining = SchemaId.from_bytes(data)
        count = struct.unpack('>I', remaining[:4])[0]
        remaining = remaining[4:]

        fields = {}
        for _ in range(count):
            name_len = struct.unpack('>H', remaining[:2])[0]
            name = remaining[2:2+name_len].decode('utf-8')
            remaining = remaining[2+name_len:]
            value, remaining = cls._deserialize_object(remaining)
            fields[name] = value

        return SStruct(schema=schema, fields=fields)

    @classmethod
    def _deserialize_optional(cls, data: bytes) -> SOptional:
        """Deserialize optional."""
        if data[0] == 0:
            return SOptional(None)
        obj, _ = cls._deserialize_object(data[1:])
        return SOptional(obj)
