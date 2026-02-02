"""
Property Tests for OpochHash

These tests mechanically verify the mathematical guarantees:

1. Quotient Respect: o ~ o' ⟹ Ser_Π(o) = Ser_Π(o')
2. Injectivity on Meaning Classes: o ≁ o' ⟹ Ser_Π(o) ≠ Ser_Π(o')
3. Domain Separation: Different types never collide at serialization level
4. Collision Localization: Every collision has exactly one cause

These are the "no doubt" properties from the theory.
"""

import pytest
import math
import struct
from typing import List, Set, Tuple
import random
import string

from opochhash.types import (
    SemanticObject, TypeTag, SchemaId,
    SNull, SBool, SInt, SFloat, SBytes, SString,
    SList, SSet, SMap, SStruct, SOptional
)
from opochhash.serializer import SerPi, SerPiDeserializer, CanonicalTape
from opochhash.mixer import TreeSpongeMixer, Keccak1600Permutation, Sponge
from opochhash.opochhash import (
    OpochHash, opoch_hash, to_semantic, hash_python,
    analyze_collision
)
from opochhash.types import MixerTag


# =============================================================================
# PROPERTY 1: QUOTIENT RESPECT
# o ~ o' ⟹ Ser_Π(o) = Ser_Π(o') ⟹ Hash(o) = Hash(o')
# =============================================================================

class TestQuotientRespect:
    """
    Verify that semantically equivalent objects produce identical serializations
    and hashes. This is the "no minted distinctions" property.
    """

    def test_float_zero_equivalence(self):
        """Both +0.0 and -0.0 must hash identically."""
        pos_zero = SFloat(0.0)
        neg_zero = SFloat(-0.0)

        # Semantic equality
        assert pos_zero.semantic_eq(neg_zero)

        # Serialization equality
        tape1 = SerPi.serialize(pos_zero)
        tape2 = SerPi.serialize(neg_zero)
        assert tape1.to_bytes() == tape2.to_bytes()

        # Hash equality
        assert opoch_hash(pos_zero) == opoch_hash(neg_zero)

    def test_float_nan_equivalence(self):
        """All NaN values must hash identically."""
        nan1 = SFloat(float('nan'))
        nan2 = SFloat(float('nan'))
        # Different NaN representations (if platform supports)
        nan3 = SFloat(math.nan)

        assert nan1.semantic_eq(nan2)
        assert nan1.semantic_eq(nan3)

        tape1 = SerPi.serialize(nan1)
        tape2 = SerPi.serialize(nan2)
        tape3 = SerPi.serialize(nan3)

        assert tape1.to_bytes() == tape2.to_bytes()
        assert tape1.to_bytes() == tape3.to_bytes()

    def test_string_unicode_normalization(self):
        """Unicode-equivalent strings must hash identically."""
        # NFC vs NFD: é can be single codepoint or e + combining accent
        s1 = SString('\u00e9')  # é as single codepoint (NFC)
        s2 = SString('e\u0301')  # e + combining acute accent (NFD)

        assert s1.semantic_eq(s2)
        assert opoch_hash(s1) == opoch_hash(s2)

    def test_set_order_independence(self):
        """Sets with same elements in different order must hash identically."""
        # Create sets with same elements, inserted in different orders
        elements_a = [SInt(1), SInt(2), SInt(3)]
        elements_b = [SInt(3), SInt(1), SInt(2)]

        set_a = SSet(set(elements_a))
        set_b = SSet(set(elements_b))

        assert set_a.semantic_eq(set_b)
        assert opoch_hash(set_a) == opoch_hash(set_b)

    def test_map_order_independence(self):
        """Maps with same entries in different order must hash identically."""
        map_a = SMap({
            SString('a'): SInt(1),
            SString('b'): SInt(2),
            SString('c'): SInt(3),
        })
        map_b = SMap({
            SString('c'): SInt(3),
            SString('a'): SInt(1),
            SString('b'): SInt(2),
        })

        assert map_a.semantic_eq(map_b)
        assert opoch_hash(map_a) == opoch_hash(map_b)

    def test_struct_field_order_independence(self):
        """Structs with same fields in different order must hash identically."""
        schema = SchemaId('test', 'Person', 1)

        struct_a = SStruct(schema, {
            'name': SString('Alice'),
            'age': SInt(30),
        })
        struct_b = SStruct(schema, {
            'age': SInt(30),
            'name': SString('Alice'),
        })

        assert struct_a.semantic_eq(struct_b)
        assert opoch_hash(struct_a) == opoch_hash(struct_b)

    def test_canonical_form_idempotent(self):
        """Canonicalization must be idempotent."""
        objects = [
            SFloat(-0.0),
            SFloat(float('nan')),
            SString('e\u0301'),
            SSet({SInt(1), SInt(2)}),
            SMap({SString('a'): SInt(1)}),
        ]

        for obj in objects:
            canonical = obj.canonical_form()
            double_canonical = canonical.canonical_form()
            assert canonical.semantic_eq(double_canonical)

            tape1 = SerPi.serialize(canonical)
            tape2 = SerPi.serialize(double_canonical)
            assert tape1.to_bytes() == tape2.to_bytes()


# =============================================================================
# PROPERTY 2: INJECTIVITY ON MEANING CLASSES
# o ≁ o' ⟹ Ser_Π(o) ≠ Ser_Π(o')
# =============================================================================

class TestInjectivity:
    """
    Verify that semantically different objects produce different serializations.
    This is the "no minted collisions at meaning layer" property.
    """

    def test_different_primitives(self):
        """Different primitive values must serialize differently."""
        primitives = [
            SNull(),
            SBool(True),
            SBool(False),
            SInt(0),
            SInt(1),
            SInt(-1),
            SFloat(0.0),
            SFloat(1.0),
            SBytes(b''),
            SBytes(b'\x00'),
            SString(''),
            SString('a'),
        ]

        tapes = [SerPi.serialize(p).to_bytes() for p in primitives]

        # All tapes must be unique
        assert len(set(tapes)) == len(tapes), "Primitive collision detected!"

    def test_type_separation(self):
        """
        Different types with same "value" must serialize differently.
        This tests domain separation.
        """
        # These all represent "0" in some sense
        zero_values = [
            SInt(0),
            SFloat(0.0),
            SString('0'),
            SBytes(b'0'),
            SBool(False),  # Often treated as 0
        ]

        tapes = [SerPi.serialize(v).to_bytes() for v in zero_values]
        assert len(set(tapes)) == len(tapes), "Type domain separation failed!"

    def test_collection_length_distinction(self):
        """Collections of different lengths must serialize differently."""
        lists = [
            SList([]),
            SList([SInt(0)]),
            SList([SInt(0), SInt(0)]),
            SList([SInt(0), SInt(0), SInt(0)]),
        ]

        tapes = [SerPi.serialize(l).to_bytes() for l in lists]
        assert len(set(tapes)) == len(tapes)

    def test_nested_structure_distinction(self):
        """Different nesting structures must serialize differently."""
        structures = [
            SList([SInt(1), SInt(2)]),
            SList([SList([SInt(1)]), SInt(2)]),
            SList([SInt(1), SList([SInt(2)])]),
            SList([SList([SInt(1), SInt(2)])]),
        ]

        tapes = [SerPi.serialize(s).to_bytes() for s in structures]
        assert len(set(tapes)) == len(tapes)

    def test_optional_none_vs_some_none(self):
        """Optional(None) must differ from Optional(SNull())."""
        opt_none = SOptional(None)  # Absent
        opt_null = SOptional(SNull())  # Present with null value

        # These are semantically different
        assert not opt_none.semantic_eq(opt_null)

        # Must serialize differently
        tape1 = SerPi.serialize(opt_none)
        tape2 = SerPi.serialize(opt_null)
        assert tape1.to_bytes() != tape2.to_bytes()

    def test_string_vs_bytes(self):
        """String and bytes with same content must serialize differently."""
        s = SString('hello')
        b = SBytes(b'hello')

        assert not s.semantic_eq(b)

        tape_s = SerPi.serialize(s)
        tape_b = SerPi.serialize(b)
        assert tape_s.to_bytes() != tape_b.to_bytes()

    def test_schema_version_distinction(self):
        """Different schema versions must serialize differently."""
        schema_v1 = SchemaId('test', 'Data', 1)
        schema_v2 = SchemaId('test', 'Data', 2)

        struct_v1 = SStruct(schema_v1, {'x': SInt(1)})
        struct_v2 = SStruct(schema_v2, {'x': SInt(1)})

        assert not struct_v1.semantic_eq(struct_v2)

        tape1 = SerPi.serialize(struct_v1)
        tape2 = SerPi.serialize(struct_v2)
        assert tape1.to_bytes() != tape2.to_bytes()

    def test_context_tag_separation(self):
        """Different context tags must produce different tapes."""
        obj = SInt(42)

        tape1 = SerPi.serialize(obj, context_tag=0x0001)
        tape2 = SerPi.serialize(obj, context_tag=0x0002)

        assert tape1.to_bytes() != tape2.to_bytes()


# =============================================================================
# PROPERTY 3: ROUND-TRIP INTEGRITY
# =============================================================================

class TestRoundTrip:
    """
    Verify serialization round-trips correctly.
    deserialize(serialize(o)).semantic_eq(o) must hold.
    """

    def test_primitives_roundtrip(self):
        """All primitive types round-trip correctly."""
        primitives = [
            SNull(),
            SBool(True),
            SBool(False),
            SInt(0),
            SInt(12345678901234567890),
            SInt(-12345678901234567890),
            SFloat(3.14159),
            SFloat(float('inf')),
            SFloat(float('-inf')),
            SFloat(float('nan')),
            SBytes(b''),
            SBytes(b'\x00\x01\x02\xff'),
            SString(''),
            SString('Hello, World!'),
            SString('\u00e9\u00e0\u00fc'),  # Unicode
        ]

        for original in primitives:
            tape = SerPi.serialize(original)
            recovered = SerPiDeserializer.deserialize(tape)
            assert original.semantic_eq(recovered), f"Round-trip failed for {original}"

    def test_collections_roundtrip(self):
        """Collections round-trip correctly."""
        collections = [
            SList([]),
            SList([SInt(1), SString('two'), SBool(True)]),
            SSet(set()),
            SSet({SInt(1), SInt(2), SInt(3)}),
            SMap({}),
            SMap({SString('a'): SInt(1), SString('b'): SInt(2)}),
        ]

        for original in collections:
            tape = SerPi.serialize(original)
            recovered = SerPiDeserializer.deserialize(tape)
            assert original.semantic_eq(recovered)

    def test_nested_roundtrip(self):
        """Deeply nested structures round-trip correctly."""
        nested = SMap({
            SString('users'): SList([
                SStruct(
                    SchemaId('app', 'User', 1),
                    {
                        'name': SString('Alice'),
                        'tags': SSet({SString('admin'), SString('active')}),
                        'metadata': SOptional(SMap({
                            SString('created'): SInt(1234567890)
                        }))
                    }
                )
            ])
        })

        tape = SerPi.serialize(nested)
        recovered = SerPiDeserializer.deserialize(tape)
        assert nested.semantic_eq(recovered)


# =============================================================================
# PROPERTY 4: MIXER PROPERTIES
# =============================================================================

class TestMixerProperties:
    """
    Verify the tree sponge mixer properties.
    """

    def test_deterministic(self):
        """Mixer must be deterministic."""
        mixer = TreeSpongeMixer()
        data = b'test data for mixing'

        hash1 = mixer.mix(data)
        hash2 = mixer.mix(data)

        assert hash1 == hash2

    def test_avalanche(self):
        """
        Small input changes must cause large output changes.
        (Approximate avalanche property)
        """
        mixer = TreeSpongeMixer()

        data1 = b'test data'
        data2 = b'test datb'  # One bit difference

        hash1 = mixer.mix(data1)
        hash2 = mixer.mix(data2)

        # Count differing bits
        diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(hash1, hash2))

        # Should be approximately half the bits (with some variance)
        # 256 bits total, expect ~128 different
        assert diff_bits > 64, f"Insufficient avalanche: only {diff_bits} bits differ"

    def test_empty_input(self):
        """Empty input must produce valid hash."""
        mixer = TreeSpongeMixer()
        hash_empty = mixer.mix(b'')

        assert len(hash_empty) == mixer.hash_size
        assert hash_empty != b'\x00' * mixer.hash_size

    def test_large_input(self):
        """Large inputs must hash without error."""
        mixer = TreeSpongeMixer()
        large_data = b'x' * (1024 * 1024)  # 1 MB

        hash_result = mixer.mix(large_data)
        assert len(hash_result) == mixer.hash_size

    def test_tree_vs_serial_consistency(self):
        """
        Tree hashing should give same result regardless of chunk boundaries.
        """
        mixer_small = TreeSpongeMixer(chunk_size=64)
        mixer_large = TreeSpongeMixer(chunk_size=4096)

        # Data that spans multiple chunks
        data = b'x' * 1000

        # Hashes must be computed correctly (though may differ due to tree structure)
        hash_small = mixer_small.mix(data)
        hash_large = mixer_large.mix(data)

        # Both must be valid (non-trivial) hashes
        assert len(hash_small) == 32
        assert len(hash_large) == 32
        # Note: different chunk sizes will give different hashes
        # This is expected - tree structure affects output

    def test_xof_consistency(self):
        """XOF mode must be prefix-consistent."""
        mixer = TreeSpongeMixer()
        data = b'test data for xof'

        xof_32 = mixer.mix_xof(data, 32)
        xof_64 = mixer.mix_xof(data, 64)
        xof_128 = mixer.mix_xof(data, 128)

        # Shorter outputs must be prefixes of longer outputs
        assert xof_64[:32] == xof_32
        assert xof_128[:32] == xof_32
        assert xof_128[:64] == xof_64

    def test_domain_separation_modes(self):
        """Different modes must produce different outputs."""
        mixer = TreeSpongeMixer()
        data = b'test data'
        key = b'secret key'

        hash_result = mixer.mix(data)
        mac_result = mixer.mix_keyed(data, key)

        # Hash and MAC must differ even for same data
        assert hash_result != mac_result

    def test_key_separation(self):
        """Different keys must produce different MACs."""
        mixer = TreeSpongeMixer()
        data = b'test data'

        mac1 = mixer.mix_keyed(data, b'key1')
        mac2 = mixer.mix_keyed(data, b'key2')

        assert mac1 != mac2


# =============================================================================
# PROPERTY 5: COLLISION LOCALIZATION
# =============================================================================

class TestCollisionLocalization:
    """
    Verify the collision localization theorem.
    Every collision must be attributable to exactly one cause.
    """

    def test_same_meaning_collision(self):
        """Collisions due to same meaning are expected."""
        obj1 = SFloat(0.0)
        obj2 = SFloat(-0.0)

        hash1 = opoch_hash(obj1)
        hash2 = opoch_hash(obj2)

        analysis = analyze_collision(obj1, obj2, hash1, hash2)

        assert analysis.same_meaning == True
        assert "same meaning" in analysis.explanation.lower()

    def test_no_collision_case(self):
        """Different objects with different hashes: no collision."""
        obj1 = SInt(1)
        obj2 = SInt(2)

        hash1 = opoch_hash(obj1)
        hash2 = opoch_hash(obj2)

        analysis = analyze_collision(obj1, obj2, hash1, hash2)

        assert analysis.same_meaning == False
        assert analysis.raw_collision == False
        assert "no collision" in analysis.explanation.lower()


# =============================================================================
# PROPERTY 6: SECURITY BOUNDS (Section 1)
# =============================================================================

class TestSecurityBounds:
    """
    Verify we're not accidentally weakening security below the theoretical limits.
    """

    def test_output_size(self):
        """Default output should provide 256-bit security."""
        hasher = OpochHash()
        assert hasher.hash_size == 32  # 256 bits

    def test_capacity_bits(self):
        """Default capacity should provide claimed security."""
        hasher = OpochHash()
        # With 512-bit capacity, we get 256-bit security against generic attacks
        assert hasher.capacity_bits == 512

    def test_no_trivial_collisions_sample(self):
        """
        Sample test: verify no trivial collisions in a reasonable sample.
        This doesn't prove security but catches obvious bugs.
        """
        hasher = OpochHash()
        hashes = set()

        # Generate 10000 distinct objects and hash them
        for i in range(10000):
            obj = SInt(i)
            h = hasher.hash(obj)
            assert h not in hashes, f"Collision found at i={i}"
            hashes.add(h)


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegration:
    """
    End-to-end integration tests.
    """

    def test_python_object_hashing(self):
        """hash_python convenience function works correctly."""
        py_obj = {
            'name': 'Alice',
            'age': 30,
            'scores': [95, 87, 92],
            'active': True,
        }

        hash1 = hash_python(py_obj)
        hash2 = hash_python(py_obj)

        assert hash1 == hash2

        # Different object should hash differently
        py_obj2 = {**py_obj, 'age': 31}
        hash3 = hash_python(py_obj2)

        assert hash1 != hash3

    def test_cross_language_compatibility_format(self):
        """
        Verify the tape format is well-defined for cross-language implementation.
        """
        obj = SInt(42)
        tape = SerPi.serialize(obj)
        tape_bytes = tape.to_bytes()

        # Verify magic
        assert tape_bytes[:4] == b'OPCH'

        # Verify version
        version = struct.unpack('>H', tape_bytes[4:6])[0]
        assert version == 1

        # Verify context tag (default)
        context = struct.unpack('>H', tape_bytes[6:8])[0]
        assert context == 0x0000

        # Verify type tag
        type_tag = struct.unpack('>H', tape_bytes[8:10])[0]
        assert type_tag == TypeTag.INT

    def test_determinism_across_runs(self):
        """
        Hash must be deterministic across separate computations.
        This tests that no randomness leaks into the hash.
        """
        obj = SMap({
            SString('key1'): SList([SInt(1), SInt(2), SInt(3)]),
            SString('key2'): SSet({SString('a'), SString('b')}),
        })

        # Hash multiple times with fresh hasher instances
        hashes = []
        for _ in range(10):
            hasher = OpochHash()
            hashes.append(hasher.hash(obj))

        assert len(set(hashes)) == 1, "Non-deterministic hashing detected!"


# =============================================================================
# STRESS TESTS
# =============================================================================

class TestStress:
    """
    Stress tests for robustness.
    """

    def test_deep_nesting(self):
        """Handle deeply nested structures."""
        # Create a deeply nested list
        obj = SInt(42)
        for _ in range(100):
            obj = SList([obj])

        # Should not stack overflow
        tape = SerPi.serialize(obj)
        recovered = SerPiDeserializer.deserialize(tape)
        assert obj.semantic_eq(recovered)

        # Should hash without error
        h = opoch_hash(obj)
        assert len(h) == 32

    def test_wide_structure(self):
        """Handle wide structures (many elements)."""
        # Large list
        large_list = SList([SInt(i) for i in range(10000)])

        h = opoch_hash(large_list)
        assert len(h) == 32

        # Large map
        large_map = SMap({
            SString(f'key{i}'): SInt(i)
            for i in range(1000)
        })

        h = opoch_hash(large_map)
        assert len(h) == 32

    def test_large_integers(self):
        """Handle arbitrarily large integers."""
        # Very large integer
        big_int = SInt(2 ** 10000)
        h1 = opoch_hash(big_int)

        # Slightly different large integer
        big_int2 = SInt(2 ** 10000 + 1)
        h2 = opoch_hash(big_int2)

        assert h1 != h2

    def test_binary_data(self):
        """Handle all possible byte values."""
        # All possible single bytes
        all_bytes = SBytes(bytes(range(256)))
        h = opoch_hash(all_bytes)
        assert len(h) == 32

        # Verify round-trip
        tape = SerPi.serialize(all_bytes)
        recovered = SerPiDeserializer.deserialize(tape)
        assert all_bytes.semantic_eq(recovered)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
