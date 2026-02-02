"""
Property-Based Testing with Hypothesis

These tests use Hypothesis to generate random inputs and verify
the mathematical properties hold for all cases.

This provides stronger guarantees than example-based tests by
exploring the input space systematically.
"""

import pytest
from hypothesis import given, strategies as st, settings, assume
from hypothesis.strategies import composite
import math

from opochhash.types import (
    SemanticObject, TypeTag, SchemaId,
    SNull, SBool, SInt, SFloat, SBytes, SString,
    SList, SSet, SMap, SStruct, SOptional
)
from opochhash.serializer import SerPi, SerPiDeserializer
from opochhash.opochhash import OpochHash, opoch_hash


# =============================================================================
# STRATEGIES FOR GENERATING SEMANTIC OBJECTS
# =============================================================================

@composite
def semantic_primitives(draw):
    """Generate random primitive semantic objects."""
    choice = draw(st.integers(min_value=0, max_value=5))

    if choice == 0:
        return SNull()
    elif choice == 1:
        return SBool(draw(st.booleans()))
    elif choice == 2:
        return SInt(draw(st.integers()))
    elif choice == 3:
        # Include special floats
        f = draw(st.one_of(
            st.floats(allow_nan=True, allow_infinity=True),
            st.just(0.0),
            st.just(-0.0),
        ))
        return SFloat(f)
    elif choice == 4:
        return SBytes(draw(st.binary(max_size=1000)))
    else:
        return SString(draw(st.text(max_size=100)))


@composite
def semantic_objects(draw, max_depth=3):
    """Generate random semantic objects (potentially nested)."""
    if max_depth <= 0:
        return draw(semantic_primitives())

    choice = draw(st.integers(min_value=0, max_value=9))

    if choice <= 5:
        # Primitive (weighted toward primitives to avoid explosion)
        return draw(semantic_primitives())
    elif choice == 6:
        # List
        elements = draw(st.lists(
            st.deferred(lambda: semantic_objects(max_depth=max_depth-1)),
            max_size=5
        ))
        return SList(elements)
    elif choice == 7:
        # Set (only hashable elements)
        elements = draw(st.lists(
            semantic_primitives(),
            max_size=5,
            unique_by=lambda x: x._structural_hash()
        ))
        return SSet(set(elements))
    elif choice == 8:
        # Map
        keys = draw(st.lists(
            semantic_primitives(),
            max_size=5,
            unique_by=lambda x: x._structural_hash()
        ))
        values = draw(st.lists(
            st.deferred(lambda: semantic_objects(max_depth=max_depth-1)),
            min_size=len(keys),
            max_size=len(keys)
        ))
        return SMap({k: v for k, v in zip(keys, values)})
    else:
        # Optional
        has_value = draw(st.booleans())
        if has_value:
            return SOptional(draw(semantic_objects(max_depth=max_depth-1)))
        return SOptional(None)


# =============================================================================
# PROPERTY: DETERMINISM
# =============================================================================

class TestDeterminism:
    """Hashing must be deterministic."""

    @given(obj=semantic_objects())
    @settings(max_examples=500)
    def test_hash_deterministic(self, obj):
        """Same object always produces same hash."""
        h1 = opoch_hash(obj)
        h2 = opoch_hash(obj)
        assert h1 == h2

    @given(obj=semantic_objects())
    @settings(max_examples=500)
    def test_serialization_deterministic(self, obj):
        """Same object always produces same serialization."""
        t1 = SerPi.serialize(obj).to_bytes()
        t2 = SerPi.serialize(obj).to_bytes()
        assert t1 == t2


# =============================================================================
# PROPERTY: QUOTIENT RESPECT (CANONICALIZATION)
# =============================================================================

class TestQuotientRespect:
    """Semantically equivalent objects must hash identically."""

    @given(value=st.floats(allow_nan=False, allow_infinity=False))
    def test_float_canonical_zero(self, value):
        """Zero values are equivalent regardless of sign."""
        if value == 0.0:
            pos = SFloat(0.0)
            neg = SFloat(-0.0)
            assert pos.semantic_eq(neg)
            assert opoch_hash(pos) == opoch_hash(neg)

    @given(data=st.data())
    @settings(max_examples=200)
    def test_set_order_invariance(self, data):
        """Set hash doesn't depend on insertion order."""
        elements = data.draw(st.lists(
            st.integers(min_value=-1000, max_value=1000),
            min_size=2,
            max_size=10,
            unique=True
        ))

        # Create two sets with different insertion orders
        set1 = SSet({SInt(e) for e in elements})
        set2 = SSet({SInt(e) for e in reversed(elements)})

        assert set1.semantic_eq(set2)
        assert opoch_hash(set1) == opoch_hash(set2)

    @given(data=st.data())
    @settings(max_examples=200)
    def test_map_order_invariance(self, data):
        """Map hash doesn't depend on insertion order."""
        keys = data.draw(st.lists(
            st.text(min_size=1, max_size=10),
            min_size=2,
            max_size=10,
            unique=True
        ))
        values = data.draw(st.lists(
            st.integers(),
            min_size=len(keys),
            max_size=len(keys)
        ))

        items = list(zip(keys, values))

        map1 = SMap({SString(k): SInt(v) for k, v in items})
        map2 = SMap({SString(k): SInt(v) for k, v in reversed(items)})

        assert map1.semantic_eq(map2)
        assert opoch_hash(map1) == opoch_hash(map2)

    @given(obj=semantic_objects())
    @settings(max_examples=300)
    def test_canonical_form_idempotent(self, obj):
        """Canonicalization is idempotent."""
        c1 = obj.canonical_form()
        c2 = c1.canonical_form()
        assert c1.semantic_eq(c2)
        assert SerPi.serialize(c1).to_bytes() == SerPi.serialize(c2).to_bytes()


# =============================================================================
# PROPERTY: ROUND-TRIP INTEGRITY
# =============================================================================

class TestRoundTrip:
    """Serialization must be invertible."""

    @given(obj=semantic_objects())
    @settings(max_examples=500)
    def test_serialize_deserialize_roundtrip(self, obj):
        """serialize(deserialize(tape)) preserves semantic equality."""
        tape = SerPi.serialize(obj)
        recovered = SerPiDeserializer.deserialize(tape)
        assert obj.semantic_eq(recovered)

    @given(obj=semantic_objects())
    @settings(max_examples=500)
    def test_roundtrip_hash_equality(self, obj):
        """Round-tripped objects hash identically."""
        original_hash = opoch_hash(obj)

        tape = SerPi.serialize(obj)
        recovered = SerPiDeserializer.deserialize(tape)
        recovered_hash = opoch_hash(recovered)

        assert original_hash == recovered_hash


# =============================================================================
# PROPERTY: INJECTIVITY ON MEANING CLASSES
# =============================================================================

class TestInjectivity:
    """Different meanings must produce different serializations."""

    @given(a=st.integers(), b=st.integers())
    def test_different_ints_different_hashes(self, a, b):
        """Different integers hash differently."""
        assume(a != b)
        assert opoch_hash(SInt(a)) != opoch_hash(SInt(b))

    @given(a=st.text(min_size=1), b=st.text(min_size=1))
    def test_different_strings_different_hashes(self, a, b):
        """Different strings hash differently (after normalization)."""
        s1 = SString(a)
        s2 = SString(b)
        if not s1.semantic_eq(s2):
            assert opoch_hash(s1) != opoch_hash(s2)

    @given(data=st.data())
    def test_type_domain_separation(self, data):
        """Same underlying value with different types hash differently."""
        i = data.draw(st.integers(min_value=0, max_value=1000))

        as_int = SInt(i)
        as_str = SString(str(i))
        as_bytes = SBytes(str(i).encode())

        h_int = opoch_hash(as_int)
        h_str = opoch_hash(as_str)
        h_bytes = opoch_hash(as_bytes)

        assert h_int != h_str
        assert h_str != h_bytes
        assert h_int != h_bytes


# =============================================================================
# PROPERTY: AVALANCHE EFFECT
# =============================================================================

class TestAvalanche:
    """Small changes should cause large output changes."""

    @given(base=st.integers())
    @settings(max_examples=100)
    def test_int_avalanche(self, base):
        """Adjacent integers have very different hashes."""
        h1 = opoch_hash(SInt(base))
        h2 = opoch_hash(SInt(base + 1))

        # Count differing bits
        diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(h1, h2))

        # Should differ in roughly half the bits (with variance)
        # 256 bits total, expect at least 64 different
        assert diff_bits > 32, f"Insufficient avalanche: {diff_bits} bits differ"

    @given(s=st.text(min_size=2, max_size=100))
    @settings(max_examples=100)
    def test_string_avalanche(self, s):
        """Strings differing by one character have different hashes."""
        # Change last character
        if len(s) > 0:
            modified = s[:-1] + chr((ord(s[-1]) + 1) % 65536)
            h1 = opoch_hash(SString(s))
            h2 = opoch_hash(SString(modified))

            if s != modified:  # Guard against wrapping
                diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(h1, h2))
                assert diff_bits > 32


# =============================================================================
# PROPERTY: COLLISION RESISTANCE (STATISTICAL)
# =============================================================================

class TestCollisionResistance:
    """No trivial collisions in reasonable samples."""

    @given(data=st.data())
    @settings(max_examples=50)
    def test_no_collisions_in_random_sample(self, data):
        """Random objects don't collide."""
        objects = [data.draw(semantic_objects()) for _ in range(100)]
        hashes = [opoch_hash(obj) for obj in objects]

        # Check for unintended collisions
        for i, (o1, h1) in enumerate(zip(objects, hashes)):
            for j, (o2, h2) in enumerate(zip(objects, hashes)):
                if i < j and h1 == h2:
                    # If hashes match, objects must be semantically equal
                    assert o1.semantic_eq(o2), f"Collision between non-equivalent objects at {i}, {j}"


# =============================================================================
# PROPERTY: CONTEXT SEPARATION
# =============================================================================

class TestContextSeparation:
    """Different contexts produce different hashes."""

    @given(obj=semantic_objects(), ctx1=st.integers(0, 65535), ctx2=st.integers(0, 65535))
    def test_context_tag_separation(self, obj, ctx1, ctx2):
        """Different context tags produce different hashes."""
        assume(ctx1 != ctx2)
        h1 = opoch_hash(obj, context=ctx1)
        h2 = opoch_hash(obj, context=ctx2)
        assert h1 != h2


# =============================================================================
# PROPERTY: XOF CONSISTENCY
# =============================================================================

class TestXofProperties:
    """XOF mode properties."""

    @given(obj=semantic_objects(), short_len=st.integers(16, 32), long_len=st.integers(33, 128))
    def test_xof_prefix_consistency(self, obj, short_len, long_len):
        """Shorter XOF output is prefix of longer output."""
        hasher = OpochHash()

        short_output = hasher.xof(obj, short_len)
        long_output = hasher.xof(obj, long_len)

        assert long_output[:short_len] == short_output


# =============================================================================
# PROPERTY: MAC SECURITY
# =============================================================================

class TestMacProperties:
    """MAC mode properties."""

    @given(
        obj=semantic_objects(),
        key1=st.binary(min_size=16, max_size=64),
        key2=st.binary(min_size=16, max_size=64)
    )
    def test_different_keys_different_macs(self, obj, key1, key2):
        """Different keys produce different MACs."""
        assume(key1 != key2)
        hasher = OpochHash()

        mac1 = hasher.mac(obj, key1)
        mac2 = hasher.mac(obj, key2)

        assert mac1 != mac2

    @given(obj=semantic_objects(), key=st.binary(min_size=16, max_size=64))
    def test_mac_differs_from_hash(self, obj, key):
        """MAC output differs from unkeyed hash."""
        hasher = OpochHash()

        h = hasher.hash(obj)
        m = hasher.mac(obj, key)

        assert h != m


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
