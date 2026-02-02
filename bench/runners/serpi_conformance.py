"""
Runner 1: Ser_Π Conformance Tests

Goal: Prove Ser_Π is canonical and injective on meaning classes.

This is the Π gate. If it fails, nothing downstream counts.

Tests:
1. Quotient respect: o ~ o' ⟹ Ser_Π(o) = Ser_Π(o')
2. Injectivity: o ≁ o' ⟹ Ser_Π(o) ≠ Ser_Π(o')
3. Canonical order: map/set reorderings don't change tape
4. Numeric normalization: float variants normalize correctly
5. Text normalization: Unicode/whitespace behaves as specified
"""

from __future__ import annotations
import json
import hashlib
import time
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple, Set
from itertools import permutations
import sys
import os

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from opochhash import (
    SerPi, SerPiDeserializer, CanonicalTape,
    SNull, SBool, SInt, SFloat, SBytes, SString,
    SList, SSet, SMap, SStruct, SOptional,
    SchemaId, SemanticObject
)


@dataclass
class ConformanceResult:
    """Result of a single conformance test."""
    test_name: str
    passed: bool
    details: str = ""
    counterexample: Optional[Dict[str, Any]] = None


@dataclass
class ConformanceReport:
    """Full conformance report."""
    timestamp: str
    total_tests: int
    passed: int
    failed: int
    tests: List[ConformanceResult]
    vectors_hash: str
    duration_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'total_tests': self.total_tests,
            'passed': self.passed,
            'failed': self.failed,
            'pass_rate': f"{100 * self.passed / self.total_tests:.2f}%" if self.total_tests > 0 else "N/A",
            'tests': [asdict(t) for t in self.tests],
            'vectors_hash': self.vectors_hash,
            'duration_ms': self.duration_ms,
        }


class SerPiConformanceRunner:
    """
    Runner for Ser_Π conformance tests.

    Proves:
    - Quotient respect (same meaning → same tape)
    - Injectivity (different meaning → different tape)
    - Determinism (same object → same tape always)
    """

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[ConformanceResult] = []
        self.vectors: Dict[str, str] = {}  # object_id → tape_hex

    def run(self) -> ConformanceReport:
        """Run all conformance tests."""
        start_time = time.perf_counter()

        # Test suites
        self._test_primitive_canonicalization()
        self._test_float_equivalence()
        self._test_string_normalization()
        self._test_set_order_independence()
        self._test_map_order_independence()
        self._test_struct_field_order()
        self._test_nested_structure_canonicalization()
        self._test_optional_semantics()
        self._test_type_domain_separation()
        self._test_context_tag_separation()
        self._test_schema_version_separation()
        self._test_large_integer_handling()
        self._test_binary_data_handling()
        self._test_round_trip_integrity()
        self._test_determinism_stress()
        self._test_permutation_invariance_scaling()

        # Generate outputs
        self._write_vectors()
        vectors_hash = self._compute_vectors_hash()

        elapsed = (time.perf_counter() - start_time) * 1000

        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed

        report = ConformanceReport(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            total_tests=len(self.results),
            passed=passed,
            failed=failed,
            tests=self.results,
            vectors_hash=vectors_hash,
            duration_ms=elapsed,
        )

        # Write report
        report_path = self.output_dir / 'serpi_report.json'
        with open(report_path, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)

        return report

    def _add_result(self, name: str, passed: bool, details: str = "",
                    counterexample: Optional[Dict] = None):
        self.results.append(ConformanceResult(
            test_name=name,
            passed=passed,
            details=details,
            counterexample=counterexample,
        ))

    def _add_vector(self, obj_id: str, obj: SemanticObject):
        tape = SerPi.serialize(obj)
        self.vectors[obj_id] = tape.to_bytes().hex()

    # =========================================================================
    # TEST SUITES
    # =========================================================================

    def _test_primitive_canonicalization(self):
        """Test that primitives serialize deterministically."""
        primitives = [
            ("null", SNull()),
            ("bool_true", SBool(True)),
            ("bool_false", SBool(False)),
            ("int_zero", SInt(0)),
            ("int_positive", SInt(42)),
            ("int_negative", SInt(-42)),
            ("int_large", SInt(2**64)),
            ("float_zero", SFloat(0.0)),
            ("float_pi", SFloat(3.14159265358979)),
            ("bytes_empty", SBytes(b'')),
            ("bytes_data", SBytes(b'\x00\x01\x02\xff')),
            ("string_empty", SString("")),
            ("string_ascii", SString("hello")),
            ("string_unicode", SString("héllo wörld 你好")),
        ]

        all_passed = True
        for obj_id, obj in primitives:
            tape1 = SerPi.serialize(obj).to_bytes()
            tape2 = SerPi.serialize(obj).to_bytes()
            if tape1 != tape2:
                all_passed = False
                self._add_result(
                    f"primitive_canonical_{obj_id}",
                    False,
                    f"Non-deterministic serialization for {obj_id}",
                    {"object": obj_id}
                )
            self._add_vector(obj_id, obj)

        self._add_result(
            "primitive_canonicalization",
            all_passed,
            f"Tested {len(primitives)} primitive types"
        )

    def _test_float_equivalence(self):
        """Test float canonical equivalences."""
        # Test 1: +0.0 and -0.0 must be equivalent
        pos_zero = SFloat(0.0)
        neg_zero = SFloat(-0.0)
        tape_pos = SerPi.serialize(pos_zero).to_bytes()
        tape_neg = SerPi.serialize(neg_zero).to_bytes()

        self._add_result(
            "float_zero_equivalence",
            tape_pos == tape_neg,
            "+0.0 and -0.0 must serialize identically",
            None if tape_pos == tape_neg else {
                "pos_zero_tape": tape_pos.hex(),
                "neg_zero_tape": tape_neg.hex(),
            }
        )

        # Test 2: All NaN values must be equivalent
        import math
        nan1 = SFloat(float('nan'))
        nan2 = SFloat(math.nan)
        tape_nan1 = SerPi.serialize(nan1).to_bytes()
        tape_nan2 = SerPi.serialize(nan2).to_bytes()

        self._add_result(
            "float_nan_equivalence",
            tape_nan1 == tape_nan2,
            "All NaN values must serialize identically",
            None if tape_nan1 == tape_nan2 else {
                "nan1_tape": tape_nan1.hex(),
                "nan2_tape": tape_nan2.hex(),
            }
        )

        # Test 3: Infinity preserved with sign
        pos_inf = SFloat(float('inf'))
        neg_inf = SFloat(float('-inf'))
        tape_pos_inf = SerPi.serialize(pos_inf).to_bytes()
        tape_neg_inf = SerPi.serialize(neg_inf).to_bytes()

        self._add_result(
            "float_infinity_distinction",
            tape_pos_inf != tape_neg_inf,
            "+inf and -inf must serialize differently",
        )

        self._add_vector("float_pos_zero", pos_zero)
        self._add_vector("float_neg_zero", neg_zero)
        self._add_vector("float_nan", nan1)
        self._add_vector("float_pos_inf", pos_inf)
        self._add_vector("float_neg_inf", neg_inf)

    def _test_string_normalization(self):
        """Test Unicode normalization (NFC)."""
        import unicodedata

        # é as single codepoint vs decomposed
        s1 = SString('\u00e9')  # é (NFC)
        s2 = SString('e\u0301')  # e + combining acute (NFD)

        tape1 = SerPi.serialize(s1).to_bytes()
        tape2 = SerPi.serialize(s2).to_bytes()

        self._add_result(
            "string_unicode_normalization",
            tape1 == tape2,
            "NFC and NFD forms of same character must serialize identically",
            None if tape1 == tape2 else {
                "nfc_tape": tape1.hex(),
                "nfd_tape": tape2.hex(),
            }
        )

        # Additional normalization tests
        test_pairs = [
            ('\u00f1', 'n\u0303'),  # ñ
            ('\u00fc', 'u\u0308'),  # ü
            ('\u00e0', 'a\u0300'),  # à
        ]

        all_passed = True
        for nfc, nfd in test_pairs:
            t1 = SerPi.serialize(SString(nfc)).to_bytes()
            t2 = SerPi.serialize(SString(nfd)).to_bytes()
            if t1 != t2:
                all_passed = False

        self._add_result(
            "string_unicode_normalization_extended",
            all_passed,
            f"Tested {len(test_pairs)} Unicode normalization pairs"
        )

    def _test_set_order_independence(self):
        """Test that set serialization is order-independent."""
        elements = [SInt(1), SInt(2), SInt(3), SInt(4), SInt(5)]

        # Get all permutations (5! = 120)
        tapes = set()
        for perm in permutations(elements):
            s = SSet(set(perm))
            tape = SerPi.serialize(s).to_bytes()
            tapes.add(tape)

        self._add_result(
            "set_order_independence",
            len(tapes) == 1,
            f"120 permutations produced {len(tapes)} distinct tape(s)",
            None if len(tapes) == 1 else {"distinct_count": len(tapes)}
        )

        self._add_vector("set_12345", SSet({SInt(1), SInt(2), SInt(3), SInt(4), SInt(5)}))

    def _test_map_order_independence(self):
        """Test that map serialization is order-independent."""
        from itertools import permutations

        keys = ['a', 'b', 'c', 'd']
        base_items = [(k, i) for i, k in enumerate(keys)]

        tapes = set()
        for perm in permutations(base_items):
            m = SMap({SString(k): SInt(v) for k, v in perm})
            tape = SerPi.serialize(m).to_bytes()
            tapes.add(tape)

        self._add_result(
            "map_order_independence",
            len(tapes) == 1,
            f"24 permutations produced {len(tapes)} distinct tape(s)",
            None if len(tapes) == 1 else {"distinct_count": len(tapes)}
        )

        self._add_vector("map_abcd", SMap({
            SString('a'): SInt(0),
            SString('b'): SInt(1),
            SString('c'): SInt(2),
            SString('d'): SInt(3),
        }))

    def _test_struct_field_order(self):
        """Test that struct field order doesn't affect serialization."""
        schema = SchemaId('test', 'Person', 1)

        # Create same struct with different field insertion order
        struct1 = SStruct(schema, {
            'name': SString('Alice'),
            'age': SInt(30),
            'active': SBool(True),
        })

        struct2 = SStruct(schema, {
            'active': SBool(True),
            'name': SString('Alice'),
            'age': SInt(30),
        })

        struct3 = SStruct(schema, {
            'age': SInt(30),
            'active': SBool(True),
            'name': SString('Alice'),
        })

        t1 = SerPi.serialize(struct1).to_bytes()
        t2 = SerPi.serialize(struct2).to_bytes()
        t3 = SerPi.serialize(struct3).to_bytes()

        self._add_result(
            "struct_field_order_independence",
            t1 == t2 == t3,
            "Struct field order must not affect serialization",
            None if t1 == t2 == t3 else {
                "tape1": t1.hex(),
                "tape2": t2.hex(),
                "tape3": t3.hex(),
            }
        )

        self._add_vector("struct_person", struct1)

    def _test_nested_structure_canonicalization(self):
        """Test deeply nested structures serialize deterministically."""
        nested = SMap({
            SString('level1'): SList([
                SMap({
                    SString('level2'): SSet({
                        SInt(1), SInt(2), SInt(3)
                    })
                }),
                SOptional(SString('nested_optional'))
            ])
        })

        tape1 = SerPi.serialize(nested).to_bytes()
        tape2 = SerPi.serialize(nested).to_bytes()

        self._add_result(
            "nested_structure_canonicalization",
            tape1 == tape2,
            "Nested structures must serialize deterministically"
        )

        self._add_vector("nested_complex", nested)

    def _test_optional_semantics(self):
        """Test Optional(None) vs Optional(SNull())."""
        opt_none = SOptional(None)  # Absent
        opt_null = SOptional(SNull())  # Present with null

        t_none = SerPi.serialize(opt_none).to_bytes()
        t_null = SerPi.serialize(opt_null).to_bytes()

        self._add_result(
            "optional_none_vs_null",
            t_none != t_null,
            "Optional(None) and Optional(SNull()) must serialize differently",
            None if t_none != t_null else {
                "opt_none": t_none.hex(),
                "opt_null": t_null.hex(),
            }
        )

        self._add_vector("optional_absent", opt_none)
        self._add_vector("optional_null", opt_null)

    def _test_type_domain_separation(self):
        """Test that different types with 'same value' serialize differently."""
        test_cases = [
            (SInt(0), SFloat(0.0), "int_0_vs_float_0"),
            (SInt(1), SBool(True), "int_1_vs_bool_true"),
            (SString("0"), SInt(0), "string_0_vs_int_0"),
            (SBytes(b"hello"), SString("hello"), "bytes_vs_string"),
            (SList([]), SSet(set()), "empty_list_vs_empty_set"),
        ]

        all_passed = True
        for obj1, obj2, name in test_cases:
            t1 = SerPi.serialize(obj1).to_bytes()
            t2 = SerPi.serialize(obj2).to_bytes()
            if t1 == t2:
                all_passed = False
                self._add_result(
                    f"type_separation_{name}",
                    False,
                    f"Type domain separation failed for {name}",
                    {"type1": type(obj1).__name__, "type2": type(obj2).__name__}
                )

        self._add_result(
            "type_domain_separation",
            all_passed,
            f"Tested {len(test_cases)} type pairs"
        )

    def _test_context_tag_separation(self):
        """Test that different context tags produce different tapes."""
        obj = SInt(42)

        contexts = [0x0000, 0x0001, 0x0002, 0x00FF, 0xFFFF]
        tapes = [SerPi.serialize(obj, context_tag=ctx).to_bytes() for ctx in contexts]

        # All must be unique
        unique_tapes = set(tapes)

        self._add_result(
            "context_tag_separation",
            len(unique_tapes) == len(contexts),
            f"{len(contexts)} contexts produced {len(unique_tapes)} distinct tapes",
            None if len(unique_tapes) == len(contexts) else {
                "expected": len(contexts),
                "actual": len(unique_tapes),
            }
        )

    def _test_schema_version_separation(self):
        """Test that different schema versions produce different tapes."""
        schema_v1 = SchemaId('app', 'Event', 1)
        schema_v2 = SchemaId('app', 'Event', 2)
        schema_diff_ns = SchemaId('other', 'Event', 1)

        fields = {'data': SInt(42)}

        t1 = SerPi.serialize(SStruct(schema_v1, fields)).to_bytes()
        t2 = SerPi.serialize(SStruct(schema_v2, fields)).to_bytes()
        t3 = SerPi.serialize(SStruct(schema_diff_ns, fields)).to_bytes()

        all_different = len({t1, t2, t3}) == 3

        self._add_result(
            "schema_version_separation",
            all_different,
            "Different schema versions/namespaces must produce different tapes",
            None if all_different else {
                "v1_tape": t1.hex()[:32],
                "v2_tape": t2.hex()[:32],
                "diff_ns_tape": t3.hex()[:32],
            }
        )

    def _test_large_integer_handling(self):
        """Test arbitrary precision integers."""
        large_ints = [
            2**64,
            2**128,
            2**256,
            2**1024,
            -(2**1024),
        ]

        all_unique = True
        tapes = []
        for i in large_ints:
            t = SerPi.serialize(SInt(i)).to_bytes()
            if t in tapes:
                all_unique = False
            tapes.append(t)

        self._add_result(
            "large_integer_handling",
            all_unique,
            f"Tested {len(large_ints)} large integers"
        )

        # Verify round-trip
        for i in large_ints:
            tape = SerPi.serialize(SInt(i))
            recovered = SerPiDeserializer.deserialize(tape)
            if not SInt(i).semantic_eq(recovered):
                self._add_result(
                    "large_integer_roundtrip",
                    False,
                    f"Round-trip failed for {i}",
                    {"value": str(i)}
                )
                return

        self._add_result(
            "large_integer_roundtrip",
            True,
            f"All {len(large_ints)} large integers round-trip correctly"
        )

    def _test_binary_data_handling(self):
        """Test binary data with all byte values."""
        # All 256 byte values
        all_bytes = SBytes(bytes(range(256)))
        tape = SerPi.serialize(all_bytes)
        recovered = SerPiDeserializer.deserialize(tape)

        self._add_result(
            "binary_all_bytes",
            all_bytes.semantic_eq(recovered),
            "All 256 byte values must round-trip correctly"
        )

        self._add_vector("bytes_all_256", all_bytes)

    def _test_round_trip_integrity(self):
        """Test serialize-deserialize round-trip for complex objects."""
        test_objects = [
            SNull(),
            SBool(True),
            SInt(12345678901234567890),
            SFloat(3.14159),
            SBytes(b'\x00\xff\x80'),
            SString("Hello, 世界!"),
            SList([SInt(1), SString("two"), SBool(True)]),
            SSet({SInt(1), SInt(2), SInt(3)}),
            SMap({SString('key'): SInt(42)}),
            SOptional(SString("present")),
            SOptional(None),
        ]

        all_passed = True
        for obj in test_objects:
            tape = SerPi.serialize(obj)
            recovered = SerPiDeserializer.deserialize(tape)
            if not obj.semantic_eq(recovered):
                all_passed = False
                self._add_result(
                    f"roundtrip_{type(obj).__name__}",
                    False,
                    f"Round-trip failed for {type(obj).__name__}"
                )

        self._add_result(
            "round_trip_integrity",
            all_passed,
            f"Tested {len(test_objects)} object types"
        )

    def _test_determinism_stress(self):
        """Stress test determinism with many iterations."""
        obj = SMap({
            SString('users'): SList([
                SStruct(SchemaId('app', 'User', 1), {
                    'id': SInt(i),
                    'name': SString(f'User{i}'),
                    'tags': SSet({SString(f'tag{j}') for j in range(3)}),
                })
                for i in range(10)
            ])
        })

        reference_tape = SerPi.serialize(obj).to_bytes()

        iterations = 1000
        all_match = True
        for _ in range(iterations):
            tape = SerPi.serialize(obj).to_bytes()
            if tape != reference_tape:
                all_match = False
                break

        self._add_result(
            "determinism_stress",
            all_match,
            f"Serialization deterministic over {iterations} iterations"
        )

    def _test_permutation_invariance_scaling(self):
        """Test map permutation invariance scales correctly."""
        for n in [3, 5, 7, 9]:
            items = [(f'key{i}', i) for i in range(n)]
            reference = None
            all_same = True

            # Test factorial permutations (capped for large n)
            import math
            max_perms = min(math.factorial(n), 1000)
            tested = 0

            for perm in permutations(items):
                if tested >= max_perms:
                    break
                m = SMap({SString(k): SInt(v) for k, v in perm})
                tape = SerPi.serialize(m).to_bytes()
                if reference is None:
                    reference = tape
                elif tape != reference:
                    all_same = False
                    break
                tested += 1

            self._add_result(
                f"permutation_invariance_n{n}",
                all_same,
                f"Map with {n} keys: {tested} permutations tested, all identical: {all_same}"
            )

    # =========================================================================
    # OUTPUT GENERATION
    # =========================================================================

    def _write_vectors(self):
        """Write golden vectors file."""
        vectors_path = self.output_dir / 'serpi_vectors.json'
        with open(vectors_path, 'w') as f:
            json.dump(self.vectors, f, indent=2, sort_keys=True)

    def _compute_vectors_hash(self) -> str:
        """Compute SHA-256 of vectors file for receipts."""
        vectors_path = self.output_dir / 'serpi_vectors.json'
        with open(vectors_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
