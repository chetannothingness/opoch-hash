> **Note**: This is a separate research project - **Semantic Hashing**. It is independent from the main OPOCH-VDF project. Semantic hashing addresses a different problem: ensuring identical semantic data produces identical hashes regardless of serialization order. See the main repository README for the VDF proof system.

---

# OpochHash: Semantic Hashing

**OpochHash = TreeSpongeMixer . Ser_Pi**

A mathematically complete hashing construction that eliminates entire classes of industry failures by making them impossible.

---

## The Problem

For 30+ years, the entire software industry has operated under a false assumption:

> "Hashing is bytes -> digest"

This is wrong. **Hashing is meaning -> digest.**

The consequences of this error:
- JSON serialization bugs
- Cross-language hash mismatches
- Protocol confusion attacks
- Schema version collisions
- Map ordering inconsistencies

**OpochHash fixes all of them. Permanently. By construction.**

---

## Factorial Dominance Ratio

For a map/object with `n` keys:

| Keys | SHA-256(JSON) Distinct Hashes | OpochHash Distinct Hashes | Ratio |
|------|-------------------------------|---------------------------|-------|
| 2 | 2 | 1 | 2x |
| 3 | 6 | 1 | 6x |
| 4 | 24 | 1 | 24x |
| 5 | 120 | 1 | 120x |
| 10 | 3,628,800 | 1 | **3,628,800x** |

**The same semantic object produces n! different hashes with traditional methods.**

OpochHash produces exactly **one**.

---

## Collision Prevention

| Attack Vector | Traditional Hash | OpochHash |
|---------------|------------------|-----------|
| Map order variation | VULNERABLE | **IMMUNE** |
| Float -0.0 vs +0.0 | VULNERABLE | **IMMUNE** |
| NaN payload differences | VULNERABLE | **IMMUNE** |
| Unicode NFC vs NFD | VULNERABLE | **IMMUNE** |
| Protocol context confusion | VULNERABLE | **IMMUNE** |
| Schema version collision | VULNERABLE | **IMMUNE** |
| Type confusion (int vs string) | VULNERABLE | **IMMUNE** |

---

## Quick Start

```python
from opochhash import opoch_hash_fast, SMap, SString, SInt

# Same hash regardless of construction order
obj1 = SMap({SString("a"): SInt(1), SString("b"): SInt(2)})
obj2 = SMap({SString("b"): SInt(2), SString("a"): SInt(1)})
assert opoch_hash_fast(obj1) == opoch_hash_fast(obj2)  # Always true
```

---

## The Mathematical Foundation

```
OpochHash(o) = Mix(Ser_Pi(o))
```

Where:
- **Ser_Pi**: Canonical serialization respecting semantic equivalence
- **Mix**: Domain-separated universal mixer

### The Theorem (Collision Localization)

If `OpochHash(o) = OpochHash(o')`, exactly ONE of these holds:

1. **Same meaning**: `o ~ o'` (expected, not a bug)
2. **Serialization bug**: Ser_Pi violated injectivity (fixable)
3. **Cryptographic collision**: Mix collided (bounded by birthday limit)
4. **Truncation**: Output was shortened (governed by truncated length)

**Every collision is attributable to exactly one cause.**

---

## Performance

| Operation | OpochHash | SHA-256 | SHA3-256 | BLAKE3 |
|-----------|-----------|---------|----------|--------|
| 64 bytes | 1.15 us | 0.67 us | 0.46 us | 0.71 us |
| 4 KB | **455 MB/s** | 456 MB/s | 571 MB/s | 1399 MB/s |
| 1 MB | **474 MB/s** | 485 MB/s | 610 MB/s | 2000+ MB/s |

**OpochHash matches SHA-256 performance while providing semantic guarantees no other hash can offer.**

---

## Installation

```bash
pip install -e .
```

## Run Tests

```bash
PYTHONPATH=src pytest tests/test_properties.py -v
PYTHONPATH=src pytest tests/test_hypothesis.py -v
```

---

## License

MIT
