# OPOCH-PoC-SHA Encoding Specification

## Overview

This document specifies the canonical encoding rules for all data structures in the OPOCH-PoC-SHA protocol.

## Byte Order

All multi-byte integers are encoded in **little-endian** format unless otherwise specified.

## Primitive Types

### Integers

| Type | Size | Encoding |
|------|------|----------|
| u8 | 1 byte | Direct |
| u16 | 2 bytes | Little-endian |
| u32 | 4 bytes | Little-endian |
| u64 | 8 bytes | Little-endian |
| i64 | variable | LEB128 signed |

### LEB128 Encoding

Variable-length integers use LEB128:

```
For positive values:
  - Each byte contains 7 bits of data
  - High bit (0x80) indicates more bytes follow
  - Final byte has high bit clear

For negative values (signed LEB128):
  - Uses two's complement representation
  - Sign extension in final byte
```

### Booleans

- `false` = 0x00
- `true` = 0x01

### Byte Arrays

```
[length: u32 LE][data: length bytes]
```

### Strings

UTF-8 encoded, length-prefixed:
```
[length: u32 LE][utf8_data: length bytes]
```

## Field Elements

### Goldilocks Fp

64-bit representation, little-endian:
```
[value: u64 LE] where 0 <= value < p
```

### Goldilocks Fp2

Two Fp elements (c0 + c1 * alpha):
```
[c0: Fp][c1: Fp]
```

## Digest Types

### SHA-256 Digest

Fixed 32 bytes, no length prefix:
```
[bytes: 32 bytes]
```

### Keccak-256 Digest

Fixed 32 bytes:
```
[bytes: 32 bytes]
```

### Poseidon Digest

Single Fp element:
```
[hash: Fp]
```

## 256-bit Integers

### U256Limbs

16 x 16-bit limbs, little-endian:
```
[limb_0: u16 LE]...[limb_15: u16 LE]
```

Note: limb_0 is the least significant.

## Merkle Structures

### Merkle Root

```
[root: 32 bytes]
```

### Merkle Path

```
[index: u64 LE]
[num_siblings: u32 LE]
[siblings: num_siblings * 32 bytes]
```

## Canonical Tape

### Header

```
[magic: "OPCH" (4 bytes)]
[version: u8]
[context_tag: u16 LE]
[type_tag: u8]
```

### Full Tape

```
[header: 8 bytes]
[payload: variable]
```

## Proof Structures

### Segment Proof

```
[segment_id: u64 LE]
[start_hash: 32 bytes]
[end_hash: 32 bytes]
[trace_commitment: 32 bytes]
[fri_proof_size: u32 LE]
[fri_proof: fri_proof_size bytes]
```

### Aggregation Proof

```
[level: u8]
[num_inputs: u32 LE]
[input_commitments: num_inputs * 32 bytes]
[output_commitment: 32 bytes]
[proof_data_size: u32 LE]
[proof_data: proof_data_size bytes]
```

### Final Proof

```
[version: u8]
[input_hash: 32 bytes]  // d0
[output_hash: 32 bytes] // y
[chain_length: u64 LE]  // N
[proof_size: u32 LE]
[proof_data: proof_size bytes]
```

## Receipt Structures

### Receipt

```
[benchmark_id_len: u32 LE]
[benchmark_id: utf8]
[name_len: u32 LE]
[name: utf8]
[status: u8]
[timestamp: u64 LE]
[previous_hash: 32 bytes]
[result_hash: 32 bytes]
[metrics: JSON bytes]
```

### Receipt Chain

```
[spec_id: 32 bytes]
[version_len: u32 LE]
[version: utf8]
[num_receipts: u32 LE]
[receipts: Receipt[]]
```

## Machine State

```
[machine_id: u16 LE]
[step: u64 LE]
[total_steps: u64 LE]
[state_hash: 32 bytes]
[input_commitment: 32 bytes]
[has_output: u8]
[output_len: u32 LE] // if has_output
[output: bytes]      // if has_output
```

## Signature Structures

### EdDSA Signature

```
[R: 32 bytes]  // Point encoding
[S: 32 bytes]  // Scalar encoding
```

### ECDSA Signature

```
[r: 32 bytes]  // Big-endian integer
[s: 32 bytes]  // Big-endian integer
```

### Public Keys

Ed25519:
```
[compressed_point: 32 bytes]
```

secp256k1 (compressed):
```
[prefix: 1 byte (0x02 or 0x03)]
[x: 32 bytes]
```

secp256k1 (uncompressed):
```
[prefix: 1 byte (0x04)]
[x: 32 bytes]
[y: 32 bytes]
```

## JSON Serialization

For interoperability, all structures support JSON encoding:

- Byte arrays: hex-encoded strings with "0x" prefix
- Field elements: decimal strings
- Integers: JSON numbers (up to 53 bits) or decimal strings
- Digests: 64-character hex strings

Example:
```json
{
  "input_hash": "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "chain_length": "1000000000",
  "status": "PASS"
}
```

## Versioning

All encoded structures include version information:
- Magic bytes identify the protocol
- Version byte allows format evolution
- Unknown versions should be rejected
