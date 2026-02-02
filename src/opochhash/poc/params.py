"""
Public Parameters for Proof of Computation

PoCParams defines all public parameters θ for PoC_Hash.
These parameters are included in the challenge derivation,
binding the proof to specific work requirements.
"""

from dataclasses import dataclass, field
from typing import Optional, Union
from enum import Enum
import hashlib

from .tags import PoCTag, tag_bytes


class LegacyHash(Enum):
    """Legacy hash algorithms for d₀ computation."""
    SHA256 = 'sha256'
    SHA384 = 'sha384'
    SHA512 = 'sha512'
    SHA3_256 = 'sha3_256'
    BLAKE2B = 'blake2b'
    SHAKE256 = 'shake256'


@dataclass(frozen=True)
class PoCParams:
    """
    Public parameters θ for proof of computation.

    PoC_Hash(x; θ) → (d₀, π)

    All parameters are immutable and hashable.
    """

    # ==========================================================================
    # Security Parameters
    # ==========================================================================

    security_bits: int = 128
    """Target soundness level. Forgery probability < 2^-security_bits."""

    # ==========================================================================
    # Work Parameters
    # ==========================================================================

    W: int = 1_000_000
    """Number of sequential work steps. This is the "proof of work" amount."""

    # ==========================================================================
    # Memory Parameters (Memory-Hard)
    # ==========================================================================

    memory_bytes: int = 256 * 1024 * 1024  # 256 MB
    """Total memory size for memory-hard computation."""

    block_size: int = 64
    """Size of each memory block in bytes."""

    @property
    def num_blocks(self) -> int:
        """Number of memory blocks."""
        return self.memory_bytes // self.block_size

    # ==========================================================================
    # STARK Parameters
    # ==========================================================================

    blowup_factor: int = 8
    """Domain extension factor for low-degree extension."""

    fri_rate: float = 0.125
    """FRI folding rate (lower rate = higher soundness per query)."""

    fri_queries: int = 68
    """Number of FRI query rounds for soundness (achieving 128+ bit security)."""

    @property
    def trace_domain_size(self) -> int:
        """Size of trace evaluation domain."""
        # Round up to power of 2
        n = self.W + 1  # W steps = W+1 states
        return 1 << (n - 1).bit_length()

    @property
    def lde_domain_size(self) -> int:
        """Size of low-degree extension domain."""
        return self.trace_domain_size * self.blowup_factor

    # ==========================================================================
    # Circuit/Protocol Identification
    # ==========================================================================

    circuit_id: bytes = field(default=b'POC_WORK_V1')
    """Circuit identifier for domain separation."""

    version: int = 1
    """Protocol version."""

    # ==========================================================================
    # Legacy Hash (for d₀)
    # ==========================================================================

    legacy_hash: Union[LegacyHash, str] = LegacyHash.SHAKE256
    """Hash algorithm for legacy digest d₀. MUST match existing infrastructure."""

    # ==========================================================================
    # Serialization
    # ==========================================================================

    def serialize(self) -> bytes:
        """
        Canonical serialization for binding in challenges.

        Format:
            TAG(2) || version(2) || security_bits(2) || W(8) ||
            memory_bytes(8) || block_size(4) ||
            blowup_factor(2) || fri_rate(8) || fri_queries(2) ||
            circuit_id_len(2) || circuit_id || legacy_hash_len(2) || legacy_hash
        """
        parts = [
            tag_bytes(PoCTag.PARAMS),
            self.version.to_bytes(2, 'big'),
            self.security_bits.to_bytes(2, 'big'),
            self.W.to_bytes(8, 'big'),
            self.memory_bytes.to_bytes(8, 'big'),
            self.block_size.to_bytes(4, 'big'),
            self.blowup_factor.to_bytes(2, 'big'),
            _float_to_bytes(self.fri_rate),
            self.fri_queries.to_bytes(2, 'big'),
            len(self.circuit_id).to_bytes(2, 'big'),
            self.circuit_id,
        ]
        # Handle legacy_hash as either enum or string
        legacy_hash_str = self.legacy_hash.value if isinstance(self.legacy_hash, LegacyHash) else self.legacy_hash
        parts.extend([
            len(legacy_hash_str).to_bytes(2, 'big'),
            legacy_hash_str.encode('utf-8'),
        ])
        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'PoCParams':
        """Deserialize from bytes."""
        offset = 0

        # Skip tag
        offset += 2

        version = int.from_bytes(data[offset:offset+2], 'big')
        offset += 2

        security_bits = int.from_bytes(data[offset:offset+2], 'big')
        offset += 2

        W = int.from_bytes(data[offset:offset+8], 'big')
        offset += 8

        memory_bytes = int.from_bytes(data[offset:offset+8], 'big')
        offset += 8

        block_size = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4

        blowup_factor = int.from_bytes(data[offset:offset+2], 'big')
        offset += 2

        fri_rate = _bytes_to_float(data[offset:offset+8])
        offset += 8

        fri_queries = int.from_bytes(data[offset:offset+2], 'big')
        offset += 2

        circuit_id_len = int.from_bytes(data[offset:offset+2], 'big')
        offset += 2
        circuit_id = data[offset:offset+circuit_id_len]
        offset += circuit_id_len

        legacy_hash_len = int.from_bytes(data[offset:offset+2], 'big')
        offset += 2
        legacy_hash = data[offset:offset+legacy_hash_len].decode('utf-8')

        return cls(
            security_bits=security_bits,
            W=W,
            memory_bytes=memory_bytes,
            block_size=block_size,
            blowup_factor=blowup_factor,
            fri_rate=fri_rate,
            fri_queries=fri_queries,
            circuit_id=circuit_id,
            version=version,
            legacy_hash=legacy_hash,
        )

    def hash(self) -> bytes:
        """Hash of parameters for binding."""
        return hashlib.shake_256(self.serialize()).digest(32)

    # ==========================================================================
    # Soundness Bounds
    # ==========================================================================

    def fri_soundness_bound(self) -> float:
        """FRI soundness: ρ^q where ρ = rate, q = queries."""
        return self.fri_rate ** self.fri_queries

    def merkle_collision_bound(self) -> float:
        """Merkle collision bound: 2^-256 for 256-bit hash."""
        return 2.0 ** -256

    def total_soundness_bound(self) -> float:
        """Combined soundness bound."""
        # Sum of individual failure probabilities (union bound)
        return (
            self.fri_soundness_bound() +
            self.merkle_collision_bound() * self.fri_queries +
            self.fri_queries / self.lde_domain_size  # constraint sampling
        )

    def meets_security_target(self) -> bool:
        """Check if parameters meet security target."""
        return self.total_soundness_bound() < 2.0 ** -self.security_bits

    def stark_soundness_bound(self) -> float:
        """STARK soundness bound (alias for total_soundness_bound)."""
        return self.total_soundness_bound()


def _float_to_bytes(f: float) -> bytes:
    """Convert float to 8 bytes (IEEE 754 double, big-endian)."""
    import struct
    return struct.pack('>d', f)


def _bytes_to_float(b: bytes) -> float:
    """Convert 8 bytes to float."""
    import struct
    return struct.unpack('>d', b)[0]


# =============================================================================
# Preset Configurations
# =============================================================================

# Small: For testing
PARAMS_SMALL = PoCParams(
    W=1000,
    memory_bytes=1024 * 1024,  # 1 MB
    security_bits=64,
)

# Medium: For development
PARAMS_MEDIUM = PoCParams(
    W=100_000,
    memory_bytes=16 * 1024 * 1024,  # 16 MB
    security_bits=100,
)

# Standard: For production
PARAMS_STANDARD = PoCParams(
    W=1_000_000,
    memory_bytes=256 * 1024 * 1024,  # 256 MB
    security_bits=128,
)

# Large: For high-security
PARAMS_LARGE = PoCParams(
    W=1_000_000_000,
    memory_bytes=1024 * 1024 * 1024,  # 1 GB
    security_bits=128,
)
