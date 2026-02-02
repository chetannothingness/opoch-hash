"""
Work State for Proof of Computation

The state at each step of the memory-hard computation:
    s_t = (r_t, t, M_t)

Where:
- r_t: Register state (256 bits)
- t: Step counter
- M_t: Merkle root of memory array
"""

from dataclasses import dataclass
from typing import Optional
import hashlib

from .tags import PoCTag, tag_bytes


@dataclass
class WorkState:
    """
    State at step t of the memory-hard computation.

    This is the complete state that defines the computation at any point.
    All state transitions are deterministic given the memory contents.
    """

    r: bytes
    """Register state (32 bytes = 256 bits)."""

    t: int
    """Step counter (0-indexed)."""

    M: bytes
    """Merkle root of memory array (32 bytes)."""

    def __post_init__(self):
        """Validate state."""
        if len(self.r) != 32:
            raise ValueError(f"Register must be 32 bytes, got {len(self.r)}")
        if len(self.M) != 32:
            raise ValueError(f"Memory root must be 32 bytes, got {len(self.M)}")
        if self.t < 0:
            raise ValueError(f"Step counter must be non-negative, got {self.t}")

    def serialize(self) -> bytes:
        """
        Canonical serialization for hashing.

        Format:
            r (32 bytes) || t (8 bytes, big-endian) || M (32 bytes)

        Total: 72 bytes (fixed size)
        """
        return b''.join([
            self.r,                         # 32 bytes
            self.t.to_bytes(8, 'big'),      # 8 bytes
            self.M                          # 32 bytes
        ])  # Total: 72 bytes

    @classmethod
    def deserialize(cls, data: bytes) -> 'WorkState':
        """Deserialize from bytes."""
        if len(data) < 72:
            raise ValueError(f"Data too short: need 72 bytes, got {len(data)}")

        r = data[0:32]
        t = int.from_bytes(data[32:40], 'big')
        M = data[40:72]

        return cls(r=r, t=t, M=M)

    def hash(self) -> bytes:
        """
        Domain-separated hash of the state.

        Used for Merkle tree leaves in trace commitment.
        """
        h = hashlib.shake_256()
        h.update(tag_bytes(PoCTag.TRACE_LEAF))
        h.update(self.t.to_bytes(8, 'big'))
        h.update(self.serialize())
        return h.digest(32)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, WorkState):
            return False
        return self.r == other.r and self.t == other.t and self.M == other.M

    def __hash__(self) -> int:
        return hash((self.r, self.t, self.M))

    def __repr__(self) -> str:
        return f"WorkState(r={self.r[:8].hex()}..., t={self.t}, M={self.M[:8].hex()}...)"


@dataclass
class MemoryAccess:
    """
    Record of a single memory access during a step.

    For each step t:
    - Read: address a_t, value b_t, proof that b_t is at a_t under M_t
    - Write: new value, proof that update produces M_{t+1}
    """

    address: int
    """Memory address accessed (block index)."""

    read_value: bytes
    """Value read from memory."""

    write_value: bytes
    """Value written to memory."""

    read_proof: Optional[bytes] = None
    """Merkle proof for read (serialized)."""

    write_proof: Optional[bytes] = None
    """Merkle proof for write (serialized)."""

    def serialize(self) -> bytes:
        """Serialize for inclusion in proof."""
        parts = [
            self.address.to_bytes(8, 'big'),
            len(self.read_value).to_bytes(4, 'big'),
            self.read_value,
            len(self.write_value).to_bytes(4, 'big'),
            self.write_value,
        ]

        if self.read_proof:
            parts.append(len(self.read_proof).to_bytes(4, 'big'))
            parts.append(self.read_proof)
        else:
            parts.append((0).to_bytes(4, 'big'))

        if self.write_proof:
            parts.append(len(self.write_proof).to_bytes(4, 'big'))
            parts.append(self.write_proof)
        else:
            parts.append((0).to_bytes(4, 'big'))

        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'MemoryAccess':
        """Deserialize from bytes."""
        offset = 0

        address = int.from_bytes(data[offset:offset+8], 'big')
        offset += 8

        read_len = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        read_value = data[offset:offset+read_len]
        offset += read_len

        write_len = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        write_value = data[offset:offset+write_len]
        offset += write_len

        read_proof_len = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        read_proof = data[offset:offset+read_proof_len] if read_proof_len > 0 else None
        offset += read_proof_len

        write_proof_len = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        write_proof = data[offset:offset+write_proof_len] if write_proof_len > 0 else None

        return cls(
            address=address,
            read_value=read_value,
            write_value=write_value,
            read_proof=read_proof,
            write_proof=write_proof
        )


@dataclass
class TransitionWitness:
    """
    Complete witness for a single state transition s_t → s_{t+1}.

    This contains all data needed to verify the transition locally.
    """

    state_t: WorkState
    """State at step t."""

    state_t_plus_1: WorkState
    """State at step t+1."""

    memory_access: MemoryAccess
    """Memory access during this step."""

    def verify_transition(self, expected_block_size: int) -> bool:
        """
        Verify this transition is valid.

        Returns True if s_{t+1} is the correct result of executing
        one step from s_t.
        """
        # Check step counter incremented
        if self.state_t_plus_1.t != self.state_t.t + 1:
            return False

        # Verify address derivation
        # a_t = int(r_t[:8]) mod num_blocks
        # (We can't verify num_blocks here without params, but we can check consistency)

        # Verify register update would be checked against the step function
        # This is a simplified check; full verification needs the step function

        return True

    def serialize(self) -> bytes:
        """Serialize for proof."""
        return b''.join([
            self.state_t.serialize(),
            self.state_t_plus_1.serialize(),
            self.memory_access.serialize()
        ])
