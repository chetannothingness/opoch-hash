"""
Kernel Primitives for Proof of Computation

Defines:
- State: Machine state at a point in execution
- Step: Deterministic state transition function
- Computation: A complete computation claim (P, x) → y
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Generic, TypeVar
import hashlib

from .tags import ProofTag, tag_bytes


def _hash(tag: ProofTag, *parts: bytes) -> bytes:
    """Domain-separated hash."""
    h = hashlib.shake_256()
    h.update(tag_bytes(tag))
    for part in parts:
        h.update(len(part).to_bytes(8, 'big'))
        h.update(part)
    return h.digest(32)


@dataclass
class MachineState:
    """
    Complete machine state at a point in execution.

    Fields:
    - pc: Program counter
    - registers: Register file
    - memory_root: Merkle root of memory (for RAM model)
    - io_buffer: I/O state
    - halted: Whether execution has terminated
    - failed: Whether execution failed (illegal operation)
    """
    pc: int
    registers: Dict[str, int] = field(default_factory=dict)
    memory_root: bytes = field(default_factory=lambda: b'\x00' * 32)
    io_buffer: bytes = b''
    halted: bool = False
    failed: bool = False

    def serialize(self) -> bytes:
        """Canonical serialization of state."""
        parts = [
            self.pc.to_bytes(8, 'big'),
            len(self.registers).to_bytes(4, 'big'),
        ]

        # Sort registers by name for determinism
        for name in sorted(self.registers.keys()):
            name_bytes = name.encode('utf-8')
            parts.append(len(name_bytes).to_bytes(2, 'big'))
            parts.append(name_bytes)
            parts.append(self.registers[name].to_bytes(8, 'big', signed=True))

        parts.append(self.memory_root)
        parts.append(len(self.io_buffer).to_bytes(4, 'big'))
        parts.append(self.io_buffer)
        parts.append(bytes([self.halted, self.failed]))

        return b''.join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> 'MachineState':
        """Deserialize state from bytes."""
        offset = 0

        pc = int.from_bytes(data[offset:offset+8], 'big')
        offset += 8

        reg_count = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4

        registers = {}
        for _ in range(reg_count):
            name_len = int.from_bytes(data[offset:offset+2], 'big')
            offset += 2
            name = data[offset:offset+name_len].decode('utf-8')
            offset += name_len
            value = int.from_bytes(data[offset:offset+8], 'big', signed=True)
            offset += 8
            registers[name] = value

        memory_root = data[offset:offset+32]
        offset += 32

        io_len = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        io_buffer = data[offset:offset+io_len]
        offset += io_len

        halted = bool(data[offset])
        failed = bool(data[offset+1])

        return cls(
            pc=pc,
            registers=registers,
            memory_root=memory_root,
            io_buffer=io_buffer,
            halted=halted,
            failed=failed
        )

    def hash(self) -> bytes:
        """Hash of this state."""
        return _hash(ProofTag.INIT, self.serialize())


class Program(ABC):
    """Abstract base class for programs."""

    @abstractmethod
    def serialize(self) -> bytes:
        """Serialize program to canonical bytes."""
        pass

    @abstractmethod
    def step(self, state: MachineState) -> MachineState:
        """
        Execute one step of the program.

        MUST be total: always returns a valid next state.
        Illegal operations should set state.failed = True.
        """
        pass

    @abstractmethod
    def init(self, input_data: bytes) -> MachineState:
        """Create initial state from input."""
        pass

    @abstractmethod
    def output(self, state: MachineState) -> bytes:
        """Extract output from final state."""
        pass

    def hash(self) -> bytes:
        """Hash of this program."""
        return _hash(ProofTag.PROGRAM, self.serialize())


@dataclass
class ComputationClaim:
    """
    A claim that y = F_P(x).

    Contains:
    - program: The program P
    - input: The input x
    - output: The claimed output y
    - steps: Number of execution steps T
    """
    program: Program
    input_data: bytes
    output_data: bytes
    steps: int

    def statement_hash(self) -> bytes:
        """
        Hash of the public statement.

        Stmt = (H(P), H(x), H(y), T)
        """
        return _hash(
            ProofTag.CHAL,
            self.program.hash(),
            _hash(ProofTag.INPUT, self.input_data),
            _hash(ProofTag.OUTPUT, self.output_data),
            self.steps.to_bytes(8, 'big')
        )


def execute(program: Program, input_data: bytes, max_steps: int = 1_000_000) -> Tuple[List[MachineState], bytes]:
    """
    Execute a program and return the full trace.

    Args:
        program: Program to execute
        input_data: Input bytes
        max_steps: Maximum steps before forced halt

    Returns:
        (trace, output) where trace is [s_0, s_1, ..., s_T]
    """
    state = program.init(input_data)
    trace = [state]

    for _ in range(max_steps):
        if state.halted or state.failed:
            break
        state = program.step(state)
        trace.append(state)

    output = program.output(state)
    return trace, output


def execute_with_serialized_trace(
    program: Program,
    input_data: bytes,
    max_steps: int = 1_000_000
) -> Tuple[List[bytes], bytes]:
    """
    Execute and return serialized trace (for Merkle tree).

    Returns:
        (serialized_trace, output)
    """
    trace, output = execute(program, input_data, max_steps)
    serialized = [state.serialize() for state in trace]
    return serialized, output
