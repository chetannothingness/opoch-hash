"""
Simple Stack VM for Proof of Computation Demonstrations

A minimal, deterministic virtual machine that can be used to
demonstrate the proof of computation framework.

Instruction Set:
- PUSH <value>: Push value onto stack
- POP: Pop and discard top of stack
- DUP: Duplicate top of stack
- SWAP: Swap top two stack elements
- ADD: Pop two, push sum
- SUB: Pop two, push difference
- MUL: Pop two, push product
- DIV: Pop two, push quotient (integer)
- MOD: Pop two, push remainder
- EQ: Pop two, push 1 if equal, 0 otherwise
- LT: Pop two, push 1 if a < b, 0 otherwise
- GT: Pop two, push 1 if a > b, 0 otherwise
- AND: Pop two, push bitwise AND
- OR: Pop two, push bitwise OR
- NOT: Pop one, push bitwise NOT
- JMP <addr>: Jump to address
- JZ <addr>: Jump if top is zero (pops)
- JNZ <addr>: Jump if top is non-zero (pops)
- LOAD: Pop address, push memory[address]
- STORE: Pop address, pop value, store value at address
- CALL <addr>: Push return address, jump to addr
- RET: Pop return address, jump to it
- HALT: Stop execution
- INPUT: Read from input buffer
- OUTPUT: Write to output buffer
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import IntEnum
import struct

from .kernel import Program, MachineState


class Opcode(IntEnum):
    """VM instruction opcodes."""
    NOP = 0x00
    PUSH = 0x01
    POP = 0x02
    DUP = 0x03
    SWAP = 0x04

    # Arithmetic
    ADD = 0x10
    SUB = 0x11
    MUL = 0x12
    DIV = 0x13
    MOD = 0x14

    # Comparison
    EQ = 0x20
    LT = 0x21
    GT = 0x22

    # Bitwise
    AND = 0x30
    OR = 0x31
    NOT = 0x32

    # Control flow
    JMP = 0x40
    JZ = 0x41
    JNZ = 0x42
    CALL = 0x43
    RET = 0x44
    HALT = 0x45

    # Memory
    LOAD = 0x50
    STORE = 0x51

    # I/O
    INPUT = 0x60
    OUTPUT = 0x61


@dataclass
class Instruction:
    """A single VM instruction."""
    opcode: Opcode
    operand: Optional[int] = None

    def serialize(self) -> bytes:
        """Serialize instruction to bytes."""
        if self.operand is not None:
            return struct.pack('>BQ', self.opcode, self.operand)
        return bytes([self.opcode])

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple['Instruction', int]:
        """Deserialize instruction from bytes."""
        opcode = Opcode(data[offset])

        # Instructions with operands
        if opcode in (Opcode.PUSH, Opcode.JMP, Opcode.JZ, Opcode.JNZ, Opcode.CALL):
            operand = struct.unpack('>Q', data[offset+1:offset+9])[0]
            return cls(opcode, operand), offset + 9

        return cls(opcode), offset + 1


class StackVM(Program):
    """
    A simple stack-based virtual machine.

    State includes:
    - pc: Program counter
    - stack: Operand stack (stored in registers as "s0", "s1", etc.)
    - sp: Stack pointer
    - memory: Dictionary-based memory (simplified, not Merkle)
    """

    def __init__(self, instructions: List[Instruction]):
        """
        Create a VM with the given program.

        Args:
            instructions: List of instructions to execute
        """
        self.instructions = instructions
        self._bytecode = self._compile()

    def _compile(self) -> bytes:
        """Compile instructions to bytecode."""
        parts = []
        for inst in self.instructions:
            parts.append(inst.serialize())
        return b''.join(parts)

    def serialize(self) -> bytes:
        """Serialize program."""
        # Header: instruction count
        header = len(self.instructions).to_bytes(4, 'big')
        return header + self._bytecode

    @classmethod
    def from_bytes(cls, data: bytes) -> 'StackVM':
        """Deserialize program from bytes."""
        inst_count = int.from_bytes(data[:4], 'big')
        instructions = []
        offset = 4

        for _ in range(inst_count):
            inst, offset = Instruction.deserialize(data, offset)
            instructions.append(inst)

        return cls(instructions)

    def init(self, input_data: bytes) -> MachineState:
        """Create initial state from input."""
        return MachineState(
            pc=0,
            registers={'sp': 0},  # Stack pointer
            memory_root=b'\x00' * 32,
            io_buffer=input_data,
            halted=False,
            failed=False
        )

    def output(self, state: MachineState) -> bytes:
        """Extract output from final state."""
        return state.io_buffer

    def step(self, state: MachineState) -> MachineState:
        """Execute one instruction."""
        if state.halted or state.failed:
            return state

        if state.pc < 0 or state.pc >= len(self.instructions):
            # Out of bounds - halt
            return MachineState(
                pc=state.pc,
                registers=state.registers.copy(),
                memory_root=state.memory_root,
                io_buffer=state.io_buffer,
                halted=True,
                failed=False
            )

        inst = self.instructions[state.pc]
        new_regs = state.registers.copy()
        new_pc = state.pc + 1
        new_io = state.io_buffer
        halted = False
        failed = False

        sp = new_regs.get('sp', 0)

        def push(val: int):
            nonlocal sp
            new_regs[f's{sp}'] = val
            sp += 1
            new_regs['sp'] = sp

        def pop() -> int:
            nonlocal sp, failed
            if sp <= 0:
                failed = True
                return 0
            sp -= 1
            new_regs['sp'] = sp
            return new_regs.get(f's{sp}', 0)

        def peek() -> int:
            if sp <= 0:
                return 0
            return new_regs.get(f's{sp-1}', 0)

        try:
            if inst.opcode == Opcode.NOP:
                pass

            elif inst.opcode == Opcode.PUSH:
                push(inst.operand or 0)

            elif inst.opcode == Opcode.POP:
                pop()

            elif inst.opcode == Opcode.DUP:
                val = peek()
                if sp > 0:
                    push(val)
                else:
                    failed = True

            elif inst.opcode == Opcode.SWAP:
                if sp >= 2:
                    a = pop()
                    b = pop()
                    push(a)
                    push(b)
                else:
                    failed = True

            elif inst.opcode == Opcode.ADD:
                b = pop()
                a = pop()
                if not failed:
                    push(a + b)

            elif inst.opcode == Opcode.SUB:
                b = pop()
                a = pop()
                if not failed:
                    push(a - b)

            elif inst.opcode == Opcode.MUL:
                b = pop()
                a = pop()
                if not failed:
                    push(a * b)

            elif inst.opcode == Opcode.DIV:
                b = pop()
                a = pop()
                if not failed:
                    if b == 0:
                        failed = True
                    else:
                        push(a // b)

            elif inst.opcode == Opcode.MOD:
                b = pop()
                a = pop()
                if not failed:
                    if b == 0:
                        failed = True
                    else:
                        push(a % b)

            elif inst.opcode == Opcode.EQ:
                b = pop()
                a = pop()
                if not failed:
                    push(1 if a == b else 0)

            elif inst.opcode == Opcode.LT:
                b = pop()
                a = pop()
                if not failed:
                    push(1 if a < b else 0)

            elif inst.opcode == Opcode.GT:
                b = pop()
                a = pop()
                if not failed:
                    push(1 if a > b else 0)

            elif inst.opcode == Opcode.AND:
                b = pop()
                a = pop()
                if not failed:
                    push(a & b)

            elif inst.opcode == Opcode.OR:
                b = pop()
                a = pop()
                if not failed:
                    push(a | b)

            elif inst.opcode == Opcode.NOT:
                a = pop()
                if not failed:
                    push(~a & 0xFFFFFFFFFFFFFFFF)

            elif inst.opcode == Opcode.JMP:
                new_pc = inst.operand or 0

            elif inst.opcode == Opcode.JZ:
                val = pop()
                if not failed and val == 0:
                    new_pc = inst.operand or 0

            elif inst.opcode == Opcode.JNZ:
                val = pop()
                if not failed and val != 0:
                    new_pc = inst.operand or 0

            elif inst.opcode == Opcode.CALL:
                push(new_pc)  # Push return address
                new_pc = inst.operand or 0

            elif inst.opcode == Opcode.RET:
                new_pc = pop()

            elif inst.opcode == Opcode.HALT:
                halted = True

            elif inst.opcode == Opcode.LOAD:
                addr = pop()
                if not failed:
                    val = new_regs.get(f'm{addr}', 0)
                    push(val)

            elif inst.opcode == Opcode.STORE:
                addr = pop()
                val = pop()
                if not failed:
                    new_regs[f'm{addr}'] = val

            elif inst.opcode == Opcode.INPUT:
                if len(new_io) > 0:
                    push(new_io[0])
                    new_io = new_io[1:]
                else:
                    push(0)  # EOF

            elif inst.opcode == Opcode.OUTPUT:
                val = pop()
                if not failed:
                    new_io = new_io + bytes([val & 0xFF])

            else:
                failed = True

        except Exception:
            failed = True

        return MachineState(
            pc=new_pc,
            registers=new_regs,
            memory_root=state.memory_root,
            io_buffer=new_io,
            halted=halted,
            failed=failed
        )


# Helper functions to build programs

def program_factorial(n: int) -> StackVM:
    """
    Create a program that computes factorial of n.

    Algorithm:
        result = 1
        while n > 1:
            result *= n
            n -= 1
        return result
    """
    # Store n at memory location 0, result at location 1
    # Indices: 0-2 init n, 3-5 init result, 6-10 loop check,
    #          11-17 multiply, 18-23 decrement, 24 jump back, 25-28 end
    instructions = [
        # Initialize: push n, store at m0 (indices 0-2)
        Instruction(Opcode.PUSH, n),       # 0
        Instruction(Opcode.PUSH, 0),        # 1
        Instruction(Opcode.STORE),          # 2

        # Initialize result = 1, store at m1 (indices 3-5)
        Instruction(Opcode.PUSH, 1),        # 3
        Instruction(Opcode.PUSH, 1),        # 4
        Instruction(Opcode.STORE),          # 5

        # Loop start (pc = 6): Load n (indices 6-7)
        Instruction(Opcode.PUSH, 0),        # 6
        Instruction(Opcode.LOAD),           # 7

        # Check if n > 1 (indices 8-9)
        Instruction(Opcode.PUSH, 1),        # 8
        Instruction(Opcode.GT),             # 9

        # If not, jump to end (index 10) -> jump to index 25
        Instruction(Opcode.JZ, 25),         # 10

        # result *= n: Load result (indices 11-12)
        Instruction(Opcode.PUSH, 1),        # 11
        Instruction(Opcode.LOAD),           # 12

        # Load n (indices 13-14)
        Instruction(Opcode.PUSH, 0),        # 13
        Instruction(Opcode.LOAD),           # 14

        # Multiply (index 15)
        Instruction(Opcode.MUL),            # 15

        # Store result (indices 16-17)
        Instruction(Opcode.PUSH, 1),        # 16
        Instruction(Opcode.STORE),          # 17

        # n -= 1: Load n (indices 18-19)
        Instruction(Opcode.PUSH, 0),        # 18
        Instruction(Opcode.LOAD),           # 19

        # Subtract 1 (indices 20-21)
        Instruction(Opcode.PUSH, 1),        # 20
        Instruction(Opcode.SUB),            # 21

        # Store n (indices 22-23)
        Instruction(Opcode.PUSH, 0),        # 22
        Instruction(Opcode.STORE),          # 23

        # Jump back to loop (index 24)
        Instruction(Opcode.JMP, 6),         # 24

        # End: load result and output (indices 25-28)
        Instruction(Opcode.PUSH, 1),        # 25
        Instruction(Opcode.LOAD),           # 26
        Instruction(Opcode.OUTPUT),         # 27
        Instruction(Opcode.HALT),           # 28
    ]

    return StackVM(instructions)


def program_fibonacci(n: int) -> StackVM:
    """
    Create a program that computes the n-th Fibonacci number.

    Algorithm:
        if n <= 1: return n
        a, b = 0, 1
        for i in range(2, n+1):
            a, b = b, a + b
        return b
    """
    # Carefully indexed instructions
    instructions = [
        # Store n at m0 (indices 0-2)
        Instruction(Opcode.PUSH, n),        # 0
        Instruction(Opcode.PUSH, 0),         # 1
        Instruction(Opcode.STORE),           # 2

        # If n > 1, skip to main loop (indices 3-7)
        Instruction(Opcode.PUSH, 0),         # 3
        Instruction(Opcode.LOAD),            # 4: load n
        Instruction(Opcode.PUSH, 1),         # 5
        Instruction(Opcode.GT),              # 6: n > 1?
        Instruction(Opcode.JNZ, 12),         # 7: if yes, jump to init (index 12)

        # Output n directly and halt (indices 8-11)
        Instruction(Opcode.PUSH, 0),         # 8
        Instruction(Opcode.LOAD),            # 9
        Instruction(Opcode.OUTPUT),          # 10
        Instruction(Opcode.HALT),            # 11

        # Initialize a=0 at m1 (indices 12-14)
        Instruction(Opcode.PUSH, 0),         # 12
        Instruction(Opcode.PUSH, 1),         # 13
        Instruction(Opcode.STORE),           # 14

        # Initialize b=1 at m2 (indices 15-17)
        Instruction(Opcode.PUSH, 1),         # 15
        Instruction(Opcode.PUSH, 2),         # 16
        Instruction(Opcode.STORE),           # 17

        # Initialize i=2 at m3 (indices 18-20)
        Instruction(Opcode.PUSH, 2),         # 18
        Instruction(Opcode.PUSH, 3),         # 19
        Instruction(Opcode.STORE),           # 20

        # Loop: while i <= n (indices 21-26)
        # Check: load i, load n, compare
        Instruction(Opcode.PUSH, 3),         # 21
        Instruction(Opcode.LOAD),            # 22: i
        Instruction(Opcode.PUSH, 0),         # 23
        Instruction(Opcode.LOAD),            # 24: n
        # We want i <= n, which is !(i > n)
        # GT computes (stack[-2] > stack[-1]) = (i > n)
        Instruction(Opcode.GT),              # 25: i > n?
        Instruction(Opcode.JNZ, 45),         # 26: if i > n, exit loop (jump to 45)

        # temp = a + b (indices 27-31)
        Instruction(Opcode.PUSH, 1),         # 27
        Instruction(Opcode.LOAD),            # 28: a
        Instruction(Opcode.PUSH, 2),         # 29
        Instruction(Opcode.LOAD),            # 30: b
        Instruction(Opcode.ADD),             # 31: a + b (temp on stack)

        # a = b (indices 32-35)
        Instruction(Opcode.PUSH, 2),         # 32
        Instruction(Opcode.LOAD),            # 33: b
        Instruction(Opcode.PUSH, 1),         # 34
        Instruction(Opcode.STORE),           # 35: m[1] = b (a = b)

        # b = temp (indices 36-37)
        Instruction(Opcode.PUSH, 2),         # 36
        Instruction(Opcode.STORE),           # 37: m[2] = temp (b = temp)

        # i += 1 (indices 38-43)
        Instruction(Opcode.PUSH, 3),         # 38
        Instruction(Opcode.LOAD),            # 39: i
        Instruction(Opcode.PUSH, 1),         # 40
        Instruction(Opcode.ADD),             # 41: i + 1
        Instruction(Opcode.PUSH, 3),         # 42
        Instruction(Opcode.STORE),           # 43: m[3] = i + 1

        # Loop back (index 44)
        Instruction(Opcode.JMP, 21),         # 44: back to loop start

        # Output b (indices 45-48)
        Instruction(Opcode.PUSH, 2),         # 45
        Instruction(Opcode.LOAD),            # 46: b
        Instruction(Opcode.OUTPUT),          # 47
        Instruction(Opcode.HALT),            # 48
    ]

    return StackVM(instructions)


def program_add(a: int, b: int) -> StackVM:
    """Simple program that adds two numbers."""
    return StackVM([
        Instruction(Opcode.PUSH, a),
        Instruction(Opcode.PUSH, b),
        Instruction(Opcode.ADD),
        Instruction(Opcode.OUTPUT),
        Instruction(Opcode.HALT),
    ])


def program_multiply(a: int, b: int) -> StackVM:
    """Simple program that multiplies two numbers."""
    return StackVM([
        Instruction(Opcode.PUSH, a),
        Instruction(Opcode.PUSH, b),
        Instruction(Opcode.MUL),
        Instruction(Opcode.OUTPUT),
        Instruction(Opcode.HALT),
    ])
