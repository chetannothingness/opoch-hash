"""
Memory-Hard Work Function

The canonical computation that is:
- Deterministic
- Sequential (cannot be parallelized meaningfully)
- Memory-hard (ASIC advantage bounded)
- Arithmetizable (provable via hash commitments)

The work function:
1. Derives address from current register (data-dependent)
2. Reads memory block with Merkle proof
3. Updates register based on read value
4. Writes back to memory (data-dependent)
5. Updates Merkle root

Each step MUST complete before the next can begin because:
- Address depends on current register
- New register depends on read value
- Write value depends on new register
"""

from typing import List, Tuple
import hashlib

from .tags import PoCTag, tag_bytes
from .params import PoCParams
from .state import WorkState, MemoryAccess
from .memory import MerkleMemory, MemoryProof, initialize_memory


def _hash(tag: PoCTag, *parts: bytes) -> bytes:
    """Domain-separated hash using SHAKE256."""
    h = hashlib.shake_256()
    h.update(tag_bytes(tag))
    for part in parts:
        h.update(len(part).to_bytes(4, 'big'))
        h.update(part)
    return h.digest(32)


def legacy_digest(input_data: bytes, algorithm = 'shake256') -> bytes:
    """
    Compute legacy digest d₀.

    This MUST match the existing hash used by infrastructure.
    Zero switching cost: old systems continue using d₀ unchanged.
    """
    # Handle LegacyHash enum or string
    from .params import LegacyHash
    if hasattr(algorithm, 'value'):
        algorithm = algorithm.value

    if algorithm == 'sha256':
        return hashlib.sha256(input_data).digest()
    elif algorithm == 'sha384':
        return hashlib.sha384(input_data).digest()
    elif algorithm == 'sha512':
        return hashlib.sha512(input_data).digest()
    elif algorithm == 'sha3_256':
        return hashlib.sha3_256(input_data).digest()
    elif algorithm == 'blake2b':
        return hashlib.blake2b(input_data, digest_size=32).digest()
    elif algorithm == 'shake256':
        return hashlib.shake_256(input_data).digest(32)
    else:
        raise ValueError(f"Unknown legacy hash: {algorithm}")


def compute_seed(d0: bytes, params: PoCParams) -> bytes:
    """
    Compute initial register from legacy digest.

    r₀ = H("SEED" || d₀ || θ)

    This binds the work to the specific input and parameters.
    """
    return _hash(PoCTag.SEED, d0, params.serialize())


def compute_address(register: bytes, num_blocks: int) -> int:
    """
    Compute memory address from register.

    a_t = int(r_t[:8], big-endian) mod num_blocks

    This is data-dependent - address depends on computation state.
    """
    addr_int = int.from_bytes(register[:8], 'big')
    return addr_int % num_blocks


def compute_step_register(
    r_t: bytes,
    b_t: bytes,
    t: int
) -> bytes:
    """
    Compute next register value.

    r_{t+1} = H("STEP" || r_t || b_t || t)

    This is the core sequential dependency.
    """
    return _hash(PoCTag.STEP, r_t, b_t, t.to_bytes(8, 'big'))


def compute_write_value(
    r_next: bytes,
    address: int,
    t: int,
    block_size: int
) -> bytes:
    """
    Compute value to write to memory.

    write_value = H("WRITE" || r_{t+1} || a_t || t)[:block_size]

    Data-dependent write based on new register state.
    """
    h = _hash(PoCTag.WRITE, r_next, address.to_bytes(8, 'big'), t.to_bytes(8, 'big'))
    # Extend to block_size if needed
    if len(h) < block_size:
        h = (h * (block_size // len(h) + 1))[:block_size]
    return h[:block_size]


def work_step(
    state: WorkState,
    memory: MerkleMemory,
    params: PoCParams
) -> Tuple[WorkState, MemoryAccess]:
    """
    Execute one step of the memory-hard computation.

    CRITICAL: This is inherently sequential because:
    1. Address a_t depends on register r_t
    2. Read value b_t depends on address (from memory)
    3. New register r_{t+1} depends on b_t
    4. Write value depends on r_{t+1}
    5. New memory root M_{t+1} depends on write value

    No step can begin before the previous completes.

    Args:
        state: Current state s_t
        memory: Memory array (will be mutated)
        params: Public parameters

    Returns:
        (next_state, memory_access)
    """
    # 1. Compute address (data-dependent)
    a_t = compute_address(state.r, params.num_blocks)

    # 2. Read memory block with proof
    b_t, read_proof = memory.read(a_t)

    # 3. Compute new register
    r_next = compute_step_register(state.r, b_t, state.t)

    # 4. Compute write value
    write_value = compute_write_value(r_next, a_t, state.t, params.block_size)

    # 5. Write to memory and update root
    new_root, old_proof, write_proof = memory.write(a_t, write_value)

    # Create memory access record
    mem_access = MemoryAccess(
        address=a_t,
        read_value=b_t,
        write_value=write_value,
        read_proof=read_proof.serialize(),
        write_proof=write_proof.serialize()
    )

    # Create new state
    next_state = WorkState(
        r=r_next,
        t=state.t + 1,
        M=new_root
    )

    return next_state, mem_access


def verify_step(
    state_t: WorkState,
    state_t1: WorkState,
    mem_access: MemoryAccess,
    params: PoCParams
) -> bool:
    """
    Verify a single step transition is valid.

    Checks:
    1. Step counter incremented correctly
    2. Address derived correctly from register
    3. Read proof valid under old root
    4. Register updated correctly
    5. Write value computed correctly
    6. Write proof valid under new root

    Args:
        state_t: State before step
        state_t1: State after step
        mem_access: Memory access record
        params: Public parameters

    Returns:
        True if step is valid
    """
    # 1. Check step counter
    if state_t1.t != state_t.t + 1:
        return False

    # 2. Check address derivation
    expected_addr = compute_address(state_t.r, params.num_blocks)
    if mem_access.address != expected_addr:
        return False

    # 3. Verify read proof
    read_proof = MemoryProof.deserialize(mem_access.read_proof)
    if not read_proof.verify(state_t.M):
        return False
    if read_proof.value != mem_access.read_value:
        return False

    # 4. Check register update
    expected_r = compute_step_register(state_t.r, mem_access.read_value, state_t.t)
    if state_t1.r != expected_r:
        return False

    # 5. Check write value
    expected_write = compute_write_value(expected_r, mem_access.address, state_t.t, params.block_size)
    if mem_access.write_value != expected_write:
        return False

    # 6. Verify write proof
    write_proof = MemoryProof.deserialize(mem_access.write_proof)
    if not write_proof.verify(state_t1.M):
        return False
    if write_proof.value != mem_access.write_value:
        return False

    return True


def execute_work(
    input_data: bytes,
    params: PoCParams,
    return_trace: bool = True
) -> Tuple[bytes, bytes, List[WorkState], List[MemoryAccess]]:
    """
    Execute complete work computation.

    Args:
        input_data: Raw input x
        params: Public parameters θ
        return_trace: If False, only return final state (saves memory)

    Returns:
        (d0, r_final, trace, memory_accesses)
        - d0: Legacy digest (for backward compatibility)
        - r_final: Final register value
        - trace: All states [s_0, s_1, ..., s_W] (if return_trace)
        - memory_accesses: Memory access records for each step
    """
    # Compute legacy digest (zero switching cost)
    d0 = legacy_digest(input_data, params.legacy_hash)

    # Compute initial seed
    r0 = compute_seed(d0, params)

    # Initialize memory
    memory, M0 = initialize_memory(r0, params.num_blocks, params.block_size)

    # Initial state
    state = WorkState(r=r0, t=0, M=M0)

    trace = [state] if return_trace else []
    memory_accesses = []

    # Sequential execution
    for step in range(params.W):
        state, mem_access = work_step(state, memory, params)
        memory_accesses.append(mem_access)
        if return_trace:
            trace.append(state)

        # Progress reporting for long computations
        if (step + 1) % 100000 == 0:
            progress = (step + 1) / params.W * 100
            # Could log progress here

    return d0, state.r, trace, memory_accesses


def verify_execution(
    d0: bytes,
    r_final: bytes,
    trace: List[WorkState],
    memory_accesses: List[MemoryAccess],
    params: PoCParams
) -> bool:
    """
    Verify complete execution by replaying all steps.

    This is O(W) verification - used for Level 0 proof.

    Args:
        d0: Legacy digest
        r_final: Claimed final register
        trace: Execution trace
        memory_accesses: Memory access records
        params: Public parameters

    Returns:
        True if execution is valid
    """
    # Verify trace length
    if len(trace) != params.W + 1:
        return False
    if len(memory_accesses) != params.W:
        return False

    # Verify initial state
    expected_r0 = compute_seed(d0, params)
    if trace[0].r != expected_r0:
        return False
    if trace[0].t != 0:
        return False

    # Verify each step
    for t in range(params.W):
        if not verify_step(trace[t], trace[t+1], memory_accesses[t], params):
            return False

    # Verify final register
    if trace[-1].r != r_final:
        return False

    return True


class WorkExecutor:
    """
    Executor for memory-hard work with state management.

    Supports:
    - Incremental execution
    - Checkpointing
    - Progress tracking
    """

    def __init__(self, params: PoCParams):
        self.params = params
        self.state: WorkState = None
        self.memory: MerkleMemory = None
        self.trace: List[WorkState] = []
        self.memory_accesses: List[MemoryAccess] = []
        self.d0: bytes = None

    def initialize(self, input_data: bytes):
        """Initialize execution from input."""
        self.d0 = legacy_digest(input_data, self.params.legacy_hash)
        r0 = compute_seed(self.d0, self.params)
        self.memory, M0 = initialize_memory(r0, self.params.num_blocks, self.params.block_size)
        self.state = WorkState(r=r0, t=0, M=M0)
        self.trace = [self.state]
        self.memory_accesses = []

    def step(self) -> bool:
        """
        Execute one step.

        Returns:
            True if more steps remain, False if complete
        """
        if self.state.t >= self.params.W:
            return False

        self.state, mem_access = work_step(self.state, self.memory, self.params)
        self.trace.append(self.state)
        self.memory_accesses.append(mem_access)

        return self.state.t < self.params.W

    def run_to_completion(self):
        """Execute all remaining steps."""
        while self.step():
            pass

    def get_result(self) -> Tuple[bytes, bytes, List[WorkState], List[MemoryAccess]]:
        """Get execution result."""
        return self.d0, self.state.r, self.trace, self.memory_accesses

    @property
    def progress(self) -> float:
        """Get progress as fraction [0, 1]."""
        if self.state is None:
            return 0.0
        return self.state.t / self.params.W

    @property
    def is_complete(self) -> bool:
        """Check if execution is complete."""
        return self.state is not None and self.state.t >= self.params.W


def compute_full_work(
    input_data: bytes,
    params: PoCParams
) -> Tuple[List[WorkState], List[MemoryAccess]]:
    """
    Compute full work and return trace + memory accesses.

    This is the main entry point for proof generation.

    Args:
        input_data: Raw input x
        params: Public parameters θ

    Returns:
        (trace, memory_accesses)
        - trace: All states [s_0, s_1, ..., s_W]
        - memory_accesses: Memory access records for each step
    """
    _, _, trace, memory_accesses = execute_work(input_data, params, return_trace=True)
    return trace, memory_accesses
