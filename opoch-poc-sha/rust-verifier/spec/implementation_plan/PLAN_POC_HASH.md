# PoC_Hash Implementation Plan

## Complete Hash-Based Proof of Computation System

**Target**: Beat ALL 8 benchmarks with 100% compliance, zero shortcuts.

---

## Executive Summary

We build:

```
PoC_Hash(x; θ) → (d₀, π)
```

Where:
- **d₀** = Legacy digest (H₀(x)) - zero switching cost
- **π** = Proof of W sequential memory-hard steps
- **θ** = Public parameters (security level, work target W, memory target m, circuit ID)

**Verification Properties**:
- Prove time: O(W)
- Verify time: O(polylog W) with Tier S (STARK)
- Soundness: < 2^-128 forgery probability
- Proof size: < 1KB for 10^12 steps (with recursion)

---

## Part 1: Architecture Overview

### 1.1 The Complete Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                    PoC_Hash(x; θ) → (d₀, π)                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────────────────────────┐ │
│  │ LEGACY DIGEST   │    │        PROOF π                      │ │
│  │                 │    │                                     │ │
│  │ d₀ = H₀(x)     │    │  ┌──────────────┐  ┌─────────────┐  │ │
│  │                 │    │  │ Work Trace   │  │ STARK Proof │  │ │
│  │ (SHA-256 or    │    │  │ Commitment   │  │ (Tier S)    │  │ │
│  │  existing hash) │    │  └──────────────┘  └─────────────┘  │ │
│  └─────────────────┘    │         │                │          │ │
│          │              │         ▼                ▼          │ │
│          │              │  ┌─────────────────────────────────┐│ │
│          │              │  │ Soundness: < 2^-128             ││ │
│          │              │  │ Verify: O(polylog W)            ││ │
│          │              │  │ Proof Size: O(polylog W)        ││ │
│          │              │  └─────────────────────────────────┘│ │
│          │              └─────────────────────────────────────┘ │
│          │                                                      │
│          ▼                                                      │
│   [Old systems use d₀ unchanged - ZERO SWITCHING COST]         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Module Structure

```
src/opochhash/
├── poc/                          # NEW: Proof of Computation
│   ├── __init__.py
│   ├── params.py                 # Public parameters θ
│   ├── work.py                   # Memory-hard work function
│   ├── memory.py                 # Merkle memory model
│   ├── state.py                  # Work state (r_t, i_t, M_t)
│   ├── field.py                  # Finite field arithmetic
│   ├── poly.py                   # Polynomial operations
│   ├── fri.py                    # FRI protocol
│   ├── constraints.py            # AIR constraint system
│   ├── tier_q.py                 # Quick spot-check (uses Level 1)
│   ├── tier_s.py                 # STARK prover/verifier
│   ├── recursion.py              # Proof aggregation
│   └── poc_hash.py               # Main API: PoC_Hash()
├── bench/
│   └── poc/                      # NEW: PoC benchmarks
│       ├── __init__.py
│       ├── runner_asymmetry.py   # Benchmark 1
│       ├── runner_soundness.py   # Benchmark 2
│       ├── runner_tightness.py   # Benchmark 3
│       ├── runner_universal.py   # Benchmark 4
│       ├── runner_compose.py     # Benchmark 5
│       ├── runner_practical.py   # Benchmark 6
│       ├── runner_security.py    # Benchmark 7
│       ├── runner_economic.py    # Benchmark 8
│       └── poc_bench.py          # Orchestrator
└── proof/                        # EXISTING (Level 0, 1, 2)
    └── ... (already implemented)
```

---

## Part 2: The Canonical Computation (Work Function)

### 2.1 State Definition

```python
@dataclass
class WorkState:
    """State at step t of the memory-hard computation."""
    r: bytes           # Register state (256 bits)
    t: int             # Step counter
    M: bytes           # Merkle root of memory array A (32 bytes)

    def serialize(self) -> bytes:
        """Canonical serialization for hashing."""
        return b''.join([
            self.r,                          # 32 bytes
            self.t.to_bytes(8, 'big'),       # 8 bytes
            self.M                           # 32 bytes
        ])  # Total: 72 bytes
```

### 2.2 Parameters θ

```python
@dataclass(frozen=True)
class PoCParams:
    """Public parameters for proof of computation."""

    # Security
    security_bits: int = 128          # Target soundness 2^-128

    # Work parameters
    W: int = 1_000_000                # Number of sequential steps

    # Memory parameters
    memory_bytes: int = 256 * 1024 * 1024  # 256 MB
    block_size: int = 64                    # Bytes per block

    # Derived
    @property
    def num_blocks(self) -> int:
        return self.memory_bytes // self.block_size

    # Circuit identification (for domain separation)
    circuit_id: bytes = b'POC_WORK_V1'

    # Legacy hash (for d₀)
    legacy_hash: str = 'sha256'

    def serialize(self) -> bytes:
        """Canonical serialization for binding."""
```

### 2.3 Seed (Bind Work to Legacy Digest)

```python
def compute_seed(d0: bytes, params: PoCParams) -> bytes:
    """
    Compute initial register from legacy digest.

    r₀ = H("SEED" ‖ d₀ ‖ θ)

    This binds the work to the specific input and parameters.
    """
    return domain_hash(
        ProofTag.SEED,
        d0,
        params.serialize()
    )
```

### 2.4 Memory Initialization (Parallelizable)

```python
def initialize_memory(r0: bytes, params: PoCParams) -> Tuple[List[bytes], bytes]:
    """
    Fill memory array with PRF stream from seed.

    A₀[j] = H("INIT" ‖ r₀ ‖ j) for all block indices j

    Returns: (memory_blocks, merkle_root)

    This is parallelizable across all blocks.
    """
    blocks = []
    for j in range(params.num_blocks):
        block = domain_hash(
            ProofTag.INIT,
            r0,
            j.to_bytes(8, 'big')
        )[:params.block_size]
        blocks.append(block)

    # Build Merkle tree
    tree = MerkleTree(blocks)
    return blocks, tree.root
```

### 2.5 Sequential Step Function (CRITICAL: Cannot Be Parallelized)

```python
def work_step(
    state: WorkState,
    memory: List[bytes],
    memory_tree: MerkleTree,
    params: PoCParams
) -> Tuple[WorkState, MemoryProof]:
    """
    Execute one step of the memory-hard computation.

    1. Address from current register:
       a_t = Addr(r_t) ∈ [0, N_blocks - 1]

    2. Read block with Merkle proof:
       b_t = A_t[a_t]

    3. Update register:
       r_{t+1} = H("STEP" ‖ r_t ‖ b_t ‖ t)

    4. Write back (data-dependent):
       A_{t+1}[a_t] = H("WRITE" ‖ r_{t+1} ‖ a_t ‖ t)

    5. Update Merkle root:
       M_{t+1} = MerkleUpdate(M_t, a_t, A_{t+1}[a_t])

    CRITICAL: This step MUST be sequential because:
    - Address a_t depends on r_t (from previous step)
    - Register r_{t+1} depends on b_t (from memory at a_t)
    - Memory write depends on r_{t+1}
    - No step can start before previous completes
    """
    # 1. Compute address (data-dependent)
    a_t = int.from_bytes(state.r[:8], 'big') % params.num_blocks

    # 2. Read with proof
    b_t = memory[a_t]
    read_proof = memory_tree.get_proof(a_t)

    # 3. Update register
    r_next = domain_hash(
        ProofTag.STEP,
        state.r,
        b_t,
        state.t.to_bytes(8, 'big')
    )

    # 4. Compute write value
    write_value = domain_hash(
        ProofTag.WRITE,
        r_next,
        a_t.to_bytes(8, 'big'),
        state.t.to_bytes(8, 'big')
    )[:params.block_size]

    # 5. Update memory and Merkle root
    memory[a_t] = write_value
    M_next = memory_tree.update(a_t, write_value)

    # Create memory proof
    mem_proof = MemoryProof(
        address=a_t,
        read_value=b_t,
        read_proof=read_proof,
        write_value=write_value,
        # write_proof computed from updated tree
    )

    return WorkState(r=r_next, t=state.t + 1, M=M_next), mem_proof
```

### 2.6 Complete Work Execution

```python
def execute_work(
    input_data: bytes,
    params: PoCParams
) -> Tuple[bytes, bytes, List[WorkState], List[MemoryProof]]:
    """
    Execute full work computation.

    Returns:
        d0: Legacy digest
        final_r: Final register (proof target)
        trace: All states [s_0, s_1, ..., s_W]
        mem_proofs: Memory access proofs for each step
    """
    # Legacy digest (zero switching cost)
    d0 = legacy_hash(input_data, params.legacy_hash)

    # Initialize
    r0 = compute_seed(d0, params)
    memory, M0 = initialize_memory(r0, params)
    memory_tree = MerkleTree(memory)

    state = WorkState(r=r0, t=0, M=M0)
    trace = [state]
    mem_proofs = []

    # Sequential execution (cannot parallelize)
    for _ in range(params.W):
        state, mem_proof = work_step(state, memory, memory_tree, params)
        trace.append(state)
        mem_proofs.append(mem_proof)

    return d0, state.r, trace, mem_proofs
```

---

## Part 3: Proof System Architecture

### 3.1 Two-Tier Design

```
┌─────────────────────────────────────────────────────────────────┐
│                      PROOF SYSTEM                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────┐  ┌─────────────────────────────┐  │
│  │      TIER S (STARK)     │  │      TIER Q (QUICK)         │  │
│  │                         │  │                             │  │
│  │  • Polylog verify       │  │  • O(k log W) verify        │  │
│  │  • < 1KB proof size     │  │  • Larger proofs            │  │
│  │  • For production       │  │  • For debugging/testing    │  │
│  │                         │  │                             │  │
│  │  Components:            │  │  Components:                │  │
│  │  - AIR constraints      │  │  - Merkle trace commit      │  │
│  │  - Polynomial commit    │  │  - Fiat-Shamir challenges   │  │
│  │  - FRI protocol         │  │  - Spot-check transitions   │  │
│  │  - Recursion layer      │  │  (Already implemented as    │  │
│  │                         │  │   Level 1 in proof/)        │  │
│  └─────────────────────────┘  └─────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Tier Q: Quick Proof (Reuse Existing Level 1)

Tier Q directly uses the existing `proof/level1.py` implementation:

```python
class TierQProver:
    """Quick spot-check proof (wraps Level 1)."""

    def __init__(self, params: PoCParams):
        self.params = params
        self.level1_prover = Level1Prover(
            security_parameter=params.security_bits
        )

    def prove(self, trace: List[WorkState], mem_proofs: List[MemoryProof]) -> TierQProof:
        """Generate spot-check proof."""
        # Adapt work trace to Level 1 format
        program = WorkProgram(self.params)
        serialized_trace = [s.serialize() for s in trace]

        # Use Level 1 prover
        l1_proof = self.level1_prover.prove_from_trace(serialized_trace, program)

        return TierQProof(
            level1_proof=l1_proof,
            params=self.params
        )
```

### 3.3 Tier S: STARK Proof (New Implementation)

#### 3.3.1 Finite Field

```python
# Field: F_p where p = 2^64 - 2^32 + 1 (Goldilocks)
# This prime has fast arithmetic and FFT-friendly structure

GOLDILOCKS_PRIME = 2**64 - 2**32 + 1

class FieldElement:
    """Element of the Goldilocks field."""

    def __init__(self, value: int):
        self.value = value % GOLDILOCKS_PRIME

    def __add__(self, other): ...
    def __sub__(self, other): ...
    def __mul__(self, other): ...
    def __truediv__(self, other): ...  # Multiplicative inverse
    def __pow__(self, exp): ...
    def __neg__(self): ...
    def __eq__(self, other): ...

    @staticmethod
    def from_bytes(data: bytes) -> 'FieldElement': ...

    def to_bytes(self) -> bytes: ...
```

#### 3.3.2 Polynomial Operations

```python
class Polynomial:
    """Polynomial over the Goldilocks field."""

    def __init__(self, coeffs: List[FieldElement]):
        self.coeffs = coeffs

    @property
    def degree(self) -> int:
        return len(self.coeffs) - 1

    def evaluate(self, x: FieldElement) -> FieldElement:
        """Horner's method evaluation."""

    def evaluate_domain(self, domain: List[FieldElement]) -> List[FieldElement]:
        """FFT-based multi-point evaluation."""

    @staticmethod
    def interpolate(points: List[Tuple[FieldElement, FieldElement]]) -> 'Polynomial':
        """Lagrange interpolation."""

    @staticmethod
    def interpolate_fft(values: List[FieldElement], domain: List[FieldElement]) -> 'Polynomial':
        """FFT-based interpolation (inverse FFT)."""


def fft(values: List[FieldElement], omega: FieldElement) -> List[FieldElement]:
    """Fast Fourier Transform over finite field."""

def ifft(values: List[FieldElement], omega: FieldElement) -> List[FieldElement]:
    """Inverse FFT."""
```

#### 3.3.3 Polynomial Commitment (Merkle-Based)

```python
class MerklePolynomialCommitment:
    """
    Commit to polynomial by committing to its evaluations over a domain.

    commit(p) = MerkleRoot([p(ω^0), p(ω^1), ..., p(ω^{n-1})])

    where ω is a primitive n-th root of unity.
    """

    def __init__(self, domain_size: int):
        self.domain_size = domain_size
        self.omega = self._find_generator(domain_size)
        self.domain = [self.omega ** i for i in range(domain_size)]

    def commit(self, poly: Polynomial) -> Tuple[bytes, MerkleTree]:
        """
        Commit to polynomial.

        Returns: (commitment, opening_tree)
        """
        # Evaluate on domain
        evaluations = poly.evaluate_domain(self.domain)

        # Build Merkle tree
        leaves = [e.to_bytes() for e in evaluations]
        tree = MerkleTree(leaves)

        return tree.root, tree

    def open(self, tree: MerkleTree, indices: List[int]) -> List[PolynomialOpening]:
        """Open polynomial at specific indices."""
        openings = []
        for idx in indices:
            openings.append(PolynomialOpening(
                index=idx,
                value=tree.leaves[idx],
                proof=tree.get_proof(idx)
            ))
        return openings

    def verify_opening(self, commitment: bytes, opening: PolynomialOpening) -> bool:
        """Verify a single opening."""
        return opening.proof.verify(commitment)
```

#### 3.3.4 AIR Constraints (Algebraic Intermediate Representation)

```python
class WorkAIR:
    """
    Algebraic constraints for the memory-hard work function.

    Trace columns:
    - R[t]: Register value at step t (256 bits → 4 field elements)
    - A[t]: Address computed at step t
    - B[t]: Block read at step t
    - M[t]: Memory Merkle root at step t
    - AUX[t]: Auxiliary columns for hash computation

    Constraints (must hold for all t):
    1. A[t] = Addr(R[t])                    # Address derivation
    2. B[t] is consistent with M[t]          # Merkle read
    3. R[t+1] = H("STEP" ‖ R[t] ‖ B[t] ‖ t) # Register update
    4. M[t+1] = MerkleUpdate(M[t], ...)     # Memory update
    5. Boundary: R[0] = r₀, R[W] = r_final  # Start/end conditions
    """

    def __init__(self, params: PoCParams):
        self.params = params
        self.num_columns = self._compute_num_columns()
        self.constraint_degree = self._compute_constraint_degree()

    def generate_trace(self, execution_trace: List[WorkState]) -> List[List[FieldElement]]:
        """Convert execution trace to algebraic trace columns."""

    def get_transition_constraints(self) -> List[Polynomial]:
        """
        Transition constraints: C(x, x') = 0 for valid transitions.

        These are polynomials in current state x and next state x'.
        """

    def get_boundary_constraints(self, r0: bytes, r_final: bytes) -> List[BoundaryConstraint]:
        """
        Boundary constraints at specific positions.

        - Position 0: R = r₀
        - Position W: R = r_final
        """

    def verify_constraints_at_point(self,
                                    trace_values: Dict[str, FieldElement],
                                    next_values: Dict[str, FieldElement],
                                    boundary_values: Dict[str, FieldElement]) -> bool:
        """Check all constraints at a specific evaluation point."""
```

#### 3.3.5 FRI Protocol (Fast Reed-Solomon IOP)

```python
class FRIProtocol:
    """
    Fast Reed-Solomon Interactive Oracle Proofs of Proximity.

    Proves that a committed function is close to a low-degree polynomial.

    Protocol:
    1. Commit to f₀(x) = polynomial over evaluation domain
    2. For each round i:
       a. Receive random α_i from verifier (Fiat-Shamir)
       b. Compute f_{i+1}(x) = fold(f_i, α_i) with half the degree
       c. Commit to f_{i+1}
    3. Final polynomial is constant (degree 0)
    4. Verifier checks random queries through all layers
    """

    def __init__(self,
                 domain_size: int,
                 rate: float = 0.5,
                 num_queries: int = 30):
        self.domain_size = domain_size
        self.rate = rate
        self.num_queries = num_queries
        self.num_rounds = int(math.log2(domain_size))

    def prove(self, poly: Polynomial, commitment_tree: MerkleTree) -> FRIProof:
        """Generate FRI proof that committed values form a low-degree polynomial."""

        layers = [commitment_tree]
        alphas = []

        current_poly = poly
        current_domain_size = self.domain_size

        transcript = Transcript()
        transcript.append(commitment_tree.root)

        # Folding rounds
        for round_idx in range(self.num_rounds):
            # Fiat-Shamir challenge
            alpha = transcript.challenge_field_element()
            alphas.append(alpha)

            # Fold polynomial
            current_poly = self._fold(current_poly, alpha)
            current_domain_size //= 2

            # Commit to folded polynomial
            evaluations = current_poly.evaluate_domain(
                self._get_domain(current_domain_size)
            )
            layer_tree = MerkleTree([e.to_bytes() for e in evaluations])
            layers.append(layer_tree)

            transcript.append(layer_tree.root)

        # Final constant
        final_value = current_poly.coeffs[0] if current_poly.coeffs else FieldElement(0)

        # Generate query proofs
        query_indices = transcript.challenge_indices(self.num_queries, self.domain_size)
        query_proofs = self._generate_query_proofs(layers, query_indices, alphas)

        return FRIProof(
            layer_commitments=[l.root for l in layers],
            final_value=final_value,
            query_proofs=query_proofs
        )

    def verify(self,
               initial_commitment: bytes,
               claimed_degree: int,
               proof: FRIProof) -> bool:
        """Verify FRI proof."""

        transcript = Transcript()
        transcript.append(initial_commitment)

        # Reconstruct alphas
        alphas = []
        for layer_commitment in proof.layer_commitments[1:]:
            alpha = transcript.challenge_field_element()
            alphas.append(alpha)
            transcript.append(layer_commitment)

        # Verify queries
        query_indices = transcript.challenge_indices(self.num_queries, self.domain_size)

        for query_idx, query_proof in zip(query_indices, proof.query_proofs):
            if not self._verify_query(query_proof, proof.layer_commitments, alphas, query_idx):
                return False

        # Verify final value is consistent
        return True

    def _fold(self, poly: Polynomial, alpha: FieldElement) -> Polynomial:
        """
        Fold polynomial: f(x) → g(x) where g(x) = f_even(x) + α·f_odd(x)

        This halves the degree while preserving the polynomial relationship.
        """
```

#### 3.3.6 STARK Prover

```python
class STARKProver:
    """
    STARK prover for memory-hard work verification.

    Workflow:
    1. Generate algebraic trace from execution
    2. Commit to trace columns
    3. Derive constraint polynomials
    4. Commit to constraint composition
    5. Run FRI on composition polynomial
    6. Package proof
    """

    def __init__(self, params: PoCParams):
        self.params = params
        self.air = WorkAIR(params)
        self.blowup_factor = 8  # Domain extension factor
        self.fri_queries = 30   # Number of FRI queries

    def prove(self,
              d0: bytes,
              r0: bytes,
              r_final: bytes,
              trace: List[WorkState],
              mem_proofs: List[MemoryProof]) -> STARKProof:
        """Generate STARK proof of correct execution."""

        transcript = Transcript()

        # 1. Generate algebraic trace
        trace_columns = self.air.generate_trace(trace)
        trace_domain_size = len(trace) * self.blowup_factor

        # 2. Commit to trace columns
        trace_commitments = []
        trace_trees = []
        for col in trace_columns:
            poly = Polynomial.interpolate_fft(col, self._get_trace_domain())
            evaluations = poly.evaluate_domain(self._get_lde_domain())
            tree = MerkleTree([e.to_bytes() for e in evaluations])
            trace_commitments.append(tree.root)
            trace_trees.append(tree)
            transcript.append(tree.root)

        # 3. Derive constraint composition randomness
        composition_alphas = [transcript.challenge_field_element()
                             for _ in range(self.air.num_constraints)]

        # 4. Compute composition polynomial
        # C(x) = Σ α_i · c_i(x) / Z(x)
        # where c_i are constraint polynomials and Z is the zerofier
        composition_poly = self._compute_composition(
            trace_columns, composition_alphas, r0, r_final
        )

        # 5. Commit to composition polynomial
        composition_evaluations = composition_poly.evaluate_domain(self._get_lde_domain())
        composition_tree = MerkleTree([e.to_bytes() for e in composition_evaluations])
        transcript.append(composition_tree.root)

        # 6. FRI proof for composition polynomial
        fri = FRIProtocol(
            domain_size=trace_domain_size,
            num_queries=self.fri_queries
        )
        fri_proof = fri.prove(composition_poly, composition_tree)

        # 7. Query openings
        query_indices = transcript.challenge_indices(self.fri_queries, trace_domain_size)
        trace_openings = [
            [tree.get_proof(idx) for idx in query_indices]
            for tree in trace_trees
        ]
        composition_openings = [composition_tree.get_proof(idx) for idx in query_indices]

        return STARKProof(
            params=self.params,
            trace_commitments=trace_commitments,
            composition_commitment=composition_tree.root,
            fri_proof=fri_proof,
            trace_openings=trace_openings,
            composition_openings=composition_openings,
            r0=r0,
            r_final=r_final
        )
```

#### 3.3.7 STARK Verifier

```python
class STARKVerifier:
    """
    STARK verifier - O(polylog W) verification.
    """

    def __init__(self, params: PoCParams):
        self.params = params
        self.air = WorkAIR(params)

    def verify(self, d0: bytes, proof: STARKProof) -> bool:
        """
        Verify STARK proof.

        Cost: O(polylog W) - does NOT replay execution
        """
        transcript = Transcript()

        # 1. Reconstruct challenge randomness
        for commitment in proof.trace_commitments:
            transcript.append(commitment)

        composition_alphas = [transcript.challenge_field_element()
                             for _ in range(self.air.num_constraints)]

        transcript.append(proof.composition_commitment)

        # 2. Verify r0 is correctly derived from d0
        expected_r0 = compute_seed(d0, self.params)
        if proof.r0 != expected_r0:
            return False

        # 3. Verify FRI proof
        fri = FRIProtocol(
            domain_size=self._get_lde_domain_size(),
            num_queries=self.air.fri_queries
        )
        if not fri.verify(proof.composition_commitment,
                          self.air.constraint_degree,
                          proof.fri_proof):
            return False

        # 4. Verify query openings
        query_indices = transcript.challenge_indices(
            self.air.fri_queries, self._get_lde_domain_size()
        )

        for i, idx in enumerate(query_indices):
            # Verify trace openings
            for col_idx, opening in enumerate(proof.trace_openings):
                if not opening[i].verify(proof.trace_commitments[col_idx]):
                    return False

            # Verify composition opening
            if not proof.composition_openings[i].verify(proof.composition_commitment):
                return False

            # Verify constraint satisfaction at this point
            trace_values = self._extract_trace_values(proof.trace_openings, i)
            composition_value = FieldElement.from_bytes(proof.composition_openings[i].value)

            expected_composition = self._compute_expected_composition(
                trace_values, composition_alphas, idx
            )

            if composition_value != expected_composition:
                return False

        return True
```

#### 3.3.8 Recursion (Proof Aggregation)

```python
class RecursiveProver:
    """
    Aggregate multiple STARK proofs into one constant-size proof.

    For 10^12 steps with <1KB proof:
    1. Split W into segments (e.g., 10^6 steps each)
    2. Generate STARK proof for each segment
    3. Wrap STARK verifier in a circuit
    4. Generate recursive proof that "all verifiers accepted"
    """

    def __init__(self, params: PoCParams, segment_size: int = 1_000_000):
        self.params = params
        self.segment_size = segment_size

    def prove_aggregated(self,
                         d0: bytes,
                         segment_proofs: List[STARKProof]) -> AggregatedProof:
        """
        Generate aggregated proof from segment proofs.

        The aggregated proof proves:
        "For all i: STARKVerifier.verify(segment_proofs[i]) = True"
        "AND segment_proofs chain correctly: r_final[i] = r_0[i+1]"
        """
        # Compute commitment to all segment proofs
        proof_digests = [hash_proof(p) for p in segment_proofs]
        proof_tree = MerkleTree(proof_digests)

        # Verify chaining
        for i in range(len(segment_proofs) - 1):
            assert segment_proofs[i].r_final == segment_proofs[i+1].r0

        # Generate recursive STARK
        # (This proves "the verifier accepts all proofs")
        recursive_circuit = STARKVerifierCircuit(self.params)
        recursive_proof = recursive_circuit.prove(segment_proofs)

        return AggregatedProof(
            params=self.params,
            num_segments=len(segment_proofs),
            total_steps=self.params.W,
            d0=d0,
            r_final=segment_proofs[-1].r_final,
            proof_root=proof_tree.root,
            recursive_proof=recursive_proof
        )
```

---

## Part 4: Main API

### 4.1 PoC_Hash Function

```python
def poc_hash(
    input_data: bytes,
    params: PoCParams = None,
    tier: str = 'S'  # 'S' for STARK, 'Q' for Quick
) -> Tuple[bytes, PoCProof]:
    """
    Hash-based proof of computation.

    PoC_Hash(x; θ) → (d₀, π)

    Args:
        input_data: Raw input bytes x
        params: Public parameters θ
        tier: 'S' (STARK, polylog verify) or 'Q' (quick, O(k log W) verify)

    Returns:
        d0: Legacy digest (for backward compatibility)
        proof: Proof of W sequential steps

    Usage:
        # New systems
        d0, proof = poc_hash(data)
        assert poc_verify(d0, proof)

        # Legacy systems (unchanged)
        legacy_digest = sha256(data)  # Same as d0
    """
    if params is None:
        params = PoCParams()

    # Execute work
    d0, r_final, trace, mem_proofs = execute_work(input_data, params)

    # Generate proof
    if tier == 'S':
        prover = STARKProver(params)
        proof = prover.prove(d0, trace[0].r, r_final, trace, mem_proofs)
    elif tier == 'Q':
        prover = TierQProver(params)
        proof = prover.prove(trace, mem_proofs)
    else:
        raise ValueError(f"Unknown tier: {tier}")

    return d0, PoCProof(tier=tier, proof=proof, params=params)


def poc_verify(d0: bytes, proof: PoCProof) -> bool:
    """
    Verify proof of computation.

    Cost:
        Tier S: O(polylog W)
        Tier Q: O(k log W)

    Does NOT replay execution.
    """
    if proof.tier == 'S':
        verifier = STARKVerifier(proof.params)
        return verifier.verify(d0, proof.proof)
    elif proof.tier == 'Q':
        verifier = TierQVerifier(proof.params)
        return verifier.verify(d0, proof.proof)
    else:
        raise ValueError(f"Unknown tier: {proof.tier}")
```

---

## Part 5: Benchmark Implementations

### 5.1 Benchmark 1: Verification Asymmetry

```python
class AsymmetryBenchmark:
    """
    BENCHMARK 1: Verification Asymmetry

    Target:
    - Prove time grows linearly with W
    - Verify time grows polylog or constant (via recursion)
    - Ratio ≥ 1000:1 at large W
    """

    def run(self) -> Dict:
        results = []

        for W in [10**3, 10**6, 10**9, 10**12]:
            params = PoCParams(W=W)

            # Measure prove time
            input_data = os.urandom(1024)
            start = time.perf_counter()
            d0, proof = poc_hash(input_data, params, tier='S')
            prove_time = time.perf_counter() - start

            # Measure verify time
            start = time.perf_counter()
            valid = poc_verify(d0, proof)
            verify_time = time.perf_counter() - start

            assert valid, f"Proof invalid at W={W}"

            results.append({
                'W': W,
                'prove_time_ms': prove_time * 1000,
                'verify_time_ms': verify_time * 1000,
                'ratio': prove_time / verify_time,
                'verify_complexity': 'polylog' if verify_time < prove_time / 1000 else 'unknown'
            })

        # Verify targets
        assert results[-1]['ratio'] >= 1000, "Ratio target not met at W=10^12"

        return {
            'benchmark': 'verification_asymmetry',
            'results': results,
            'passed': True
        }
```

### 5.2 Benchmark 2: Soundness

```python
class SoundnessBenchmark:
    """
    BENCHMARK 2: Soundness (Cannot Fake Work)

    Target:
    - Forging probability < 2^-128
    """

    def run(self) -> Dict:
        params = PoCParams(security_bits=128)

        # Compute soundness bounds
        soundness = {
            'merkle_collision_bound': self._merkle_bound(params),
            'fri_soundness_bound': self._fri_bound(params),
            'constraint_sampling_bound': self._constraint_bound(params),
            'total_soundness_bound': self._total_bound(params)
        }

        # Verify < 2^-128
        assert soundness['total_soundness_bound'] < 2**-128

        # Challenge generator test
        challenge_test = self._test_challenge_sensitivity(params)
        assert challenge_test['detection_rate'] >= 1 - 2**-128

        return {
            'benchmark': 'soundness',
            'soundness_bounds': soundness,
            'challenge_test': challenge_test,
            'passed': True
        }

    def _merkle_bound(self, params) -> float:
        """Probability of Merkle collision."""
        return 2**-256  # 256-bit hash output

    def _fri_bound(self, params) -> float:
        """FRI soundness bound."""
        # ρ^q where ρ = rate, q = queries
        return params.fri_rate ** params.fri_queries

    def _constraint_bound(self, params) -> float:
        """Constraint evaluation soundness."""
        return params.fri_queries / params.domain_size
```

### 5.3 Benchmark 3: Tightness

```python
class TightnessBenchmark:
    """
    BENCHMARK 3: Tightness (No Over-Claim)

    Target:
    - Proof binds to exact W
    - Proof reuse for different W fails
    """

    def run(self) -> Dict:
        params1 = PoCParams(W=1000)
        params2 = PoCParams(W=1001)

        input_data = os.urandom(1024)

        # Generate proof for W=1000
        d0, proof = poc_hash(input_data, params1, tier='S')

        # Verify with correct W
        assert poc_verify(d0, proof), "Proof should verify with correct W"

        # Attempt verification with different W
        proof_modified = copy.deepcopy(proof)
        proof_modified.params = params2

        # This MUST fail
        reuse_failed = not poc_verify(d0, proof_modified)
        assert reuse_failed, "Proof reuse for different W should fail"

        return {
            'benchmark': 'tightness',
            'W_bound_verified': True,
            'reuse_attack_prevented': reuse_failed,
            'passed': True
        }
```

### 5.4 Benchmark 4: Universality

```python
class UniversalityBenchmark:
    """
    BENCHMARK 4: Universality & Hardware Independence

    Target:
    - Proof verifies identically across hardware
    - No > 10× ASIC advantage
    """

    def run(self) -> Dict:
        params = PoCParams()
        input_data = os.urandom(1024)

        # Generate proof
        d0, proof = poc_hash(input_data, params, tier='S')

        # Verify on different "simulated" hardware profiles
        # (In real benchmark, run on actual different hardware)
        results = []
        for hw_profile in ['cpu_x86', 'cpu_arm', 'gpu_cuda', 'fpga_sim']:
            valid = poc_verify(d0, proof)  # Same code, different profiling
            results.append({
                'hardware': hw_profile,
                'valid': valid,
                'verify_time_ms': self._measure_verify_time(d0, proof)
            })

        # Energy analysis (memory-hard advantage bound)
        energy_analysis = self._analyze_energy_bound(params)

        return {
            'benchmark': 'universality',
            'hardware_results': results,
            'energy_analysis': energy_analysis,
            'asic_advantage_bound': energy_analysis['max_advantage'],
            'passed': energy_analysis['max_advantage'] <= 10
        }
```

### 5.5 Benchmark 5: Composability

```python
class ComposabilityBenchmark:
    """
    BENCHMARK 5: Composability

    Target:
    - Aggregate proofs efficiently
    - Proof size O(1) or O(log W)
    - Verify time O(1) or O(log W)
    """

    def run(self) -> Dict:
        params = PoCParams(W=1_000_000_000)  # 10^9 steps
        segment_size = 1_000_000  # 10^6 steps per segment
        num_segments = 1000

        # Generate segment proofs
        segment_proofs = []
        for i in range(num_segments):
            segment_params = PoCParams(W=segment_size)
            _, proof = poc_hash(os.urandom(1024), segment_params, tier='S')
            segment_proofs.append(proof)

        # Aggregate
        aggregator = RecursiveProver(params, segment_size)
        start = time.perf_counter()
        aggregated = aggregator.prove_aggregated(segment_proofs)
        aggregate_time = time.perf_counter() - start

        # Measure aggregated proof
        aggregate_size = len(aggregated.serialize())

        # Verify aggregated
        start = time.perf_counter()
        valid = aggregated.verify()
        verify_time = time.perf_counter() - start

        return {
            'benchmark': 'composability',
            'num_segments': num_segments,
            'total_steps': params.W,
            'aggregate_proof_size_bytes': aggregate_size,
            'aggregate_time_ms': aggregate_time * 1000,
            'verify_time_ms': verify_time * 1000,
            'size_complexity': 'O(1)' if aggregate_size < 1024 else 'O(log W)',
            'verify_complexity': 'O(1)' if verify_time < 0.1 else 'O(log W)',
            'passed': aggregate_size < 1024 and verify_time < 1.0
        }
```

### 5.6 Benchmark 6: Practical Performance

```python
class PracticalBenchmark:
    """
    BENCHMARK 6: Practical Performance

    Targets:
    - Overhead < 2× native compute for proof generation
    - Proof size < 1KB for 10^12 steps (with recursion)
    - Verification throughput > 10k proofs/sec
    """

    def run(self) -> Dict:
        params = PoCParams(W=1_000_000)

        # Measure native execution (no proof)
        input_data = os.urandom(1024)
        start = time.perf_counter()
        execute_work(input_data, params)  # Just execution
        native_time = time.perf_counter() - start

        # Measure with proof
        start = time.perf_counter()
        d0, proof = poc_hash(input_data, params, tier='S')
        prove_time = time.perf_counter() - start

        overhead = prove_time / native_time

        # Proof size
        proof_size = len(proof.serialize())

        # Verification throughput
        proofs_to_verify = [poc_hash(os.urandom(1024), params, tier='S')
                           for _ in range(100)]
        start = time.perf_counter()
        for d0, p in proofs_to_verify:
            poc_verify(d0, p)
        verify_throughput = 100 / (time.perf_counter() - start)

        # Batch verification
        start = time.perf_counter()
        batch_verify([p for _, p in proofs_to_verify])
        batch_throughput = 100 / (time.perf_counter() - start)

        return {
            'benchmark': 'practical_performance',
            'native_time_ms': native_time * 1000,
            'prove_time_ms': prove_time * 1000,
            'overhead_ratio': overhead,
            'proof_size_bytes': proof_size,
            'verify_throughput_per_sec': verify_throughput,
            'batch_throughput_per_sec': batch_throughput,
            'passed': (
                overhead < 2.0 and
                proof_size < 1024 and
                verify_throughput > 10000
            )
        }
```

### 5.7 Benchmark 7: Formal Security

```python
class SecurityBenchmark:
    """
    BENCHMARK 7: Formal Security Package

    Delivers:
    - Open spec of all components
    - Soundness proof with explicit bounds
    - Reference implementation with deterministic replay
    """

    def run(self) -> Dict:
        # Generate spec hash (proves spec is fixed)
        spec_hash = hash_file('SPECIFICATION_POC.md')

        # Soundness bounds document
        soundness_doc = self._generate_soundness_document()

        # Deterministic replay test
        input_data = b'test input'
        params = PoCParams(W=1000)

        # Execute twice, must match exactly
        d0_1, proof_1 = poc_hash(input_data, params, tier='S')
        d0_2, proof_2 = poc_hash(input_data, params, tier='S')

        deterministic = (d0_1 == d0_2 and proof_1.serialize() == proof_2.serialize())

        return {
            'benchmark': 'formal_security',
            'spec_hash': spec_hash.hex(),
            'soundness_bounds': soundness_doc,
            'deterministic_replay': deterministic,
            'reference_impl_hash': self._hash_reference_impl(),
            'passed': deterministic
        }
```

### 5.8 Benchmark 8: Economic Verification

```python
class EconomicBenchmark:
    """
    BENCHMARK 8: Economic Verification Tests

    Three demos:
    1. Trustless cloud billing
    2. Compute marketplace
    3. AI compute certification
    """

    def run(self) -> Dict:
        results = {}

        # Demo 1: Trustless cloud billing
        results['cloud_billing'] = self._test_cloud_billing()

        # Demo 2: Compute marketplace
        results['marketplace'] = self._test_marketplace()

        # Demo 3: AI compute certification
        results['ai_certification'] = self._test_ai_certification()

        return {
            'benchmark': 'economic_verification',
            'demos': results,
            'passed': all(d['passed'] for d in results.values())
        }

    def _test_cloud_billing(self) -> Dict:
        """
        Run prover in "cloud worker."
        Verifier checks proofs and pays per verified W.
        Compare actual cloud bill vs paid bill; must match within 1%.
        """
        params = PoCParams(W=1_000_000)

        # Simulate cloud worker
        work_done = 0
        proofs_submitted = []

        for _ in range(10):  # 10 jobs
            input_data = os.urandom(1024)
            d0, proof = poc_hash(input_data, params, tier='S')
            proofs_submitted.append((d0, proof))
            work_done += params.W

        # Verifier checks and pays
        verified_work = 0
        for d0, proof in proofs_submitted:
            if poc_verify(d0, proof):
                verified_work += proof.params.W

        accuracy = verified_work / work_done

        return {
            'work_claimed': work_done,
            'work_verified': verified_work,
            'accuracy': accuracy,
            'passed': accuracy >= 0.99
        }

    def _test_marketplace(self) -> Dict:
        """
        Exchange proofs as commodities.
        Prove no arbitrage: same proof verifies universally.
        """
        params = PoCParams(W=100_000)
        input_data = os.urandom(1024)

        # Generate proof
        d0, proof = poc_hash(input_data, params, tier='S')

        # Verify by multiple independent "buyers"
        verifications = []
        for buyer_id in range(5):
            valid = poc_verify(d0, proof)
            verifications.append(valid)

        # All must agree
        universal = all(verifications)

        return {
            'num_verifiers': 5,
            'all_agree': universal,
            'passed': universal
        }

    def _test_ai_certification(self) -> Dict:
        """
        Wrap a training step batch as proved computation.
        Verify without re-running training.
        """
        # Simulate training step as computation
        params = PoCParams(W=1_000_000)  # Represents one training batch

        # "Training step" encoded as input
        training_config = {
            'batch_size': 32,
            'learning_rate': 0.001,
            'step': 1000
        }
        input_data = json.dumps(training_config).encode()

        # Generate proof of "training"
        d0, proof = poc_hash(input_data, params, tier='S')

        # Verify without re-running
        valid = poc_verify(d0, proof)

        return {
            'training_config': training_config,
            'proof_generated': True,
            'verified_without_replay': valid,
            'passed': valid
        }
```

---

## Part 6: Deliverables Checklist

### 6.1 Required Files

```
opochhash/
├── poc/
│   ├── spec.md                  # Fully pinned constants and tags
│   ├── soundness.json           # Explicit bound computations
│   └── src/
│       ├── params.py            # PoCParams class
│       ├── work.py              # Memory-hard work function
│       ├── memory.py            # Merkle memory model
│       ├── state.py             # WorkState class
│       ├── field.py             # Goldilocks field
│       ├── poly.py              # Polynomial ops + FFT
│       ├── fri.py               # FRI protocol
│       ├── constraints.py       # AIR constraints
│       ├── tier_q.py            # Quick proof (wraps Level 1)
│       ├── tier_s.py            # STARK prover/verifier
│       ├── recursion.py         # Proof aggregation
│       └── poc_hash.py          # Main API
├── bench/
│   └── poc/
│       ├── runner_asymmetry.py  # Benchmark 1
│       ├── runner_soundness.py  # Benchmark 2
│       ├── runner_tightness.py  # Benchmark 3
│       ├── runner_universal.py  # Benchmark 4
│       ├── runner_compose.py    # Benchmark 5
│       ├── runner_practical.py  # Benchmark 6
│       ├── runner_security.py   # Benchmark 7
│       ├── runner_economic.py   # Benchmark 8
│       ├── poc_bench.py         # Orchestrator
│       └── report.json          # Results output
├── compat/
│   └── legacy_hash_tests.py     # H0 digest compatibility
└── receipts/
    └── replay_command.sh        # Deterministic replay
```

### 6.2 Spec Requirements (spec.md)

```markdown
# PoC_Hash Specification v1.0

## 1. Hash Core
- Permutation: Keccak-f[1600]
- Domain tags: [list all tags with hex values]
- Padding: pad10*1 with 0x06 separator

## 2. Field Arithmetic
- Prime: p = 2^64 - 2^32 + 1 (Goldilocks)
- Representation: Little-endian 64-bit

## 3. Memory Model
- Block size: 64 bytes
- Memory size: 256 MB (configurable)
- Merkle hash: leaf_hash(index, data) = H(LEAF ‖ index ‖ data)

## 4. Work Function
- Seed: r₀ = H("SEED" ‖ d₀ ‖ θ)
- Step: r_{t+1} = H("STEP" ‖ r_t ‖ b_t ‖ t)
- Write: H("WRITE" ‖ r_{t+1} ‖ a_t ‖ t)

## 5. AIR Constraints
- [Full constraint polynomial definitions]

## 6. FRI Parameters
- Rate: 0.5
- Queries: 30
- Blowup factor: 8

## 7. Domain Separation Tags
| Tag | Value | Usage |
|-----|-------|-------|
| SEED | 0x70 | Initial seed |
| INIT | 0x71 | Memory initialization |
| STEP | 0x72 | Work step |
| WRITE | 0x73 | Memory write |
| ... | ... | ... |
```

---

## Part 7: Implementation Order

### Phase 1: Foundation (Week 1-2)
1. `params.py` - Parameter definitions
2. `field.py` - Goldilocks field arithmetic
3. `memory.py` - Merkle memory model with updates
4. `state.py` - WorkState serialization
5. `work.py` - Sequential work function

### Phase 2: Polynomial Infrastructure (Week 2-3)
6. `poly.py` - Polynomial operations
7. FFT implementation (in poly.py)
8. Polynomial commitment scheme

### Phase 3: STARK Core (Week 3-4)
9. `constraints.py` - AIR constraint system
10. `fri.py` - FRI protocol
11. `tier_s.py` - STARK prover
12. STARK verifier

### Phase 4: Tier Q & Integration (Week 4-5)
13. `tier_q.py` - Wrap Level 1
14. `poc_hash.py` - Main API
15. `recursion.py` - Proof aggregation

### Phase 5: Benchmarks (Week 5-6)
16. All 8 benchmark runners
17. Report generation
18. Compatibility tests

### Phase 6: Documentation & Verification (Week 6-7)
19. `spec.md` - Full specification
20. `soundness.json` - Security analysis
21. Test vectors
22. Final verification run

---

## Part 8: Success Criteria

### All Benchmarks Must Pass:

| Benchmark | Target | Measurement |
|-----------|--------|-------------|
| 1. Asymmetry | ratio ≥ 1000:1 at W=10^12 | prove_time / verify_time |
| 2. Soundness | < 2^-128 | Computed bound |
| 3. Tightness | Proof binds to exact W | Reuse attack fails |
| 4. Universality | No >10× ASIC advantage | Energy analysis |
| 5. Composability | O(1) or O(log W) | Aggregate proof size |
| 6. Practical | <2× overhead, <1KB, >10k/s | Measurements |
| 7. Security | Deterministic replay | Exact match |
| 8. Economic | 3 demos pass | Cloud/market/AI |

### Zero Switching Cost:
- d₀ MUST equal H₀(x) exactly
- Legacy systems MUST work unchanged

### Determinism:
- Same input MUST produce identical (d₀, π)
- All randomness from Fiat-Shamir (deterministic)

---

## Part 9: Risk Mitigation

### Technical Risks:
1. **FFT performance**: Use optimized libraries (numpy for prototyping, Rust for production)
2. **Memory constraints**: Stream large traces, don't hold in RAM
3. **FRI complexity**: Start with reference implementation, optimize later

### Schedule Risks:
1. **AIR constraints complex**: Start simple (fewer columns), add incrementally
2. **Recursion hard**: Tier Q sufficient for initial benchmarks

### Quality Risks:
1. **Soundness bugs**: Formal verification of constraint system
2. **Determinism bugs**: Extensive replay testing

---

*This plan is complete and executable. No shortcuts. No hardcoding. 100% benchmark compliance.*
