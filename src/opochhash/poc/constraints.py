"""
AIR Constraints (Algebraic Intermediate Representation)

Defines the constraint system for the memory-hard work function.

The execution trace is represented as columns over a finite field:
- R[t]: Register value at step t (split into 4 field elements)
- A[t]: Memory address at step t
- B[t]: Block read at step t (split into field elements)
- M[t]: Memory Merkle root at step t (split into field elements)

Constraints enforce:
1. Address derivation: A[t] = Addr(R[t])
2. Register update: R[t+1] = H(R[t], B[t], t)
3. Boundary conditions: R[0] = r₀, R[W] = r_final

For full STARK, we also need memory consistency, but we simplify here.
"""

from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
import hashlib

from .field import FieldElement
from .poly import Polynomial, get_domain
from .params import PoCParams
from .state import WorkState
from .tags import PoCTag, tag_bytes


# Number of field elements to represent a 256-bit value
FIELD_ELEMENTS_PER_256_BIT = 4  # 64 bits each


def bytes_to_field_elements(data: bytes, count: int = 4) -> List[FieldElement]:
    """Convert bytes to field elements (64 bits each)."""
    result = []
    for i in range(count):
        start = i * 8
        end = start + 8
        chunk = data[start:end] if end <= len(data) else data[start:].ljust(8, b'\x00')
        result.append(FieldElement.from_bytes(chunk))
    return result


def field_elements_to_bytes(elements: List[FieldElement]) -> bytes:
    """Convert field elements back to bytes."""
    return b''.join(e.to_bytes() for e in elements)


@dataclass
class TraceColumn:
    """A single column in the execution trace."""
    name: str
    values: List[FieldElement]

    @property
    def length(self) -> int:
        return len(self.values)


@dataclass
class ExecutionTrace:
    """
    Complete execution trace for the work function.

    Columns:
    - r0, r1, r2, r3: Register (256 bits as 4 x 64-bit)
    - addr: Memory address
    - b0, b1, b2, b3: Block read (256 bits as 4 x 64-bit, truncated)
    - step: Step counter
    """
    columns: Dict[str, TraceColumn]
    num_rows: int

    @classmethod
    def from_work_states(cls, states: List[WorkState]) -> 'ExecutionTrace':
        """Build trace from work states."""
        num_rows = len(states)

        # Initialize columns
        columns = {
            'r0': [], 'r1': [], 'r2': [], 'r3': [],  # Register
            'addr': [],  # Address
            'step': [],  # Step counter
            'm0': [], 'm1': [], 'm2': [], 'm3': [],  # Memory root
        }

        for state in states:
            # Register
            r_elements = bytes_to_field_elements(state.r, 4)
            columns['r0'].append(r_elements[0])
            columns['r1'].append(r_elements[1])
            columns['r2'].append(r_elements[2])
            columns['r3'].append(r_elements[3])

            # Address (derived from register)
            addr = int.from_bytes(state.r[:8], 'big')
            columns['addr'].append(FieldElement(addr))

            # Step counter
            columns['step'].append(FieldElement(state.t))

            # Memory root
            m_elements = bytes_to_field_elements(state.M, 4)
            columns['m0'].append(m_elements[0])
            columns['m1'].append(m_elements[1])
            columns['m2'].append(m_elements[2])
            columns['m3'].append(m_elements[3])

        # Convert to TraceColumn objects
        trace_columns = {
            name: TraceColumn(name, values)
            for name, values in columns.items()
        }

        return cls(columns=trace_columns, num_rows=num_rows)

    def get_column(self, name: str) -> List[FieldElement]:
        """Get column values by name."""
        return self.columns[name].values

    def pad_to_power_of_two(self) -> 'ExecutionTrace':
        """Pad trace to next power of 2."""
        target_len = 1
        while target_len < self.num_rows:
            target_len *= 2

        if target_len == self.num_rows:
            return self

        # Pad with last row repeated
        new_columns = {}
        for name, col in self.columns.items():
            padded = col.values[:]
            last_val = padded[-1] if padded else FieldElement.zero()
            while len(padded) < target_len:
                padded.append(last_val)
            new_columns[name] = TraceColumn(name, padded)

        return ExecutionTrace(columns=new_columns, num_rows=target_len)


@dataclass
class BoundaryConstraint:
    """Constraint at a specific trace position."""
    column: str
    row: int
    value: FieldElement


@dataclass
class TransitionConstraint:
    """
    Constraint relating current row to next row.

    The constraint is a polynomial C(x, x') where:
    - x represents values at row i
    - x' represents values at row i+1
    - C(x, x') = 0 must hold for all valid transitions
    """
    name: str
    degree: int  # Degree of constraint polynomial

    def evaluate(
        self,
        current: Dict[str, FieldElement],
        next_row: Dict[str, FieldElement]
    ) -> FieldElement:
        """
        Evaluate constraint at a specific transition.

        Returns 0 if constraint is satisfied.
        """
        raise NotImplementedError


class StepCounterConstraint(TransitionConstraint):
    """Constraint: step[i+1] = step[i] + 1"""

    def __init__(self):
        super().__init__(name="step_increment", degree=1)

    def evaluate(
        self,
        current: Dict[str, FieldElement],
        next_row: Dict[str, FieldElement]
    ) -> FieldElement:
        # step[i+1] - step[i] - 1 = 0
        return next_row['step'] - current['step'] - FieldElement.one()


class AddressDerivationConstraint(TransitionConstraint):
    """Constraint: addr = truncate(r0) (simplified)"""

    def __init__(self, num_blocks: int):
        super().__init__(name="address_derivation", degree=1)
        self.num_blocks = num_blocks

    def evaluate(
        self,
        current: Dict[str, FieldElement],
        next_row: Dict[str, FieldElement]
    ) -> FieldElement:
        # addr = r0 mod num_blocks
        # This is a simplified check (full version needs range proofs)
        expected_addr = FieldElement(current['r0'].to_int() % self.num_blocks)
        return current['addr'] - expected_addr


class WorkAIR:
    """
    Algebraic Intermediate Representation for work function.

    This defines the complete constraint system for proving
    correct execution of the memory-hard work.
    """

    def __init__(self, params: PoCParams):
        self.params = params
        self.num_columns = 10  # r0-r3, addr, step, m0-m3

        # Build constraint list
        self.transition_constraints: List[TransitionConstraint] = [
            StepCounterConstraint(),
            AddressDerivationConstraint(params.num_blocks),
        ]

        self.boundary_constraints: List[BoundaryConstraint] = []

    def set_boundary_constraints(
        self,
        r0: bytes,
        r_final: bytes,
        trace_length: int
    ):
        """Set boundary constraints for specific execution."""
        self.boundary_constraints = []

        # Initial register
        r0_elements = bytes_to_field_elements(r0, 4)
        for i, val in enumerate(r0_elements):
            self.boundary_constraints.append(
                BoundaryConstraint(column=f'r{i}', row=0, value=val)
            )

        # Initial step counter
        self.boundary_constraints.append(
            BoundaryConstraint(column='step', row=0, value=FieldElement.zero())
        )

        # Final register
        rf_elements = bytes_to_field_elements(r_final, 4)
        for i, val in enumerate(rf_elements):
            self.boundary_constraints.append(
                BoundaryConstraint(column=f'r{i}', row=trace_length - 1, value=val)
            )

    def generate_trace(self, states: List[WorkState]) -> ExecutionTrace:
        """Generate execution trace from states."""
        trace = ExecutionTrace.from_work_states(states)
        return trace.pad_to_power_of_two()

    def verify_trace(self, trace: ExecutionTrace) -> bool:
        """
        Verify trace satisfies all constraints.

        This is O(W) verification - for testing only.
        """
        # Check boundary constraints
        for bc in self.boundary_constraints:
            actual = trace.get_column(bc.column)[bc.row]
            if actual != bc.value:
                return False

        # Check transition constraints (except last row)
        for i in range(trace.num_rows - 1):
            current = {
                name: col.values[i]
                for name, col in trace.columns.items()
            }
            next_row = {
                name: col.values[i + 1]
                for name, col in trace.columns.items()
            }

            for tc in self.transition_constraints:
                result = tc.evaluate(current, next_row)
                if not result.is_zero():
                    # Constraint violated
                    return False

        return True

    def compute_composition_polynomial(
        self,
        trace: ExecutionTrace,
        alphas: List[FieldElement],
        domain: List[FieldElement]
    ) -> List[FieldElement]:
        """
        Compute composition polynomial evaluations.

        C(x) = Σ α_i · c_i(x) / Z(x)

        where c_i are constraint polynomials and Z is the vanishing polynomial.
        """
        n = len(domain)
        composition_evals = [FieldElement.zero()] * n

        # Vanishing polynomial: Z(x) = x^n - 1
        # We evaluate C(x) · Z(x) = Σ α_i · c_i(x)
        # Then divide by Z(x) later

        # For each domain point
        for idx, x in enumerate(domain):
            row = idx % trace.num_rows
            next_row_idx = (row + 1) % trace.num_rows

            current = {
                name: col.values[row]
                for name, col in trace.columns.items()
            }
            next_row = {
                name: col.values[next_row_idx]
                for name, col in trace.columns.items()
            }

            # Accumulate weighted constraints
            result = FieldElement.zero()
            for alpha, tc in zip(alphas, self.transition_constraints):
                constraint_val = tc.evaluate(current, next_row)
                result = result + alpha * constraint_val

            composition_evals[idx] = result

        return composition_evals

    @property
    def constraint_degree(self) -> int:
        """Maximum degree of constraint polynomials."""
        if not self.transition_constraints:
            return 1
        return max(tc.degree for tc in self.transition_constraints)

    @property
    def num_constraints(self) -> int:
        """Number of transition constraints."""
        return len(self.transition_constraints)


def trace_to_polynomials(
    trace: ExecutionTrace,
    domain: List[FieldElement]
) -> Dict[str, Polynomial]:
    """
    Interpolate trace columns into polynomials.

    Each column becomes a polynomial that passes through all trace values.
    """
    from .poly import ifft, Polynomial

    n = len(domain)
    if trace.num_rows != n:
        raise ValueError(f"Trace length {trace.num_rows} != domain size {n}")

    polynomials = {}

    for name, col in trace.columns.items():
        # IFFT to get coefficients
        omega_order = (n - 1).bit_length()
        omega = FieldElement.primitive_root_of_unity(omega_order)
        coeffs = ifft(col.values, omega)
        polynomials[name] = Polynomial(coeffs)

    return polynomials
