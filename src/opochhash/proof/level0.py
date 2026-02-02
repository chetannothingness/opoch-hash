"""
Level 0: Receipted Replay

Proof that the prover ran exactly these steps.
Verification is by replay - O(T) cost but perfect integrity.

The receipt chain provides tamper-evidence:
    c_0 = H("STEP" ‖ 0 ‖ P ‖ x)
    c_{t+1} = H("STEP" ‖ (t+1) ‖ c_t ‖ s_t ‖ s_{t+1})
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple
import hashlib

from .tags import ProofTag, tag_bytes
from .kernel import Program, MachineState, ComputationClaim, execute


def _hash(tag: ProofTag, *parts: bytes) -> bytes:
    """Domain-separated hash."""
    h = hashlib.shake_256()
    h.update(tag_bytes(tag))
    for part in parts:
        h.update(len(part).to_bytes(8, 'big'))
        h.update(part)
    return h.digest(32)


def compute_receipt_chain(
    program: Program,
    input_data: bytes,
    trace: List[MachineState]
) -> List[bytes]:
    """
    Compute the full receipt chain for an execution trace.

    Args:
        program: The program P
        input_data: The input x
        trace: Execution trace [s_0, s_1, ..., s_T]

    Returns:
        Receipt chain [c_0, c_1, ..., c_T]
    """
    if not trace:
        raise ValueError("Empty trace")

    # c_0 = H("STEP" ‖ 0 ‖ P ‖ x)
    c_0 = _hash(
        ProofTag.STEP,
        (0).to_bytes(8, 'big'),
        program.serialize(),
        input_data
    )

    chain = [c_0]

    # c_{t+1} = H("STEP" ‖ (t+1) ‖ c_t ‖ s_t ‖ s_{t+1})
    for t in range(len(trace) - 1):
        c_next = _hash(
            ProofTag.STEP,
            (t + 1).to_bytes(8, 'big'),
            chain[-1],
            trace[t].serialize(),
            trace[t + 1].serialize()
        )
        chain.append(c_next)

    return chain


@dataclass
class Level0Proof:
    """
    Level 0 proof: Receipted replay.

    Contains:
    - program: The program P (serialized)
    - input_data: The input x
    - output_data: The claimed output y
    - steps: Execution length T
    - final_receipt: c_T (the final receipt)
    """
    program_bytes: bytes
    input_data: bytes
    output_data: bytes
    steps: int
    final_receipt: bytes

    def serialize(self) -> bytes:
        """Serialize proof for transmission."""
        parts = [
            len(self.program_bytes).to_bytes(4, 'big'),
            self.program_bytes,
            len(self.input_data).to_bytes(4, 'big'),
            self.input_data,
            len(self.output_data).to_bytes(4, 'big'),
            self.output_data,
            self.steps.to_bytes(8, 'big'),
            self.final_receipt,
        ]
        return b''.join(parts)


class Level0Prover:
    """
    Generate Level 0 proofs via receipted execution.
    """

    def __init__(self, program: Program):
        self.program = program

    def prove(self, input_data: bytes, max_steps: int = 1_000_000) -> Level0Proof:
        """
        Execute program and generate proof.

        Returns:
            Level0Proof with final receipt
        """
        # Execute to get trace
        trace, output = execute(self.program, input_data, max_steps)

        # Compute receipt chain
        chain = compute_receipt_chain(self.program, input_data, trace)

        return Level0Proof(
            program_bytes=self.program.serialize(),
            input_data=input_data,
            output_data=output,
            steps=len(trace) - 1,  # T = number of transitions
            final_receipt=chain[-1]
        )


@dataclass
class Level0VerificationResult:
    """Result of Level 0 verification."""
    valid: bool
    output_matches: bool
    receipt_matches: bool
    computed_output: Optional[bytes] = None
    computed_receipt: Optional[bytes] = None
    error: Optional[str] = None


class Level0Verifier:
    """
    Verify Level 0 proofs by replay.

    Verification cost: O(T) - must replay entire execution.
    But provides PERFECT integrity guarantee.
    """

    def verify(
        self,
        proof: Level0Proof,
        program: Program,
        max_steps: int = 1_000_000
    ) -> Level0VerificationResult:
        """
        Verify a Level 0 proof by replaying execution.

        Args:
            proof: The proof to verify
            program: The program (must match proof.program_bytes)
            max_steps: Maximum steps allowed

        Returns:
            Verification result with details
        """
        # Check program matches
        if program.serialize() != proof.program_bytes:
            return Level0VerificationResult(
                valid=False,
                output_matches=False,
                receipt_matches=False,
                error="Program mismatch"
            )

        # Replay execution
        try:
            trace, computed_output = execute(program, proof.input_data, max_steps)
        except Exception as e:
            return Level0VerificationResult(
                valid=False,
                output_matches=False,
                receipt_matches=False,
                error=f"Execution failed: {e}"
            )

        # Check step count
        if len(trace) - 1 != proof.steps:
            return Level0VerificationResult(
                valid=False,
                output_matches=False,
                receipt_matches=False,
                computed_output=computed_output,
                error=f"Step count mismatch: expected {proof.steps}, got {len(trace) - 1}"
            )

        # Compute receipt chain
        chain = compute_receipt_chain(program, proof.input_data, trace)
        computed_receipt = chain[-1]

        # Check output
        output_matches = computed_output == proof.output_data

        # Check receipt
        receipt_matches = computed_receipt == proof.final_receipt

        return Level0VerificationResult(
            valid=output_matches and receipt_matches,
            output_matches=output_matches,
            receipt_matches=receipt_matches,
            computed_output=computed_output,
            computed_receipt=computed_receipt
        )


def prove_level0(program: Program, input_data: bytes) -> Level0Proof:
    """Convenience function to generate Level 0 proof."""
    return Level0Prover(program).prove(input_data)


def verify_level0(proof: Level0Proof, program: Program) -> bool:
    """Convenience function to verify Level 0 proof."""
    result = Level0Verifier().verify(proof, program)
    return result.valid
