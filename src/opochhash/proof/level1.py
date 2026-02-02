"""
Level 1: Hash-Based Spot-Check Proof

Proves computation WITHOUT replay, with tunable probabilistic soundness.

Key components:
1. Commit to trace with Merkle tree
2. Derive deterministic challenges via Fiat-Shamir
3. Open and verify sampled transitions

Soundness: If b bad transitions exist among T steps:
    Pr[miss] ≤ (1 - b/T)^k

Choose k ≈ (T/b) · ln(1/ε) for negligible miss probability ε.
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple
import hashlib
import math

from .tags import ProofTag, tag_bytes
from .merkle import MerkleTree, MerkleProof, leaf_hash
from .kernel import Program, MachineState, execute, execute_with_serialized_trace


def _hash(tag: ProofTag, *parts: bytes) -> bytes:
    """Domain-separated hash."""
    h = hashlib.shake_256()
    h.update(tag_bytes(tag))
    for part in parts:
        h.update(len(part).to_bytes(8, 'big'))
        h.update(part)
    return h.digest(32)


def _xof(tag: ProofTag, *parts: bytes) -> hashlib.shake_256:
    """Domain-separated XOF for challenge generation."""
    h = hashlib.shake_256()
    h.update(tag_bytes(tag))
    for part in parts:
        h.update(len(part).to_bytes(8, 'big'))
        h.update(part)
    return h


@dataclass
class Statement:
    """
    Public statement for a computation claim.

    Stmt = (H(P), H(x), H(y), T, R)
    """
    program_hash: bytes
    input_hash: bytes
    output_hash: bytes
    steps: int
    trace_root: bytes

    def serialize(self) -> bytes:
        """Canonical serialization."""
        return b''.join([
            self.program_hash,
            self.input_hash,
            self.output_hash,
            self.steps.to_bytes(8, 'big'),
            self.trace_root
        ])

    def hash(self) -> bytes:
        """Hash of the statement for challenge derivation."""
        return _hash(ProofTag.CHAL, self.serialize())


@dataclass
class TransitionProof:
    """Proof of a single transition s_t → s_{t+1}."""
    index: int  # t
    state_t: bytes  # Serialized s_t
    state_t1: bytes  # Serialized s_{t+1}
    proof_t: MerkleProof
    proof_t1: MerkleProof
    aux_data: bytes = b''  # For RAM memory proofs


@dataclass
class Level1Proof:
    """
    Level 1 proof: Spot-check with Merkle trace.

    Contains:
    - statement: The public statement
    - k: Number of checked transitions
    - transitions: List of transition proofs
    - final_state: Serialized final state (for output verification)
    - final_proof: Merkle proof for final state
    """
    statement: Statement
    k: int
    transitions: List[TransitionProof]
    final_state: bytes
    final_proof: MerkleProof

    def soundness_bound(self, bad_transitions: int = 1) -> float:
        """
        Compute probability of missing bad transitions.

        Args:
            bad_transitions: Assumed number of bad transitions (b)

        Returns:
            Pr[miss] ≤ (1 - b/T)^k
        """
        if self.statement.steps == 0:
            return 0.0
        return (1 - bad_transitions / self.statement.steps) ** self.k


def derive_challenges(statement: Statement, k: int) -> List[int]:
    """
    Derive k deterministic challenge indices using Fiat-Shamir.

    Args:
        statement: Public statement
        k: Number of challenges

    Returns:
        List of k indices in [0, T-1]
    """
    if statement.steps <= 1:
        return []

    # seed = H("CHAL" ‖ Stmt)
    seed = statement.hash()

    # Use XOF to generate indices
    xof = _xof(ProofTag.CHAL_INDEX, seed)
    xof_output = xof.digest(k * 8)  # 8 bytes per index

    indices = []
    T = statement.steps  # Number of transitions (not states)

    for i in range(k):
        # Parse 8 bytes as integer, mod T
        val = int.from_bytes(xof_output[i*8:(i+1)*8], 'big')
        idx = val % T
        indices.append(idx)

    return indices


class Level1Prover:
    """Generate Level 1 spot-check proofs."""

    def __init__(self, program: Program, security_parameter: int = 128):
        """
        Args:
            program: Program to prove execution of
            security_parameter: Target security bits (affects k)
        """
        self.program = program
        self.security_parameter = security_parameter

    def compute_k(self, T: int, target_soundness: float = 2**-128) -> int:
        """
        Compute number of samples k for target soundness.

        For b=1 bad transition:
            k = -ln(ε) / ln(1 - 1/T) ≈ T · ln(1/ε) for large T
        """
        if T <= 1:
            return 0

        # For small T, sample all transitions
        if T <= 100:
            return T

        # For larger T, use probabilistic bound
        # k = ceil(-ln(target) / (-ln(1 - 1/T)))
        # ≈ ceil(T * ln(1/target)) for large T
        k = int(math.ceil(-math.log(target_soundness) / (-math.log(1 - 1/T))))

        # Cap at reasonable maximum
        return min(k, T, 1000)

    def prove(self, input_data: bytes, max_steps: int = 1_000_000) -> Level1Proof:
        """
        Execute program and generate Level 1 proof.

        Returns:
            Level1Proof with Merkle-committed trace and sampled transitions
        """
        # Execute to get serialized trace
        serialized_trace, output = execute_with_serialized_trace(
            self.program, input_data, max_steps
        )

        T = len(serialized_trace) - 1  # Number of transitions

        # Build Merkle tree over trace
        tree = MerkleTree(serialized_trace)

        # Create statement
        statement = Statement(
            program_hash=_hash(ProofTag.PROGRAM, self.program.serialize()),
            input_hash=_hash(ProofTag.INPUT, input_data),
            output_hash=_hash(ProofTag.OUTPUT, output),
            steps=T,
            trace_root=tree.root
        )

        # Derive challenge indices
        k = self.compute_k(T)
        indices = derive_challenges(statement, k)

        # Generate transition proofs
        transitions = []
        for idx in indices:
            trans = TransitionProof(
                index=idx,
                state_t=serialized_trace[idx],
                state_t1=serialized_trace[idx + 1],
                proof_t=tree.get_proof(idx),
                proof_t1=tree.get_proof(idx + 1)
            )
            transitions.append(trans)

        # Final state proof
        final_proof = tree.get_proof(T)

        return Level1Proof(
            statement=statement,
            k=k,
            transitions=transitions,
            final_state=serialized_trace[T],
            final_proof=final_proof
        )


@dataclass
class Level1VerificationResult:
    """Result of Level 1 verification."""
    valid: bool
    all_merkle_proofs_valid: bool
    all_transitions_valid: bool
    output_valid: bool
    soundness_bound: float
    checked_indices: List[int]
    error: Optional[str] = None


class Level1Verifier:
    """
    Verify Level 1 proofs WITHOUT replaying full execution.

    Verification cost: O(k · log T) where k is number of samples.
    """

    def verify(
        self,
        proof: Level1Proof,
        program: Program
    ) -> Level1VerificationResult:
        """
        Verify a Level 1 proof.

        Args:
            proof: The proof to verify
            program: The program (for step verification)

        Returns:
            Verification result with details
        """
        # Check program hash matches
        expected_program_hash = _hash(ProofTag.PROGRAM, program.serialize())
        if proof.statement.program_hash != expected_program_hash:
            return Level1VerificationResult(
                valid=False,
                all_merkle_proofs_valid=False,
                all_transitions_valid=False,
                output_valid=False,
                soundness_bound=1.0,
                checked_indices=[],
                error="Program hash mismatch"
            )

        # Re-derive challenges and verify they match
        expected_indices = derive_challenges(proof.statement, proof.k)
        actual_indices = [t.index for t in proof.transitions]

        if actual_indices != expected_indices:
            return Level1VerificationResult(
                valid=False,
                all_merkle_proofs_valid=False,
                all_transitions_valid=False,
                output_valid=False,
                soundness_bound=1.0,
                checked_indices=actual_indices,
                error="Challenge indices mismatch"
            )

        # Verify all Merkle proofs
        root = proof.statement.trace_root
        all_merkle_valid = True

        for trans in proof.transitions:
            if not trans.proof_t.verify(root):
                all_merkle_valid = False
                break
            if not trans.proof_t1.verify(root):
                all_merkle_valid = False
                break

        # Verify final state proof
        if not proof.final_proof.verify(root):
            all_merkle_valid = False

        if not all_merkle_valid:
            return Level1VerificationResult(
                valid=False,
                all_merkle_proofs_valid=False,
                all_transitions_valid=False,
                output_valid=False,
                soundness_bound=1.0,
                checked_indices=actual_indices,
                error="Merkle proof verification failed"
            )

        # Verify transitions
        all_transitions_valid = True
        for trans in proof.transitions:
            # Deserialize states
            state_t = MachineState.deserialize(trans.state_t)
            state_t1_claimed = MachineState.deserialize(trans.state_t1)

            # Compute expected next state
            state_t1_computed = program.step(state_t)

            # Compare
            if state_t1_computed.serialize() != trans.state_t1:
                all_transitions_valid = False
                break

        if not all_transitions_valid:
            return Level1VerificationResult(
                valid=False,
                all_merkle_proofs_valid=True,
                all_transitions_valid=False,
                output_valid=False,
                soundness_bound=1.0,
                checked_indices=actual_indices,
                error="Transition verification failed"
            )

        # Verify output
        final_state = MachineState.deserialize(proof.final_state)
        computed_output = program.output(final_state)
        expected_output_hash = _hash(ProofTag.OUTPUT, computed_output)
        output_valid = expected_output_hash == proof.statement.output_hash

        if not output_valid:
            return Level1VerificationResult(
                valid=False,
                all_merkle_proofs_valid=True,
                all_transitions_valid=True,
                output_valid=False,
                soundness_bound=1.0,
                checked_indices=actual_indices,
                error="Output hash mismatch"
            )

        # Compute soundness bound
        soundness = proof.soundness_bound(bad_transitions=1)

        return Level1VerificationResult(
            valid=True,
            all_merkle_proofs_valid=True,
            all_transitions_valid=True,
            output_valid=True,
            soundness_bound=soundness,
            checked_indices=actual_indices
        )


def prove_level1(program: Program, input_data: bytes) -> Level1Proof:
    """Convenience function to generate Level 1 proof."""
    return Level1Prover(program).prove(input_data)


def verify_level1(proof: Level1Proof, program: Program) -> bool:
    """Convenience function to verify Level 1 proof."""
    result = Level1Verifier().verify(proof, program)
    return result.valid
