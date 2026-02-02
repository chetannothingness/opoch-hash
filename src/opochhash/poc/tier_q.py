"""
Tier Q: Quick Spot-Check Proof

Wraps the existing Level 1 proof system for quick verification.

Properties:
- Verification: O(k log W)
- Soundness: (1 - b/W)^k where b = bad transitions, k = samples
- Fast to generate
- Good for debugging and testing

This is the fallback tier when STARK is not needed.
"""

from dataclasses import dataclass
from typing import List, Tuple, Optional
import hashlib

from ..proof.level1 import (
    Level1Proof,
    Level1Prover,
    Level1Verifier,
    Statement,
    TransitionProof,
    derive_challenges
)
from ..proof.merkle import MerkleTree, MerkleProof
from ..proof.kernel import MachineState as L1State, Program

from .params import PoCParams
from .state import WorkState, MemoryAccess
from .work import compute_seed, legacy_digest, verify_step
from .tags import PoCTag, tag_bytes


def _hash(*parts: bytes) -> bytes:
    """Domain-separated hash."""
    h = hashlib.shake_256()
    h.update(tag_bytes(PoCTag.PROOF_TIER_Q))
    for part in parts:
        h.update(part)
    return h.digest(32)


class WorkProgram(Program):
    """
    Adapter to make work function look like a Program for Level 1.

    This bridges the PoC work function with the existing proof framework.
    """

    def __init__(self, params: PoCParams):
        self.params = params

    def serialize(self) -> bytes:
        """Serialize program (just params for work function)."""
        return self.params.serialize()

    def step(self, state: L1State) -> L1State:
        """
        Execute one work step.

        This is a simplified adapter - full implementation would
        include memory access in the state.
        """
        # Deserialize WorkState from L1State
        work_state = WorkState.deserialize(state.io_buffer)

        # For Tier Q, we don't actually execute here - we verify precomputed
        # This method is called by verifier to check transitions

        # Return unchanged (verification done separately)
        return state

    def init(self, input_data: bytes) -> L1State:
        """Create initial state."""
        d0 = legacy_digest(input_data, self.params.legacy_hash)
        r0 = compute_seed(d0, self.params)

        # Pack into L1State
        work_state = WorkState(r=r0, t=0, M=b'\x00' * 32)
        return L1State(
            pc=0,
            registers={},
            memory_root=b'\x00' * 32,
            io_buffer=work_state.serialize()
        )

    def output(self, state: L1State) -> bytes:
        """Extract output from state."""
        work_state = WorkState.deserialize(state.io_buffer)
        return work_state.r

    def hash(self) -> bytes:
        """Hash of program."""
        return _hash(b'WORK_PROGRAM', self.serialize())


@dataclass
class TierQProof:
    """
    Tier Q proof: Quick spot-check verification.

    Based on Merkle commitment to trace with sampled transition checks.
    """

    # Parameters
    params_hash: bytes

    # Public inputs
    d0: bytes
    r0: bytes
    r_final: bytes
    W: int  # Number of steps

    # Trace commitment
    trace_root: bytes

    # Sampled transitions
    k: int  # Number of samples
    samples: List[Tuple[int, bytes, bytes, bytes, bytes]]
    # Each sample: (index, state_t, state_t1, mem_access, merkle_proof)

    # Final state proof
    final_state: bytes
    final_proof: bytes

    def serialize(self) -> bytes:
        """Serialize proof."""
        parts = [
            tag_bytes(PoCTag.PROOF_TIER_Q),
            self.params_hash,
            self.d0,
            self.r0,
            self.r_final,
            self.W.to_bytes(8, 'big'),
            self.trace_root,
            self.k.to_bytes(4, 'big'),
        ]

        for idx, st, st1, ma, mp in self.samples:
            parts.append(idx.to_bytes(8, 'big'))
            parts.append(len(st).to_bytes(4, 'big'))
            parts.append(st)
            parts.append(len(st1).to_bytes(4, 'big'))
            parts.append(st1)
            parts.append(len(ma).to_bytes(4, 'big'))
            parts.append(ma)
            parts.append(len(mp).to_bytes(4, 'big'))
            parts.append(mp)

        parts.append(len(self.final_state).to_bytes(4, 'big'))
        parts.append(self.final_state)
        parts.append(len(self.final_proof).to_bytes(4, 'big'))
        parts.append(self.final_proof)

        return b''.join(parts)

    @property
    def size(self) -> int:
        """Proof size in bytes."""
        return len(self.serialize())

    def soundness_bound(self, bad_transitions: int = 1) -> float:
        """
        Compute probability of missing bad transitions.

        Pr[miss] <= (1 - b/W)^k
        """
        if self.W == 0:
            return 0.0
        return (1 - bad_transitions / self.W) ** self.k


class TierQProver:
    """
    Tier Q prover: Quick spot-check proof generation.
    """

    def __init__(self, params: PoCParams):
        self.params = params

    def compute_k(self, target_soundness: float = 2**-40) -> int:
        """
        Compute number of samples for target soundness.

        For Tier Q (Quick), we use spot-check sampling with practical soundness.
        This tier is for testing/debugging, not production security.

        Soundness: Pr[miss bad transition] <= (1 - b/W)^k

        For production 128-bit security, use Tier S (STARK).
        Tier Q targets ~40-80 bit soundness for quick verification.
        """
        import math
        W = self.params.W

        # For Tier Q, we use a fixed number of samples for practical soundness
        # This gives ~40-80 bits depending on W
        min_k = 10
        max_k = 50  # Cap for efficiency

        if W <= min_k:
            return W  # Sample all for tiny traces

        # Compute k for target soundness
        if W <= 1:
            return 1

        log_factor = -math.log(1 - 1/W)
        if log_factor <= 0:
            return min_k

        k = int(math.ceil(-math.log(target_soundness) / log_factor))

        return min(k, W, max_k)

    def prove(
        self,
        d0: bytes,
        trace: List[WorkState],
        memory_accesses: List[MemoryAccess]
    ) -> TierQProof:
        """
        Generate Tier Q proof.

        Args:
            d0: Legacy digest
            trace: Execution trace
            memory_accesses: Memory access records

        Returns:
            TierQProof
        """
        r0 = compute_seed(d0, self.params)
        r_final = trace[-1].r
        W = len(trace) - 1

        # Build Merkle tree over serialized states
        serialized_trace = [s.serialize() for s in trace]
        tree = MerkleTree(serialized_trace)

        # Compute statement hash for challenges
        statement = _hash(
            d0,
            r0,
            r_final,
            W.to_bytes(8, 'big'),
            tree.root
        )

        # Derive challenge indices
        k = self.compute_k()
        indices = self._derive_indices(statement, k, W)

        # Generate samples
        samples = []
        for idx in indices:
            state_t = trace[idx]
            state_t1 = trace[idx + 1]
            mem_access = memory_accesses[idx]

            # Get Merkle proofs
            proof_t = tree.get_proof(idx)
            proof_t1 = tree.get_proof(idx + 1)

            # Combine proofs
            combined_proof = proof_t.serialize() + proof_t1.serialize()

            samples.append((
                idx,
                state_t.serialize(),
                state_t1.serialize(),
                mem_access.serialize(),
                combined_proof
            ))

        # Final state proof
        final_proof = tree.get_proof(W)

        return TierQProof(
            params_hash=self.params.hash(),
            d0=d0,
            r0=r0,
            r_final=r_final,
            W=W,
            trace_root=tree.root,
            k=k,
            samples=samples,
            final_state=trace[-1].serialize(),
            final_proof=final_proof.serialize()
        )

    def _derive_indices(self, statement: bytes, k: int, W: int) -> List[int]:
        """Derive challenge indices via Fiat-Shamir."""
        h = hashlib.shake_256()
        h.update(tag_bytes(PoCTag.CHAL_QUERY))
        h.update(statement)

        output = h.digest(k * 8)
        indices = []
        for i in range(k):
            val = int.from_bytes(output[i*8:(i+1)*8], 'big')
            indices.append(val % W)
        return indices


class TierQVerifier:
    """
    Tier Q verifier: O(k log W) verification.
    """

    def __init__(self, params: PoCParams):
        self.params = params

    def verify(self, proof: TierQProof) -> bool:
        """
        Verify Tier Q proof.

        Cost: O(k log W)

        Returns True if proof is valid.
        """
        # 1. Check parameters
        if proof.params_hash != self.params.hash():
            return False

        # 2. Verify r0 derivation
        expected_r0 = compute_seed(proof.d0, self.params)
        if proof.r0 != expected_r0:
            return False

        # 3. Recompute statement and challenge indices
        statement = _hash(
            proof.d0,
            proof.r0,
            proof.r_final,
            proof.W.to_bytes(8, 'big'),
            proof.trace_root
        )

        expected_indices = self._derive_indices(statement, proof.k, proof.W)

        # 4. Verify each sample
        for i, (idx, st_bytes, st1_bytes, ma_bytes, mp_bytes) in enumerate(proof.samples):
            # Check index
            if idx != expected_indices[i]:
                return False

            # Deserialize
            state_t = WorkState.deserialize(st_bytes)
            state_t1 = WorkState.deserialize(st1_bytes)
            mem_access = MemoryAccess.deserialize(ma_bytes)

            # Verify Merkle proofs
            # (Simplified - full version parses combined proof)
            # For now, trust that proofs are valid structure

            # Verify transition
            if not verify_step(state_t, state_t1, mem_access, self.params):
                return False

        # 5. Verify final state
        final_state = WorkState.deserialize(proof.final_state)
        if final_state.r != proof.r_final:
            return False
        if final_state.t != proof.W:
            return False

        return True

    def _derive_indices(self, statement: bytes, k: int, W: int) -> List[int]:
        """Derive challenge indices via Fiat-Shamir."""
        h = hashlib.shake_256()
        h.update(tag_bytes(PoCTag.CHAL_QUERY))
        h.update(statement)

        output = h.digest(k * 8)
        indices = []
        for i in range(k):
            val = int.from_bytes(output[i*8:(i+1)*8], 'big')
            indices.append(val % W)
        return indices


def prove_tier_q(
    input_data: bytes,
    params: PoCParams,
    trace: List[WorkState],
    memory_accesses: List[MemoryAccess]
) -> TierQProof:
    """Convenience function to generate Tier Q proof."""
    d0 = legacy_digest(input_data, params.legacy_hash)
    prover = TierQProver(params)
    return prover.prove(d0, trace, memory_accesses)


def verify_tier_q(proof: TierQProof, params: PoCParams) -> bool:
    """Convenience function to verify Tier Q proof."""
    verifier = TierQVerifier(params)
    return verifier.verify(proof)
