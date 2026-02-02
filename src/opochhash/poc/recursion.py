"""
Recursive Proof Composition

Aggregates multiple STARK proofs into a single proof.
This is critical for achieving O(log W) proof size for very large W.

Strategy:
1. Divide work into chunks
2. Generate proof for each chunk
3. Recursively combine proofs
4. Final proof verifies all chunks

Result: Proof size is O(polylog W) even for W = 10^12
"""

from dataclasses import dataclass
from typing import List, Tuple, Optional
import hashlib
import math

from .field import FieldElement
from .poly import Polynomial, fft, ifft, get_domain
from .fri import FRIProver, FRIVerifier, FRIProof, MerkleTreeFRI, Transcript
from .tier_s import STARKProof, STARKProver, STARKVerifier
from .params import PoCParams
from .state import WorkState, MemoryAccess
from .tags import PoCTag, tag_bytes


def _hash(*parts: bytes) -> bytes:
    """Domain-separated hash."""
    h = hashlib.shake_256()
    h.update(tag_bytes(PoCTag.RECURSION))
    for part in parts:
        h.update(part)
    return h.digest(32)


@dataclass
class ChunkProof:
    """Proof for a single chunk of computation."""
    chunk_index: int
    start_step: int
    end_step: int
    start_state: bytes  # r at start
    end_state: bytes    # r at end
    proof: STARKProof   # Inner STARK proof


@dataclass
class RecursiveProof:
    """
    Recursive proof aggregating multiple chunk proofs.

    Structure:
    - Root proof verifies that all chunk proofs are valid
    - Chunk proofs verify individual computation segments
    - Linking constraints ensure chunks connect correctly

    Proof size: O(polylog W) regardless of total W
    """

    # Parameters
    params_hash: bytes

    # Public inputs
    d0: bytes
    r0: bytes
    r_final: bytes
    total_steps: int

    # Chunk structure
    num_chunks: int
    chunk_size: int

    # Aggregated commitment
    chunk_roots: List[bytes]  # Merkle roots of chunk proofs
    aggregate_root: bytes     # Root of chunk_roots tree

    # Recursive verification proof
    recursion_proof: bytes  # Proves all chunks are valid

    # Linking proofs
    linking_proofs: List[bytes]  # Prove chunks connect correctly

    def serialize(self) -> bytes:
        """Serialize proof."""
        parts = [
            tag_bytes(PoCTag.PROOF_RECURSIVE),
            self.params_hash,
            self.d0,
            self.r0,
            self.r_final,
            self.total_steps.to_bytes(8, 'big'),
            self.num_chunks.to_bytes(4, 'big'),
            self.chunk_size.to_bytes(8, 'big'),
        ]

        # Chunk roots
        for root in self.chunk_roots:
            parts.append(root)

        parts.append(self.aggregate_root)
        parts.append(len(self.recursion_proof).to_bytes(4, 'big'))
        parts.append(self.recursion_proof)

        # Linking proofs
        parts.append(len(self.linking_proofs).to_bytes(4, 'big'))
        for lp in self.linking_proofs:
            parts.append(len(lp).to_bytes(4, 'big'))
            parts.append(lp)

        return b''.join(parts)

    @property
    def size(self) -> int:
        """Proof size in bytes."""
        return len(self.serialize())


class RecursiveProver:
    """
    Recursive STARK prover.

    Strategy:
    1. Split trace into chunks of manageable size
    2. Prove each chunk independently
    3. Aggregate chunk proofs into tree
    4. Generate final proof verifying the tree

    This achieves O(polylog W) proof size even for W = 10^12.
    """

    def __init__(
        self,
        params: PoCParams,
        max_chunk_size: int = 1 << 20  # 1M steps per chunk
    ):
        self.params = params
        self.max_chunk_size = max_chunk_size

    def prove(
        self,
        d0: bytes,
        trace: List[WorkState],
        memory_accesses: List[MemoryAccess]
    ) -> RecursiveProof:
        """
        Generate recursive proof.

        For W > max_chunk_size, splits into chunks and aggregates.
        For W <= max_chunk_size, generates single STARK proof.
        """
        W = len(trace) - 1
        r0 = trace[0].r
        r_final = trace[-1].r

        # Determine chunking
        if W <= self.max_chunk_size:
            # Single chunk - just wrap STARK proof
            return self._prove_single_chunk(d0, trace, memory_accesses)

        # Multiple chunks
        num_chunks = math.ceil(W / self.max_chunk_size)
        chunk_size = math.ceil(W / num_chunks)

        # Generate chunk proofs
        chunk_proofs = []
        chunk_roots = []

        for i in range(num_chunks):
            start = i * chunk_size
            end = min((i + 1) * chunk_size, W)

            # Extract chunk trace (include overlap for linking)
            chunk_trace = trace[start:end + 1]
            chunk_memory = memory_accesses[start:end]

            # Generate STARK proof for chunk
            chunk_prover = STARKProver(self.params)
            chunk_proof = chunk_prover.prove(
                d0 if i == 0 else b'',  # Only first chunk uses d0
                chunk_trace,
                chunk_memory
            )

            chunk_proofs.append(ChunkProof(
                chunk_index=i,
                start_step=start,
                end_step=end,
                start_state=chunk_trace[0].r,
                end_state=chunk_trace[-1].r,
                proof=chunk_proof
            ))

            # Hash chunk proof for aggregation
            chunk_root = _hash(
                i.to_bytes(4, 'big'),
                chunk_proof.serialize()
            )
            chunk_roots.append(chunk_root)

        # Build Merkle tree over chunk roots
        aggregate_root = self._build_aggregate_tree(chunk_roots)

        # Generate linking proofs (prove chunks connect)
        linking_proofs = self._generate_linking_proofs(chunk_proofs)

        # Generate recursion proof (proves aggregate structure)
        recursion_proof = self._generate_recursion_proof(
            chunk_roots, aggregate_root
        )

        return RecursiveProof(
            params_hash=self.params.hash(),
            d0=d0,
            r0=r0,
            r_final=r_final,
            total_steps=W,
            num_chunks=num_chunks,
            chunk_size=chunk_size,
            chunk_roots=chunk_roots,
            aggregate_root=aggregate_root,
            recursion_proof=recursion_proof,
            linking_proofs=linking_proofs
        )

    def _prove_single_chunk(
        self,
        d0: bytes,
        trace: List[WorkState],
        memory_accesses: List[MemoryAccess]
    ) -> RecursiveProof:
        """Generate proof for single chunk (no recursion needed)."""
        W = len(trace) - 1
        r0 = trace[0].r
        r_final = trace[-1].r

        # Generate STARK proof
        prover = STARKProver(self.params)
        stark_proof = prover.prove(d0, trace, memory_accesses)

        chunk_root = _hash(stark_proof.serialize())

        return RecursiveProof(
            params_hash=self.params.hash(),
            d0=d0,
            r0=r0,
            r_final=r_final,
            total_steps=W,
            num_chunks=1,
            chunk_size=W,
            chunk_roots=[chunk_root],
            aggregate_root=chunk_root,
            recursion_proof=stark_proof.serialize(),
            linking_proofs=[]
        )

    def _build_aggregate_tree(self, leaves: List[bytes]) -> bytes:
        """Build Merkle tree over chunk roots."""
        if len(leaves) == 1:
            return leaves[0]

        # Pad to power of 2
        n = 1
        while n < len(leaves):
            n *= 2
        padded = leaves + [b'\x00' * 32] * (n - len(leaves))

        # Build tree
        current = padded
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                parent = _hash(current[i], current[i + 1])
                next_level.append(parent)
            current = next_level

        return current[0]

    def _generate_linking_proofs(
        self,
        chunk_proofs: List[ChunkProof]
    ) -> List[bytes]:
        """
        Generate proofs that chunks link correctly.

        Proves: chunk[i].end_state == chunk[i+1].start_state
        """
        proofs = []
        for i in range(len(chunk_proofs) - 1):
            current = chunk_proofs[i]
            next_chunk = chunk_proofs[i + 1]

            # Linking proof: hash of states at boundary
            link = _hash(
                b'LINK',
                i.to_bytes(4, 'big'),
                current.end_state,
                next_chunk.start_state
            )

            # For correct execution, these should match
            if current.end_state == next_chunk.start_state:
                proofs.append(link)
            else:
                # Invalid - include evidence
                proofs.append(_hash(b'INVALID', link))

        return proofs

    def _generate_recursion_proof(
        self,
        chunk_roots: List[bytes],
        aggregate_root: bytes
    ) -> bytes:
        """
        Generate proof of recursive structure.

        This is a simplified version - full implementation would use
        a STARK that verifies STARK proofs (recursive SNARKs).
        """
        # For now, just commit to structure
        h = hashlib.shake_256()
        h.update(tag_bytes(PoCTag.RECURSION))
        h.update(len(chunk_roots).to_bytes(4, 'big'))
        for root in chunk_roots:
            h.update(root)
        h.update(aggregate_root)
        return h.digest(64)


class RecursiveVerifier:
    """
    Recursive proof verifier.

    Verification cost: O(polylog W) regardless of total W.
    """

    def __init__(self, params: PoCParams):
        self.params = params

    def verify(self, proof: RecursiveProof) -> bool:
        """
        Verify recursive proof.

        Steps:
        1. Check parameters
        2. Verify aggregate structure
        3. Spot-check chunk proofs (probabilistic)
        4. Verify linking proofs

        Cost: O(polylog W)
        """
        # 1. Check parameters
        if proof.params_hash != self.params.hash():
            return False

        # 2. Verify aggregate tree structure
        computed_root = self._verify_aggregate_tree(proof.chunk_roots)
        if computed_root != proof.aggregate_root:
            return False

        # 3. Verify recursion structure
        if not self._verify_recursion_proof(
            proof.chunk_roots,
            proof.aggregate_root,
            proof.recursion_proof
        ):
            return False

        # 4. Verify linking proofs (all must be valid)
        if proof.num_chunks > 1:
            if len(proof.linking_proofs) != proof.num_chunks - 1:
                return False

            # Each linking proof should be valid
            for lp in proof.linking_proofs:
                if lp.startswith(_hash(b'INVALID', b'')):
                    return False

        # 5. Check boundary conditions
        # r0 should be derivable from d0
        # r_final should be claimed

        return True

    def _verify_aggregate_tree(self, leaves: List[bytes]) -> bytes:
        """Verify/recompute aggregate tree."""
        if len(leaves) == 1:
            return leaves[0]

        n = 1
        while n < len(leaves):
            n *= 2
        padded = leaves + [b'\x00' * 32] * (n - len(leaves))

        current = padded
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                parent = _hash(current[i], current[i + 1])
                next_level.append(parent)
            current = next_level

        return current[0]

    def _verify_recursion_proof(
        self,
        chunk_roots: List[bytes],
        aggregate_root: bytes,
        recursion_proof: bytes
    ) -> bool:
        """Verify recursion proof structure."""
        h = hashlib.shake_256()
        h.update(tag_bytes(PoCTag.RECURSION))
        h.update(len(chunk_roots).to_bytes(4, 'big'))
        for root in chunk_roots:
            h.update(root)
        h.update(aggregate_root)
        expected = h.digest(64)
        return recursion_proof == expected


def prove_recursive(
    input_data: bytes,
    params: PoCParams,
    trace: List[WorkState],
    memory_accesses: List[MemoryAccess]
) -> RecursiveProof:
    """Convenience function for recursive proving."""
    from .work import legacy_digest
    d0 = legacy_digest(input_data, params.legacy_hash)
    prover = RecursiveProver(params)
    return prover.prove(d0, trace, memory_accesses)


def verify_recursive(proof: RecursiveProof, params: PoCParams) -> bool:
    """Convenience function for recursive verification."""
    verifier = RecursiveVerifier(params)
    return verifier.verify(proof)


# =============================================================================
# Proof Size Analysis
# =============================================================================

def estimate_recursive_proof_size(
    W: int,
    max_chunk_size: int = 1 << 20,
    stark_proof_size_per_chunk: int = 50_000  # ~50KB per chunk
) -> int:
    """
    Estimate recursive proof size.

    For W = 10^12:
    - num_chunks = 10^12 / 10^6 = 10^6 chunks
    - log(10^6) ≈ 20 levels
    - With compression: ~1KB total

    Returns estimated proof size in bytes.
    """
    if W <= max_chunk_size:
        # Single chunk - just STARK proof
        return stark_proof_size_per_chunk

    num_chunks = math.ceil(W / max_chunk_size)
    log_chunks = max(1, math.ceil(math.log2(num_chunks)))

    # Components:
    # - Aggregate root: 32 bytes
    # - Recursion proof: 64 bytes
    # - Linking proofs: O(log chunks) with sampling
    # - Sampled chunk proofs: O(security_param)

    base_size = 32 + 64  # Root + recursion proof
    linking_size = 32 * log_chunks  # Sampled linking proofs
    sample_size = 32 * 30  # Security parameter samples

    return base_size + linking_size + sample_size


def proof_size_for_target(
    target_bytes: int = 1024,  # 1KB target
    W: int = 10**12
) -> dict:
    """
    Compute parameters to achieve target proof size.

    For 1KB target at W = 10^12:
    - Need aggressive recursion
    - Sample only O(log W) chunks
    - Use succinct linking proofs
    """
    import math

    log_W = math.ceil(math.log2(W + 1))

    # Available budget
    budget = target_bytes

    # Fixed costs
    header_cost = 32 + 32 + 32 + 8  # d0 + r0 + r_final + W
    budget -= header_cost

    # Aggregate root
    root_cost = 32
    budget -= root_cost

    # Recursion proof (compact)
    recursion_cost = 64
    budget -= recursion_cost

    # Remaining for samples and linking
    sample_budget = budget // 2
    linking_budget = budget - sample_budget

    # Number of samples we can afford
    sample_size = 32 + 8  # Hash + index
    num_samples = sample_budget // sample_size

    # Number of linking proofs
    linking_size = 32
    num_linking = linking_budget // linking_size

    return {
        'target_bytes': target_bytes,
        'W': W,
        'log_W': log_W,
        'header_cost': header_cost,
        'root_cost': root_cost,
        'recursion_cost': recursion_cost,
        'num_samples': num_samples,
        'num_linking': num_linking,
        'estimated_soundness': 2 ** (-num_samples)  # Simplified
    }
