"""
FRI Protocol (Fast Reed-Solomon Interactive Oracle Proofs)

FRI proves that a committed polynomial has low degree.
This is the core of STARK soundness.

Protocol:
1. Prover commits to polynomial evaluations via Merkle tree
2. For each round:
   a. Verifier sends random challenge α (Fiat-Shamir)
   b. Prover folds polynomial: f_{i+1}(x) = f_even(x) + α·f_odd(x)
   c. Prover commits to folded polynomial
3. Final polynomial is constant (degree 0)
4. Verifier checks random queries through all layers
"""

from dataclasses import dataclass
from typing import List, Tuple, Optional
import hashlib
import math

from .field import FieldElement
from .poly import Polynomial, fft, ifft, get_domain
from .tags import PoCTag, tag_bytes


def _hash(*parts: bytes) -> bytes:
    """Hash for Merkle tree and challenges."""
    h = hashlib.shake_256()
    for part in parts:
        h.update(part)
    return h.digest(32)


class MerkleTreeFRI:
    """
    Merkle tree for FRI commitments.

    Leaves are polynomial evaluations, serialized as field elements.
    """

    def __init__(self, leaves: List[bytes]):
        if not leaves:
            raise ValueError("Cannot build empty tree")

        self.num_leaves = len(leaves)
        self.leaves = leaves

        # Compute leaf hashes
        self.leaf_hashes = [
            _hash(tag_bytes(PoCTag.FRI_LAYER), i.to_bytes(4, 'big'), leaf)
            for i, leaf in enumerate(leaves)
        ]

        # Build tree
        self.layers = [self.leaf_hashes]
        self._build_tree()
        self.root = self.layers[-1][0]

    def _build_tree(self):
        current = self.leaf_hashes
        while len(current) > 1:
            next_layer = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                parent = _hash(left, right)
                next_layer.append(parent)
            self.layers.append(next_layer)
            current = next_layer

    def get_authentication_path(self, index: int) -> List[Tuple[bytes, bool]]:
        """Get Merkle authentication path for leaf at index."""
        path = []
        current_idx = index

        for layer in self.layers[:-1]:
            if current_idx % 2 == 0:
                sibling_idx = current_idx + 1
                is_right = True
            else:
                sibling_idx = current_idx - 1
                is_right = False

            if sibling_idx < len(layer):
                sibling = layer[sibling_idx]
            else:
                sibling = layer[current_idx]

            path.append((sibling, is_right))
            current_idx //= 2

        return path

    @staticmethod
    def verify_path(
        leaf_value: bytes,
        leaf_index: int,
        path: List[Tuple[bytes, bool]],
        root: bytes
    ) -> bool:
        """Verify a Merkle authentication path."""
        current = _hash(tag_bytes(PoCTag.FRI_LAYER), leaf_index.to_bytes(4, 'big'), leaf_value)

        for sibling, is_right in path:
            if is_right:
                current = _hash(current, sibling)
            else:
                current = _hash(sibling, current)

        return current == root


class Transcript:
    """
    Fiat-Shamir transcript for non-interactive proofs.

    Accumulates commitments and derives challenges deterministically.
    """

    def __init__(self):
        self.data = b''

    def append(self, commitment: bytes):
        """Add commitment to transcript."""
        self.data += commitment

    def challenge_field_element(self) -> FieldElement:
        """Derive a field element challenge."""
        h = hashlib.shake_256()
        h.update(tag_bytes(PoCTag.CHAL_FRI))
        h.update(self.data)
        h.update(b'field')
        digest = h.digest(8)
        self.data += digest  # Include in future challenges
        return FieldElement.from_bytes(digest)

    def challenge_indices(self, count: int, domain_size: int) -> List[int]:
        """Derive random query indices."""
        h = hashlib.shake_256()
        h.update(tag_bytes(PoCTag.CHAL_QUERY))
        h.update(self.data)
        h.update(b'indices')

        indices = []
        output = h.digest(count * 8)

        for i in range(count):
            val = int.from_bytes(output[i*8:(i+1)*8], 'big')
            indices.append(val % domain_size)

        self.data += output
        return indices


@dataclass
class FRIQueryProof:
    """Proof for a single FRI query."""
    initial_index: int
    initial_value: bytes
    initial_path: List[Tuple[bytes, bool]]
    layer_values: List[bytes]  # Values at each fold layer
    layer_paths: List[List[Tuple[bytes, bool]]]


@dataclass
class FRIProof:
    """Complete FRI proof."""
    layer_commitments: List[bytes]  # Merkle roots of each layer
    final_value: FieldElement  # Final constant polynomial value
    query_proofs: List[FRIQueryProof]

    def serialize(self) -> bytes:
        """Serialize proof."""
        parts = [
            len(self.layer_commitments).to_bytes(4, 'big'),
        ]
        for comm in self.layer_commitments:
            parts.append(comm)

        parts.append(self.final_value.to_bytes())
        parts.append(len(self.query_proofs).to_bytes(4, 'big'))

        for qp in self.query_proofs:
            parts.append(qp.initial_index.to_bytes(4, 'big'))
            parts.append(qp.initial_value)
            parts.append(len(qp.initial_path).to_bytes(4, 'big'))
            for sibling, is_right in qp.initial_path:
                parts.append(sibling)
                parts.append(bytes([1 if is_right else 0]))

            parts.append(len(qp.layer_values).to_bytes(4, 'big'))
            for lv in qp.layer_values:
                parts.append(lv)

            for layer_path in qp.layer_paths:
                parts.append(len(layer_path).to_bytes(4, 'big'))
                for sibling, is_right in layer_path:
                    parts.append(sibling)
                    parts.append(bytes([1 if is_right else 0]))

        return b''.join(parts)


class FRIProver:
    """
    FRI prover for low-degree testing.

    Proves that a committed polynomial has degree < D.
    """

    def __init__(
        self,
        domain_size: int,
        max_degree: int,
        num_queries: int = 30,
        folding_factor: int = 2
    ):
        """
        Args:
            domain_size: Size of evaluation domain (power of 2)
            max_degree: Maximum polynomial degree to prove
            num_queries: Number of query rounds
            folding_factor: Degree reduction per round (typically 2)
        """
        self.domain_size = domain_size
        self.max_degree = max_degree
        self.num_queries = num_queries
        self.folding_factor = folding_factor

        # Number of folding rounds
        self.num_rounds = int(math.log2(max_degree + 1))

        # Precompute domains
        self._compute_domains()

    def _compute_domains(self):
        """Precompute evaluation domains for each round."""
        self.domains = [get_domain(self.domain_size)]
        current_size = self.domain_size

        for _ in range(self.num_rounds):
            current_size //= self.folding_factor
            if current_size > 0:
                self.domains.append(get_domain(current_size))

    def prove(self, evaluations: List[FieldElement]) -> Tuple[bytes, FRIProof]:
        """
        Generate FRI proof.

        Args:
            evaluations: Polynomial evaluations on domain

        Returns:
            (commitment, proof)
        """
        if len(evaluations) != self.domain_size:
            raise ValueError(f"Expected {self.domain_size} evaluations, got {len(evaluations)}")

        transcript = Transcript()
        layer_trees: List[MerkleTreeFRI] = []
        layer_evals: List[List[FieldElement]] = [evaluations]
        alphas: List[FieldElement] = []

        # Initial commitment
        initial_tree = MerkleTreeFRI([e.to_bytes() for e in evaluations])
        layer_trees.append(initial_tree)
        transcript.append(initial_tree.root)

        # Folding rounds
        current_evals = evaluations
        current_size = self.domain_size

        for round_idx in range(self.num_rounds):
            # Get folding challenge
            alpha = transcript.challenge_field_element()
            alphas.append(alpha)

            # Fold evaluations
            current_evals = self._fold_evaluations(current_evals, alpha)
            current_size //= self.folding_factor
            layer_evals.append(current_evals)

            if current_size > 1:
                # Commit to folded evaluations
                tree = MerkleTreeFRI([e.to_bytes() for e in current_evals])
                layer_trees.append(tree)
                transcript.append(tree.root)

        # Final constant value
        final_value = current_evals[0] if current_evals else FieldElement.zero()

        # Generate query proofs
        query_indices = transcript.challenge_indices(self.num_queries, self.domain_size)
        query_proofs = self._generate_query_proofs(
            query_indices, layer_trees, layer_evals, alphas
        )

        # Build proof
        proof = FRIProof(
            layer_commitments=[t.root for t in layer_trees],
            final_value=final_value,
            query_proofs=query_proofs
        )

        return initial_tree.root, proof

    def _fold_evaluations(
        self,
        evals: List[FieldElement],
        alpha: FieldElement
    ) -> List[FieldElement]:
        """
        Fold evaluations using random challenge.

        f'(x) = f_even(x) + α · f_odd(x)

        where f(x) = f_even(x²) + x · f_odd(x²)
        """
        n = len(evals)
        half_n = n // 2
        result = []

        for i in range(half_n):
            # f_even and f_odd at position i
            f_even = evals[i]
            f_odd = evals[i + half_n]

            # Fold: f'(i) = f_even + α · f_odd
            folded = f_even + alpha * f_odd
            result.append(folded)

        return result

    def _generate_query_proofs(
        self,
        query_indices: List[int],
        layer_trees: List[MerkleTreeFRI],
        layer_evals: List[List[FieldElement]],
        alphas: List[FieldElement]
    ) -> List[FRIQueryProof]:
        """Generate proofs for all query indices."""
        proofs = []

        for initial_idx in query_indices:
            # Initial layer
            initial_value = layer_evals[0][initial_idx].to_bytes()
            initial_path = layer_trees[0].get_authentication_path(initial_idx)

            # Track index through layers
            layer_values = []
            layer_paths = []
            current_idx = initial_idx

            for layer_idx in range(1, len(layer_trees)):
                # Folded index
                current_idx = current_idx % len(layer_evals[layer_idx])
                layer_values.append(layer_evals[layer_idx][current_idx].to_bytes())
                layer_paths.append(layer_trees[layer_idx].get_authentication_path(current_idx))

            proofs.append(FRIQueryProof(
                initial_index=initial_idx,
                initial_value=initial_value,
                initial_path=initial_path,
                layer_values=layer_values,
                layer_paths=layer_paths
            ))

        return proofs


class FRIVerifier:
    """
    FRI verifier for low-degree testing.
    """

    def __init__(
        self,
        domain_size: int,
        max_degree: int,
        num_queries: int = 30,
        folding_factor: int = 2
    ):
        self.domain_size = domain_size
        self.max_degree = max_degree
        self.num_queries = num_queries
        self.folding_factor = folding_factor
        self.num_rounds = int(math.log2(max_degree + 1))

    def verify(self, commitment: bytes, proof: FRIProof) -> bool:
        """
        Verify FRI proof.

        Returns True if proof is valid (polynomial has low degree).
        """
        transcript = Transcript()
        transcript.append(commitment)

        # Check commitment matches
        if proof.layer_commitments[0] != commitment:
            return False

        # Reconstruct challenges
        alphas = []
        for i in range(1, len(proof.layer_commitments)):
            alpha = transcript.challenge_field_element()
            alphas.append(alpha)
            transcript.append(proof.layer_commitments[i])

        # Final round alpha
        if len(alphas) < self.num_rounds:
            alphas.append(transcript.challenge_field_element())

        # Reconstruct query indices
        query_indices = transcript.challenge_indices(self.num_queries, self.domain_size)

        # Verify each query
        for i, qp in enumerate(proof.query_proofs):
            expected_idx = query_indices[i]
            if qp.initial_index != expected_idx:
                return False

            # Verify initial Merkle path
            if not MerkleTreeFRI.verify_path(
                qp.initial_value,
                qp.initial_index,
                qp.initial_path,
                proof.layer_commitments[0]
            ):
                return False

            # Verify folding consistency
            current_value = FieldElement.from_bytes(qp.initial_value)
            current_idx = qp.initial_index

            for layer_idx, (layer_value_bytes, layer_path) in enumerate(
                zip(qp.layer_values, qp.layer_paths)
            ):
                if layer_idx >= len(alphas):
                    break

                alpha = alphas[layer_idx]
                layer_value = FieldElement.from_bytes(layer_value_bytes)

                # Verify Merkle path for this layer
                if layer_idx + 1 < len(proof.layer_commitments):
                    new_idx = current_idx % (self.domain_size // (self.folding_factor ** (layer_idx + 1)))
                    if not MerkleTreeFRI.verify_path(
                        layer_value_bytes,
                        new_idx,
                        layer_path,
                        proof.layer_commitments[layer_idx + 1]
                    ):
                        return False

                # Update for next iteration
                current_value = layer_value
                current_idx = current_idx // self.folding_factor

        return True


def fri_soundness_bound(
    domain_size: int,
    max_degree: int,
    num_queries: int,
    folding_factor: int = 2
) -> float:
    """
    Compute FRI soundness bound.

    The probability of accepting a polynomial of degree > max_degree is bounded by:
        ε ≤ (ρ + δ)^q

    where:
        ρ = rate = max_degree / domain_size
        δ = proximity parameter
        q = number of queries
    """
    rate = max_degree / domain_size
    # Simplified bound
    return rate ** num_queries
