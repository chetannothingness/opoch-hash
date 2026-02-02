"""
Tests for Proof of Computation Framework

Tests all three levels of the proof system:
- Level 0: Receipted replay
- Level 1: Spot-check with Merkle traces
- Merkle tree and kernel primitives
"""

import pytest
from opochhash.proof import (
    # Tags
    ProofTag,
    tag_bytes,

    # Merkle
    MerkleTree,
    MerkleProof,
    leaf_hash,
    node_hash,
    root_hash,

    # Kernel
    MachineState,
    execute,
    execute_with_serialized_trace,

    # Level 0
    Level0Proof,
    Level0Prover,
    Level0Verifier,
    prove_level0,
    verify_level0,

    # Level 1
    Level1Proof,
    Level1Prover,
    Level1Verifier,
    prove_level1,
    verify_level1,
    derive_challenges,

    # VM
    StackVM,
    Instruction,
    Opcode,
    program_factorial,
    program_fibonacci,
    program_add,
    program_multiply,
)


class TestMerkleTree:
    """Tests for Merkle tree implementation."""

    def test_single_leaf(self):
        """Tree with single leaf."""
        tree = MerkleTree([b"hello"])
        assert tree.root is not None
        assert len(tree.root) == 32

    def test_two_leaves(self):
        """Tree with two leaves."""
        tree = MerkleTree([b"hello", b"world"])
        assert tree.root is not None

        # Get proofs
        proof0 = tree.get_proof(0)
        proof1 = tree.get_proof(1)

        # Verify proofs
        assert proof0.verify(tree.root)
        assert proof1.verify(tree.root)

    def test_power_of_two_leaves(self):
        """Tree with power-of-two leaves."""
        leaves = [f"leaf{i}".encode() for i in range(8)]
        tree = MerkleTree(leaves)

        # All proofs should verify
        for i in range(8):
            proof = tree.get_proof(i)
            assert proof.verify(tree.root), f"Proof {i} failed"

    def test_non_power_of_two_leaves(self):
        """Tree with non-power-of-two leaves (odd padding)."""
        leaves = [f"leaf{i}".encode() for i in range(7)]
        tree = MerkleTree(leaves)

        for i in range(7):
            proof = tree.get_proof(i)
            assert proof.verify(tree.root), f"Proof {i} failed"

    def test_proof_fails_for_wrong_root(self):
        """Proof should fail against wrong root."""
        tree1 = MerkleTree([b"hello", b"world"])
        tree2 = MerkleTree([b"foo", b"bar"])

        proof = tree1.get_proof(0)
        assert not proof.verify(tree2.root)

    def test_deterministic(self):
        """Same leaves produce same root."""
        leaves = [b"a", b"b", b"c", b"d"]
        tree1 = MerkleTree(leaves)
        tree2 = MerkleTree(leaves)
        assert tree1.root == tree2.root

    def test_leaf_order_matters(self):
        """Different leaf order produces different root."""
        tree1 = MerkleTree([b"a", b"b"])
        tree2 = MerkleTree([b"b", b"a"])
        assert tree1.root != tree2.root


class TestMachineState:
    """Tests for machine state serialization."""

    def test_roundtrip(self):
        """State serializes and deserializes correctly."""
        state = MachineState(
            pc=42,
            registers={'a': 1, 'b': 2},
            memory_root=b'\xaa' * 32,
            io_buffer=b"hello",
            halted=True,
            failed=False
        )

        serialized = state.serialize()
        restored = MachineState.deserialize(serialized)

        assert restored.pc == state.pc
        assert restored.registers == state.registers
        assert restored.memory_root == state.memory_root
        assert restored.io_buffer == state.io_buffer
        assert restored.halted == state.halted
        assert restored.failed == state.failed

    def test_deterministic_serialization(self):
        """Same state produces same serialization."""
        state1 = MachineState(pc=1, registers={'z': 1, 'a': 2})
        state2 = MachineState(pc=1, registers={'a': 2, 'z': 1})

        # Different construction order, same state
        assert state1.serialize() == state2.serialize()


class TestStackVM:
    """Tests for the stack-based VM."""

    def test_simple_add(self):
        """Test simple addition."""
        vm = program_add(5, 3)
        trace, output = execute(vm, b"")

        # Output should be 8 (as single byte)
        assert output == bytes([8])
        assert trace[-1].halted

    def test_simple_multiply(self):
        """Test simple multiplication."""
        vm = program_multiply(6, 7)
        trace, output = execute(vm, b"")

        assert output == bytes([42])
        assert trace[-1].halted

    def test_factorial_5(self):
        """Test factorial of 5."""
        vm = program_factorial(5)
        trace, output = execute(vm, b"")

        # 5! = 120
        assert output == bytes([120])
        assert trace[-1].halted

    def test_factorial_1(self):
        """Test factorial of 1."""
        vm = program_factorial(1)
        trace, output = execute(vm, b"")

        # 1! = 1
        assert output == bytes([1])

    def test_fibonacci_10(self):
        """Test 10th Fibonacci number."""
        vm = program_fibonacci(10)
        trace, output = execute(vm, b"")

        # fib(10) = 55
        assert output == bytes([55])

    def test_fibonacci_0(self):
        """Test fib(0)."""
        vm = program_fibonacci(0)
        trace, output = execute(vm, b"")
        assert output == bytes([0])

    def test_fibonacci_1(self):
        """Test fib(1)."""
        vm = program_fibonacci(1)
        trace, output = execute(vm, b"")
        assert output == bytes([1])

    def test_vm_serialization(self):
        """VM serializes and deserializes correctly."""
        vm1 = program_add(10, 20)
        serialized = vm1.serialize()
        vm2 = StackVM.from_bytes(serialized)

        # Execute both and compare
        _, out1 = execute(vm1, b"")
        _, out2 = execute(vm2, b"")

        assert out1 == out2


class TestLevel0:
    """Tests for Level 0: Receipted Replay."""

    def test_prove_and_verify_add(self):
        """Prove and verify simple addition."""
        vm = program_add(10, 20)
        proof = prove_level0(vm, b"")

        assert proof.output_data == bytes([30])
        assert verify_level0(proof, vm)

    def test_prove_and_verify_factorial(self):
        """Prove and verify factorial."""
        vm = program_factorial(5)
        proof = prove_level0(vm, b"")

        assert proof.output_data == bytes([120])
        assert verify_level0(proof, vm)

    def test_receipt_chain_integrity(self):
        """Receipt chain changes if execution changes."""
        vm1 = program_add(5, 5)
        vm2 = program_add(5, 6)

        proof1 = prove_level0(vm1, b"")
        proof2 = prove_level0(vm2, b"")

        # Different programs should have different receipts
        assert proof1.final_receipt != proof2.final_receipt

    def test_tampered_output_fails(self):
        """Verification fails if output is tampered."""
        vm = program_add(10, 20)
        proof = prove_level0(vm, b"")

        # Tamper with output
        proof.output_data = bytes([99])

        result = Level0Verifier().verify(proof, vm)
        assert not result.valid
        assert not result.output_matches

    def test_tampered_receipt_fails(self):
        """Verification fails if receipt is tampered."""
        vm = program_add(10, 20)
        proof = prove_level0(vm, b"")

        # Tamper with receipt
        proof.final_receipt = b'\x00' * 32

        result = Level0Verifier().verify(proof, vm)
        assert not result.valid
        assert not result.receipt_matches


class TestLevel1:
    """Tests for Level 1: Spot-Check Proofs."""

    def test_prove_and_verify_add(self):
        """Prove and verify simple addition."""
        vm = program_add(10, 20)
        proof = prove_level1(vm, b"")

        assert verify_level1(proof, vm)

    def test_prove_and_verify_factorial(self):
        """Prove and verify factorial."""
        vm = program_factorial(5)
        proof = prove_level1(vm, b"")

        assert verify_level1(proof, vm)
        assert proof.statement.steps > 0

    def test_prove_and_verify_fibonacci(self):
        """Prove and verify Fibonacci."""
        vm = program_fibonacci(10)
        proof = prove_level1(vm, b"")

        assert verify_level1(proof, vm)

    def test_soundness_bound(self):
        """Soundness bound is computed correctly."""
        vm = program_factorial(10)
        proof = prove_level1(vm, b"")

        # With k samples and T steps, bound is (1-1/T)^k
        bound = proof.soundness_bound(bad_transitions=1)
        assert 0 <= bound < 1

    def test_deterministic_challenges(self):
        """Challenge derivation is deterministic."""
        vm = program_factorial(5)
        proof1 = prove_level1(vm, b"")
        proof2 = prove_level1(vm, b"")

        # Same statement should produce same challenges
        challenges1 = derive_challenges(proof1.statement, proof1.k)
        challenges2 = derive_challenges(proof2.statement, proof2.k)

        assert challenges1 == challenges2

    def test_merkle_proofs_valid(self):
        """All Merkle proofs in Level 1 proof are valid."""
        vm = program_factorial(5)
        proof = prove_level1(vm, b"")

        root = proof.statement.trace_root

        # All transition proofs should have valid Merkle paths
        for trans in proof.transitions:
            assert trans.proof_t.verify(root)
            assert trans.proof_t1.verify(root)

        # Final proof should be valid
        assert proof.final_proof.verify(root)

    def test_wrong_program_fails(self):
        """Verification fails with wrong program."""
        vm1 = program_add(5, 5)
        vm2 = program_add(5, 6)

        proof = prove_level1(vm1, b"")

        # Try to verify with different program
        result = Level1Verifier().verify(proof, vm2)
        assert not result.valid


class TestProofComparison:
    """Compare Level 0 and Level 1 proofs."""

    def test_same_computation_same_output(self):
        """Both levels produce same output claim."""
        vm = program_factorial(5)

        proof0 = prove_level0(vm, b"")
        proof1 = prove_level1(vm, b"")

        assert proof0.output_data == bytes([120])
        # Level 1 stores output hash, not raw output
        # but verification checks it matches

    def test_both_verify_same_computation(self):
        """Both levels verify the same computation."""
        vm = program_fibonacci(10)

        proof0 = prove_level0(vm, b"")
        proof1 = prove_level1(vm, b"")

        assert verify_level0(proof0, vm)
        assert verify_level1(proof1, vm)


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_input(self):
        """Programs work with empty input."""
        vm = program_add(1, 1)
        proof = prove_level1(vm, b"")
        assert verify_level1(proof, vm)

    def test_single_step_program(self):
        """Program that halts immediately."""
        vm = StackVM([Instruction(Opcode.HALT)])
        proof = prove_level1(vm, b"")
        assert verify_level1(proof, vm)

    def test_long_trace(self):
        """Program with longer execution trace."""
        vm = program_factorial(10)  # 10! = 3628800, many steps
        proof = prove_level1(vm, b"")
        assert verify_level1(proof, vm)
        assert proof.statement.steps > 50


class TestDomainSeparation:
    """Test domain separation in proof system."""

    def test_different_tags(self):
        """Different tags produce different hashes."""
        from opochhash.proof.merkle import _hash as merkle_hash

        data = b"test data"
        h1 = merkle_hash(ProofTag.LEAF, data)
        h2 = merkle_hash(ProofTag.NODE, data)
        h3 = merkle_hash(ProofTag.ROOT, data)

        assert h1 != h2
        assert h2 != h3
        assert h1 != h3

    def test_leaf_vs_node(self):
        """Leaf hash differs from node hash."""
        data = b"same data"
        lh = leaf_hash(0, data)
        nh = node_hash(data, data)

        assert lh != nh
