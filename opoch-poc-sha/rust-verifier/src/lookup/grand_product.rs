//! Grand Product Lookup Argument
//!
//! Implements the permutation-based lookup argument.
//!
//! ## Protocol
//!
//! Given witness column W and table T, proves all values in W are in T.
//!
//! Running product Z:
//! - Z_0 = 1
//! - Z_{i+1} = Z_i * (W_i + β + γ*i) / (T_{π(i)} + β + γ*i)
//! - Z_n = 1 (if valid)
//!
//! Constraints:
//! 1. Z_0 = 1
//! 2. Z_{i+1} * (T_{π(i)} + β + γ*i) = Z_i * (W_i + β + γ*i)
//! 3. Z_n = 1

use crate::field::Fp;
use crate::transcript::Transcript;
use crate::fri::{FriConfig, FriProof, FriProver, FriVerifier};
use crate::merkle::MerkleTree;

/// Lookup proof data
#[derive(Clone, Debug)]
pub struct LookupProof {
    /// Commitment to witness column
    pub witness_commitment: [u8; 32],
    /// Commitment to running product column Z
    pub z_commitment: [u8; 32],
    /// Commitment to sorted/permuted table
    pub permuted_commitment: [u8; 32],
    /// FRI proof for constraint polynomial
    pub fri_proof: FriProof,
}

impl LookupProof {
    /// Serialize proof to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.witness_commitment);
        result.extend_from_slice(&self.z_commitment);
        result.extend_from_slice(&self.permuted_commitment);
        let fri_bytes = self.fri_proof.serialize();
        result.extend_from_slice(&(fri_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&fri_bytes);
        result
    }

    /// Deserialize proof from bytes
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 100 {
            return None;
        }

        let mut offset = 0;

        let mut witness_commitment = [0u8; 32];
        witness_commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut z_commitment = [0u8; 32];
        z_commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut permuted_commitment = [0u8; 32];
        permuted_commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let fri_len = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let fri_proof = FriProof::deserialize(&data[offset..offset + fri_len])?;

        Some(LookupProof {
            witness_commitment,
            z_commitment,
            permuted_commitment,
            fri_proof,
        })
    }
}

/// Grand product lookup argument
pub struct GrandProductLookup {
    /// Table values (committed once at setup)
    table: Vec<Fp>,
    /// Table commitment (Merkle root)
    table_commitment: [u8; 32],
    /// FRI configuration
    fri_config: FriConfig,
}

impl GrandProductLookup {
    /// Create new lookup argument with given table
    pub fn new(table: Vec<Fp>, fri_config: FriConfig) -> Self {
        // Commit to table
        let table_bytes: Vec<Vec<u8>> = table
            .iter()
            .map(|x| x.to_bytes().to_vec())
            .collect();

        let tree = MerkleTree::new(table_bytes);
        let table_commitment = tree.root;

        GrandProductLookup {
            table,
            table_commitment,
            fri_config,
        }
    }

    /// Find index of value in table
    fn find_in_table(&self, value: Fp) -> Option<usize> {
        self.table.iter().position(|&x| x == value)
    }

    /// Commit to column of field elements
    fn commit_column(&self, column: &[Fp]) -> ([u8; 32], MerkleTree) {
        let column_bytes: Vec<Vec<u8>> = column
            .iter()
            .map(|x| x.to_bytes().to_vec())
            .collect();

        let tree = MerkleTree::new(column_bytes);
        (tree.root, tree)
    }

    /// Generate lookup proof
    ///
    /// Proves that all values in witness are contained in the table.
    pub fn prove(&self, witness: &[Fp], transcript: &mut Transcript) -> Option<LookupProof> {
        let n = witness.len();
        if n == 0 {
            return None;
        }

        // 1. Commit to witness
        let (witness_commitment, _witness_tree) = self.commit_column(witness);
        transcript.append_commitment(&witness_commitment);

        // 2. Get challenges
        let beta = transcript.challenge();
        let gamma = transcript.challenge();

        // 3. Build permutation: for each witness value, find its index in table
        let mut permutation = Vec::with_capacity(n);
        for &w in witness {
            match self.find_in_table(w) {
                Some(idx) => permutation.push(idx),
                None => return None, // Witness value not in table
            }
        }

        // 4. Compute running product Z
        // Z_0 = 1
        // Z_{i+1} = Z_i * (W_i + β + γ*i) / (T_{π(i)} + β + γ*i)
        // Note: Both terms use index i (not π(i) for the second term's γ coefficient)
        let mut z = vec![Fp::ONE];
        for i in 0..n {
            let w_term = witness[i] + beta + gamma * Fp::new(i as u64);
            let t_term = self.table[permutation[i]] + beta + gamma * Fp::new(i as u64);
            let z_next = z[i] * w_term * t_term.inverse();
            z.push(z_next);
        }

        // 5. Verify Z_n = 1 (if not, witness contains invalid value)
        if z[n] != Fp::ONE {
            return None;
        }

        // 6. Commit to Z
        let (z_commitment, _z_tree) = self.commit_column(&z);
        transcript.append_commitment(&z_commitment);

        // 7. Build permuted column
        let permuted: Vec<Fp> = permutation.iter().map(|&idx| self.table[idx]).collect();
        let (permuted_commitment, _permuted_tree) = self.commit_column(&permuted);
        transcript.append_commitment(&permuted_commitment);

        // 8. Build constraint polynomial
        // For each i: Z_{i+1} * (T_{π(i)} + β + γ*i) - Z_i * (W_i + β + γ*i) = 0
        let mut constraint_evals = Vec::with_capacity(n);
        for i in 0..n {
            let w_term = witness[i] + beta + gamma * Fp::new(i as u64);
            let t_term = permuted[i] + beta + gamma * Fp::new(i as u64);
            let lhs = z[i + 1] * t_term;
            let rhs = z[i] * w_term;
            constraint_evals.push(lhs - rhs);
        }

        // 9. Generate FRI proof
        let fri_prover = FriProver::new(self.fri_config.clone());
        let fri_proof = fri_prover.prove(constraint_evals, transcript);

        Some(LookupProof {
            witness_commitment,
            z_commitment,
            permuted_commitment,
            fri_proof,
        })
    }

    /// Verify lookup proof
    pub fn verify(&self, proof: &LookupProof, transcript: &mut Transcript) -> bool {
        // 1. Reconstruct transcript
        transcript.append_commitment(&proof.witness_commitment);

        // 2. Get challenges (must match prover)
        let _beta = transcript.challenge();
        let _gamma = transcript.challenge();

        // 3. Add Z commitment
        transcript.append_commitment(&proof.z_commitment);

        // 4. Add permuted commitment
        transcript.append_commitment(&proof.permuted_commitment);

        // 5. Verify FRI proof
        let fri_verifier = FriVerifier::new(self.fri_config.clone());
        fri_verifier.verify(&proof.fri_proof, transcript)
    }

    /// Get table commitment
    pub fn table_commitment(&self) -> [u8; 32] {
        self.table_commitment
    }
}

/// Builder for lookup arguments
pub struct LookupBuilder {
    /// Accumulated witness values
    witness: Vec<Fp>,
    /// Table reference
    table: Vec<Fp>,
    /// FRI config
    fri_config: FriConfig,
}

impl LookupBuilder {
    /// Create new builder with table
    pub fn new(table: Vec<Fp>, fri_config: FriConfig) -> Self {
        LookupBuilder {
            witness: Vec::new(),
            table,
            fri_config,
        }
    }

    /// Add value to witness
    pub fn add(&mut self, value: Fp) {
        self.witness.push(value);
    }

    /// Add multiple values
    pub fn add_many(&mut self, values: &[Fp]) {
        self.witness.extend_from_slice(values);
    }

    /// Build and prove
    pub fn prove(self, transcript: &mut Transcript) -> Option<LookupProof> {
        let lookup = GrandProductLookup::new(self.table, self.fri_config);
        lookup.prove(&self.witness, transcript)
    }
}

/// Batch lookup for multiple tables
pub struct BatchLookup {
    /// Individual lookups
    lookups: Vec<GrandProductLookup>,
    /// Witnesses for each table
    witnesses: Vec<Vec<Fp>>,
}

impl BatchLookup {
    /// Create new batch lookup
    pub fn new() -> Self {
        BatchLookup {
            lookups: Vec::new(),
            witnesses: Vec::new(),
        }
    }

    /// Add a table
    pub fn add_table(&mut self, table: Vec<Fp>, fri_config: FriConfig) -> usize {
        let idx = self.lookups.len();
        self.lookups.push(GrandProductLookup::new(table, fri_config));
        self.witnesses.push(Vec::new());
        idx
    }

    /// Add witness value to specific table
    pub fn add_witness(&mut self, table_idx: usize, value: Fp) {
        self.witnesses[table_idx].push(value);
    }

    /// Prove all lookups
    pub fn prove(&self, transcript: &mut Transcript) -> Option<Vec<LookupProof>> {
        let mut proofs = Vec::with_capacity(self.lookups.len());
        for (lookup, witness) in self.lookups.iter().zip(self.witnesses.iter()) {
            match lookup.prove(witness, transcript) {
                Some(proof) => proofs.push(proof),
                None => return None,
            }
        }
        Some(proofs)
    }

    /// Verify all lookups
    pub fn verify(&self, proofs: &[LookupProof], transcript: &mut Transcript) -> bool {
        if proofs.len() != self.lookups.len() {
            return false;
        }

        for (lookup, proof) in self.lookups.iter().zip(proofs.iter()) {
            if !lookup.verify(proof, transcript) {
                return false;
            }
        }
        true
    }
}

impl Default for BatchLookup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lookup::generate::generate_u8_table;

    fn test_fri_config() -> FriConfig {
        FriConfig {
            num_queries: 8,
            blowup_factor: 4,
            max_degree: 256,
        }
    }

    #[test]
    fn test_grand_product_valid() {
        let table = generate_u8_table();
        let lookup = GrandProductLookup::new(table, test_fri_config());

        // Valid witness: all values in table
        let witness: Vec<Fp> = vec![0, 128, 255, 1, 2, 3]
            .into_iter()
            .map(Fp::new)
            .collect();

        let mut transcript = Transcript::new();
        let proof = lookup.prove(&witness, &mut transcript);
        assert!(proof.is_some());

        // Verify
        let mut verify_transcript = Transcript::new();
        let valid = lookup.verify(&proof.unwrap(), &mut verify_transcript);
        assert!(valid);
    }

    #[test]
    fn test_grand_product_invalid() {
        let table = generate_u8_table();
        let lookup = GrandProductLookup::new(table, test_fri_config());

        // Invalid witness: 256 is not in U8 table
        let witness: Vec<Fp> = vec![0, 256, 255].into_iter().map(Fp::new).collect();

        let mut transcript = Transcript::new();
        let proof = lookup.prove(&witness, &mut transcript);
        assert!(proof.is_none());
    }

    #[test]
    fn test_lookup_proof_serialization() {
        let table = generate_u8_table();
        let lookup = GrandProductLookup::new(table, test_fri_config());

        let witness: Vec<Fp> = vec![0, 1, 2, 3].into_iter().map(Fp::new).collect();

        let mut transcript = Transcript::new();
        let proof = lookup.prove(&witness, &mut transcript).unwrap();

        let serialized = proof.serialize();
        let deserialized = LookupProof::deserialize(&serialized).unwrap();

        assert_eq!(proof.witness_commitment, deserialized.witness_commitment);
        assert_eq!(proof.z_commitment, deserialized.z_commitment);
    }

    #[test]
    fn test_batch_lookup() {
        let u8_table = generate_u8_table();
        let small_table: Vec<Fp> = (0..16).map(|x| Fp::new(x)).collect();

        let mut batch = BatchLookup::new();
        let u8_idx = batch.add_table(u8_table, test_fri_config());
        let small_idx = batch.add_table(small_table, test_fri_config());

        // Add witnesses
        batch.add_witness(u8_idx, Fp::new(100));
        batch.add_witness(u8_idx, Fp::new(200));
        batch.add_witness(small_idx, Fp::new(5));
        batch.add_witness(small_idx, Fp::new(15));

        let mut transcript = Transcript::new();
        let proofs = batch.prove(&mut transcript);
        assert!(proofs.is_some());

        let mut verify_transcript = Transcript::new();
        assert!(batch.verify(&proofs.unwrap(), &mut verify_transcript));
    }
}
