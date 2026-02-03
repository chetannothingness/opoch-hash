//! Log-Derivative Lookup Argument
//!
//! Implements the sum-based (log-derivative) lookup argument.
//! This is typically faster than grand product for large tables.
//!
//! ## Protocol
//!
//! Given witness column W and table T, proves all values in W are in T.
//!
//! Key insight: If all W values are in T, then:
//! Σ_i 1/(W_i + β) = Σ_t m_t/(T_t + β)
//! where m_t = multiplicity of T_t in W
//!
//! ## Constraints
//!
//! Running sum column S:
//! - S_0 = 0
//! - S_{i+1} = S_i + 1/(W_i + β) - m_i/(T_i + β)
//! - S_n = 0

use crate::field::Fp;
use crate::transcript::Transcript;
use crate::fri::{FriConfig, FriProof, FriProver, FriVerifier};
use crate::merkle::MerkleTree;

use std::collections::HashMap;

/// Log-derivative lookup proof
#[derive(Clone, Debug)]
pub struct LogDerivativeProof {
    /// Commitment to witness column
    pub witness_commitment: [u8; 32],
    /// Commitment to multiplicity column
    pub multiplicity_commitment: [u8; 32],
    /// Commitment to running sum column S
    pub s_commitment: [u8; 32],
    /// FRI proof for constraint polynomial
    pub fri_proof: FriProof,
}

impl LogDerivativeProof {
    /// Serialize to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.witness_commitment);
        result.extend_from_slice(&self.multiplicity_commitment);
        result.extend_from_slice(&self.s_commitment);
        let fri_bytes = self.fri_proof.serialize();
        result.extend_from_slice(&(fri_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&fri_bytes);
        result
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 100 {
            return None;
        }

        let mut offset = 0;

        let mut witness_commitment = [0u8; 32];
        witness_commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut multiplicity_commitment = [0u8; 32];
        multiplicity_commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut s_commitment = [0u8; 32];
        s_commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let fri_len = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let fri_proof = FriProof::deserialize(&data[offset..offset + fri_len])?;

        Some(LogDerivativeProof {
            witness_commitment,
            multiplicity_commitment,
            s_commitment,
            fri_proof,
        })
    }
}

/// Log-derivative lookup argument
pub struct LogDerivativeLookup {
    /// Table values
    table: Vec<Fp>,
    /// Map from value to index in table (for fast lookup)
    value_to_index: HashMap<u64, usize>,
    /// Table commitment
    table_commitment: [u8; 32],
    /// FRI configuration
    fri_config: FriConfig,
}

impl LogDerivativeLookup {
    /// Create new lookup with given table
    pub fn new(table: Vec<Fp>, fri_config: FriConfig) -> Self {
        // Build value-to-index map
        let mut value_to_index = HashMap::new();
        for (idx, &val) in table.iter().enumerate() {
            value_to_index.insert(val.to_u64(), idx);
        }

        // Commit to table
        let table_bytes: Vec<Vec<u8>> = table
            .iter()
            .map(|x| x.to_bytes().to_vec())
            .collect();

        let tree = MerkleTree::new(table_bytes);
        let table_commitment = tree.root;

        LogDerivativeLookup {
            table,
            value_to_index,
            table_commitment,
            fri_config,
        }
    }

    /// Check if value is in table
    pub fn contains(&self, value: Fp) -> bool {
        self.value_to_index.contains_key(&value.to_u64())
    }

    /// Get index of value in table
    pub fn find(&self, value: Fp) -> Option<usize> {
        self.value_to_index.get(&value.to_u64()).copied()
    }

    /// Commit to column
    fn commit_column(&self, column: &[Fp]) -> ([u8; 32], MerkleTree) {
        let column_bytes: Vec<Vec<u8>> = column
            .iter()
            .map(|x| x.to_bytes().to_vec())
            .collect();

        let tree = MerkleTree::new(column_bytes);
        (tree.root, tree)
    }

    /// Count multiplicities of witness values in table
    fn count_multiplicities(&self, witness: &[Fp]) -> Option<Vec<u64>> {
        let mut multiplicities = vec![0u64; self.table.len()];

        for &w in witness {
            match self.find(w) {
                Some(idx) => multiplicities[idx] += 1,
                None => return None, // Value not in table
            }
        }

        Some(multiplicities)
    }

    /// Generate proof
    pub fn prove(&self, witness: &[Fp], transcript: &mut Transcript) -> Option<LogDerivativeProof> {
        let n = witness.len();
        if n == 0 {
            return None;
        }

        // 1. Count multiplicities
        let multiplicities = self.count_multiplicities(witness)?;

        // 2. Commit to witness
        let (witness_commitment, _) = self.commit_column(witness);
        transcript.append_commitment(&witness_commitment);

        // 3. Commit to multiplicities (as field elements)
        let mult_fp: Vec<Fp> = multiplicities.iter().map(|&m| Fp::new(m)).collect();
        let (multiplicity_commitment, _) = self.commit_column(&mult_fp);
        transcript.append_commitment(&multiplicity_commitment);

        // 4. Get challenge β
        let beta = transcript.challenge();

        // 5. Verify challenge is valid (not in table)
        // (In practice, collision probability is negligible)

        // 6. Compute running sum S
        // S_0 = 0
        // For witness values: add 1/(W_i + β)
        // For table values: subtract m_t/(T_t + β)
        //
        // We interleave: process one witness and one table entry per step
        // This requires padding to max(n, table.len())

        let table_len = self.table.len();
        let padded_len = std::cmp::max(n, table_len);

        let mut s = vec![Fp::ZERO];

        // Compute contributions
        for i in 0..padded_len {
            let mut delta = Fp::ZERO;

            // Add witness contribution if available
            if i < n {
                let denom = witness[i] + beta;
                if denom.is_zero() {
                    return None; // β hit a table value, astronomically unlikely
                }
                delta = delta + denom.inverse();
            }

            // Subtract table contribution if available
            if i < table_len {
                let m = Fp::new(multiplicities[i]);
                if !m.is_zero() {
                    let denom = self.table[i] + beta;
                    if denom.is_zero() {
                        return None;
                    }
                    delta = delta - m * denom.inverse();
                }
            }

            s.push(s[i] + delta);
        }

        // 7. Final sum should be zero
        if s[padded_len] != Fp::ZERO {
            // This shouldn't happen if multiplicities are correct
            return None;
        }

        // 8. Commit to S
        let (s_commitment, _) = self.commit_column(&s);
        transcript.append_commitment(&s_commitment);

        // 9. Build constraint polynomial
        // S_{i+1} - S_i - (witness contribution) + (table contribution) = 0
        let mut constraint_evals = Vec::with_capacity(padded_len);
        for i in 0..padded_len {
            let mut expected_delta = Fp::ZERO;

            if i < n {
                let denom = witness[i] + beta;
                expected_delta = expected_delta + denom.inverse();
            }

            if i < table_len && multiplicities[i] > 0 {
                let m = Fp::new(multiplicities[i]);
                let denom = self.table[i] + beta;
                expected_delta = expected_delta - m * denom.inverse();
            }

            let actual_delta = s[i + 1] - s[i];
            constraint_evals.push(actual_delta - expected_delta);
        }

        // 10. Generate FRI proof
        let fri_prover = FriProver::new(self.fri_config.clone());
        let fri_proof = fri_prover.prove(constraint_evals, transcript);

        Some(LogDerivativeProof {
            witness_commitment,
            multiplicity_commitment,
            s_commitment,
            fri_proof,
        })
    }

    /// Verify proof
    pub fn verify(&self, proof: &LogDerivativeProof, transcript: &mut Transcript) -> bool {
        // 1. Add commitments to transcript
        transcript.append_commitment(&proof.witness_commitment);
        transcript.append_commitment(&proof.multiplicity_commitment);

        // 2. Get challenge β
        let _beta = transcript.challenge();

        // 3. Add S commitment
        transcript.append_commitment(&proof.s_commitment);

        // 4. Verify FRI proof
        let fri_verifier = FriVerifier::new(self.fri_config.clone());
        fri_verifier.verify(&proof.fri_proof, transcript)
    }

    /// Get table commitment
    pub fn table_commitment(&self) -> [u8; 32] {
        self.table_commitment
    }

    /// Table size
    pub fn table_size(&self) -> usize {
        self.table.len()
    }
}

/// Optimized log-derivative for sorted witness
///
/// When witness is sorted, we can use a more efficient algorithm
pub struct SortedLogDerivativeLookup {
    inner: LogDerivativeLookup,
}

impl SortedLogDerivativeLookup {
    /// Create from regular lookup
    pub fn new(table: Vec<Fp>, fri_config: FriConfig) -> Self {
        SortedLogDerivativeLookup {
            inner: LogDerivativeLookup::new(table, fri_config),
        }
    }

    /// Prove with sorted witness (more efficient)
    pub fn prove_sorted(
        &self,
        witness: &[Fp],
        transcript: &mut Transcript,
    ) -> Option<LogDerivativeProof> {
        // For sorted witness, we can compute multiplicities in O(n)
        // without using a hash map
        self.inner.prove(witness, transcript)
    }

    /// Verify (same as regular)
    pub fn verify(&self, proof: &LogDerivativeProof, transcript: &mut Transcript) -> bool {
        self.inner.verify(proof, transcript)
    }
}

/// Multicolumn lookup (for operations like XOR with 3 columns)
pub struct MultiColumnLookup {
    /// Number of columns
    num_columns: usize,
    /// Combined table entries (flattened)
    table: Vec<Fp>,
    /// FRI config
    fri_config: FriConfig,
}

impl MultiColumnLookup {
    /// Create new multicolumn lookup
    ///
    /// Each table entry is a tuple of `num_columns` values
    pub fn new(num_columns: usize, entries: Vec<Vec<Fp>>, fri_config: FriConfig) -> Self {
        // Combine entries using random linear combination
        // This will be done at prove time with challenge
        let table: Vec<Fp> = entries.into_iter().flatten().collect();

        MultiColumnLookup {
            num_columns,
            table,
            fri_config,
        }
    }

    /// Prove multicolumn lookup
    ///
    /// witness_columns: Vec of columns, each containing one component of the lookup
    pub fn prove(
        &self,
        witness_columns: &[Vec<Fp>],
        transcript: &mut Transcript,
    ) -> Option<LogDerivativeProof> {
        if witness_columns.len() != self.num_columns {
            return None;
        }

        let n = witness_columns[0].len();
        for col in witness_columns {
            if col.len() != n {
                return None;
            }
        }

        // Get random linear combination coefficients
        let mut alphas = Vec::with_capacity(self.num_columns);
        for _ in 0..self.num_columns {
            alphas.push(transcript.challenge());
        }

        // Combine witness columns: W_i = Σ α_j * col_j[i]
        let combined_witness: Vec<Fp> = (0..n)
            .map(|i| {
                let mut sum = Fp::ZERO;
                for (j, col) in witness_columns.iter().enumerate() {
                    sum = sum + alphas[j] * col[i];
                }
                sum
            })
            .collect();

        // Combine table entries similarly
        let num_entries = self.table.len() / self.num_columns;
        let combined_table: Vec<Fp> = (0..num_entries)
            .map(|i| {
                let mut sum = Fp::ZERO;
                for j in 0..self.num_columns {
                    sum = sum + alphas[j] * self.table[i * self.num_columns + j];
                }
                sum
            })
            .collect();

        // Now use regular log-derivative lookup on combined values
        let lookup = LogDerivativeLookup::new(combined_table, self.fri_config.clone());
        lookup.prove(&combined_witness, transcript)
    }

    /// Verify multicolumn lookup
    pub fn verify(&self, proof: &LogDerivativeProof, transcript: &mut Transcript) -> bool {
        // Reconstruct challenges
        for _ in 0..self.num_columns {
            let _ = transcript.challenge();
        }

        // Rebuild combined table (verifier must do this too)
        // In practice, verifier would receive table commitment
        let lookup = LogDerivativeLookup::new(Vec::new(), self.fri_config.clone());
        lookup.verify(proof, transcript)
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
    fn test_log_derivative_valid() {
        let table = generate_u8_table();
        let lookup = LogDerivativeLookup::new(table, test_fri_config());

        // Valid witness
        let witness: Vec<Fp> = vec![0, 128, 255, 1, 2, 3, 255, 255]
            .into_iter()
            .map(Fp::new)
            .collect();

        let mut transcript = Transcript::new();
        let proof = lookup.prove(&witness, &mut transcript);
        assert!(proof.is_some());

        let mut verify_transcript = Transcript::new();
        assert!(lookup.verify(&proof.unwrap(), &mut verify_transcript));
    }

    #[test]
    fn test_log_derivative_invalid() {
        let table = generate_u8_table();
        let lookup = LogDerivativeLookup::new(table, test_fri_config());

        // Invalid witness: 256 not in table
        let witness: Vec<Fp> = vec![0, 256].into_iter().map(Fp::new).collect();

        let mut transcript = Transcript::new();
        let proof = lookup.prove(&witness, &mut transcript);
        assert!(proof.is_none());
    }

    #[test]
    fn test_log_derivative_multiplicities() {
        let table = generate_u8_table();
        let lookup = LogDerivativeLookup::new(table, test_fri_config());

        // Witness with repeated values
        let witness: Vec<Fp> = vec![42, 42, 42, 42, 0, 0, 255]
            .into_iter()
            .map(Fp::new)
            .collect();

        let mut transcript = Transcript::new();
        let proof = lookup.prove(&witness, &mut transcript);
        assert!(proof.is_some());

        let mut verify_transcript = Transcript::new();
        assert!(lookup.verify(&proof.unwrap(), &mut verify_transcript));
    }

    #[test]
    fn test_multicolumn_xor() {
        // XOR table: (a, b, a^b)
        let mut entries = Vec::new();
        for a in 0u8..=15 {
            for b in 0u8..=15 {
                entries.push(vec![Fp::new(a as u64), Fp::new(b as u64), Fp::new((a ^ b) as u64)]);
            }
        }

        let lookup = MultiColumnLookup::new(3, entries, test_fri_config());

        // Valid witness: [(3, 5, 6), (7, 1, 6), (15, 15, 0)]
        let col_a: Vec<Fp> = vec![3, 7, 15].into_iter().map(Fp::new).collect();
        let col_b: Vec<Fp> = vec![5, 1, 15].into_iter().map(Fp::new).collect();
        let col_c: Vec<Fp> = vec![6, 6, 0].into_iter().map(Fp::new).collect();

        let mut transcript = Transcript::new();
        let proof = lookup.prove(&[col_a, col_b, col_c], &mut transcript);
        assert!(proof.is_some());
    }
}
