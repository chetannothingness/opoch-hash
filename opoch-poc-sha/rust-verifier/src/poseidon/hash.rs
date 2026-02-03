//! Poseidon Hash Function
//!
//! Complete hash function using sponge construction.

use crate::field::Fp;
use super::constants::{POSEIDON_T, POSEIDON_C, POSEIDON_R, POSEIDON_RF, POSEIDON_RP};
use super::round::{full_round, partial_round};
use super::PoseidonState;

/// Poseidon permutation
///
/// Applies all rounds: 4 full, 22 partial, 4 full
pub fn poseidon_permutation(state: &PoseidonState) -> PoseidonState {
    let mut state = state.clone();

    // First 4 full rounds
    for r in 0..POSEIDON_RF / 2 {
        state = full_round(&state, r);
    }

    // 22 partial rounds
    for r in 0..POSEIDON_RP {
        state = partial_round(&state, POSEIDON_RF / 2 + r);
    }

    // Last 4 full rounds
    for r in 0..POSEIDON_RF / 2 {
        state = full_round(&state, POSEIDON_RF / 2 + POSEIDON_RP + r);
    }

    state
}

/// Hash a slice of field elements
///
/// Uses sponge construction:
/// 1. Initialize state to zero
/// 2. Absorb input (rate elements at a time)
/// 3. Squeeze output
pub fn poseidon_hash(input: &[Fp]) -> Vec<Fp> {
    let mut state = PoseidonState::zero();

    // Absorb phase: XOR input into rate portion, then permute
    let mut i = 0;
    while i < input.len() {
        // XOR up to POSEIDON_R elements into state
        for j in 0..POSEIDON_R {
            if i + j < input.len() {
                state.elements[j] = state.elements[j] + input[i + j];
            }
        }

        // Apply permutation
        state = poseidon_permutation(&state);

        i += POSEIDON_R;
    }

    // Squeeze phase: return first POSEIDON_R elements
    state.elements[0..POSEIDON_R].to_vec()
}

/// Hash multiple inputs to single output
pub fn poseidon_hash_many(inputs: &[&[Fp]]) -> Vec<Fp> {
    let flattened: Vec<Fp> = inputs.iter().flat_map(|x| x.iter().copied()).collect();
    poseidon_hash(&flattened)
}

/// Hash to single field element
pub fn poseidon_hash_single(input: &[Fp]) -> Fp {
    poseidon_hash(input)[0]
}

/// Hash two field elements (common operation for Merkle trees)
pub fn poseidon_hash_pair(a: Fp, b: Fp) -> Fp {
    poseidon_hash(&[a, b])[0]
}

/// Hash bytes (convert to field elements first)
pub fn poseidon_hash_bytes(input: &[u8]) -> Vec<Fp> {
    // Pack bytes into field elements (7 bytes per element for safety margin)
    const BYTES_PER_FP: usize = 7;

    let mut field_elements = Vec::new();
    let mut i = 0;

    while i < input.len() {
        let mut value = 0u64;
        for j in 0..BYTES_PER_FP {
            if i + j < input.len() {
                value |= (input[i + j] as u64) << (8 * j);
            }
        }
        field_elements.push(Fp::new(value));
        i += BYTES_PER_FP;
    }

    // Add length as final element for domain separation
    field_elements.push(Fp::new(input.len() as u64));

    poseidon_hash(&field_elements)
}

/// Poseidon hasher with incremental API
pub struct PoseidonHasher {
    state: PoseidonState,
    buffer: Vec<Fp>,
}

impl PoseidonHasher {
    /// Create new hasher
    pub fn new() -> Self {
        PoseidonHasher {
            state: PoseidonState::zero(),
            buffer: Vec::with_capacity(POSEIDON_R),
        }
    }

    /// Update with more input
    pub fn update(&mut self, input: &[Fp]) {
        self.buffer.extend_from_slice(input);

        // Process full blocks
        while self.buffer.len() >= POSEIDON_R {
            for j in 0..POSEIDON_R {
                self.state.elements[j] = self.state.elements[j] + self.buffer[j];
            }
            self.state = poseidon_permutation(&self.state);
            self.buffer = self.buffer[POSEIDON_R..].to_vec();
        }
    }

    /// Finalize and get hash
    pub fn finalize(mut self) -> Vec<Fp> {
        // Absorb remaining buffer
        for (j, &val) in self.buffer.iter().enumerate() {
            self.state.elements[j] = self.state.elements[j] + val;
        }
        self.state = poseidon_permutation(&self.state);

        self.state.elements[0..POSEIDON_R].to_vec()
    }

    /// Finalize to single element
    pub fn finalize_single(self) -> Fp {
        self.finalize()[0]
    }
}

impl Default for PoseidonHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_permutation_deterministic() {
        let state = PoseidonState::zero();
        let result1 = poseidon_permutation(&state);
        let result2 = poseidon_permutation(&state);

        for i in 0..POSEIDON_T {
            assert_eq!(result1.elements[i], result2.elements[i]);
        }
    }

    #[test]
    fn test_poseidon_hash_deterministic() {
        let input = [Fp::new(1), Fp::new(2), Fp::new(3)];
        let result1 = poseidon_hash(&input);
        let result2 = poseidon_hash(&input);

        for i in 0..result1.len() {
            assert_eq!(result1[i], result2[i]);
        }
    }

    #[test]
    fn test_poseidon_different_inputs() {
        let input1 = [Fp::new(1), Fp::new(2)];
        let input2 = [Fp::new(1), Fp::new(3)];

        let result1 = poseidon_hash(&input1);
        let result2 = poseidon_hash(&input2);

        // Should be different
        assert_ne!(result1[0], result2[0]);
    }

    #[test]
    fn test_poseidon_hash_pair() {
        let a = Fp::new(123);
        let b = Fp::new(456);

        let hash1 = poseidon_hash_pair(a, b);
        let hash2 = poseidon_hash(&[a, b])[0];

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_hash_bytes() {
        let input = b"Hello, Poseidon!";
        let result1 = poseidon_hash_bytes(input);
        let result2 = poseidon_hash_bytes(input);

        assert_eq!(result1[0], result2[0]);
    }

    #[test]
    fn test_poseidon_hasher_incremental() {
        let input = [Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4)];

        // One-shot
        let direct = poseidon_hash(&input);

        // Incremental
        let mut hasher = PoseidonHasher::new();
        hasher.update(&[Fp::new(1), Fp::new(2)]);
        hasher.update(&[Fp::new(3), Fp::new(4)]);
        let incremental = hasher.finalize();

        assert_eq!(direct[0], incremental[0]);
    }

    #[test]
    fn test_poseidon_empty_input() {
        let result = poseidon_hash(&[]);
        assert_eq!(result.len(), POSEIDON_R);
    }

    #[test]
    fn test_poseidon_large_input() {
        // Input larger than rate
        let input: Vec<Fp> = (0..100).map(|i| Fp::new(i)).collect();
        let result = poseidon_hash(&input);
        assert_eq!(result.len(), POSEIDON_R);
    }
}
