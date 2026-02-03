//! Poseidon Round Functions
//!
//! Implements full and partial round transformations.

use crate::field::Fp;
use super::constants::{POSEIDON_T, POSEIDON_MDS, POSEIDON_RC, mds, rc};
use super::sbox::{sbox, SboxIntermediates};
use super::PoseidonState;

/// Apply MDS matrix multiplication
pub fn mds_multiply(state: &PoseidonState) -> PoseidonState {
    let mut result = [Fp::ZERO; POSEIDON_T];

    for i in 0..POSEIDON_T {
        let mut sum = Fp::ZERO;
        for j in 0..POSEIDON_T {
            sum = sum + mds(i, j) * state.elements[j];
        }
        result[i] = sum;
    }

    PoseidonState::from_elements(result)
}

/// Add round constants
pub fn add_round_constants(state: &PoseidonState, round: usize) -> PoseidonState {
    let mut result = state.elements;
    for i in 0..POSEIDON_T {
        result[i] = result[i] + rc(round, i);
    }
    PoseidonState::from_elements(result)
}

/// Apply S-box to all elements (full round)
fn sbox_full(state: &PoseidonState) -> PoseidonState {
    let mut result = [Fp::ZERO; POSEIDON_T];
    for i in 0..POSEIDON_T {
        result[i] = sbox(state.elements[i]);
    }
    PoseidonState::from_elements(result)
}

/// Apply S-box to first element only (partial round)
fn sbox_partial(state: &PoseidonState) -> PoseidonState {
    let mut result = state.elements;
    result[0] = sbox(result[0]);
    PoseidonState::from_elements(result)
}

/// Full round: AddConstants -> S-box(all) -> MDS
pub fn full_round(state: &PoseidonState, round: usize) -> PoseidonState {
    let state = add_round_constants(state, round);
    let state = sbox_full(&state);
    mds_multiply(&state)
}

/// Partial round: AddConstants -> S-box(first only) -> MDS
pub fn partial_round(state: &PoseidonState, round: usize) -> PoseidonState {
    let state = add_round_constants(state, round);
    let state = sbox_partial(&state);
    mds_multiply(&state)
}

/// Full round with intermediate values (for AIR constraints)
#[derive(Clone, Debug)]
pub struct FullRoundTrace {
    pub state_in: PoseidonState,
    pub after_constants: PoseidonState,
    pub sbox_intermediates: [SboxIntermediates; POSEIDON_T],
    pub state_out: PoseidonState,
}

impl FullRoundTrace {
    /// Compute full round with trace
    pub fn compute(state: &PoseidonState, round: usize) -> Self {
        let after_constants = add_round_constants(state, round);

        let mut sbox_intermediates = [SboxIntermediates {
            x2: Fp::ZERO,
            x3: Fp::ZERO,
            x6: Fp::ZERO,
            x7: Fp::ZERO,
        }; POSEIDON_T];

        let mut after_sbox = [Fp::ZERO; POSEIDON_T];
        for i in 0..POSEIDON_T {
            let inter = SboxIntermediates::compute(after_constants.elements[i]);
            after_sbox[i] = inter.x7;
            sbox_intermediates[i] = inter;
        }

        let after_sbox_state = PoseidonState::from_elements(after_sbox);
        let state_out = mds_multiply(&after_sbox_state);

        FullRoundTrace {
            state_in: state.clone(),
            after_constants,
            sbox_intermediates,
            state_out,
        }
    }

    /// Verify all constraints
    pub fn verify(&self, round: usize) -> bool {
        // Verify constants addition
        for i in 0..POSEIDON_T {
            if self.after_constants.elements[i] != self.state_in.elements[i] + rc(round, i) {
                return false;
            }
        }

        // Verify S-box intermediates
        for i in 0..POSEIDON_T {
            if !self.sbox_intermediates[i].verify(self.after_constants.elements[i]) {
                return false;
            }
        }

        // Verify MDS
        for i in 0..POSEIDON_T {
            let mut expected = Fp::ZERO;
            for j in 0..POSEIDON_T {
                expected = expected + mds(i, j) * self.sbox_intermediates[j].x7;
            }
            if self.state_out.elements[i] != expected {
                return false;
            }
        }

        true
    }
}

/// Partial round with intermediate values (for AIR constraints)
#[derive(Clone, Debug)]
pub struct PartialRoundTrace {
    pub state_in: PoseidonState,
    pub after_constants: PoseidonState,
    pub sbox_intermediate: SboxIntermediates, // Only for element 0
    pub state_out: PoseidonState,
}

impl PartialRoundTrace {
    /// Compute partial round with trace
    pub fn compute(state: &PoseidonState, round: usize) -> Self {
        let after_constants = add_round_constants(state, round);

        let sbox_intermediate = SboxIntermediates::compute(after_constants.elements[0]);

        // After S-box: first element is x7, rest are unchanged from after_constants
        let mut after_sbox = after_constants.elements;
        after_sbox[0] = sbox_intermediate.x7;
        let after_sbox_state = PoseidonState::from_elements(after_sbox);

        let state_out = mds_multiply(&after_sbox_state);

        PartialRoundTrace {
            state_in: state.clone(),
            after_constants,
            sbox_intermediate,
            state_out,
        }
    }

    /// Verify all constraints
    pub fn verify(&self, round: usize) -> bool {
        // Verify constants addition
        for i in 0..POSEIDON_T {
            if self.after_constants.elements[i] != self.state_in.elements[i] + rc(round, i) {
                return false;
            }
        }

        // Verify S-box on first element only
        if !self.sbox_intermediate.verify(self.after_constants.elements[0]) {
            return false;
        }

        // Verify MDS
        for i in 0..POSEIDON_T {
            let mut expected = mds(i, 0) * self.sbox_intermediate.x7;
            for j in 1..POSEIDON_T {
                expected = expected + mds(i, j) * self.after_constants.elements[j];
            }
            if self.state_out.elements[i] != expected {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mds_multiply() {
        // Test with known input
        let mut state = PoseidonState::zero();
        state.elements[0] = Fp::ONE;

        let result = mds_multiply(&state);

        // First column of MDS should be result
        for i in 0..POSEIDON_T {
            assert_eq!(result.elements[i], mds(i, 0));
        }
    }

    #[test]
    fn test_add_round_constants() {
        let state = PoseidonState::zero();
        let result = add_round_constants(&state, 0);

        for i in 0..POSEIDON_T {
            assert_eq!(result.elements[i], rc(0, i));
        }
    }

    #[test]
    fn test_full_round_trace() {
        let mut state = PoseidonState::zero();
        for i in 0..POSEIDON_T {
            state.elements[i] = Fp::new(i as u64 + 1);
        }

        let trace = FullRoundTrace::compute(&state, 0);
        assert!(trace.verify(0));

        // Output should match direct computation
        let expected = full_round(&state, 0);
        for i in 0..POSEIDON_T {
            assert_eq!(trace.state_out.elements[i], expected.elements[i]);
        }
    }

    #[test]
    fn test_partial_round_trace() {
        let mut state = PoseidonState::zero();
        for i in 0..POSEIDON_T {
            state.elements[i] = Fp::new(i as u64 + 1);
        }

        let trace = PartialRoundTrace::compute(&state, 4); // Use a partial round index
        assert!(trace.verify(4));

        // Output should match direct computation
        let expected = partial_round(&state, 4);
        for i in 0..POSEIDON_T {
            assert_eq!(trace.state_out.elements[i], expected.elements[i]);
        }
    }
}
