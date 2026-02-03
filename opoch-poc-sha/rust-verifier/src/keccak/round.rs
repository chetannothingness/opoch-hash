//! Keccak Complete Round
//!
//! Combines θ, ρ, π, χ, ι steps into a single round.

use super::state::KeccakState;
use super::theta::{theta, ThetaTrace};
use super::rho_pi::{rho_pi, RhoPiTrace};
use super::chi::{chi, ChiTrace};
use super::iota::{iota, IotaTrace};
use super::{ROUNDS, STATE_BYTES};

/// Apply one Keccak round
pub fn keccak_round(state: &KeccakState, round: usize) -> KeccakState {
    let state = theta(state);
    let state = rho_pi(&state);
    let state = chi(&state);
    iota(&state, round)
}

/// Apply all 24 rounds (Keccak-f[1600] permutation)
pub fn keccak_f(state: &KeccakState) -> KeccakState {
    let mut state = state.clone();
    for round in 0..ROUNDS {
        state = keccak_round(&state, round);
    }
    state
}

/// Keccak round trace for AIR constraints
#[derive(Clone, Debug)]
pub struct KeccakRoundTrace {
    pub round: usize,
    pub state_in: KeccakState,
    pub theta_trace: ThetaTrace,
    pub rho_pi_trace: RhoPiTrace,
    pub chi_trace: ChiTrace,
    pub iota_trace: IotaTrace,
    pub state_out: KeccakState,
}

impl KeccakRoundTrace {
    /// Compute round with trace
    pub fn compute(state: &KeccakState, round: usize) -> Self {
        let theta_trace = ThetaTrace::compute(state);
        let rho_pi_trace = RhoPiTrace::compute(&theta_trace.state_out);
        let chi_trace = ChiTrace::compute(&rho_pi_trace.state_out);
        let iota_trace = IotaTrace::compute(&chi_trace.state_out, round);
        let state_out = iota_trace.state_out.clone();

        KeccakRoundTrace {
            round,
            state_in: state.clone(),
            theta_trace,
            rho_pi_trace,
            chi_trace,
            iota_trace,
            state_out,
        }
    }

    /// Verify all round constraints
    pub fn verify(&self) -> bool {
        self.theta_trace.verify()
            && self.rho_pi_trace.verify()
            && self.chi_trace.verify()
            && self.iota_trace.verify()
    }
}

/// Complete Keccak permutation trace
#[derive(Clone, Debug)]
pub struct KeccakPermutationTrace {
    pub state_in: KeccakState,
    pub round_traces: Vec<KeccakRoundTrace>,
    pub state_out: KeccakState,
}

impl KeccakPermutationTrace {
    /// Compute full permutation with trace
    pub fn compute(state: &KeccakState) -> Self {
        let mut round_traces = Vec::with_capacity(ROUNDS);
        let mut current_state = state.clone();

        for round in 0..ROUNDS {
            let trace = KeccakRoundTrace::compute(&current_state, round);
            current_state = trace.state_out.clone();
            round_traces.push(trace);
        }

        KeccakPermutationTrace {
            state_in: state.clone(),
            round_traces,
            state_out: current_state,
        }
    }

    /// Verify all constraints
    pub fn verify(&self) -> bool {
        // Verify each round
        for trace in &self.round_traces {
            if !trace.verify() {
                return false;
            }
        }

        // Verify round chaining
        let mut expected_state = self.state_in.clone();
        for (i, trace) in self.round_traces.iter().enumerate() {
            // Input should match expected
            for j in 0..STATE_BYTES {
                if trace.state_in.bytes[j] != expected_state.bytes[j] {
                    return false;
                }
            }

            // Update expected for next round
            expected_state = trace.state_out.clone();
        }

        // Final output should match
        for i in 0..STATE_BYTES {
            if self.state_out.bytes[i] != expected_state.bytes[i] {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keccak::STATE_BYTES;

    #[test]
    fn test_keccak_round() {
        let state = KeccakState::zero();
        let result = keccak_round(&state, 0);

        // Round 0 of zero state should have RC[0] = 1 in lane[0][0]
        assert_eq!(result.get_lane_u64(0, 0), 1);
    }

    #[test]
    fn test_keccak_f_deterministic() {
        let state = KeccakState::zero();
        let result1 = keccak_f(&state);
        let result2 = keccak_f(&state);

        for i in 0..STATE_BYTES {
            assert_eq!(result1.bytes[i], result2.bytes[i]);
        }
    }

    #[test]
    fn test_round_trace() {
        let mut state = KeccakState::zero();
        state.set_lane_u64(0, 0, 0xDEADBEEF);

        let trace = KeccakRoundTrace::compute(&state, 0);
        assert!(trace.verify());

        // Direct computation should match
        let direct = keccak_round(&state, 0);
        for i in 0..STATE_BYTES {
            assert_eq!(trace.state_out.bytes[i], direct.bytes[i]);
        }
    }

    #[test]
    fn test_permutation_trace() {
        let state = KeccakState::zero();
        let trace = KeccakPermutationTrace::compute(&state);

        assert_eq!(trace.round_traces.len(), ROUNDS);
        assert!(trace.verify());

        // Direct computation should match
        let direct = keccak_f(&state);
        for i in 0..STATE_BYTES {
            assert_eq!(trace.state_out.bytes[i], direct.bytes[i]);
        }
    }
}
