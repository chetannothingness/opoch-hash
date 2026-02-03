//! Keccak ρ (Rho) and π (Pi) Steps
//!
//! ρ: Rotate each lane by fixed offset
//! π: Permute lane positions

use crate::field::Fp;
use super::state::KeccakState;
use super::constants::{RHO_OFFSETS, pi_x, pi_y};
use super::LANE_BYTES;

/// Rotate a 64-bit lane left by `n` bits (bytewise)
fn rotate_lane_left(lane: &[Fp; LANE_BYTES], n: usize) -> [Fp; LANE_BYTES] {
    let n = n % 64;
    if n == 0 {
        return *lane;
    }

    // Convert to u64, rotate, convert back
    let mut value = 0u64;
    for (i, &b) in lane.iter().enumerate() {
        value |= (b.to_u64()) << (8 * i);
    }

    let rotated = value.rotate_left(n as u32);

    let mut result = [Fp::ZERO; LANE_BYTES];
    for i in 0..LANE_BYTES {
        result[i] = Fp::new((rotated >> (8 * i)) & 0xFF);
    }

    result
}

/// Apply rho step: rotate each lane by fixed offset
pub fn rho(state: &KeccakState) -> KeccakState {
    let mut result = KeccakState::zero();

    for x in 0..5 {
        for y in 0..5 {
            let lane = state.get_lane(x, y);
            let offset = RHO_OFFSETS[x][y];
            let rotated = rotate_lane_left(&lane, offset);
            result.set_lane(x, y, &rotated);
        }
    }

    result
}

/// Apply pi step: permute lane positions
/// (x, y) -> (y, 2*x + 3*y mod 5)
pub fn pi(state: &KeccakState) -> KeccakState {
    let mut result = KeccakState::zero();

    for x in 0..5 {
        for y in 0..5 {
            let new_x = pi_x(x, y);
            let new_y = pi_y(x, y);
            let lane = state.get_lane(x, y);
            result.set_lane(new_x, new_y, &lane);
        }
    }

    result
}

/// Combined rho and pi steps (more efficient)
pub fn rho_pi(state: &KeccakState) -> KeccakState {
    let mut result = KeccakState::zero();

    for x in 0..5 {
        for y in 0..5 {
            let lane = state.get_lane(x, y);
            let offset = RHO_OFFSETS[x][y];
            let rotated = rotate_lane_left(&lane, offset);

            let new_x = pi_x(x, y);
            let new_y = pi_y(x, y);
            result.set_lane(new_x, new_y, &rotated);
        }
    }

    result
}

/// Rho-Pi trace for AIR constraints
#[derive(Clone, Debug)]
pub struct RhoPiTrace {
    pub state_in: KeccakState,
    pub after_rho: KeccakState,
    pub state_out: KeccakState,
}

impl RhoPiTrace {
    /// Compute rho-pi with trace
    pub fn compute(state: &KeccakState) -> Self {
        let after_rho = rho(state);
        let state_out = pi(&after_rho);

        RhoPiTrace {
            state_in: state.clone(),
            after_rho,
            state_out,
        }
    }

    /// Verify rho-pi constraints
    pub fn verify(&self) -> bool {
        // Verify rho
        for x in 0..5 {
            for y in 0..5 {
                let lane = self.state_in.get_lane(x, y);
                let offset = RHO_OFFSETS[x][y];
                let expected = rotate_lane_left(&lane, offset);

                for byte_idx in 0..LANE_BYTES {
                    if self.after_rho.get_lane_byte(x, y, byte_idx) != expected[byte_idx] {
                        return false;
                    }
                }
            }
        }

        // Verify pi
        for x in 0..5 {
            for y in 0..5 {
                let new_x = pi_x(x, y);
                let new_y = pi_y(x, y);

                for byte_idx in 0..LANE_BYTES {
                    if self.state_out.get_lane_byte(new_x, new_y, byte_idx)
                        != self.after_rho.get_lane_byte(x, y, byte_idx)
                    {
                        return false;
                    }
                }
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotate_lane() {
        let mut lane = [Fp::ZERO; LANE_BYTES];
        lane[0] = Fp::new(1); // 0x0000000000000001

        // Rotate by 8 bits: 0x0000000000000100
        let rotated = rotate_lane_left(&lane, 8);
        assert_eq!(rotated[0].to_u64(), 0);
        assert_eq!(rotated[1].to_u64(), 1);

        // Rotate by 1 bit: 0x0000000000000002
        let rotated = rotate_lane_left(&lane, 1);
        assert_eq!(rotated[0].to_u64(), 2);
    }

    #[test]
    fn test_rho_zero_state() {
        let state = KeccakState::zero();
        let result = rho(&state);

        // Rho of zero is zero
        for &b in &result.bytes {
            assert!(b.is_zero());
        }
    }

    #[test]
    fn test_pi_permutation() {
        let mut state = KeccakState::zero();
        state.set_lane_u64(1, 0, 0xDEADBEEF);

        let result = pi(&state);

        // (1, 0) -> (0, 2)
        assert_eq!(result.get_lane_u64(0, 2), 0xDEADBEEF);
        assert_eq!(result.get_lane_u64(1, 0), 0);
    }

    #[test]
    fn test_rho_pi_trace() {
        let mut state = KeccakState::zero();
        state.set_lane_u64(0, 0, 0x123456789ABCDEF0);

        let trace = RhoPiTrace::compute(&state);
        assert!(trace.verify());

        // Combined should match
        let combined = rho_pi(&state);
        for i in 0..super::super::STATE_BYTES {
            assert_eq!(trace.state_out.bytes[i], combined.bytes[i]);
        }
    }
}
