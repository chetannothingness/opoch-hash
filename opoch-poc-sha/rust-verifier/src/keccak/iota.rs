//! Keccak ι (Iota) Step
//!
//! XOR round constant into lane[0][0]

use crate::field::Fp;
use super::state::KeccakState;
use super::constants::KECCAK_RC;
use super::LANE_BYTES;

/// Apply iota step: XOR round constant into lane[0][0]
pub fn iota(state: &KeccakState, round: usize) -> KeccakState {
    let mut result = state.clone();

    let rc = KECCAK_RC[round];
    let rc_bytes = rc.to_le_bytes();

    for byte_idx in 0..LANE_BYTES {
        let current = result.get_lane_byte(0, 0, byte_idx).to_u64() as u8;
        let xored = current ^ rc_bytes[byte_idx];
        result.set_lane_byte(0, 0, byte_idx, Fp::new(xored as u64));
    }

    result
}

/// Iota trace for AIR constraints
#[derive(Clone, Debug)]
pub struct IotaTrace {
    pub state_in: KeccakState,
    pub round: usize,
    pub state_out: KeccakState,
}

impl IotaTrace {
    /// Compute iota with trace
    pub fn compute(state: &KeccakState, round: usize) -> Self {
        let state_out = iota(state, round);

        IotaTrace {
            state_in: state.clone(),
            round,
            state_out,
        }
    }

    /// Verify iota constraints
    pub fn verify(&self) -> bool {
        let rc = KECCAK_RC[self.round];
        let rc_bytes = rc.to_le_bytes();

        // Verify lane[0][0] XOR'd with RC
        for byte_idx in 0..LANE_BYTES {
            let in_byte = self.state_in.get_lane_byte(0, 0, byte_idx).to_u64() as u8;
            let expected = (in_byte ^ rc_bytes[byte_idx]) as u64;
            if self.state_out.get_lane_byte(0, 0, byte_idx).to_u64() != expected {
                return false;
            }
        }

        // Verify all other lanes unchanged
        for x in 0..5 {
            for y in 0..5 {
                if x == 0 && y == 0 {
                    continue;
                }
                for byte_idx in 0..LANE_BYTES {
                    if self.state_out.get_lane_byte(x, y, byte_idx)
                        != self.state_in.get_lane_byte(x, y, byte_idx)
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
    fn test_iota_round_0() {
        let state = KeccakState::zero();
        let result = iota(&state, 0);

        // RC[0] = 1, so lane[0][0] should be 1
        assert_eq!(result.get_lane_u64(0, 0), 1);

        // Other lanes unchanged
        assert_eq!(result.get_lane_u64(1, 0), 0);
    }

    #[test]
    fn test_iota_trace() {
        let mut state = KeccakState::zero();
        state.set_lane_u64(0, 0, 0xDEADBEEF);

        let trace = IotaTrace::compute(&state, 5);
        assert!(trace.verify());

        // Direct computation should match
        let direct = iota(&state, 5);
        for i in 0..super::super::STATE_BYTES {
            assert_eq!(trace.state_out.bytes[i], direct.bytes[i]);
        }
    }

    #[test]
    fn test_all_rounds() {
        let state = KeccakState::zero();

        for round in 0..24 {
            let trace = IotaTrace::compute(&state, round);
            assert!(trace.verify(), "Failed for round {}", round);
        }
    }
}
