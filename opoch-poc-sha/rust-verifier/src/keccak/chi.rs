//! Keccak χ (Chi) Step
//!
//! Non-linear mixing: A'[x,y] = A[x,y] XOR ((NOT A[x+1,y]) AND A[x+2,y])

use crate::field::Fp;
use super::state::KeccakState;
use super::LANE_BYTES;

/// Apply chi step
pub fn chi(state: &KeccakState) -> KeccakState {
    let mut result = KeccakState::zero();

    for y in 0..5 {
        for x in 0..5 {
            let x_plus_1 = (x + 1) % 5;
            let x_plus_2 = (x + 2) % 5;

            for byte_idx in 0..LANE_BYTES {
                let a_xy = state.get_lane_byte(x, y, byte_idx).to_u64() as u8;
                let a_x1y = state.get_lane_byte(x_plus_1, y, byte_idx).to_u64() as u8;
                let a_x2y = state.get_lane_byte(x_plus_2, y, byte_idx).to_u64() as u8;

                // A'[x,y] = A[x,y] XOR ((NOT A[x+1,y]) AND A[x+2,y])
                let not_a_x1y = !a_x1y;
                let and_result = not_a_x1y & a_x2y;
                let out = a_xy ^ and_result;

                result.set_lane_byte(x, y, byte_idx, Fp::new(out as u64));
            }
        }
    }

    result
}

/// Chi trace for AIR constraints
#[derive(Clone, Debug)]
pub struct ChiTrace {
    pub state_in: KeccakState,
    /// NOT A[x+1,y] for each position
    pub not_values: KeccakState,
    /// (NOT A[x+1,y]) AND A[x+2,y] for each position
    pub and_values: KeccakState,
    pub state_out: KeccakState,
}

impl ChiTrace {
    /// Compute chi with trace
    pub fn compute(state: &KeccakState) -> Self {
        let mut not_values = KeccakState::zero();
        let mut and_values = KeccakState::zero();
        let mut state_out = KeccakState::zero();

        for y in 0..5 {
            for x in 0..5 {
                let x_plus_1 = (x + 1) % 5;
                let x_plus_2 = (x + 2) % 5;

                for byte_idx in 0..LANE_BYTES {
                    let a_xy = state.get_lane_byte(x, y, byte_idx).to_u64() as u8;
                    let a_x1y = state.get_lane_byte(x_plus_1, y, byte_idx).to_u64() as u8;
                    let a_x2y = state.get_lane_byte(x_plus_2, y, byte_idx).to_u64() as u8;

                    let not_a_x1y = !a_x1y;
                    let and_result = not_a_x1y & a_x2y;
                    let out = a_xy ^ and_result;

                    not_values.set_lane_byte(x, y, byte_idx, Fp::new(not_a_x1y as u64));
                    and_values.set_lane_byte(x, y, byte_idx, Fp::new(and_result as u64));
                    state_out.set_lane_byte(x, y, byte_idx, Fp::new(out as u64));
                }
            }
        }

        ChiTrace {
            state_in: state.clone(),
            not_values,
            and_values,
            state_out,
        }
    }

    /// Verify chi constraints
    pub fn verify(&self) -> bool {
        for y in 0..5 {
            for x in 0..5 {
                let x_plus_1 = (x + 1) % 5;
                let x_plus_2 = (x + 2) % 5;

                for byte_idx in 0..LANE_BYTES {
                    let a_xy = self.state_in.get_lane_byte(x, y, byte_idx).to_u64() as u8;
                    let a_x1y = self.state_in.get_lane_byte(x_plus_1, y, byte_idx).to_u64() as u8;
                    let a_x2y = self.state_in.get_lane_byte(x_plus_2, y, byte_idx).to_u64() as u8;

                    // Verify NOT
                    let expected_not = (!a_x1y) as u64;
                    if self.not_values.get_lane_byte(x, y, byte_idx).to_u64() != expected_not {
                        return false;
                    }

                    // Verify AND
                    let expected_and = (((!a_x1y) & a_x2y) & 0xFF) as u64;
                    if self.and_values.get_lane_byte(x, y, byte_idx).to_u64() != expected_and {
                        return false;
                    }

                    // Verify XOR (output)
                    let expected_out = ((a_xy ^ ((!a_x1y) & a_x2y)) & 0xFF) as u64;
                    if self.state_out.get_lane_byte(x, y, byte_idx).to_u64() != expected_out {
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
    fn test_chi_zero_state() {
        let state = KeccakState::zero();
        let result = chi(&state);

        // Chi of zero: 0 XOR ((NOT 0) AND 0) = 0 XOR (FF AND 0) = 0
        for &b in &result.bytes {
            assert!(b.is_zero());
        }
    }

    #[test]
    fn test_chi_all_ones() {
        let mut state = KeccakState::zero();
        for b in &mut state.bytes {
            *b = Fp::new(0xFF);
        }

        let result = chi(&state);

        // Chi of all ones: FF XOR ((NOT FF) AND FF) = FF XOR (0 AND FF) = FF
        for &b in &result.bytes {
            assert_eq!(b.to_u64(), 0xFF);
        }
    }

    #[test]
    fn test_chi_trace() {
        let mut state = KeccakState::zero();
        state.set_lane_u64(0, 0, 0xDEADBEEF12345678);
        state.set_lane_u64(1, 0, 0xCAFEBABE87654321);
        state.set_lane_u64(2, 0, 0x1234567890ABCDEF);

        let trace = ChiTrace::compute(&state);
        assert!(trace.verify());

        // Direct computation should match
        let direct = chi(&state);
        for i in 0..super::super::STATE_BYTES {
            assert_eq!(trace.state_out.bytes[i], direct.bytes[i]);
        }
    }
}
