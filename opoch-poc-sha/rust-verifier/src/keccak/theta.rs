//! Keccak θ (Theta) Step
//!
//! XOR each lane with parity of columns.

use crate::field::Fp;
use super::state::KeccakState;
use super::LANE_BYTES;

/// Compute column parity C[x] = A[x,0] XOR A[x,1] XOR A[x,2] XOR A[x,3] XOR A[x,4]
fn compute_column_parity(state: &KeccakState) -> [[Fp; LANE_BYTES]; 5] {
    let mut c = [[Fp::ZERO; LANE_BYTES]; 5];

    for x in 0..5 {
        for byte_idx in 0..LANE_BYTES {
            let mut parity = 0u8;
            for y in 0..5 {
                parity ^= state.get_lane_byte(x, y, byte_idx).to_u64() as u8;
            }
            c[x][byte_idx] = Fp::new(parity as u64);
        }
    }

    c
}

/// Rotate a lane left by 1 bit (bytewise with carry)
fn rotate_lane_left_1(lane: &[Fp; LANE_BYTES]) -> [Fp; LANE_BYTES] {
    let mut result = [Fp::ZERO; LANE_BYTES];

    // Get the top bit of the last byte (will wrap to bottom of first byte)
    let top_bit = (lane[7].to_u64() >> 7) & 1;

    for i in 0..LANE_BYTES {
        let current = lane[i].to_u64() as u8;
        let next = if i + 1 < LANE_BYTES {
            lane[i + 1].to_u64() as u8
        } else {
            lane[0].to_u64() as u8
        };

        // Rotate: take bottom 7 bits shifted left, OR with top bit of previous byte
        let rotated = if i == 0 {
            ((current << 1) | top_bit as u8) as u64
        } else {
            (((current << 1) | (lane[i - 1].to_u64() as u8 >> 7)) & 0xFF) as u64
        };

        result[i] = Fp::new(rotated);
    }

    result
}

/// Compute D[x] = C[x-1] XOR ROT1(C[x+1])
fn compute_d(c: &[[Fp; LANE_BYTES]; 5]) -> [[Fp; LANE_BYTES]; 5] {
    let mut d = [[Fp::ZERO; LANE_BYTES]; 5];

    for x in 0..5 {
        let x_minus_1 = (x + 4) % 5;
        let x_plus_1 = (x + 1) % 5;

        let c_rotated = rotate_lane_left_1(&c[x_plus_1]);

        for byte_idx in 0..LANE_BYTES {
            let c_prev = c[x_minus_1][byte_idx].to_u64() as u8;
            let c_rot = c_rotated[byte_idx].to_u64() as u8;
            d[x][byte_idx] = Fp::new((c_prev ^ c_rot) as u64);
        }
    }

    d
}

/// Apply theta step: A'[x,y] = A[x,y] XOR D[x]
pub fn theta(state: &KeccakState) -> KeccakState {
    let c = compute_column_parity(state);
    let d = compute_d(&c);

    let mut result = KeccakState::zero();

    for x in 0..5 {
        for y in 0..5 {
            for byte_idx in 0..LANE_BYTES {
                let a = state.get_lane_byte(x, y, byte_idx).to_u64() as u8;
                let d_val = d[x][byte_idx].to_u64() as u8;
                result.set_lane_byte(x, y, byte_idx, Fp::new((a ^ d_val) as u64));
            }
        }
    }

    result
}

/// Theta step with intermediate values for AIR constraints
#[derive(Clone, Debug)]
pub struct ThetaTrace {
    pub state_in: KeccakState,
    pub c: [[Fp; LANE_BYTES]; 5],
    pub d: [[Fp; LANE_BYTES]; 5],
    pub state_out: KeccakState,
}

impl ThetaTrace {
    /// Compute theta with trace
    pub fn compute(state: &KeccakState) -> Self {
        let c = compute_column_parity(state);
        let d = compute_d(&c);

        let mut state_out = KeccakState::zero();
        for x in 0..5 {
            for y in 0..5 {
                for byte_idx in 0..LANE_BYTES {
                    let a = state.get_lane_byte(x, y, byte_idx).to_u64() as u8;
                    let d_val = d[x][byte_idx].to_u64() as u8;
                    state_out.set_lane_byte(x, y, byte_idx, Fp::new((a ^ d_val) as u64));
                }
            }
        }

        ThetaTrace {
            state_in: state.clone(),
            c,
            d,
            state_out,
        }
    }

    /// Verify theta constraints
    pub fn verify(&self) -> bool {
        // Verify C computation
        for x in 0..5 {
            for byte_idx in 0..LANE_BYTES {
                let mut expected = 0u8;
                for y in 0..5 {
                    expected ^= self.state_in.get_lane_byte(x, y, byte_idx).to_u64() as u8;
                }
                if self.c[x][byte_idx].to_u64() as u8 != expected {
                    return false;
                }
            }
        }

        // Verify D computation
        let computed_d = compute_d(&self.c);
        for x in 0..5 {
            for byte_idx in 0..LANE_BYTES {
                if self.d[x][byte_idx] != computed_d[x][byte_idx] {
                    return false;
                }
            }
        }

        // Verify output
        for x in 0..5 {
            for y in 0..5 {
                for byte_idx in 0..LANE_BYTES {
                    let a = self.state_in.get_lane_byte(x, y, byte_idx).to_u64() as u8;
                    let d_val = self.d[x][byte_idx].to_u64() as u8;
                    let expected = (a ^ d_val) as u64;
                    if self.state_out.get_lane_byte(x, y, byte_idx).to_u64() != expected {
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
    fn test_theta_zero_state() {
        let state = KeccakState::zero();
        let result = theta(&state);

        // Theta of zero state is zero
        for &b in &result.bytes {
            assert!(b.is_zero());
        }
    }

    #[test]
    fn test_theta_trace() {
        let mut state = KeccakState::zero();
        state.set_lane_u64(0, 0, 0x123456789ABCDEF0);
        state.set_lane_u64(1, 0, 0xFEDCBA9876543210);

        let trace = ThetaTrace::compute(&state);
        assert!(trace.verify());

        // Direct computation should match
        let direct = theta(&state);
        for i in 0..super::super::STATE_BYTES {
            assert_eq!(trace.state_out.bytes[i], direct.bytes[i]);
        }
    }

    #[test]
    fn test_rotate_lane_left_1() {
        let mut lane = [Fp::ZERO; LANE_BYTES];
        lane[0] = Fp::new(0x80); // 10000000

        let rotated = rotate_lane_left_1(&lane);

        // After rotation: 0x00 in byte 0, 0x01 in byte 1
        assert_eq!(rotated[0].to_u64(), 0x00);
        assert_eq!(rotated[1].to_u64(), 0x01);
    }
}
