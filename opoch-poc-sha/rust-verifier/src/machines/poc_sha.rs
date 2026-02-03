//! PoC SHA Chain Machine (M_POC_SHA_CHAIN)
//!
//! Proves computation of: h_N = SHA256^N(h_0)

use super::{Machine, MachineId};
use crate::sha256::{Sha256, sha256_32, hash_chain};

/// SHA-256 hash chain machine
pub struct PocShaMachine {
    /// Initial hash (d0)
    pub d0: [u8; 32],
    /// Number of steps
    pub n: u64,
}

impl PocShaMachine {
    /// Create a new PoC SHA machine
    pub fn new(input: &[u8], n: u64) -> Self {
        let d0 = Sha256::hash(input);
        Self { d0, n }
    }

    /// Create from existing d0
    pub fn from_d0(d0: [u8; 32], n: u64) -> Self {
        Self { d0, n }
    }

    /// Compute the final hash y = h_N
    pub fn compute(&self) -> [u8; 32] {
        hash_chain(&self.d0, self.n)
    }

    /// Compute a partial chain
    pub fn compute_partial(&self, steps: u64) -> [u8; 32] {
        hash_chain(&self.d0, steps.min(self.n))
    }

    /// Get intermediate state at step i
    pub fn state_at(&self, step: u64) -> [u8; 32] {
        if step == 0 {
            self.d0
        } else {
            hash_chain(&self.d0, step.min(self.n))
        }
    }

    /// Verify a claimed computation
    pub fn verify(d0: &[u8; 32], n: u64, claimed_y: &[u8; 32]) -> bool {
        let computed = hash_chain(d0, n);
        computed == *claimed_y
    }
}

impl Machine for PocShaMachine {
    fn machine_id(&self) -> MachineId {
        MachineId::PocShaChain
    }

    fn input_type(&self) -> &'static str {
        "(d0: [u8; 32], n: u64)"
    }

    fn output_type(&self) -> &'static str {
        "y: [u8; 32]"
    }

    fn estimated_cycles(&self) -> u64 {
        // ~1000 cycles per SHA-256 on modern CPUs
        self.n * 1000
    }
}

/// Configuration for PoC proofs
#[derive(Debug, Clone)]
pub struct PocConfig {
    /// Segment length (L)
    pub segment_length: u64,
    /// Total chain length (N)
    pub chain_length: u64,
    /// Number of FRI queries
    pub fri_queries: usize,
    /// FRI blowup factor
    pub fri_blowup: usize,
}

impl Default for PocConfig {
    fn default() -> Self {
        Self {
            segment_length: 1024,
            chain_length: 1_000_000_000,
            fri_queries: 68,
            fri_blowup: 8,
        }
    }
}

impl PocConfig {
    /// Number of segments
    pub fn num_segments(&self) -> u64 {
        (self.chain_length + self.segment_length - 1) / self.segment_length
    }

    /// For N = 10^6 (testing)
    pub fn test_million() -> Self {
        Self {
            segment_length: 1024,
            chain_length: 1_000_000,
            fri_queries: 32,
            fri_blowup: 4,
        }
    }

    /// For N = 10^9 (production)
    pub fn production_billion() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poc_sha_machine() {
        let machine = PocShaMachine::new(b"test", 100);
        let y = machine.compute();
        assert_ne!(y, machine.d0);
    }

    #[test]
    fn test_poc_sha_verify() {
        let machine = PocShaMachine::new(b"input", 50);
        let y = machine.compute();
        assert!(PocShaMachine::verify(&machine.d0, 50, &y));
        assert!(!PocShaMachine::verify(&machine.d0, 51, &y));
    }

    #[test]
    fn test_state_at() {
        let machine = PocShaMachine::new(b"test", 10);
        let s0 = machine.state_at(0);
        assert_eq!(s0, machine.d0);

        let s5 = machine.state_at(5);
        let s10 = machine.state_at(10);
        assert_ne!(s5, s10);

        // state_at(10) should equal final result
        assert_eq!(s10, machine.compute());
    }

    #[test]
    fn test_poc_config() {
        let config = PocConfig::default();
        assert_eq!(config.chain_length, 1_000_000_000);
        assert_eq!(config.num_segments(), 976563); // ceil(10^9 / 1024)
    }
}
