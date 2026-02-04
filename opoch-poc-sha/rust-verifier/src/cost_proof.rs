//! Cost-Extended Proof Structures
//!
//! This module extends the proof system with verified cost information,
//! transforming proofs into universally settleable receipts.
//!
//! # Key Structures
//!
//! - `CostProofHeader`: Extended header with cost and meter information
//! - `CostSegmentProof`: Segment proof with cost bounds
//! - `CostAggregationProof`: Aggregation with cost summation
//! - `CostReceipt`: Tradable compute receipt

use crate::field::Fp;
use crate::sha256::Sha256;
use crate::meter::{MeterConfig, CostAccumulator, CostBreakdown, sha256_chain_cost, total_proof_cost};
use crate::feasibility::{FeasibilityConfig, SurvivorClass, is_feasible, feasibility_bound};

/// Extended proof header with verified cost.
#[derive(Clone, Debug)]
pub struct CostProofHeader {
    /// Protocol magic ("OPCH" for OPOCH with Cost)
    pub magic: [u8; 4],

    /// Version (2 = cost-extended version)
    pub version: u8,

    /// Chain length N
    pub n: u64,

    /// Segment length L
    pub l: u64,

    /// Initial hash d0 = SHA-256(x)
    pub d0: [u8; 32],

    /// Final hash y = SHA-256^N(d0)
    pub y: [u8; 32],

    /// Total verified cost in meter units
    pub total_cost: u64,

    /// Cost breakdown by category
    pub cost_breakdown: CostBreakdown,

    /// Meter configuration ID (hash of meter config)
    pub meter_id: [u8; 32],

    /// Feasibility configuration ID
    pub feasibility_id: [u8; 32],

    /// Parameters hash (includes cost parameters)
    pub params_hash: [u8; 32],
}

impl CostProofHeader {
    /// Create a new cost proof header.
    pub fn new(
        n: u64,
        l: u64,
        d0: [u8; 32],
        y: [u8; 32],
        total_cost: u64,
        cost_breakdown: CostBreakdown,
        meter: &MeterConfig,
        feasibility: &FeasibilityConfig,
    ) -> Self {
        let meter_id = meter.meter_id();
        let feasibility_id = compute_feasibility_id(feasibility);
        let params_hash = compute_cost_params_hash(n, l, total_cost, &meter_id);

        CostProofHeader {
            magic: *b"OPCH",
            version: 2,
            n,
            l,
            d0,
            y,
            total_cost,
            cost_breakdown,
            meter_id,
            feasibility_id,
            params_hash,
        }
    }

    /// Verify the header is well-formed.
    pub fn verify(&self) -> bool {
        // Check magic
        if &self.magic != b"OPCH" {
            return false;
        }

        // Check version
        if self.version != 2 {
            return false;
        }

        // Check params hash
        let expected_hash = compute_cost_params_hash(
            self.n,
            self.l,
            self.total_cost,
            &self.meter_id,
        );
        if self.params_hash != expected_hash {
            return false;
        }

        true
    }

    /// Serialize the header.
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(256);

        result.extend_from_slice(&self.magic);
        result.push(self.version);
        result.extend_from_slice(&self.n.to_le_bytes());
        result.extend_from_slice(&self.l.to_le_bytes());
        result.extend_from_slice(&self.d0);
        result.extend_from_slice(&self.y);
        result.extend_from_slice(&self.total_cost.to_le_bytes());

        // Cost breakdown
        result.extend_from_slice(&self.cost_breakdown.hash_ops.to_le_bytes());
        result.extend_from_slice(&self.cost_breakdown.field_ops.to_le_bytes());
        result.extend_from_slice(&self.cost_breakdown.memory_ops.to_le_bytes());
        result.extend_from_slice(&self.cost_breakdown.lookup_ops.to_le_bytes());
        result.extend_from_slice(&self.cost_breakdown.ec_ops.to_le_bytes());
        result.extend_from_slice(&self.cost_breakdown.recursion_ops.to_le_bytes());

        result.extend_from_slice(&self.meter_id);
        result.extend_from_slice(&self.feasibility_id);
        result.extend_from_slice(&self.params_hash);

        result
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 197 {  // Minimum size
            return None;
        }

        let mut offset = 0;

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[offset..offset + 4]);
        offset += 4;

        let version = data[offset];
        offset += 1;

        let n = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let l = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let mut d0 = [0u8; 32];
        d0.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut y = [0u8; 32];
        y.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let total_cost = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let cost_breakdown = CostBreakdown {
            hash_ops: u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?),
            field_ops: u64::from_le_bytes(data[offset + 8..offset + 16].try_into().ok()?),
            memory_ops: u64::from_le_bytes(data[offset + 16..offset + 24].try_into().ok()?),
            lookup_ops: u64::from_le_bytes(data[offset + 24..offset + 32].try_into().ok()?),
            ec_ops: u64::from_le_bytes(data[offset + 32..offset + 40].try_into().ok()?),
            recursion_ops: u64::from_le_bytes(data[offset + 40..offset + 48].try_into().ok()?),
        };
        offset += 48;

        let mut meter_id = [0u8; 32];
        meter_id.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut feasibility_id = [0u8; 32];
        feasibility_id.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut params_hash = [0u8; 32];
        params_hash.copy_from_slice(&data[offset..offset + 32]);

        Some(CostProofHeader {
            magic,
            version,
            n,
            l,
            d0,
            y,
            total_cost,
            cost_breakdown,
            meter_id,
            feasibility_id,
            params_hash,
        })
    }
}

/// Cost-extended segment proof.
#[derive(Clone, Debug)]
pub struct CostSegmentProof {
    /// Segment index
    pub segment_index: u32,

    /// Start hash of segment
    pub start_hash: [u8; 32],

    /// End hash of segment
    pub end_hash: [u8; 32],

    /// Cost at segment start
    pub start_cost: Fp,

    /// Cost at segment end
    pub end_cost: Fp,

    /// Segment cost (verified: end_cost - start_cost)
    pub segment_cost: Fp,

    /// Cost commitment (Merkle root of per-step costs)
    pub cost_commitment: [u8; 32],
}

impl CostSegmentProof {
    /// Verify cost consistency.
    pub fn verify_cost_consistency(&self) -> bool {
        // segment_cost should equal end_cost - start_cost
        self.segment_cost == self.end_cost - self.start_cost
    }
}

/// Cost-extended aggregation proof.
#[derive(Clone, Debug)]
pub struct CostAggregationProof {
    /// Aggregation level (1 or 2)
    pub level: u8,

    /// Number of children aggregated
    pub num_children: u32,

    /// Merkle root of children
    pub children_root: [u8; 32],

    /// Chain start hash
    pub chain_start: [u8; 32],

    /// Chain end hash
    pub chain_end: [u8; 32],

    /// Total cost of all children
    pub total_cost: Fp,

    /// Cost commitment (Merkle root of child costs)
    pub cost_commitment: [u8; 32],

    /// Individual child costs (for verification)
    pub child_costs: Vec<Fp>,
}

impl CostAggregationProof {
    /// Verify cost aggregation.
    pub fn verify_cost_aggregation(&self) -> bool {
        // Total cost should equal sum of child costs
        let sum: Fp = self.child_costs.iter().copied().fold(Fp::ZERO, |a, b| a + b);
        self.total_cost == sum
    }
}

/// A tradable compute receipt.
///
/// This is the minimal structure needed for settlement:
/// - What was computed (d0, y, n)
/// - How much it cost (total_cost)
/// - Under which rules (meter_id)
/// - Proof that it's all correct (proof_hash)
#[derive(Clone, Debug)]
pub struct CostReceipt {
    /// Initial input hash
    pub d0: [u8; 32],

    /// Final output hash
    pub y: [u8; 32],

    /// Number of computation steps
    pub n: u64,

    /// Verified total cost
    pub total_cost: u64,

    /// Meter configuration ID
    pub meter_id: [u8; 32],

    /// Hash of the full proof (for verification reference)
    pub proof_hash: [u8; 32],

    /// Timestamp of generation (Unix epoch seconds)
    pub timestamp: u64,
}

impl CostReceipt {
    /// Create a receipt from a cost proof header.
    pub fn from_header(header: &CostProofHeader, proof_bytes: &[u8]) -> Self {
        CostReceipt {
            d0: header.d0,
            y: header.y,
            n: header.n,
            total_cost: header.total_cost,
            meter_id: header.meter_id,
            proof_hash: Sha256::hash(proof_bytes),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Compute the receipt ID (unique identifier).
    pub fn receipt_id(&self) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&self.d0);
        data.extend_from_slice(&self.y);
        data.extend_from_slice(&self.n.to_le_bytes());
        data.extend_from_slice(&self.total_cost.to_le_bytes());
        data.extend_from_slice(&self.meter_id);
        data.extend_from_slice(&self.proof_hash);
        Sha256::hash(&data)
    }

    /// Serialize for storage/transmission.
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(152);
        result.extend_from_slice(&self.d0);
        result.extend_from_slice(&self.y);
        result.extend_from_slice(&self.n.to_le_bytes());
        result.extend_from_slice(&self.total_cost.to_le_bytes());
        result.extend_from_slice(&self.meter_id);
        result.extend_from_slice(&self.proof_hash);
        result.extend_from_slice(&self.timestamp.to_le_bytes());
        result
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 152 {
            return None;
        }

        let mut d0 = [0u8; 32];
        d0.copy_from_slice(&data[0..32]);

        let mut y = [0u8; 32];
        y.copy_from_slice(&data[32..64]);

        let n = u64::from_le_bytes(data[64..72].try_into().ok()?);
        let total_cost = u64::from_le_bytes(data[72..80].try_into().ok()?);

        let mut meter_id = [0u8; 32];
        meter_id.copy_from_slice(&data[80..112]);

        let mut proof_hash = [0u8; 32];
        proof_hash.copy_from_slice(&data[112..144]);

        let timestamp = u64::from_le_bytes(data[144..152].try_into().ok()?);

        Some(CostReceipt {
            d0,
            y,
            n,
            total_cost,
            meter_id,
            proof_hash,
            timestamp,
        })
    }

    /// Compute settlement amount.
    ///
    /// pay = α * total_cost + β
    ///
    /// where α is the price per meter unit and β is the base fee.
    pub fn compute_payment(&self, price_per_unit: f64, base_fee: f64) -> f64 {
        price_per_unit * (self.total_cost as f64) + base_fee
    }
}

/// Compute feasibility configuration ID.
pub fn compute_feasibility_id(config: &FeasibilityConfig) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(&config.version.to_le_bytes());
    data.extend_from_slice(&config.base_factor.to_le_bytes());
    data.extend_from_slice(&config.min_survivor_log.to_le_bytes());
    data.extend_from_slice(&config.max_step_cost.to_le_bytes());
    data.push(config.strict_mode as u8);
    Sha256::hash(&data)
}

/// Compute parameters hash including cost.
pub fn compute_cost_params_hash(n: u64, l: u64, total_cost: u64, meter_id: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(&n.to_le_bytes());
    data.extend_from_slice(&l.to_le_bytes());
    data.extend_from_slice(&total_cost.to_le_bytes());
    data.extend_from_slice(meter_id);
    Sha256::hash(&data)
}

/// Verify a cost claim against the meter.
///
/// This verifies that the claimed cost matches the expected cost
/// for computing an N-step SHA-256 chain.
pub fn verify_cost_claim(
    claimed_cost: u64,
    n: u64,
    _l: u64,
    meter: &MeterConfig,
) -> bool {
    // Verify against the pure chain computation cost
    let expected_cost = sha256_chain_cost(meter, n);
    claimed_cost == expected_cost
}

/// Verify cost composition law.
///
/// For composed receipts: cost(A+B) = cost(A) + cost(B)
pub fn verify_cost_composition(
    receipt_a: &CostReceipt,
    receipt_b: &CostReceipt,
    composed_cost: u64,
) -> bool {
    composed_cost == receipt_a.total_cost + receipt_b.total_cost
}

/// Aggregate multiple receipts into one.
pub fn aggregate_receipts(receipts: &[CostReceipt]) -> CostReceipt {
    assert!(!receipts.is_empty(), "Cannot aggregate empty receipts");

    let first = &receipts[0];
    let last = &receipts[receipts.len() - 1];

    // Sum all costs
    let total_cost: u64 = receipts.iter().map(|r| r.total_cost).sum();

    // Sum all n values
    let total_n: u64 = receipts.iter().map(|r| r.n).sum();

    // Compute combined proof hash
    let mut combined = Vec::new();
    for r in receipts {
        combined.extend_from_slice(&r.proof_hash);
    }
    let proof_hash = Sha256::hash(&combined);

    CostReceipt {
        d0: first.d0,
        y: last.y,
        n: total_n,
        total_cost,
        meter_id: first.meter_id,  // Assume same meter
        proof_hash,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cost_proof_header() {
        let meter = MeterConfig::canonical_v1();
        let feasibility = FeasibilityConfig::canonical_v1();
        let cost = sha256_chain_cost(&meter, 1000);

        let header = CostProofHeader::new(
            1000,
            64,
            [1u8; 32],
            [2u8; 32],
            cost,
            CostBreakdown {
                hash_ops: cost,
                ..Default::default()
            },
            &meter,
            &feasibility,
        );

        assert!(header.verify());

        // Serialize and deserialize
        let bytes = header.serialize();
        let restored = CostProofHeader::deserialize(&bytes).unwrap();

        assert_eq!(restored.n, header.n);
        assert_eq!(restored.total_cost, header.total_cost);
        assert_eq!(restored.meter_id, header.meter_id);
    }

    #[test]
    fn test_cost_receipt() {
        let meter = MeterConfig::canonical_v1();
        let cost = sha256_chain_cost(&meter, 1000);

        let receipt = CostReceipt {
            d0: [1u8; 32],
            y: [2u8; 32],
            n: 1000,
            total_cost: cost,
            meter_id: meter.meter_id(),
            proof_hash: [3u8; 32],
            timestamp: 1234567890,
        };

        // Test serialization
        let bytes = receipt.serialize();
        let restored = CostReceipt::deserialize(&bytes).unwrap();

        assert_eq!(restored.n, receipt.n);
        assert_eq!(restored.total_cost, receipt.total_cost);

        // Test payment computation
        let payment = receipt.compute_payment(0.001, 1.0);
        assert!(payment > 1.0);  // At least base fee
    }

    #[test]
    fn test_cost_composition() {
        let meter = MeterConfig::canonical_v1();

        let receipt_a = CostReceipt {
            d0: [1u8; 32],
            y: [2u8; 32],
            n: 500,
            total_cost: sha256_chain_cost(&meter, 500),
            meter_id: meter.meter_id(),
            proof_hash: [3u8; 32],
            timestamp: 0,
        };

        let receipt_b = CostReceipt {
            d0: [2u8; 32],
            y: [3u8; 32],
            n: 500,
            total_cost: sha256_chain_cost(&meter, 500),
            meter_id: meter.meter_id(),
            proof_hash: [4u8; 32],
            timestamp: 0,
        };

        // Composition law: cost(A) + cost(B) = cost(A+B)
        let composed_cost = receipt_a.total_cost + receipt_b.total_cost;
        let expected_cost = sha256_chain_cost(&meter, 1000);

        assert_eq!(composed_cost, expected_cost);
        assert!(verify_cost_composition(&receipt_a, &receipt_b, composed_cost));
    }

    #[test]
    fn test_aggregate_receipts() {
        let meter = MeterConfig::canonical_v1();

        let receipts: Vec<CostReceipt> = (0..5).map(|i| CostReceipt {
            d0: [i as u8; 32],
            y: [(i + 1) as u8; 32],
            n: 100,
            total_cost: sha256_chain_cost(&meter, 100),
            meter_id: meter.meter_id(),
            proof_hash: [i as u8; 32],
            timestamp: 0,
        }).collect();

        let aggregated = aggregate_receipts(&receipts);

        assert_eq!(aggregated.n, 500);  // 5 * 100
        assert_eq!(aggregated.total_cost, 5 * sha256_chain_cost(&meter, 100));
        assert_eq!(aggregated.d0, [0u8; 32]);  // First receipt's d0
        assert_eq!(aggregated.y, [5u8; 32]);   // Last receipt's y
    }

    #[test]
    fn test_verify_cost_claim() {
        let meter = MeterConfig::canonical_v1();

        // Correct claim for chain computation
        let expected = sha256_chain_cost(&meter, 1000);
        assert!(verify_cost_claim(expected, 1000, 64, &meter));

        // Wrong claim
        assert!(!verify_cost_claim(expected - 1, 1000, 64, &meter));
        assert!(!verify_cost_claim(expected + 1, 1000, 64, &meter));
    }

    #[test]
    fn test_receipt_id_uniqueness() {
        let meter = MeterConfig::canonical_v1();

        let receipt1 = CostReceipt {
            d0: [1u8; 32],
            y: [2u8; 32],
            n: 1000,
            total_cost: sha256_chain_cost(&meter, 1000),
            meter_id: meter.meter_id(),
            proof_hash: [3u8; 32],
            timestamp: 0,
        };

        let receipt2 = CostReceipt {
            d0: [1u8; 32],
            y: [2u8; 32],
            n: 1001,  // Different n
            total_cost: sha256_chain_cost(&meter, 1001),
            meter_id: meter.meter_id(),
            proof_hash: [3u8; 32],
            timestamp: 0,
        };

        // Receipt IDs should be different
        assert_ne!(receipt1.receipt_id(), receipt2.receipt_id());
    }
}
