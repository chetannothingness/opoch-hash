//! Proof data structures and serialization
//!
//! Defines the complete proof format for OPOCH-PoC-SHA.

use crate::fri::FriProof;

/// Magic bytes for proof identification
pub const PROOF_MAGIC: &[u8; 4] = b"OPSH";

/// Proof version
pub const PROOF_VERSION: u32 = 1;

/// Proof header (fixed 128 bytes)
#[derive(Clone, Debug)]
pub struct ProofHeader {
    /// Magic bytes "OPSH"
    pub magic: [u8; 4],
    /// Version number
    pub version: u32,
    /// Total chain length N
    pub n: u64,
    /// Segment length L
    pub l: u64,
    /// Initial hash d0
    pub d0: [u8; 32],
    /// Final hash y
    pub y: [u8; 32],
    /// Parameters hash
    pub params_hash: [u8; 32],
    /// Reserved bytes
    pub reserved: [u8; 8],
}

impl ProofHeader {
    pub fn new(n: u64, l: u64, d0: [u8; 32], y: [u8; 32], params_hash: [u8; 32]) -> Self {
        ProofHeader {
            magic: *PROOF_MAGIC,
            version: PROOF_VERSION,
            n,
            l,
            d0,
            y,
            params_hash,
            reserved: [0u8; 8],
        }
    }

    pub fn serialize(&self) -> [u8; 128] {
        let mut result = [0u8; 128];
        result[0..4].copy_from_slice(&self.magic);
        result[4..8].copy_from_slice(&self.version.to_be_bytes());
        result[8..16].copy_from_slice(&self.n.to_be_bytes());
        result[16..24].copy_from_slice(&self.l.to_be_bytes());
        result[24..56].copy_from_slice(&self.d0);
        result[56..88].copy_from_slice(&self.y);
        result[88..120].copy_from_slice(&self.params_hash);
        result[120..128].copy_from_slice(&self.reserved);
        result
    }

    pub fn deserialize(data: &[u8; 128]) -> Option<Self> {
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);
        if &magic != PROOF_MAGIC {
            return None;
        }

        let version = u32::from_be_bytes(data[4..8].try_into().ok()?);
        if version != PROOF_VERSION {
            return None;
        }

        let n = u64::from_be_bytes(data[8..16].try_into().ok()?);
        let l = u64::from_be_bytes(data[16..24].try_into().ok()?);

        let mut d0 = [0u8; 32];
        d0.copy_from_slice(&data[24..56]);

        let mut y = [0u8; 32];
        y.copy_from_slice(&data[56..88]);

        let mut params_hash = [0u8; 32];
        params_hash.copy_from_slice(&data[88..120]);

        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&data[120..128]);

        Some(ProofHeader {
            magic,
            version,
            n,
            l,
            d0,
            y,
            params_hash,
            reserved,
        })
    }
}

/// Segment proof - COMPLETE with all verification data
#[derive(Clone, Debug)]
pub struct SegmentProof {
    /// Segment index
    pub segment_index: u32,
    /// Starting hash for this segment
    pub start_hash: [u8; 32],
    /// Ending hash for this segment
    pub end_hash: [u8; 32],
    /// Merkle commitments to trace columns (32 columns)
    pub column_commitments: Vec<[u8; 32]>,
    /// Boundary constraint evaluations (should all be zero)
    pub boundary_values: Vec<crate::field::Fp>,
    /// FRI proof for segment constraints
    pub fri_proof: FriProof,
}

impl SegmentProof {
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.segment_index.to_be_bytes());
        result.extend_from_slice(&self.start_hash);
        result.extend_from_slice(&self.end_hash);

        // Column commitments
        result.extend_from_slice(&(self.column_commitments.len() as u32).to_be_bytes());
        for commitment in &self.column_commitments {
            result.extend_from_slice(commitment);
        }

        // Boundary values
        result.extend_from_slice(&(self.boundary_values.len() as u32).to_be_bytes());
        for val in &self.boundary_values {
            result.extend_from_slice(&val.to_bytes());
        }

        // FRI proof
        let fri_bytes = self.fri_proof.serialize();
        result.extend_from_slice(&(fri_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&fri_bytes);
        result
    }

    pub fn deserialize(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        if offset + 4 > data.len() { return None; }
        let segment_index = u32::from_be_bytes(data[offset..offset+4].try_into().ok()?);
        offset += 4;

        if offset + 32 > data.len() { return None; }
        let mut start_hash = [0u8; 32];
        start_hash.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        if offset + 32 > data.len() { return None; }
        let mut end_hash = [0u8; 32];
        end_hash.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        // Column commitments
        if offset + 4 > data.len() { return None; }
        let num_commitments = u32::from_be_bytes(data[offset..offset+4].try_into().ok()?) as usize;
        offset += 4;

        let mut column_commitments = Vec::with_capacity(num_commitments);
        for _ in 0..num_commitments {
            if offset + 32 > data.len() { return None; }
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&data[offset..offset+32]);
            column_commitments.push(commitment);
            offset += 32;
        }

        // Boundary values
        if offset + 4 > data.len() { return None; }
        let num_boundary = u32::from_be_bytes(data[offset..offset+4].try_into().ok()?) as usize;
        offset += 4;

        let mut boundary_values = Vec::with_capacity(num_boundary);
        for _ in 0..num_boundary {
            if offset + 8 > data.len() { return None; }
            let val = crate::field::Fp::from_bytes(&data[offset..offset+8]);
            boundary_values.push(val);
            offset += 8;
        }

        // FRI proof
        if offset + 4 > data.len() { return None; }
        let fri_len = u32::from_be_bytes(data[offset..offset+4].try_into().ok()?) as usize;
        offset += 4;

        if offset + fri_len > data.len() { return None; }
        let fri_proof = FriProof::deserialize(&data[offset..offset+fri_len])?;
        offset += fri_len;

        Some((SegmentProof {
            segment_index,
            start_hash,
            end_hash,
            column_commitments,
            boundary_values,
            fri_proof,
        }, offset))
    }
}

/// Aggregation proof (recursive) - COMPLETE with chain verification
#[derive(Clone, Debug)]
pub struct AggregationProof {
    /// Recursion level (1 or 2)
    pub level: u32,
    /// Number of child proofs aggregated
    pub num_children: u32,
    /// Merkle root of child proof commitments
    pub children_root: [u8; 32],
    /// Starting hash of the chain covered by this proof
    pub chain_start: [u8; 32],
    /// Ending hash of the chain covered by this proof
    pub chain_end: [u8; 32],
    /// FRI proof for aggregation circuit
    pub fri_proof: FriProof,
}

impl AggregationProof {
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.level.to_be_bytes());
        result.extend_from_slice(&self.num_children.to_be_bytes());
        result.extend_from_slice(&self.children_root);
        result.extend_from_slice(&self.chain_start);
        result.extend_from_slice(&self.chain_end);
        let fri_bytes = self.fri_proof.serialize();
        result.extend_from_slice(&(fri_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&fri_bytes);
        result
    }

    pub fn deserialize(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        if offset + 4 > data.len() { return None; }
        let level = u32::from_be_bytes(data[offset..offset+4].try_into().ok()?);
        offset += 4;

        if offset + 4 > data.len() { return None; }
        let num_children = u32::from_be_bytes(data[offset..offset+4].try_into().ok()?);
        offset += 4;

        if offset + 32 > data.len() { return None; }
        let mut children_root = [0u8; 32];
        children_root.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        if offset + 32 > data.len() { return None; }
        let mut chain_start = [0u8; 32];
        chain_start.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        if offset + 32 > data.len() { return None; }
        let mut chain_end = [0u8; 32];
        chain_end.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        if offset + 4 > data.len() { return None; }
        let fri_len = u32::from_be_bytes(data[offset..offset+4].try_into().ok()?) as usize;
        offset += 4;

        if offset + fri_len > data.len() { return None; }
        let fri_proof = FriProof::deserialize(&data[offset..offset+fri_len])?;
        offset += fri_len;

        Some((AggregationProof {
            level,
            num_children,
            children_root,
            chain_start,
            chain_end,
            fri_proof,
        }, offset))
    }
}

/// Complete OPOCH-PoC-SHA proof
#[derive(Clone, Debug)]
pub struct OpochProof {
    /// Proof header
    pub header: ProofHeader,
    /// Final aggregation proof (what verifier checks)
    pub final_proof: AggregationProof,
}

impl OpochProof {
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.header.serialize());
        result.extend_from_slice(&self.final_proof.serialize());
        result
    }

    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 128 {
            return None;
        }

        let mut header_bytes = [0u8; 128];
        header_bytes.copy_from_slice(&data[0..128]);
        let header = ProofHeader::deserialize(&header_bytes)?;

        let (final_proof, _) = AggregationProof::deserialize(&data[128..])?;

        Some(OpochProof { header, final_proof })
    }

    /// Get proof size in bytes
    pub fn size(&self) -> usize {
        self.serialize().len()
    }
}

/// Public parameters hash
pub fn compute_params_hash(n: u64, l: u64) -> [u8; 32] {
    use crate::sha256::Sha256;

    let mut hasher = Sha256::new();
    hasher.update(b"OPOCH-PoC-SHA-PARAMS-v1");
    hasher.update(&n.to_be_bytes());
    hasher.update(&l.to_be_bytes());
    // Add other pinned parameters
    hasher.update(&68u32.to_be_bytes()); // num_queries
    hasher.update(&8u32.to_be_bytes());  // blowup_factor
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = ProofHeader::new(
            1_000_000_000,
            1024,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );

        let serialized = header.serialize();
        let deserialized = ProofHeader::deserialize(&serialized).unwrap();

        assert_eq!(header.n, deserialized.n);
        assert_eq!(header.l, deserialized.l);
        assert_eq!(header.d0, deserialized.d0);
        assert_eq!(header.y, deserialized.y);
    }
}
