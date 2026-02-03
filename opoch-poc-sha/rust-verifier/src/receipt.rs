//! Receipt Chain for Benchmark Results
//!
//! Cryptographic chain linking all benchmark results together.

use serde::{Serialize, Deserialize};
use crate::sha256::Sha256;
use crate::serpi::{SerPi, CanonicalTape, TypeTag, SemanticObject, SerPiError, context};

/// Benchmark status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BenchmarkStatus {
    /// Benchmark passed all checks
    Pass,
    /// Benchmark failed
    Fail,
    /// Benchmark was skipped
    Skip,
    /// Benchmark is pending
    Pending,
}

impl BenchmarkStatus {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            BenchmarkStatus::Pass => "PASS",
            BenchmarkStatus::Fail => "FAIL",
            BenchmarkStatus::Skip => "SKIP",
            BenchmarkStatus::Pending => "PENDING",
        }
    }

    /// Create from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "PASS" => Some(BenchmarkStatus::Pass),
            "FAIL" => Some(BenchmarkStatus::Fail),
            "SKIP" => Some(BenchmarkStatus::Skip),
            "PENDING" => Some(BenchmarkStatus::Pending),
            _ => None,
        }
    }
}

/// Benchmark metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetrics {
    /// Execution time in microseconds
    pub time_us: Option<u64>,
    /// Proof size in bytes
    pub proof_size: Option<usize>,
    /// Verification time in microseconds
    pub verify_time_us: Option<u64>,
    /// Throughput (operations per second)
    pub throughput: Option<f64>,
    /// Custom metrics
    #[serde(default)]
    pub custom: std::collections::HashMap<String, serde_json::Value>,
}

impl Default for BenchmarkMetrics {
    fn default() -> Self {
        Self {
            time_us: None,
            proof_size: None,
            verify_time_us: None,
            throughput: None,
            custom: std::collections::HashMap::new(),
        }
    }
}

impl BenchmarkMetrics {
    /// Create empty metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Set execution time
    pub fn with_time(mut self, time_us: u64) -> Self {
        self.time_us = Some(time_us);
        self
    }

    /// Set verification time
    pub fn with_verify_time(mut self, time_us: u64) -> Self {
        self.verify_time_us = Some(time_us);
        self
    }

    /// Set proof size
    pub fn with_proof_size(mut self, size: usize) -> Self {
        self.proof_size = Some(size);
        self
    }

    /// Set throughput
    pub fn with_throughput(mut self, ops_per_sec: f64) -> Self {
        self.throughput = Some(ops_per_sec);
        self
    }

    /// Add custom metric
    pub fn with_custom(mut self, key: &str, value: serde_json::Value) -> Self {
        self.custom.insert(key.to_string(), value);
        self
    }
}

/// A single benchmark receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Benchmark identifier (A, B, C, etc.)
    pub benchmark_id: String,
    /// Benchmark name
    pub name: String,
    /// Status
    pub status: BenchmarkStatus,
    /// Timestamp (Unix seconds)
    pub timestamp: u64,
    /// Hash of the previous receipt
    pub previous_hash: [u8; 32],
    /// Hash of the benchmark results
    pub result_hash: [u8; 32],
    /// Metrics
    pub metrics: BenchmarkMetrics,
    /// Optional notes
    pub notes: Option<String>,
}

impl Receipt {
    /// Create a new receipt
    pub fn new(
        benchmark_id: &str,
        name: &str,
        status: BenchmarkStatus,
        previous_hash: [u8; 32],
        result_hash: [u8; 32],
    ) -> Self {
        Self {
            benchmark_id: benchmark_id.to_string(),
            name: name.to_string(),
            status,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            previous_hash,
            result_hash,
            metrics: BenchmarkMetrics::default(),
            notes: None,
        }
    }

    /// Compute the hash of this receipt
    pub fn hash(&self) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(self.benchmark_id.as_bytes());
        data.push(0);
        data.extend_from_slice(self.name.as_bytes());
        data.push(0);
        data.push(self.status as u8);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.previous_hash);
        data.extend_from_slice(&self.result_hash);
        Sha256::hash(&data)
    }

    /// Create a genesis receipt (first in chain)
    pub fn genesis(spec_hash: [u8; 32]) -> Self {
        Self {
            benchmark_id: "GENESIS".to_string(),
            name: "Genesis Receipt".to_string(),
            status: BenchmarkStatus::Pass,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            previous_hash: [0u8; 32],
            result_hash: spec_hash,
            metrics: BenchmarkMetrics::default(),
            notes: Some("Initial receipt binding to specification".to_string()),
        }
    }

    /// Set metrics
    pub fn with_metrics(mut self, metrics: BenchmarkMetrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// Set notes
    pub fn with_notes(mut self, notes: &str) -> Self {
        self.notes = Some(notes.to_string());
        self
    }
}

impl SemanticObject for Receipt {
    fn type_tag(&self) -> TypeTag {
        TypeTag::Receipt
    }

    fn serialize_payload(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    fn deserialize_payload(bytes: &[u8]) -> Result<Self, SerPiError> {
        serde_json::from_slice(bytes)
            .map_err(|e| SerPiError::Custom(e.to_string()))
    }
}

/// A chain of receipts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptChain {
    /// All receipts in order
    pub receipts: Vec<Receipt>,
    /// Specification ID (hash of spec.md)
    pub spec_id: [u8; 32],
    /// Protocol version
    pub version: String,
}

impl ReceiptChain {
    /// Create a new receipt chain
    pub fn new(spec_id: [u8; 32]) -> Self {
        let genesis = Receipt::genesis(spec_id);
        Self {
            receipts: vec![genesis],
            spec_id,
            version: crate::VERSION.to_string(),
        }
    }

    /// Add a receipt to the chain
    pub fn add(&mut self, mut receipt: Receipt) {
        // Set previous hash to hash of last receipt
        if let Some(last) = self.receipts.last() {
            receipt.previous_hash = last.hash();
        }
        self.receipts.push(receipt);
    }

    /// Create and add a receipt for a benchmark result
    pub fn add_benchmark(
        &mut self,
        benchmark_id: &str,
        name: &str,
        status: BenchmarkStatus,
        result_hash: [u8; 32],
        metrics: BenchmarkMetrics,
    ) {
        let previous_hash = self.receipts.last()
            .map(|r| r.hash())
            .unwrap_or([0u8; 32]);

        let receipt = Receipt::new(benchmark_id, name, status, previous_hash, result_hash)
            .with_metrics(metrics);

        self.receipts.push(receipt);
    }

    /// Verify the chain integrity
    pub fn verify(&self) -> bool {
        if self.receipts.is_empty() {
            return false;
        }

        // Genesis should have zero previous hash
        if self.receipts[0].previous_hash != [0u8; 32] {
            return false;
        }

        // Genesis should bind to spec_id
        if self.receipts[0].result_hash != self.spec_id {
            return false;
        }

        // Verify chain links
        for i in 1..self.receipts.len() {
            let expected_prev = self.receipts[i - 1].hash();
            if self.receipts[i].previous_hash != expected_prev {
                return false;
            }
        }

        true
    }

    /// Get the final hash (hash of last receipt)
    pub fn final_hash(&self) -> [u8; 32] {
        self.receipts.last()
            .map(|r| r.hash())
            .unwrap_or([0u8; 32])
    }

    /// Get all benchmark statuses
    pub fn summary(&self) -> Vec<(String, BenchmarkStatus)> {
        self.receipts
            .iter()
            .filter(|r| r.benchmark_id != "GENESIS")
            .map(|r| (r.benchmark_id.clone(), r.status))
            .collect()
    }

    /// Check if all benchmarks passed
    pub fn all_pass(&self) -> bool {
        self.receipts
            .iter()
            .filter(|r| r.benchmark_id != "GENESIS")
            .all(|r| r.status == BenchmarkStatus::Pass)
    }

    /// Count by status
    pub fn count_by_status(&self) -> (usize, usize, usize) {
        let mut pass = 0;
        let mut fail = 0;
        let mut skip = 0;

        for r in &self.receipts {
            if r.benchmark_id == "GENESIS" { continue; }
            match r.status {
                BenchmarkStatus::Pass => pass += 1,
                BenchmarkStatus::Fail => fail += 1,
                BenchmarkStatus::Skip => skip += 1,
                BenchmarkStatus::Pending => {},
            }
        }

        (pass, fail, skip)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl SemanticObject for ReceiptChain {
    fn type_tag(&self) -> TypeTag {
        TypeTag::ReceiptChain
    }

    fn serialize_payload(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    fn deserialize_payload(bytes: &[u8]) -> Result<Self, SerPiError> {
        serde_json::from_slice(bytes)
            .map_err(|e| SerPiError::Custom(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_creation() {
        let receipt = Receipt::new(
            "A",
            "SHA-256 Primitive",
            BenchmarkStatus::Pass,
            [0u8; 32],
            [1u8; 32],
        );

        assert_eq!(receipt.benchmark_id, "A");
        assert_eq!(receipt.status, BenchmarkStatus::Pass);
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let receipt = Receipt::new(
            "B",
            "Test",
            BenchmarkStatus::Pass,
            [0u8; 32],
            [1u8; 32],
        );

        let h1 = receipt.hash();
        let h2 = receipt.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_chain_creation() {
        let spec_id = Sha256::hash(b"test spec");
        let chain = ReceiptChain::new(spec_id);

        assert_eq!(chain.receipts.len(), 1);
        assert_eq!(chain.receipts[0].benchmark_id, "GENESIS");
        assert!(chain.verify());
    }

    #[test]
    fn test_chain_add() {
        let spec_id = Sha256::hash(b"test spec");
        let mut chain = ReceiptChain::new(spec_id);

        chain.add_benchmark(
            "A",
            "SHA-256",
            BenchmarkStatus::Pass,
            [1u8; 32],
            BenchmarkMetrics::new().with_time(1000),
        );

        assert_eq!(chain.receipts.len(), 2);
        assert!(chain.verify());
    }

    #[test]
    fn test_chain_integrity() {
        let spec_id = Sha256::hash(b"spec");
        let mut chain = ReceiptChain::new(spec_id);

        for i in 0..5 {
            chain.add_benchmark(
                &format!("{}", (b'A' + i) as char),
                "Test",
                BenchmarkStatus::Pass,
                [i + 1; 32],
                BenchmarkMetrics::default(),
            );
        }

        assert!(chain.verify());
        assert!(chain.all_pass());
        assert_eq!(chain.count_by_status(), (5, 0, 0));
    }

    #[test]
    fn test_chain_tampering_detected() {
        let spec_id = Sha256::hash(b"spec");
        let mut chain = ReceiptChain::new(spec_id);

        chain.add_benchmark("A", "Test", BenchmarkStatus::Pass, [1u8; 32], BenchmarkMetrics::default());
        chain.add_benchmark("B", "Test", BenchmarkStatus::Pass, [2u8; 32], BenchmarkMetrics::default());

        // Tamper with a receipt
        chain.receipts[1].result_hash = [99u8; 32];

        // Chain should no longer verify
        assert!(!chain.verify());
    }

    #[test]
    fn test_status_from_str() {
        assert_eq!(BenchmarkStatus::from_str("PASS"), Some(BenchmarkStatus::Pass));
        assert_eq!(BenchmarkStatus::from_str("pass"), Some(BenchmarkStatus::Pass));
        assert_eq!(BenchmarkStatus::from_str("FAIL"), Some(BenchmarkStatus::Fail));
        assert_eq!(BenchmarkStatus::from_str("INVALID"), None);
    }

    #[test]
    fn test_chain_json_roundtrip() {
        let spec_id = Sha256::hash(b"spec");
        let mut chain = ReceiptChain::new(spec_id);
        chain.add_benchmark("A", "Test", BenchmarkStatus::Pass, [1u8; 32], BenchmarkMetrics::default());

        let json = chain.to_json();
        let recovered = ReceiptChain::from_json(&json).unwrap();

        assert_eq!(recovered.receipts.len(), chain.receipts.len());
        assert!(recovered.verify());
    }
}
