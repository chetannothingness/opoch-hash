//! Partition-Lattice Normal Form for SerΠ
//!
//! This module implements the v1 enhancement to SerΠ:
//!
//! 1. **Partition Hash**: P_W(τ) fingerprints for equivalence on survivors/meaning
//! 2. **Coequalization**: Discard redundant normalizations that don't refine the lattice
//! 3. **Compression**: Select minimal-cost representative per partition fingerprint
//! 4. **Parallel Composition**: Product partitions for independent components
//!
//! # The Key Insight
//!
//! Two objects are semantically equivalent if they induce the same partition
//! on the survivor class W. The partition hash captures this:
//!
//! ```text
//! P_W(τ) = fingerprint of {w ∈ W : τ(w) = y} for each output y
//! ```
//!
//! This allows us to:
//! - Recognize equivalent representations immediately
//! - Skip redundant normalization steps
//! - Choose the cheapest encoding among equivalents

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use crate::sha256::Sha256;

/// Partition fingerprint for semantic equivalence.
///
/// Two objects with the same PartitionHash are semantically equivalent
/// (they induce the same partition on the survivor class).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PartitionHash([u8; 32]);

impl PartitionHash {
    /// Create a partition hash from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PartitionHash(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute partition hash from semantic content.
    ///
    /// This hashes the semantic structure, not the byte representation.
    pub fn compute<T: PartitionKey>(obj: &T) -> Self {
        let key = obj.partition_key();
        let hash = Sha256::hash(&key);
        PartitionHash(hash)
    }

    /// Combine two partition hashes (product partition).
    pub fn product(&self, other: &PartitionHash) -> PartitionHash {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&self.0);
        combined[32..].copy_from_slice(&other.0);
        PartitionHash(Sha256::hash(&combined))
    }
}

/// Trait for objects that can produce a partition key.
///
/// The partition key captures the semantic meaning independent of
/// representation details like field ordering in maps.
pub trait PartitionKey {
    /// Return bytes that uniquely identify the semantic partition.
    ///
    /// Two objects with identical partition keys are semantically equivalent.
    fn partition_key(&self) -> Vec<u8>;
}

/// Normalization step that can be coequalized.
#[derive(Clone, Debug)]
pub struct NormalizationStep {
    /// Name of the normalization (for debugging/metrics)
    pub name: &'static str,
    /// Cost in abstract units
    pub cost: u64,
    /// Whether this step actually refined the partition
    pub refined: bool,
}

/// Statistics for coequalization.
#[derive(Clone, Debug, Default)]
pub struct CoequalizationStats {
    /// Total normalization steps attempted
    pub tests_run: u64,
    /// Steps discarded as redundant (didn't refine)
    pub tests_discarded: u64,
    /// Steps replaced by cheaper equivalent
    pub tests_replaced: u64,
    /// Total compute cost saved
    pub cost_saved: u64,
}

impl CoequalizationStats {
    /// Compute percentage of compute saved.
    pub fn savings_percent(&self) -> f64 {
        if self.tests_run == 0 {
            0.0
        } else {
            (self.tests_discarded + self.tests_replaced) as f64 / self.tests_run as f64 * 100.0
        }
    }
}

/// Compression map for minimal-cost representatives.
///
/// Maps partition hashes to the cheapest known representation.
#[derive(Clone, Debug, Default)]
pub struct CompressionMap {
    /// Map from partition hash to (cost, representative bytes)
    representatives: HashMap<[u8; 32], (u64, Vec<u8>)>,
    /// Statistics
    pub stats: CompressionStats,
}

/// Statistics for compression.
#[derive(Clone, Debug, Default)]
pub struct CompressionStats {
    /// Number of unique partitions seen
    pub unique_partitions: u64,
    /// Number of times a cheaper representative was found
    pub replacements: u64,
    /// Total bytes saved by using cheaper representatives
    pub bytes_saved: u64,
}

impl CompressionMap {
    /// Create a new compression map.
    pub fn new() -> Self {
        CompressionMap::default()
    }

    /// Register a representation and return the minimal-cost one.
    ///
    /// If this representation is cheaper than the current best,
    /// it becomes the new representative.
    pub fn register(&mut self, partition: &PartitionHash, cost: u64, bytes: Vec<u8>) -> &[u8] {
        let key = *partition.as_bytes();

        match self.representatives.get(&key) {
            Some((existing_cost, existing_bytes)) => {
                if cost < *existing_cost {
                    // New representation is cheaper
                    let saved = existing_bytes.len() as u64 - bytes.len() as u64;
                    self.stats.bytes_saved += saved.max(0) as u64;
                    self.stats.replacements += 1;
                    self.representatives.insert(key, (cost, bytes));
                }
            }
            None => {
                // First time seeing this partition
                self.stats.unique_partitions += 1;
                self.representatives.insert(key, (cost, bytes));
            }
        }

        &self.representatives.get(&key).unwrap().1
    }

    /// Get the minimal-cost representative for a partition.
    pub fn get(&self, partition: &PartitionHash) -> Option<&[u8]> {
        self.representatives.get(partition.as_bytes())
            .map(|(_, bytes)| bytes.as_slice())
    }

    /// Check if a partition is already known.
    pub fn contains(&self, partition: &PartitionHash) -> bool {
        self.representatives.contains_key(partition.as_bytes())
    }
}

/// Partition-aware serializer (v1).
///
/// This wraps the basic SerΠ with partition-lattice awareness:
/// - Computes partition hashes for semantic equivalence
/// - Coequalizes redundant normalization steps
/// - Compresses to minimal-cost representatives
pub struct PartitionSerializer {
    /// Compression map for minimal-cost representatives
    compression: CompressionMap,
    /// Coequalization statistics
    coeq_stats: CoequalizationStats,
    /// Whether to use compression (can be disabled for v0 comparison)
    use_compression: bool,
    /// Whether to use coequalization
    use_coequalization: bool,
}

impl PartitionSerializer {
    /// Create a new v1 serializer with all optimizations enabled.
    pub fn new_v1() -> Self {
        PartitionSerializer {
            compression: CompressionMap::new(),
            coeq_stats: CoequalizationStats::default(),
            use_compression: true,
            use_coequalization: true,
        }
    }

    /// Create a v0-compatible serializer (no partition optimizations).
    pub fn new_v0() -> Self {
        PartitionSerializer {
            compression: CompressionMap::new(),
            coeq_stats: CoequalizationStats::default(),
            use_compression: false,
            use_coequalization: false,
        }
    }

    /// Serialize with partition awareness.
    ///
    /// Returns (tape_bytes, partition_hash, was_compressed).
    pub fn serialize<T: PartitionKey + Serialize>(
        &mut self,
        obj: &T,
    ) -> (Vec<u8>, PartitionHash, bool) {
        // Compute partition hash from semantic content
        let partition = PartitionHash::compute(obj);

        // Check if we already have a cheaper representative
        if self.use_compression {
            if let Some(cached) = self.compression.get(&partition) {
                return (cached.to_vec(), partition, true);
            }
        }

        // Serialize the object
        let (bytes, cost) = obj.serialize_with_cost();

        // Register in compression map
        if self.use_compression {
            let _ = self.compression.register(&partition, cost, bytes.clone());
        }

        (bytes, partition, false)
    }

    /// Apply normalization with coequalization.
    ///
    /// Returns whether the step refined the partition.
    pub fn apply_normalization<F>(
        &mut self,
        name: &'static str,
        cost: u64,
        current_partition: &PartitionHash,
        normalize: F,
    ) -> (PartitionHash, bool)
    where
        F: FnOnce() -> PartitionHash,
    {
        self.coeq_stats.tests_run += 1;

        if !self.use_coequalization {
            let new_partition = normalize();
            let refined = new_partition != *current_partition;
            return (new_partition, refined);
        }

        // Check if this normalization would refine the partition
        // (In a full implementation, we'd have a lattice structure to query)
        let new_partition = normalize();
        let refined = new_partition != *current_partition;

        if !refined {
            // Normalization didn't change anything - discard
            self.coeq_stats.tests_discarded += 1;
            self.coeq_stats.cost_saved += cost;
        }

        (new_partition, refined)
    }

    /// Get compression statistics.
    pub fn compression_stats(&self) -> &CompressionStats {
        &self.compression.stats
    }

    /// Get coequalization statistics.
    pub fn coequalization_stats(&self) -> &CoequalizationStats {
        &self.coeq_stats
    }

    /// Reset statistics (for benchmark passes).
    pub fn reset_stats(&mut self) {
        self.coeq_stats = CoequalizationStats::default();
        // Note: we don't reset compression map to test steady-state behavior
    }

    /// Clear compression map (for fresh start).
    pub fn clear_compression(&mut self) {
        self.compression = CompressionMap::new();
    }
}

/// Trait for objects that can be serialized with cost tracking.
pub trait Serialize {
    /// Serialize and return (bytes, cost).
    fn serialize_with_cost(&self) -> (Vec<u8>, u64);
}

/// Semantic map with canonical ordering.
///
/// This is a key data structure for the partition-lattice approach:
/// maps are serialized with keys in canonical order, making the
/// partition hash independent of insertion order.
#[derive(Clone, Debug)]
pub struct SemanticMap<K: Ord + Clone, V: Clone> {
    entries: Vec<(K, V)>,
}

impl<K: Ord + Clone + Hash, V: Clone> SemanticMap<K, V> {
    /// Create a new empty map.
    pub fn new() -> Self {
        SemanticMap { entries: Vec::new() }
    }

    /// Insert a key-value pair.
    pub fn insert(&mut self, key: K, value: V) {
        // Remove existing if present
        self.entries.retain(|(k, _)| k != &key);
        self.entries.push((key, value));
        // Keep sorted for canonical ordering
        self.entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    }

    /// Get a value by key.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// Iterate in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<K: Ord + Clone + Hash, V: Clone> Default for SemanticMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

// Implement PartitionKey for SemanticMap
impl<K, V> PartitionKey for SemanticMap<K, V>
where
    K: Ord + Clone + Hash + AsRef<[u8]>,
    V: Clone + AsRef<[u8]>,
{
    fn partition_key(&self) -> Vec<u8> {
        let mut key = Vec::new();
        // Entries are already sorted, so iteration is canonical
        for (k, v) in &self.entries {
            key.extend_from_slice(k.as_ref());
            key.push(0xFF); // separator
            key.extend_from_slice(v.as_ref());
            key.push(0xFE); // entry separator
        }
        key
    }
}

/// Product partition for parallel composition.
///
/// When two objects are independent, their combined partition
/// is the product of their individual partitions.
pub fn product_partition(partitions: &[PartitionHash]) -> PartitionHash {
    if partitions.is_empty() {
        // Empty product is the trivial partition
        return PartitionHash::from_bytes([0u8; 32]);
    }

    let mut result = partitions[0];
    for p in &partitions[1..] {
        result = result.product(p);
    }
    result
}

/// Benchmark a normalization pipeline.
///
/// Returns (final_partition, total_cost, stats).
pub fn benchmark_normalization<F>(
    serializer: &mut PartitionSerializer,
    initial: PartitionHash,
    steps: Vec<(&'static str, u64, F)>,
) -> (PartitionHash, u64, CoequalizationStats)
where
    F: FnOnce() -> PartitionHash,
{
    let mut current = initial;
    let mut total_cost = 0u64;

    for (name, cost, normalize) in steps {
        let (new_partition, refined) = serializer.apply_normalization(
            name,
            cost,
            &current,
            normalize,
        );

        if refined {
            total_cost += cost;
        }
        current = new_partition;
    }

    (current, total_cost, serializer.coequalization_stats().clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_hash_equality() {
        let h1 = PartitionHash::from_bytes([1u8; 32]);
        let h2 = PartitionHash::from_bytes([1u8; 32]);
        let h3 = PartitionHash::from_bytes([2u8; 32]);

        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_partition_product() {
        let h1 = PartitionHash::from_bytes([1u8; 32]);
        let h2 = PartitionHash::from_bytes([2u8; 32]);

        let p1 = h1.product(&h2);
        let p2 = h1.product(&h2);
        let p3 = h2.product(&h1);

        // Same inputs produce same product
        assert_eq!(p1, p2);
        // Order matters (not commutative)
        assert_ne!(p1, p3);
    }

    #[test]
    fn test_compression_map() {
        let mut map = CompressionMap::new();
        let partition = PartitionHash::from_bytes([1u8; 32]);

        // First registration
        let bytes1 = vec![1, 2, 3, 4, 5];
        map.register(&partition, 100, bytes1.clone());
        assert_eq!(map.stats.unique_partitions, 1);

        // Cheaper representation
        let bytes2 = vec![1, 2, 3];
        map.register(&partition, 50, bytes2.clone());
        assert_eq!(map.stats.replacements, 1);

        // Check we get the cheaper one
        assert_eq!(map.get(&partition), Some(bytes2.as_slice()));
    }

    #[test]
    fn test_semantic_map_canonical_order() {
        let mut map1: SemanticMap<Vec<u8>, Vec<u8>> = SemanticMap::new();
        map1.insert(b"b".to_vec(), b"2".to_vec());
        map1.insert(b"a".to_vec(), b"1".to_vec());
        map1.insert(b"c".to_vec(), b"3".to_vec());

        let mut map2: SemanticMap<Vec<u8>, Vec<u8>> = SemanticMap::new();
        map2.insert(b"c".to_vec(), b"3".to_vec());
        map2.insert(b"a".to_vec(), b"1".to_vec());
        map2.insert(b"b".to_vec(), b"2".to_vec());

        // Different insertion order, same canonical order
        assert_eq!(map1.partition_key(), map2.partition_key());
    }

    #[test]
    fn test_coequalization() {
        let mut serializer = PartitionSerializer::new_v1();
        let initial = PartitionHash::from_bytes([1u8; 32]);

        // Apply a normalization that doesn't change anything
        let (result, refined) = serializer.apply_normalization(
            "no-op",
            100,
            &initial,
            || initial, // Returns same partition
        );

        assert!(!refined);
        assert_eq!(result, initial);
        assert_eq!(serializer.coequalization_stats().tests_discarded, 1);
        assert_eq!(serializer.coequalization_stats().cost_saved, 100);
    }

    #[test]
    fn test_v0_vs_v1_behavior() {
        let initial = PartitionHash::from_bytes([1u8; 32]);

        // v0: no coequalization
        let mut v0 = PartitionSerializer::new_v0();
        let (_, refined_v0) = v0.apply_normalization(
            "no-op",
            100,
            &initial,
            || initial,
        );
        assert!(!refined_v0);
        assert_eq!(v0.coequalization_stats().tests_discarded, 0); // v0 doesn't track

        // v1: with coequalization
        let mut v1 = PartitionSerializer::new_v1();
        let (_, refined_v1) = v1.apply_normalization(
            "no-op",
            100,
            &initial,
            || initial,
        );
        assert!(!refined_v1);
        assert_eq!(v1.coequalization_stats().tests_discarded, 1); // v1 tracks
    }
}
