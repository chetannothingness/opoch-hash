//! Merkle Tree Implementation for STARK Commitments
//!
//! Uses SHA-256 with domain separation as specified.

use crate::sha256::Sha256;

/// Domain separation tags
const TAG_LEAF: u8 = 0x00;
const TAG_NODE: u8 = 0x01;
const TAG_ROOT: u8 = 0x02;

/// Compute leaf hash: SHA-256(0x00 || index_le64 || data)
pub fn leaf_hash(index: u64, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[TAG_LEAF]);
    hasher.update(&index.to_le_bytes());
    hasher.update(data);
    hasher.finalize()
}

/// Compute node hash: SHA-256(0x01 || left || right)
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[TAG_NODE]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

/// Compute root hash: SHA-256(0x02 || h)
pub fn root_hash(h: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[TAG_ROOT]);
    hasher.update(h);
    hasher.finalize()
}

/// Merkle tree for commitments
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    layers: Vec<Vec<[u8; 32]>>,
    pub root: [u8; 32],
}

impl MerkleTree {
    /// Build Merkle tree from leaf data
    pub fn new(leaf_data: Vec<Vec<u8>>) -> Self {
        assert!(!leaf_data.is_empty(), "Cannot build empty tree");

        // Hash leaves with indices
        let leaves: Vec<[u8; 32]> = leaf_data
            .iter()
            .enumerate()
            .map(|(i, data)| leaf_hash(i as u64, data))
            .collect();

        // Pad to power of 2
        let n = leaves.len().next_power_of_two();
        let mut padded_leaves = leaves.clone();
        while padded_leaves.len() < n {
            padded_leaves.push([0u8; 32]);
        }

        // Build layers
        let mut layers = vec![padded_leaves.clone()];
        let mut current = padded_leaves;

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len() / 2);
            for i in (0..current.len()).step_by(2) {
                let left = &current[i];
                let right = if i + 1 < current.len() {
                    &current[i + 1]
                } else {
                    left
                };
                next.push(node_hash(left, right));
            }
            layers.push(next.clone());
            current = next;
        }

        let root = root_hash(&current[0]);

        MerkleTree { leaves, layers, root }
    }

    /// Get authentication path for leaf at index
    pub fn get_path(&self, index: usize) -> MerklePath {
        let mut siblings = Vec::new();
        let mut current_index = index;

        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling = if sibling_index < layer.len() {
                layer[sibling_index]
            } else {
                layer[current_index]
            };

            let is_right = current_index % 2 == 0;
            siblings.push((sibling, is_right));
            current_index /= 2;
        }

        MerklePath {
            index,
            siblings,
        }
    }

    /// Verify a path
    pub fn verify_path(&self, path: &MerklePath, leaf_data: &[u8]) -> bool {
        let mut current = leaf_hash(path.index as u64, leaf_data);

        for (sibling, is_right) in &path.siblings {
            if *is_right {
                current = node_hash(&current, sibling);
            } else {
                current = node_hash(sibling, &current);
            }
        }

        root_hash(&current) == self.root
    }
}

/// Merkle authentication path
#[derive(Clone, Debug)]
pub struct MerklePath {
    pub index: usize,
    pub siblings: Vec<([u8; 32], bool)>, // (sibling_hash, sibling_is_right)
}

impl MerklePath {
    /// Verify this path against a root
    pub fn verify(&self, leaf_data: &[u8], root: &[u8; 32]) -> bool {
        let mut current = leaf_hash(self.index as u64, leaf_data);

        for (sibling, is_right) in &self.siblings {
            if *is_right {
                current = node_hash(&current, sibling);
            } else {
                current = node_hash(sibling, &current);
            }
        }

        &root_hash(&current) == root
    }

    /// Serialize path
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&(self.index as u64).to_le_bytes());
        result.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());
        for (sibling, is_right) in &self.siblings {
            result.extend_from_slice(sibling);
            result.push(if *is_right { 1 } else { 0 });
        }
        result
    }

    /// Deserialize path
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }

        let index = u64::from_le_bytes(data[0..8].try_into().ok()?) as usize;
        let num_siblings = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;

        let mut offset = 12;
        let mut siblings = Vec::with_capacity(num_siblings);

        for _ in 0..num_siblings {
            if offset + 33 > data.len() {
                return None;
            }
            let mut sibling = [0u8; 32];
            sibling.copy_from_slice(&data[offset..offset + 32]);
            let is_right = data[offset + 32] == 1;
            siblings.push((sibling, is_right));
            offset += 33;
        }

        Some(MerklePath { index, siblings })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree() {
        let leaves = vec![
            b"leaf0".to_vec(),
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
            b"leaf3".to_vec(),
        ];

        let tree = MerkleTree::new(leaves.clone());

        // Verify all paths
        for (i, leaf) in leaves.iter().enumerate() {
            let path = tree.get_path(i);
            assert!(tree.verify_path(&path, leaf));
            assert!(path.verify(leaf, &tree.root));
        }
    }

    #[test]
    fn test_path_serialization() {
        let leaves = vec![b"a".to_vec(), b"b".to_vec()];
        let tree = MerkleTree::new(leaves);
        let path = tree.get_path(0);

        let serialized = path.serialize();
        let deserialized = MerklePath::deserialize(&serialized).unwrap();

        assert_eq!(path.index, deserialized.index);
        assert_eq!(path.siblings.len(), deserialized.siblings.len());
    }
}
