//! Merkle tree for trace commitment.
//!
//! Enables O(log n) verification of individual trace steps
//! without revealing the entire trace.

use crate::{hash_pair, Hash256};
use serde::{Deserialize, Serialize};

/// A Merkle tree built from execution trace step hashes.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Leaf hashes (step hashes).
    leaves: Vec<Hash256>,

    /// Internal nodes (bottom-up, level by level).
    /// nodes[0] = level above leaves, etc.
    nodes: Vec<Vec<Hash256>>,

    /// Root hash.
    root: Hash256,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf hashes.
    ///
    /// Time: O(n)
    /// Space: O(n)
    pub fn build(leaves: Vec<Hash256>) -> Self {
        if leaves.is_empty() {
            return Self {
                leaves: vec![],
                nodes: vec![],
                root: [0; 32],
            };
        }

        if leaves.len() == 1 {
            return Self {
                root: leaves[0],
                leaves,
                nodes: vec![],
            };
        }

        let mut nodes = Vec::new();
        let mut current_level = leaves.clone();

        // Pad to power of 2 for balanced tree
        while current_level.len() & (current_level.len() - 1) != 0 {
            let Some(last) = current_level.last().copied() else {
                return Self {
                    leaves: vec![],
                    nodes: vec![],
                    root: [0; 32],
                };
            };
            current_level.push(last);
        }

        // Build tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len() / 2);

            for chunk in current_level.chunks(2) {
                let hash = hash_pair(&chunk[0], &chunk[1]);
                next_level.push(hash);
            }

            nodes.push(current_level);
            current_level = next_level;
        }

        let root = current_level[0];

        Self {
            leaves,
            nodes,
            root,
        }
    }

    /// Get the root hash.
    pub fn root(&self) -> Hash256 {
        self.root
    }

    /// Get number of leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Generate a proof for a specific leaf index.
    ///
    /// Time: O(log n)
    /// Proof size: O(log n)
    pub fn prove(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let leaf_hash = self.leaves[index];
        let mut siblings = Vec::new();
        let mut current_index = index;

        // Pad index for balanced tree
        let _padded_len = self.nodes.first().map(|n| n.len()).unwrap_or(1);

        for level in &self.nodes {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < level.len() {
                siblings.push(MerkleSibling {
                    hash: level[sibling_index],
                    is_left: current_index % 2 == 1,
                });
            }

            current_index /= 2;
        }

        Some(MerkleProof {
            leaf_index: index,
            leaf_hash,
            siblings,
        })
    }
}

/// A sibling node in a Merkle proof path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleSibling {
    /// Hash of the sibling node.
    pub hash: Hash256,

    /// True if sibling is on the left.
    pub is_left: bool,
}

/// A Merkle proof for a single leaf.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the leaf being proven.
    pub leaf_index: usize,

    /// Hash of the leaf.
    pub leaf_hash: Hash256,

    /// Sibling hashes along the path to root.
    pub siblings: Vec<MerkleSibling>,
}

impl MerkleProof {
    /// Verify this proof against an expected root.
    ///
    /// Time: O(log n)
    pub fn verify(&self, expected_root: &Hash256) -> bool {
        let mut current = self.leaf_hash;

        for sibling in &self.siblings {
            current = if sibling.is_left {
                hash_pair(&sibling.hash, &current)
            } else {
                hash_pair(&current, &sibling.hash)
            };
        }

        current == *expected_root
    }

    /// Compute the size of this proof in bytes.
    pub fn size_bytes(&self) -> usize {
        8 + 32 + self.siblings.len() * 33 // index + leaf + siblings*(hash + bool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    fn make_leaves(n: usize) -> Vec<Hash256> {
        (0..n).map(|i| sha256(&i.to_le_bytes())).collect()
    }

    #[test]
    fn single_leaf_tree() {
        let leaves = make_leaves(1);
        let tree = MerkleTree::build(leaves.clone());

        assert_eq!(tree.root(), leaves[0]);
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn two_leaf_tree() {
        let leaves = make_leaves(2);
        let tree = MerkleTree::build(leaves.clone());

        let expected_root = hash_pair(&leaves[0], &leaves[1]);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn proof_verifies_correctly() {
        let leaves = make_leaves(8);
        let tree = MerkleTree::build(leaves);
        let root = tree.root();

        for i in 0..8 {
            let proof = tree.prove(i).unwrap();
            assert!(proof.verify(&root), "Proof for leaf {} should verify", i);
        }
    }

    #[test]
    fn proof_fails_for_wrong_root() {
        let leaves = make_leaves(8);
        let tree = MerkleTree::build(leaves);

        let proof = tree.prove(0).unwrap();
        let wrong_root = sha256(b"wrong");

        assert!(!proof.verify(&wrong_root));
    }

    #[test]
    fn proof_size_logarithmic() {
        // 8 leaves = 3 levels = 3 siblings
        let leaves8 = make_leaves(8);
        let tree8 = MerkleTree::build(leaves8);
        let proof8 = tree8.prove(0).unwrap();

        // 1024 leaves = 10 levels = 10 siblings
        let leaves1k = make_leaves(1024);
        let tree1k = MerkleTree::build(leaves1k);
        let proof1k = tree1k.prove(0).unwrap();

        // Proof for 1024 leaves should be ~3x larger than 8 leaves
        // (10 siblings vs 3 siblings)
        let ratio = proof1k.size_bytes() as f64 / proof8.size_bytes() as f64;
        assert!(ratio < 4.0, "Proof size should be logarithmic");
    }

    #[test]
    fn large_tree_all_proofs_valid() {
        let leaves = make_leaves(1000);
        let tree = MerkleTree::build(leaves);
        let root = tree.root();

        // Verify a sample of proofs
        for i in (0..1000).step_by(100) {
            let proof = tree.prove(i).unwrap();
            assert!(proof.verify(&root), "Proof for leaf {} should verify", i);
        }
    }
}
