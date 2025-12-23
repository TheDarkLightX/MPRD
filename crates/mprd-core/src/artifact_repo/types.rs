//! Core types for MPRD Artifact Repository.
//!
//! All types are content-addressed and deterministic.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

use super::bounds::{BLOCK_HASH_PREFIX, BLOCK_SOURCE_PREFIX, MST_KEY_HASH_PREFIX};

/// 32-byte identifier (content-addressed hash).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, PartialOrd, Ord)]
pub struct Id32(pub [u8; 32]);

impl Id32 {
    pub const ZERO: Id32 = Id32([0u8; 32]);

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Id32(arr))
    }
}

impl fmt::Debug for Id32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id32({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for Id32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex()[..16])
    }
}

impl AsRef<[u8]> for Id32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Id32 {
    fn from(arr: [u8; 32]) -> Self {
        Id32(arr)
    }
}

/// Content-addressed block identifier.
pub type BlockId = Id32;

/// Commit identifier (commit is a content-addressed block).
pub type CommitId = BlockId;

/// Source identifier for block sources.
pub type SourceId = Id32;

/// Repository key (canonicalized UTF-8 string bytes).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Key(pub Vec<u8>);

impl Key {
    pub fn new(s: impl AsRef<[u8]>) -> Self {
        Key(s.as_ref().to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Compute the key hash for MST routing.
    /// KeyHash = sha256("MPRD_MST_KEY_V1" || key_bytes)
    pub fn hash(&self) -> KeyHash {
        let mut hasher = Sha256::new();
        hasher.update(MST_KEY_HASH_PREFIX);
        hasher.update(&self.0);
        let result = hasher.finalize();
        KeyHash(result.into())
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "Key({:?})", s),
            None => write!(f, "Key({} bytes)", self.0.len()),
        }
    }
}

impl From<&str> for Key {
    fn from(s: &str) -> Self {
        Key::new(s)
    }
}

impl From<String> for Key {
    fn from(s: String) -> Self {
        Key(s.into_bytes())
    }
}

/// Key hash for MST routing (64 nibbles).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHash(pub [u8; 32]);

impl KeyHash {
    /// Convert to 64 nibbles for MST traversal.
    /// nibble[i] = high nibble of byte[i/2] when i is even
    /// nibble[i] = low nibble of byte[i/2] when i is odd
    pub fn to_nibbles(&self) -> [u8; 64] {
        let mut nibbles = [0u8; 64];
        for (i, byte) in self.0.iter().enumerate() {
            nibbles[i * 2] = byte >> 4; // high nibble
            nibbles[i * 2 + 1] = byte & 0x0F; // low nibble
        }
        nibbles
    }

    /// Get nibble at specific depth (0-63).
    pub fn nibble_at(&self, depth: usize) -> Option<u8> {
        if depth >= 64 {
            return None;
        }
        let byte_idx = depth / 2;
        if depth % 2 == 0 {
            Some(self.0[byte_idx] >> 4)
        } else {
            Some(self.0[byte_idx] & 0x0F)
        }
    }
}

impl fmt::Debug for KeyHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyHash({})", hex::encode(&self.0[..8]))
    }
}

/// Compute block ID from block bytes.
/// BlockId = sha256("MPRD_BLOCK_V1" || block_bytes)
pub fn compute_block_id(block_bytes: &[u8]) -> BlockId {
    let mut hasher = Sha256::new();
    hasher.update(BLOCK_HASH_PREFIX);
    hasher.update(block_bytes);
    let result = hasher.finalize();
    Id32(result.into())
}

/// Compute a stable source ID for a block/commit source descriptor.
///
/// SourceId = sha256("MPRD_BLOCK_SOURCE_V1" || descriptor_bytes)
pub fn compute_source_id(descriptor_bytes: &[u8]) -> SourceId {
    let mut hasher = Sha256::new();
    hasher.update(BLOCK_SOURCE_PREFIX);
    hasher.update(descriptor_bytes);
    let result = hasher.finalize();
    Id32(result.into())
}

/// Block tag identifying the block type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockTag {
    MstNode = 0x01,
    Blob = 0x02,
    Commit = 0x03,
    EventChunk = 0x04,
}

impl BlockTag {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(BlockTag::MstNode),
            0x02 => Some(BlockTag::Blob),
            0x03 => Some(BlockTag::Commit),
            0x04 => Some(BlockTag::EventChunk),
            _ => None,
        }
    }
}

/// Signed commit object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub repo_version: u32,
    pub prev_commit: CommitId,
    pub commit_height: u64,
    pub repo_root: BlockId,
    pub policy_epoch: u64,
    pub registry_root: Id32,
    pub manifest_digest: Id32,
    pub signed_at_ms: i64,
    pub signer_pubkey: [u8; 32],
    pub signature: [u8; 64],
}

impl Commit {
    /// Compute the canonical signing bytes (excludes signature).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 4 + 32 + 8 + 32 + 8 + 32 + 32 + 8 + 32);
        bytes.extend_from_slice(super::bounds::COMMIT_SIGN_PREFIX);
        bytes.extend_from_slice(&self.repo_version.to_le_bytes());
        bytes.extend_from_slice(&self.prev_commit.0);
        bytes.extend_from_slice(&self.commit_height.to_le_bytes());
        bytes.extend_from_slice(&self.repo_root.0);
        bytes.extend_from_slice(&self.policy_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.registry_root.0);
        bytes.extend_from_slice(&self.manifest_digest.0);
        bytes.extend_from_slice(&self.signed_at_ms.to_le_bytes());
        bytes.extend_from_slice(&self.signer_pubkey);
        bytes
    }
}

/// MST node entry (either a leaf or a child pointer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MstEntry {
    Leaf { key: Key, value_block_id: BlockId },
    Child { child_id: BlockId },
}

impl MstEntry {
    pub fn is_leaf(&self) -> bool {
        matches!(self, MstEntry::Leaf { .. })
    }

    pub fn is_child(&self) -> bool {
        matches!(self, MstEntry::Child { .. })
    }
}

/// MST node (nibble-indexed map with at most 16 entries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MstNode {
    /// Entries indexed by nibble (0-15). None means no entry at that nibble.
    entries: [Option<MstEntry>; 16],
}

impl MstNode {
    pub fn new() -> Self {
        Self {
            entries: Default::default(),
        }
    }

    pub fn entry_at(&self, nibble: u8) -> Option<&MstEntry> {
        if nibble >= 16 {
            return None;
        }
        self.entries[nibble as usize].as_ref()
    }

    pub fn with_leaf_at(&self, nibble: u8, key: Key, value_block_id: BlockId) -> Self {
        let mut new = self.clone();
        if nibble < 16 {
            new.entries[nibble as usize] = Some(MstEntry::Leaf {
                key,
                value_block_id,
            });
        }
        new
    }

    pub fn with_child_at(&self, nibble: u8, child_id: BlockId) -> Self {
        let mut new = self.clone();
        if nibble < 16 {
            new.entries[nibble as usize] = Some(MstEntry::Child { child_id });
        }
        new
    }

    pub fn without_entry_at(&self, nibble: u8) -> Self {
        let mut new = self.clone();
        if nibble < 16 {
            new.entries[nibble as usize] = None;
        }
        new
    }

    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(|e| e.is_none())
    }

    pub fn entry_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    /// Iterate over (nibble, entry) pairs in order.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &MstEntry)> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|entry| (i as u8, entry)))
    }
}

impl Default for MstNode {
    fn default() -> Self {
        Self::new()
    }
}

/// Reason for non-inclusion in MST lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonInclusionReason {
    /// No child pointer at the expected nibble.
    MissingChild { depth: usize, nibble: u8 },
    /// A different key occupies the slot.
    OccupiedByDifferentKey {
        depth: usize,
        nibble: u8,
        collision_key: Key,
    },
}

/// Inclusion proof for a key-value pair.
#[derive(Debug, Clone)]
pub struct InclusionProof {
    pub root: BlockId,
    pub key: Key,
    pub value_block_id: BlockId,
    pub value_bytes: Vec<u8>,
    pub blocks: Vec<(BlockId, Vec<u8>)>,
}

/// Non-inclusion proof for a key.
#[derive(Debug, Clone)]
pub struct NonInclusionProof {
    pub root: BlockId,
    pub key: Key,
    pub reason: NonInclusionReason,
    pub blocks: Vec<(BlockId, Vec<u8>)>,
}

/// Result of an MST lookup.
#[derive(Debug, Clone)]
pub enum LookupResult {
    Found(InclusionProof),
    NotFound(NonInclusionProof),
}

/// Diff entry representing a change between two MST states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffEntry {
    Added {
        key: Key,
        value: BlockId,
    },
    Deleted {
        key: Key,
        value: BlockId,
    },
    Modified {
        key: Key,
        old_value: BlockId,
        new_value: BlockId,
    },
}

/// Result of commit chain verification.
#[derive(Debug, Clone)]
pub struct ChainVerified {
    pub start_height: u64,
    pub end_height: u64,
    pub signer: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_hash_nibbles() {
        let key = Key::new("registry/policy_epoch");
        let hash = key.hash();
        let nibbles = hash.to_nibbles();

        // Verify nibble extraction
        for i in 0..64 {
            assert!(nibbles[i] < 16, "nibble {} should be < 16", i);
            assert_eq!(hash.nibble_at(i), Some(nibbles[i]));
        }
        assert_eq!(hash.nibble_at(64), None);
    }

    #[test]
    fn key_hash_matches_spec_vector() {
        // internal/specs/mprd_artifact_repo_algorithms_v1.md (v1.4)
        let key = Key::new("registry/policy_epoch");
        let hash = key.hash();
        let expected =
            Id32::from_hex("cbadd4ea829083f198b236e1bf71e1f617e3ccf013c778ac7fa4de490c7b7ffd")
                .unwrap();
        assert_eq!(Id32(hash.0), expected);
    }

    #[test]
    fn block_id_computation() {
        let data = b"test block data";
        let id = compute_block_id(data);

        // Verify determinism
        let id2 = compute_block_id(data);
        assert_eq!(id, id2);

        // Different data = different ID
        let id3 = compute_block_id(b"different data");
        assert_ne!(id, id3);
    }

    #[test]
    fn mst_node_operations() {
        let node = MstNode::new();
        assert!(node.is_empty());

        let key = Key::new("test");
        let value = BlockId::ZERO;

        let node = node.with_leaf_at(5, key.clone(), value);
        assert!(!node.is_empty());
        assert_eq!(node.entry_count(), 1);

        let entry = node.entry_at(5).unwrap();
        assert!(entry.is_leaf());

        let node = node.without_entry_at(5);
        assert!(node.is_empty());
    }

    #[test]
    fn id32_hex_roundtrip() {
        let original = Id32([0xab; 32]);
        let hex = original.to_hex();
        let parsed = Id32::from_hex(&hex).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn source_id_deterministic() {
        let a1 = compute_source_id(b"https://example.com/a");
        let a2 = compute_source_id(b"https://example.com/a");
        let b = compute_source_id(b"https://example.com/b");
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
    }
}
