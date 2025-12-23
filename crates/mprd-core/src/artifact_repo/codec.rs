//! Block codec for MPRD Artifact Repository.
//!
//! All blocks use the format: tag:u8 || codec_version:u8 || payload...
//! BlockId = sha256("MPRD_BLOCK_V1" || block_bytes)

use super::bounds::{MAX_BLOCK_BYTES, MAX_KEY_BYTES, MAX_NODE_ENTRIES, MAX_VALUE_BYTES};
use super::error::{ArtifactRepoError, Result};
use super::types::{BlockTag, Commit, Id32, Key, MstEntry, MstNode};

const CODEC_VERSION: u8 = 1;

/// Decode block tag and version from block bytes.
pub fn decode_block_header(bytes: &[u8]) -> Result<(BlockTag, u8)> {
    if bytes.len() < 2 {
        return Err(ArtifactRepoError::MalformedBlock(
            "block too short for header".into(),
        ));
    }
    let tag = BlockTag::from_byte(bytes[0]).ok_or(ArtifactRepoError::InvalidBlockTag(bytes[0]))?;
    let version = bytes[1];
    Ok((tag, version))
}

/// Encode an MST node to block bytes.
///
/// Format:
/// - tag: u8 = 0x01 (MstNode)
/// - version: u8 = 1
/// - entry_count: u8 (<= 16)
/// - for each entry (sorted by nibble ascending):
///   - nibble: u8 (0..=15, unique)
///   - entry_type: u8 (0 = Leaf, 1 = Child)
///   - if Leaf:
///     - key_len: u16
///     - key_bytes: [u8; key_len]
///     - value_block_id: [u8; 32]
///   - if Child:
///     - child_id: [u8; 32]
pub fn encode_mst_node(node: &MstNode) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(256);

    // Header
    bytes.push(BlockTag::MstNode as u8);
    bytes.push(CODEC_VERSION);

    // Entry count
    let entry_count = node.entry_count();
    if entry_count > MAX_NODE_ENTRIES {
        return Err(ArtifactRepoError::MalformedMstNode(format!(
            "too many entries: {} > {}",
            entry_count, MAX_NODE_ENTRIES
        )));
    }
    bytes.push(entry_count as u8);

    // Entries in nibble order (canonical)
    for (nibble, entry) in node.iter() {
        bytes.push(nibble);
        match entry {
            MstEntry::Leaf {
                key,
                value_block_id,
            } => {
                bytes.push(0); // Leaf type
                let key_bytes = key.as_bytes();
                validate_key_bytes(key_bytes)?;
                bytes.extend_from_slice(&(key_bytes.len() as u16).to_le_bytes());
                bytes.extend_from_slice(key_bytes);
                bytes.extend_from_slice(&value_block_id.0);
            }
            MstEntry::Child { child_id } => {
                bytes.push(1); // Child type
                bytes.extend_from_slice(&child_id.0);
            }
        }
    }

    if bytes.len() > MAX_BLOCK_BYTES {
        return Err(ArtifactRepoError::BlockTooLarge {
            size: bytes.len(),
            max: MAX_BLOCK_BYTES,
        });
    }

    Ok(bytes)
}

/// Decode an MST node from block bytes.
pub fn decode_mst_node(bytes: &[u8]) -> Result<MstNode> {
    if bytes.len() > MAX_BLOCK_BYTES {
        return Err(ArtifactRepoError::BlockTooLarge {
            size: bytes.len(),
            max: MAX_BLOCK_BYTES,
        });
    }

    if bytes.len() < 3 {
        return Err(ArtifactRepoError::MalformedMstNode(
            "block too short".into(),
        ));
    }

    let (tag, version) = decode_block_header(bytes)?;
    if tag != BlockTag::MstNode {
        return Err(ArtifactRepoError::InvalidBlockTag(bytes[0]));
    }
    if version != CODEC_VERSION {
        return Err(ArtifactRepoError::InvalidCodecVersion(version));
    }

    let entry_count = bytes[2] as usize;
    if entry_count > MAX_NODE_ENTRIES {
        return Err(ArtifactRepoError::MalformedMstNode(format!(
            "too many entries: {} > {}",
            entry_count, MAX_NODE_ENTRIES
        )));
    }

    let mut node = MstNode::new();
    let mut offset = 3;
    let mut last_nibble: Option<u8> = None;

    for _ in 0..entry_count {
        if offset + 2 > bytes.len() {
            return Err(ArtifactRepoError::MalformedMstNode(
                "truncated entry header".into(),
            ));
        }

        let nibble = bytes[offset];
        let entry_type = bytes[offset + 1];
        offset += 2;

        if nibble > 15 {
            return Err(ArtifactRepoError::MalformedMstNode(format!(
                "invalid nibble: {}",
                nibble
            )));
        }
        if let Some(prev) = last_nibble {
            if nibble <= prev {
                return Err(ArtifactRepoError::MalformedMstNode(
                    "nibbles not strictly increasing".into(),
                ));
            }
        }
        last_nibble = Some(nibble);

        match entry_type {
            0 => {
                if offset + 2 > bytes.len() {
                    return Err(ArtifactRepoError::MalformedMstNode(
                        "truncated key length".into(),
                    ));
                }

                let key_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
                offset += 2;

                if key_len == 0 {
                    return Err(ArtifactRepoError::MalformedMstNode(
                        "empty key is not allowed".into(),
                    ));
                }
                if key_len > MAX_KEY_BYTES {
                    return Err(ArtifactRepoError::KeyTooLarge {
                        size: key_len,
                        max: MAX_KEY_BYTES,
                    });
                }
                if offset + key_len + 32 > bytes.len() {
                    return Err(ArtifactRepoError::MalformedMstNode(
                        "truncated leaf entry".into(),
                    ));
                }

                let key_bytes = &bytes[offset..offset + key_len];
                validate_key_bytes(key_bytes)?;
                let key = Key(key_bytes.to_vec());
                offset += key_len;

                let mut value_id = [0u8; 32];
                value_id.copy_from_slice(&bytes[offset..offset + 32]);
                offset += 32;

                node = node.with_leaf_at(nibble, key, Id32(value_id));
            }
            1 => {
                if offset + 32 > bytes.len() {
                    return Err(ArtifactRepoError::MalformedMstNode(
                        "truncated child entry".into(),
                    ));
                }

                let mut child_id = [0u8; 32];
                child_id.copy_from_slice(&bytes[offset..offset + 32]);
                offset += 32;

                node = node.with_child_at(nibble, Id32(child_id));
            }
            _ => {
                return Err(ArtifactRepoError::MalformedMstNode(format!(
                    "invalid entry type: {}",
                    entry_type
                )));
            }
        }
    }

    if offset != bytes.len() {
        return Err(ArtifactRepoError::MalformedMstNode(
            "trailing bytes in MST node".into(),
        ));
    }

    Ok(node)
}

/// Encode a blob to block bytes.
///
/// Format:
/// - tag: u8 = 0x02 (Blob)
/// - version: u8 = 1
/// - len: u32 (payload length)
/// - payload: [u8; len]
pub fn encode_blob(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_VALUE_BYTES {
        return Err(ArtifactRepoError::ValueTooLarge {
            size: payload.len(),
            max: MAX_VALUE_BYTES,
        });
    }

    let total_len = 2 + 4 + payload.len();
    if total_len > MAX_BLOCK_BYTES {
        return Err(ArtifactRepoError::BlockTooLarge {
            size: total_len,
            max: MAX_BLOCK_BYTES,
        });
    }

    let mut bytes = Vec::with_capacity(total_len);
    bytes.push(BlockTag::Blob as u8);
    bytes.push(CODEC_VERSION);
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// Decode a blob from block bytes, returning the payload.
pub fn decode_blob(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.len() > MAX_BLOCK_BYTES {
        return Err(ArtifactRepoError::BlockTooLarge {
            size: bytes.len(),
            max: MAX_BLOCK_BYTES,
        });
    }

    if bytes.len() < 6 {
        return Err(ArtifactRepoError::MalformedBlock(
            "block too short for blob".into(),
        ));
    }

    let (tag, version) = decode_block_header(bytes)?;
    if tag != BlockTag::Blob {
        return Err(ArtifactRepoError::InvalidBlockTag(bytes[0]));
    }
    if version != CODEC_VERSION {
        return Err(ArtifactRepoError::InvalidCodecVersion(version));
    }

    let len = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    if len > MAX_VALUE_BYTES {
        return Err(ArtifactRepoError::ValueTooLarge {
            size: len,
            max: MAX_VALUE_BYTES,
        });
    }

    let expected_len = 2 + 4 + len;
    if bytes.len() != expected_len {
        return Err(ArtifactRepoError::MalformedBlock(format!(
            "blob length mismatch: bytes_len={} expected={}",
            bytes.len(),
            expected_len
        )));
    }

    Ok(&bytes[6..])
}

/// Encode a commit to block bytes.
///
/// Format:
/// - tag: u8 = 0x03 (Commit)
/// - version: u8 = 1
/// - repo_version: u32
/// - prev_commit: [u8; 32]
/// - commit_height: u64
/// - repo_root: [u8; 32]
/// - policy_epoch: u64
/// - registry_root: [u8; 32]
/// - manifest_digest: [u8; 32]
/// - signed_at_ms: i64
/// - signer_pubkey: [u8; 32]
/// - signature: [u8; 64]
pub fn encode_commit(commit: &Commit) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + 4 + 32 + 8 + 32 + 8 + 32 + 32 + 8 + 32 + 64);

    bytes.push(BlockTag::Commit as u8);
    bytes.push(CODEC_VERSION);
    bytes.extend_from_slice(&commit.repo_version.to_le_bytes());
    bytes.extend_from_slice(&commit.prev_commit.0);
    bytes.extend_from_slice(&commit.commit_height.to_le_bytes());
    bytes.extend_from_slice(&commit.repo_root.0);
    bytes.extend_from_slice(&commit.policy_epoch.to_le_bytes());
    bytes.extend_from_slice(&commit.registry_root.0);
    bytes.extend_from_slice(&commit.manifest_digest.0);
    bytes.extend_from_slice(&commit.signed_at_ms.to_le_bytes());
    bytes.extend_from_slice(&commit.signer_pubkey);
    bytes.extend_from_slice(&commit.signature);

    bytes
}

/// Decode a commit from block bytes.
pub fn decode_commit(bytes: &[u8]) -> Result<Commit> {
    const EXPECTED_LEN: usize = 2 + 4 + 32 + 8 + 32 + 8 + 32 + 32 + 8 + 32 + 64;

    if bytes.len() != EXPECTED_LEN {
        return Err(ArtifactRepoError::MalformedCommit(format!(
            "wrong length: {} != {}",
            bytes.len(),
            EXPECTED_LEN
        )));
    }

    let (tag, version) = decode_block_header(bytes)?;
    if tag != BlockTag::Commit {
        return Err(ArtifactRepoError::InvalidBlockTag(bytes[0]));
    }
    if version != CODEC_VERSION {
        return Err(ArtifactRepoError::InvalidCodecVersion(version));
    }

    let mut offset = 2;

    let repo_version = u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]);
    offset += 4;

    if repo_version != 1 {
        return Err(ArtifactRepoError::MalformedCommit(format!(
            "unsupported repo_version: {}",
            repo_version
        )));
    }

    let mut prev_commit = [0u8; 32];
    prev_commit.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;

    let commit_height = u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]);
    offset += 8;

    let mut repo_root = [0u8; 32];
    repo_root.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;

    let policy_epoch = u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]);
    offset += 8;

    let mut registry_root = [0u8; 32];
    registry_root.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;

    let mut manifest_digest = [0u8; 32];
    manifest_digest.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;

    let signed_at_ms = i64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]);
    offset += 8;

    let mut signer_pubkey = [0u8; 32];
    signer_pubkey.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&bytes[offset..offset + 64]);

    Ok(Commit {
        repo_version,
        prev_commit: Id32(prev_commit),
        commit_height,
        repo_root: Id32(repo_root),
        policy_epoch,
        registry_root: super::types::Id32(registry_root),
        manifest_digest: super::types::Id32(manifest_digest),
        signed_at_ms,
        signer_pubkey,
        signature,
    })
}

fn validate_key_bytes(key_bytes: &[u8]) -> Result<()> {
    if key_bytes.is_empty() {
        return Err(ArtifactRepoError::MalformedMstNode(
            "empty key is not allowed".into(),
        ));
    }
    if key_bytes.len() > MAX_KEY_BYTES {
        return Err(ArtifactRepoError::KeyTooLarge {
            size: key_bytes.len(),
            max: MAX_KEY_BYTES,
        });
    }

    for &b in key_bytes {
        let ok = matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'/' | b'-');
        if !ok {
            return Err(ArtifactRepoError::MalformedMstNode(
                "key bytes not canonical".into(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_repo::types::compute_block_id;
    use crate::artifact_repo::types::Id32;
    use proptest::prelude::*;

    #[test]
    fn mst_node_roundtrip() {
        let mut node = MstNode::new();
        node = node.with_leaf_at(0, Key::new("key0"), Id32([1u8; 32]));
        node = node.with_child_at(5, Id32([2u8; 32]));
        node = node.with_leaf_at(15, Key::new("key15"), Id32([3u8; 32]));

        let bytes = encode_mst_node(&node).unwrap();
        let decoded = decode_mst_node(&bytes).unwrap();

        assert_eq!(node.entry_count(), decoded.entry_count());

        // Verify entries
        match decoded.entry_at(0) {
            Some(MstEntry::Leaf {
                key,
                value_block_id,
            }) => {
                assert_eq!(key.as_bytes(), b"key0");
                assert_eq!(value_block_id.0, [1u8; 32]);
            }
            _ => panic!("expected leaf at nibble 0"),
        }

        match decoded.entry_at(5) {
            Some(MstEntry::Child { child_id }) => {
                assert_eq!(child_id.0, [2u8; 32]);
            }
            _ => panic!("expected child at nibble 5"),
        }
    }

    #[test]
    fn blob_roundtrip() {
        let payload = b"test payload data";
        let bytes = encode_blob(payload).unwrap();
        let decoded = decode_blob(&bytes).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn blob_matches_spec_vector() {
        // internal/specs/mprd_artifact_repo_algorithms_v1.md (v1.4)
        let bytes = encode_blob(b"hello").unwrap();
        assert_eq!(hex::encode(&bytes), "02010500000068656c6c6f");

        let block_id = compute_block_id(&bytes);
        assert_eq!(
            block_id.to_hex(),
            "5d887e5c805e523a9aecd676cfab6dc6c2c3db7567e7b09470117db83ac68240"
        );
    }

    #[test]
    fn blob_rejects_trailing_bytes() {
        let mut bytes = encode_blob(b"hi").unwrap();
        bytes.push(0);
        assert!(decode_blob(&bytes).is_err());
    }

    #[test]
    fn blob_accepts_exactly_max_block_bytes() {
        let payload = vec![0u8; MAX_BLOCK_BYTES - 6];
        let bytes = encode_blob(&payload).unwrap();
        assert_eq!(bytes.len(), MAX_BLOCK_BYTES);
        assert_eq!(decode_blob(&bytes).unwrap(), payload.as_slice());
    }

    #[test]
    fn blob_rejects_over_max_block_bytes() {
        let payload = vec![0u8; MAX_BLOCK_BYTES - 6];
        let mut bytes = encode_blob(&payload).unwrap();
        bytes.push(0);
        assert!(matches!(
            decode_blob(&bytes),
            Err(ArtifactRepoError::BlockTooLarge { .. })
        ));
    }

    #[test]
    fn mst_node_rejects_trailing_bytes() {
        let node = MstNode::new().with_leaf_at(0, Key::new("a"), Id32([1u8; 32]));
        let mut bytes = encode_mst_node(&node).unwrap();
        bytes.push(0);
        assert!(decode_mst_node(&bytes).is_err());
    }

    #[test]
    fn mst_node_does_not_reject_exactly_max_block_bytes_as_too_large() {
        let bytes = vec![0u8; MAX_BLOCK_BYTES];
        let err = decode_mst_node(&bytes).unwrap_err();
        assert!(!matches!(err, ArtifactRepoError::BlockTooLarge { .. }));
    }

    #[test]
    fn commit_roundtrip() {
        let commit = Commit {
            repo_version: 1,
            prev_commit: Id32([0xaa; 32]),
            commit_height: 42,
            repo_root: Id32([0xbb; 32]),
            policy_epoch: 100,
            registry_root: super::super::types::Id32([0xcc; 32]),
            manifest_digest: super::super::types::Id32([0xdd; 32]),
            signed_at_ms: 1234567890,
            signer_pubkey: [0xee; 32],
            signature: [0xff; 64],
        };

        let bytes = encode_commit(&commit);
        let decoded = decode_commit(&bytes).unwrap();

        assert_eq!(commit.repo_version, decoded.repo_version);
        assert_eq!(commit.prev_commit, decoded.prev_commit);
        assert_eq!(commit.commit_height, decoded.commit_height);
        assert_eq!(commit.repo_root, decoded.repo_root);
        assert_eq!(commit.policy_epoch, decoded.policy_epoch);
        assert_eq!(commit.registry_root, decoded.registry_root);
        assert_eq!(commit.manifest_digest, decoded.manifest_digest);
        assert_eq!(commit.signed_at_ms, decoded.signed_at_ms);
        assert_eq!(commit.signer_pubkey, decoded.signer_pubkey);
        assert_eq!(commit.signature, decoded.signature);
    }

    #[derive(Clone, Debug)]
    enum GenEntry {
        Leaf {
            key: String,
            value_block_id: [u8; 32],
        },
        Child {
            child_id: [u8; 32],
        },
    }

    fn gen_key() -> impl Strategy<Value = String> {
        // Must satisfy validate_key_bytes (and keep test cases small).
        "[a-z0-9_./-]{1,32}".prop_map(|s| s)
    }

    fn gen_entry() -> impl Strategy<Value = GenEntry> {
        prop_oneof![
            (gen_key(), any::<[u8; 32]>()).prop_map(|(key, value_block_id)| GenEntry::Leaf {
                key,
                value_block_id
            }),
            any::<[u8; 32]>().prop_map(|child_id| GenEntry::Child { child_id }),
        ]
    }

    fn gen_mst_node() -> impl Strategy<Value = MstNode> {
        proptest::collection::btree_map(0u8..16, gen_entry(), 0..=16).prop_map(|entries| {
            let mut node = MstNode::new();
            for (nibble, entry) in entries {
                match entry {
                    GenEntry::Leaf {
                        key,
                        value_block_id,
                    } => {
                        node = node.with_leaf_at(nibble, Key::new(key), Id32(value_block_id));
                    }
                    GenEntry::Child { child_id } => {
                        node = node.with_child_at(nibble, Id32(child_id));
                    }
                }
            }
            node
        })
    }

    proptest! {
        #[test]
        fn mst_node_encode_decode_roundtrips(node in gen_mst_node()) {
            let bytes = encode_mst_node(&node).expect("encode");
            let decoded = decode_mst_node(&bytes).expect("decode");
            prop_assert_eq!(decoded, node);
        }

        #[test]
        fn mst_node_decoder_never_panics_for_small_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = decode_mst_node(&bytes);
        }

        #[test]
        fn blob_roundtrips(payload in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let bytes = encode_blob(&payload).expect("encode");
            let decoded = decode_blob(&bytes).expect("decode");
            prop_assert_eq!(decoded, payload.as_slice());
        }

        #[test]
        fn blob_decode_rejects_wrong_length(
            payload in proptest::collection::vec(any::<u8>(), 0..256),
            extra in proptest::collection::vec(any::<u8>(), 1..32),
        ) {
            let mut bytes = encode_blob(&payload).expect("encode");
            bytes.extend_from_slice(&extra);
            prop_assert!(decode_blob(&bytes).is_err());
        }

        #[test]
        fn commit_encode_decode_roundtrips(
            prev_commit in any::<[u8; 32]>(),
            commit_height in any::<u64>(),
            repo_root in any::<[u8; 32]>(),
            policy_epoch in any::<u64>(),
            registry_root in any::<[u8; 32]>(),
            manifest_digest in any::<[u8; 32]>(),
            signed_at_ms in any::<i64>(),
            signer_pubkey in any::<[u8; 32]>(),
            signature in any::<[u8; 64]>(),
        ) {
            let commit = Commit {
                repo_version: 1,
                prev_commit: Id32(prev_commit),
                commit_height,
                repo_root: Id32(repo_root),
                policy_epoch,
                registry_root: Id32(registry_root),
                manifest_digest: Id32(manifest_digest),
                signed_at_ms,
                signer_pubkey,
                signature,
            };
            let bytes = encode_commit(&commit);
            let decoded = decode_commit(&bytes).expect("decode");
            prop_assert_eq!(decoded, commit);
        }

        #[test]
        fn commit_decode_rejects_wrong_length(bytes in proptest::collection::vec(any::<u8>(), 0..255)) {
            prop_assume!(bytes.len() != 2 + 4 + 32 + 8 + 32 + 8 + 32 + 32 + 8 + 32 + 64);
            prop_assert!(decode_commit(&bytes).is_err());
        }
    }
}
