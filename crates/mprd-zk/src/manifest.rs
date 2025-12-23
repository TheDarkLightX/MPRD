//! Signed guest image manifest (production deployment artifact).
//!
//! The manifest maps `(policy_exec_kind_id, policy_exec_version_id) -> image_id` and is intended
//! to be distributed and pinned by verifiers so image routing does not depend on any host-provided
//! hints.

use mprd_core::{MprdError, Result, TokenSigningKey, TokenVerifyingKey};
use mprd_risc0_shared::{Id32, JOURNAL_VERSION};
use serde::{Deserialize, Serialize};

/// Manifest schema version.
pub const MANIFEST_VERSION: u32 = 1;

/// Domain separation for manifest signatures.
pub const MANIFEST_DOMAIN_V1: &[u8] = b"MPRD_GUEST_IMAGE_MANIFEST_V1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestImageEntryV1 {
    pub policy_exec_kind_id: Id32,
    pub policy_exec_version_id: Id32,
    pub image_id: Id32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestImageManifestV1 {
    pub manifest_version: u32,
    /// Intended journal ABI version (fail-closed informational pin).
    pub journal_version: u32,
    pub entries: Vec<GuestImageEntryV1>,
    pub signed_at_ms: i64,
    /// Public key used to sign this manifest (ed25519).
    pub signer_pubkey: [u8; 32],
    /// Signature over canonical `signing_bytes_v1()`.
    pub signature: Vec<u8>,
}

impl GuestImageManifestV1 {
    pub fn signing_bytes_v1(&self) -> Result<Vec<u8>> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err(MprdError::InvalidInput(
                "unsupported manifest_version".into(),
            ));
        }
        if self.journal_version != JOURNAL_VERSION {
            return Err(MprdError::InvalidInput(
                "unsupported journal_version in manifest".into(),
            ));
        }

        let mut entries = self.entries.clone();
        entries.sort_by(|a, b| {
            a.policy_exec_kind_id
                .cmp(&b.policy_exec_kind_id)
                .then(a.policy_exec_version_id.cmp(&b.policy_exec_version_id))
        });

        // Fail-closed: require entries already canonical (sorted, unique).
        if entries != self.entries {
            return Err(MprdError::InvalidInput(
                "manifest entries must be sorted and canonical".into(),
            ));
        }
        for w in entries.windows(2) {
            if w[0].policy_exec_kind_id == w[1].policy_exec_kind_id
                && w[0].policy_exec_version_id == w[1].policy_exec_version_id
            {
                return Err(MprdError::InvalidInput(
                    "duplicate (exec_kind, exec_version) in manifest".into(),
                ));
            }
        }

        let mut out = Vec::with_capacity(64 + entries.len() * 96);
        out.extend_from_slice(MANIFEST_DOMAIN_V1);
        out.extend_from_slice(&self.manifest_version.to_le_bytes());
        out.extend_from_slice(&self.journal_version.to_le_bytes());
        out.extend_from_slice(&self.signed_at_ms.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for e in entries {
            out.extend_from_slice(&e.policy_exec_kind_id);
            out.extend_from_slice(&e.policy_exec_version_id);
            out.extend_from_slice(&e.image_id);
        }
        Ok(out)
    }

    pub fn verify_with_key(&self, vk: &TokenVerifyingKey) -> Result<()> {
        if vk.to_bytes() != self.signer_pubkey {
            return Err(MprdError::SignatureInvalid(
                "manifest signer_pubkey does not match expected key".into(),
            ));
        }
        let msg = self.signing_bytes_v1()?;
        vk.verify_bytes(&msg, &self.signature)?;
        Ok(())
    }

    pub fn image_id_for(&self, exec_kind: &Id32, exec_version: &Id32) -> Option<Id32> {
        self.entries
            .iter()
            .find(|e| {
                &e.policy_exec_kind_id == exec_kind && &e.policy_exec_version_id == exec_version
            })
            .map(|e| e.image_id)
    }

    pub fn sign(
        signing_key: &TokenSigningKey,
        signed_at_ms: i64,
        mut entries: Vec<GuestImageEntryV1>,
    ) -> Result<Self> {
        entries.sort_by(|a, b| {
            a.policy_exec_kind_id
                .cmp(&b.policy_exec_kind_id)
                .then(a.policy_exec_version_id.cmp(&b.policy_exec_version_id))
        });

        let signer_pubkey = signing_key.verifying_key().to_bytes();
        let mut m = Self {
            manifest_version: MANIFEST_VERSION,
            journal_version: JOURNAL_VERSION,
            entries,
            signed_at_ms,
            signer_pubkey,
            signature: Vec::new(),
        };
        let msg = m.signing_bytes_v1()?;
        m.signature = signing_key.sign_bytes(&msg).to_vec();
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mprd_risc0_shared::{policy_exec_kind_mpb_id_v1, policy_exec_version_id_v1};

    #[test]
    fn manifest_roundtrip_sign_and_verify() {
        let key = TokenSigningKey::from_seed(&[1u8; 32]);
        let vk = key.verifying_key();
        let entries = vec![GuestImageEntryV1 {
            policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            image_id: [7u8; 32],
        }];

        let m = GuestImageManifestV1::sign(&key, 123, entries).expect("sign");
        m.verify_with_key(&vk).expect("verify");
        assert_eq!(
            m.image_id_for(&policy_exec_kind_mpb_id_v1(), &policy_exec_version_id_v1()),
            Some([7u8; 32])
        );
    }

    #[test]
    fn manifest_rejects_unsorted_entries() {
        let key = TokenSigningKey::from_seed(&[2u8; 32]);
        let vk = key.verifying_key();
        let a = GuestImageEntryV1 {
            policy_exec_kind_id: [2u8; 32],
            policy_exec_version_id: [1u8; 32],
            image_id: [7u8; 32],
        };
        let b = GuestImageEntryV1 {
            policy_exec_kind_id: [1u8; 32],
            policy_exec_version_id: [1u8; 32],
            image_id: [8u8; 32],
        };

        // Sign produces canonical order.
        let m = GuestImageManifestV1::sign(&key, 123, vec![a.clone(), b.clone()]).expect("sign");
        m.verify_with_key(&vk).expect("verify");

        // Malformed manifest with unsorted entries fails.
        let mut malformed = m.clone();
        malformed.entries = vec![a, b]; // unsorted
        assert!(malformed.verify_with_key(&vk).is_err());
    }
}
