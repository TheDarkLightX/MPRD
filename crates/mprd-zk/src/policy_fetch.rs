//! Registry-bound policy fetching for proving (fail-fast, fail-closed).
//!
//! Verifiers already enforce:
//! - `policy_epoch/registry_root` pinning, and
//! - policy authorization (by policy_hash and exec kind/version).
//!
//! Production deployments should also enforce these at the *prover/attestor boundary* to avoid:
//! - proving with unauthorized policies,
//! - running with missing policy artifacts,
//! - mismatched exec-kind artifacts.

use crate::policy_artifacts::decode_mpb_policy_artifact_bytes_v1;
use crate::registry_state::{AuthorizedPolicyResolutionV1, PolicyAuthorizationProvider};
use crate::risc0_host::{MpbPolicyArtifactV1, MpbPolicyProvider, TauCompiledPolicyProvider};
use mprd_core::artifact_repo::{
    mst_lookup, BlockId, BlockStore as ArtifactBlockStore, Key, LookupResult,
};
use mprd_core::{Hash32, MprdError, PolicyHash, PolicyRef, Result};
use mprd_risc0_shared::{
    policy_exec_kind_mpb_id_v1, policy_exec_version_id_v1, tau_compiled_policy_hash_v1,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Minimal interface for retrieving raw policy artifact bytes by content ID.
///
/// The store does not need to be trusted; callers MUST validate bytes against the expected
/// hash/exec kind (fail-closed).
pub trait PolicyArtifactStore: Send + Sync {
    fn get(&self, policy_hash: &Hash32) -> Result<Option<Vec<u8>>>;
    fn backend_name(&self) -> &'static str;
}

/// Directory-backed store for policy artifacts.
///
/// Reads files from a directory where filenames are `<hex(policy_hash)>` (no extension).
#[derive(Clone, Debug)]
pub struct DirPolicyArtifactStore {
    root: PathBuf,
}

impl DirPolicyArtifactStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path_for(&self, policy_hash: &Hash32) -> PathBuf {
        self.root.join(hex::encode(policy_hash.0))
    }

    fn read_file(path: &Path) -> Result<Vec<u8>> {
        std::fs::read(path)
            .map_err(|e| MprdError::ExecutionError(format!("failed to read policy artifact: {e}")))
    }
}

impl PolicyArtifactStore for DirPolicyArtifactStore {
    fn get(&self, policy_hash: &Hash32) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(policy_hash);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(Self::read_file(&path)?))
    }

    fn backend_name(&self) -> &'static str {
        "dir"
    }
}

#[derive(Clone, Default)]
pub struct InMemoryPolicyArtifactStore {
    inner: Arc<Mutex<HashMap<Hash32, Vec<u8>>>>,
}

impl InMemoryPolicyArtifactStore {
    pub fn insert(&self, hash: Hash32, bytes: Vec<u8>) -> Result<()> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| MprdError::ExecutionError("policy store mutex poisoned".into()))?;
        g.insert(hash, bytes);
        Ok(())
    }
}

impl PolicyArtifactStore for InMemoryPolicyArtifactStore {
    fn get(&self, policy_hash: &Hash32) -> Result<Option<Vec<u8>>> {
        let g = self
            .inner
            .lock()
            .map_err(|_| MprdError::ExecutionError("policy store mutex poisoned".into()))?;
        Ok(g.get(policy_hash).cloned())
    }

    fn backend_name(&self) -> &'static str {
        "memory"
    }
}

/// Artifact-repo-backed policy artifact store.
///
/// Reads policy artifact bytes from a verified repo root (MST) by key:
/// - `policy/<policy_namespace>/<hex(policy_hash)>`
///
/// This store is untrusted: callers MUST still validate bytes against `policy_hash` and
/// the expected exec kind/version (fail-closed). This type only provides content
/// distribution.
#[derive(Clone)]
pub struct ArtifactRepoPolicyArtifactStore {
    store: Arc<dyn ArtifactBlockStore>,
    repo_root: BlockId,
    policy_namespace: String,
    max_block_fetch: usize,
}

impl ArtifactRepoPolicyArtifactStore {
    pub fn new(
        store: Arc<dyn ArtifactBlockStore>,
        repo_root: BlockId,
        policy_namespace: impl Into<String>,
        max_block_fetch: usize,
    ) -> Self {
        Self {
            store,
            repo_root,
            policy_namespace: policy_namespace.into(),
            max_block_fetch,
        }
    }

    fn key_for(&self, policy_hash: &Hash32) -> Key {
        let mut k = String::with_capacity(7 + self.policy_namespace.len() + 1 + 64);
        k.push_str("policy/");
        k.push_str(&self.policy_namespace);
        k.push('/');
        k.push_str(&hex::encode(policy_hash.0));
        Key::new(k)
    }
}

impl PolicyArtifactStore for ArtifactRepoPolicyArtifactStore {
    fn get(&self, policy_hash: &Hash32) -> Result<Option<Vec<u8>>> {
        let key = self.key_for(policy_hash);
        let result = mst_lookup(
            self.store.as_ref(),
            &self.repo_root,
            &key,
            self.max_block_fetch,
        )
        .map_err(|e| {
            MprdError::ExecutionError(format!(
                "artifact repo policy lookup failed (backend={}): {e}",
                self.backend_name()
            ))
        })?;

        match result {
            LookupResult::Found(p) => Ok(Some(p.value_bytes)),
            LookupResult::NotFound(_) => Ok(None),
        }
    }

    fn backend_name(&self) -> &'static str {
        "artifact_repo"
    }
}

/// Registry-bound MPB policy provider.
///
/// This implements `MpbPolicyProvider` for use by the Risc0 MPB attestor, but refuses to return
/// any policy unless:
/// - the policy is authorized in the verifier-trusted registry state for the configured `policy_ref`, and
/// - the exec kind/version match `mpb-v1`, and
/// - the fetched artifact bytes decode and hash back to the requested `policy_hash`.
pub struct RegistryBoundMpbPolicyProvider {
    policy_ref: PolicyRef,
    authorization: Arc<dyn PolicyAuthorizationProvider>,
    store: Arc<dyn PolicyArtifactStore>,
    cache: Mutex<HashMap<Hash32, MpbPolicyArtifactV1>>,
}

impl RegistryBoundMpbPolicyProvider {
    pub fn new(
        policy_ref: PolicyRef,
        authorization: Arc<dyn PolicyAuthorizationProvider>,
        store: Arc<dyn PolicyArtifactStore>,
    ) -> Self {
        Self {
            policy_ref,
            authorization,
            store,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn resolve(&self, policy_hash: &Hash32) -> Result<AuthorizedPolicyResolutionV1> {
        self.authorization.resolve(policy_hash, &self.policy_ref)
    }
}

impl MpbPolicyProvider for RegistryBoundMpbPolicyProvider {
    fn get(&self, policy_hash: &PolicyHash) -> Option<MpbPolicyArtifactV1> {
        // The provider trait cannot return Result; therefore we must conservatively return None
        // on any failure and rely on the attestor to fail closed with PolicyNotFound.
        let Ok(cache) = self.cache.lock() else {
            return None;
        };
        if let Some(v) = cache.get(policy_hash).cloned() {
            return Some(v);
        }
        drop(cache);

        let resolved = self.resolve(policy_hash).ok()?;
        if resolved.authorized_policy.policy_exec_kind_id != policy_exec_kind_mpb_id_v1()
            || resolved.authorized_policy.policy_exec_version_id != policy_exec_version_id_v1()
        {
            return None;
        }

        let bytes = self.store.get(policy_hash).ok()??;
        let artifact = decode_mpb_policy_artifact_bytes_v1(&bytes).ok()?;

        let refs: Vec<(&[u8], u8)> = artifact
            .variables
            .iter()
            .map(|(name, reg)| (name.as_bytes(), *reg))
            .collect();
        let computed = Hash32(mprd_mpb::policy_hash_v1(&artifact.bytecode, &refs));
        if computed != *policy_hash {
            return None;
        }

        let Ok(mut cache) = self.cache.lock() else {
            return None;
        };
        cache.insert(policy_hash.clone(), artifact.clone());
        Some(artifact)
    }
}

/// Registry-bound tau-compiled policy provider (bytes-only).
pub struct RegistryBoundTauCompiledPolicyProvider {
    policy_ref: PolicyRef,
    authorization: Arc<dyn PolicyAuthorizationProvider>,
    store: Arc<dyn PolicyArtifactStore>,
}

impl RegistryBoundTauCompiledPolicyProvider {
    pub fn new(
        policy_ref: PolicyRef,
        authorization: Arc<dyn PolicyAuthorizationProvider>,
        store: Arc<dyn PolicyArtifactStore>,
    ) -> Self {
        Self {
            policy_ref,
            authorization,
            store,
        }
    }

    pub fn get(&self, policy_hash: &Hash32) -> Result<Vec<u8>> {
        let resolved = self.authorization.resolve(policy_hash, &self.policy_ref)?;
        if resolved.authorized_policy.policy_exec_kind_id
            != mprd_risc0_shared::policy_exec_kind_tau_compiled_id_v1()
            || resolved.authorized_policy.policy_exec_version_id != policy_exec_version_id_v1()
        {
            return Err(MprdError::ZkError(
                "policy_exec_kind/version mismatch for tau_compiled_v1".into(),
            ));
        }
        let bytes = self
            .store
            .get(policy_hash)?
            .ok_or_else(|| MprdError::PolicyNotFound {
                hash: policy_hash.clone(),
            })?;
        let computed = Hash32(tau_compiled_policy_hash_v1(&bytes));
        if computed != *policy_hash {
            return Err(MprdError::ZkError(
                "tau_compiled policy_hash mismatch (artifact tamper)".into(),
            ));
        }
        Ok(bytes)
    }
}

/// Adapter to expose a registry-bound tau-compiled policy fetcher through the legacy
/// `TauCompiledPolicyProvider` trait (which cannot return `Result`).
pub struct RegistryBoundTauCompiledPolicyProviderAdapter {
    inner: RegistryBoundTauCompiledPolicyProvider,
}

impl RegistryBoundTauCompiledPolicyProviderAdapter {
    pub fn new(
        policy_ref: PolicyRef,
        authorization: Arc<dyn PolicyAuthorizationProvider>,
        store: Arc<dyn PolicyArtifactStore>,
    ) -> Self {
        Self {
            inner: RegistryBoundTauCompiledPolicyProvider::new(policy_ref, authorization, store),
        }
    }
}

impl TauCompiledPolicyProvider for RegistryBoundTauCompiledPolicyProviderAdapter {
    fn get(&self, policy_hash: &PolicyHash) -> Option<Vec<u8>> {
        self.inner.get(policy_hash).ok()
    }
}

#[cfg(test)]
mod artifact_repo_store_tests {
    use super::*;
    use mprd_core::artifact_repo::{compute_block_id, encode_blob, mst_insert, MemoryBlockStore};

    #[test]
    fn artifact_repo_policy_store_roundtrip() {
        let store = MemoryBlockStore::new();

        let policy_hash = Hash32([0x11; 32]);
        let policy_bytes = b"policy-artifact-bytes-v1";

        let blob = encode_blob(policy_bytes).unwrap();
        let blob_id = compute_block_id(&blob);
        store.put(blob_id, blob).unwrap();

        let root = mst_insert(
            &store,
            None,
            &Key::new(format!("policy/mpb_v1/{}", hex::encode(policy_hash.0))),
            blob_id,
        )
        .unwrap();

        let repo_store =
            ArtifactRepoPolicyArtifactStore::new(Arc::new(store), root, "mpb_v1", 10_000);

        let got = repo_store.get(&policy_hash).unwrap().expect("present");
        assert_eq!(got, policy_bytes);
        assert!(repo_store.get(&Hash32([0x22; 32])).unwrap().is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{GuestImageEntryV1, GuestImageManifestV1};
    use crate::registry_state::{RegistryStateProvider, RegistryStateV1, SignedRegistryStateV1};
    use mprd_core::{TokenSigningKey, TokenVerifyingKey};
    use mprd_risc0_shared::{policy_exec_kind_mpb_id_v1, policy_exec_version_id_v1};

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn encode_mpb_policy_artifact_bytes_v1(bytecode: &[u8], vars: &[(&str, u8)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(bytecode.len() as u32).to_le_bytes());
        out.extend_from_slice(bytecode);
        out.extend_from_slice(&(vars.len() as u32).to_le_bytes());
        for (name, reg) in vars {
            out.extend_from_slice(&(name.len() as u32).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.push(*reg);
        }
        out
    }

    struct StaticRegistryProvider {
        state: RegistryStateV1,
    }

    impl RegistryStateProvider for StaticRegistryProvider {
        fn get(&self) -> Result<RegistryStateV1> {
            Ok(self.state.clone())
        }
    }

    fn signed_registry_state(
        signer: &TokenSigningKey,
        policy_ref: PolicyRef,
        policy_hash: Hash32,
    ) -> SignedRegistryStateV1 {
        let entries = vec![GuestImageEntryV1 {
            policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            image_id: [1u8; 32],
        }];
        let guest_image_manifest =
            GuestImageManifestV1::sign(signer, 1, entries).expect("manifest sign");

        let state = RegistryStateV1 {
            policy_epoch: policy_ref.policy_epoch,
            registry_root: policy_ref.registry_root,
            authorized_policies: vec![crate::registry_state::AuthorizedPolicyV1 {
                policy_hash,
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: None,
                policy_source_hash: None,
            }],
            guest_image_manifest,
        };

        let mut signed = SignedRegistryStateV1 {
            registry_state_version: crate::registry_state::REGISTRY_STATE_VERSION,
            state,
            signed_at_ms: 1,
            signer_pubkey: signer.verifying_key().to_bytes(),
            signature: Vec::new(),
        };
        signed.signature = signer
            .sign_bytes(&signed.signing_bytes_v1().unwrap())
            .to_vec();
        signed
    }

    #[test]
    fn registry_bound_mpb_provider_returns_none_for_unauthorized_policy() {
        let signer = TokenSigningKey::from_seed(&[11u8; 32]);
        let manifest_vk =
            TokenVerifyingKey::from_bytes(&signer.verifying_key().to_bytes()).expect("vk");

        // Registry authorizes policy A only.
        let policy_ref = PolicyRef {
            policy_epoch: 7,
            registry_root: dummy_hash(9),
        };
        let policy_a = dummy_hash(1);
        let signed = signed_registry_state(&signer, policy_ref.clone(), policy_a);

        let provider = StaticRegistryProvider {
            state: signed.state,
        };
        let auth = Arc::new(
            crate::registry_state::RegistryStatePolicyAuthorizationProvider::new(
                Arc::new(provider),
                manifest_vk,
            ),
        );

        let store = Arc::new(InMemoryPolicyArtifactStore::default());
        let mpb = RegistryBoundMpbPolicyProvider::new(policy_ref, auth, store);

        // Query a different policy hash => None (fail-closed).
        let out = mpb.get(&dummy_hash(2));
        assert!(out.is_none());
    }

    #[test]
    fn registry_bound_mpb_provider_decodes_and_verifies_hash() {
        let signer = TokenSigningKey::from_seed(&[12u8; 32]);
        let manifest_vk =
            TokenVerifyingKey::from_bytes(&signer.verifying_key().to_bytes()).expect("vk");

        let policy_ref = PolicyRef {
            policy_epoch: 7,
            registry_root: dummy_hash(9),
        };

        let bytes = encode_mpb_policy_artifact_bytes_v1(&[0xFF], &[("a", 0)]);
        let computed = {
            let refs: Vec<(&[u8], u8)> = vec![("a".as_bytes(), 0)];
            Hash32(mprd_mpb::policy_hash_v1(&[0xFF], &refs))
        };

        let signed = signed_registry_state(&signer, policy_ref.clone(), computed.clone());
        let provider = StaticRegistryProvider {
            state: signed.state,
        };
        let auth = Arc::new(
            crate::registry_state::RegistryStatePolicyAuthorizationProvider::new(
                Arc::new(provider),
                manifest_vk,
            ),
        );

        let store = Arc::new(InMemoryPolicyArtifactStore::default());
        store.insert(computed.clone(), bytes).expect("insert");

        let mpb = RegistryBoundMpbPolicyProvider::new(policy_ref, auth, store);
        let out = mpb.get(&computed).expect("expected policy");
        assert_eq!(out.bytecode, vec![0xFF]);
        assert_eq!(out.variables, vec![("a".to_string(), 0)]);
    }
}
