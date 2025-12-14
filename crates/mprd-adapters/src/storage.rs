//! Policy Storage Adapters
//!
//! This module provides storage backends for MPRD policies:
//!
//! - **LocalPolicyStorage**: File-based storage for development
//! - **IpfsPolicyStorage**: Content-addressed storage via IPFS
//!
//! # Content Addressing
//!
//! Policies are stored by their hash, ensuring:
//! 1. Immutability: A hash always refers to the same policy
//! 2. Integrity: Corruption is detectable
//! 3. Deduplication: Identical policies share storage

use mprd_core::{Hash32, MprdError, PolicyHash, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::egress;

// =============================================================================
// Policy Storage Trait
// =============================================================================

/// Trait for storing and retrieving policies by hash.
///
/// Implementations must ensure:
/// - `store` returns a hash that can later retrieve the same bytes
/// - `retrieve` returns `None` only if the hash was never stored
/// - Content is immutable once stored
pub trait PolicyStorage: Send + Sync {
    /// Store a policy and return its hash.
    fn store(&self, policy_bytes: &[u8]) -> Result<PolicyHash>;

    /// Retrieve a policy by its hash.
    fn retrieve(&self, hash: &PolicyHash) -> Result<Option<Vec<u8>>>;

    /// Check if a policy exists without retrieving it.
    fn exists(&self, hash: &PolicyHash) -> Result<bool>;

    /// List all stored policy hashes.
    fn list(&self) -> Result<Vec<PolicyHash>>;
}

// =============================================================================
// Local File Storage
// =============================================================================

/// File-based policy storage for development and testing.
///
/// Policies are stored as files named by their hex-encoded hash.
pub struct LocalPolicyStorage {
    base_dir: PathBuf,
    cache: Arc<RwLock<HashMap<PolicyHash, Vec<u8>>>>,
}

impl LocalPolicyStorage {
    /// Create a new local storage at the given directory.
    pub fn new(base_dir: impl Into<PathBuf>) -> Result<Self> {
        let base_dir = base_dir.into();
        fs::create_dir_all(&base_dir)
            .map_err(|e| MprdError::ConfigError(format!("Failed to create storage dir: {}", e)))?;

        Ok(Self {
            base_dir,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get the file path for a policy hash.
    fn path_for(&self, hash: &PolicyHash) -> PathBuf {
        self.base_dir
            .join(format!("{}.policy", hex::encode(hash.0)))
    }

    /// Compute the hash of policy bytes.
    fn compute_hash(bytes: &[u8]) -> PolicyHash {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"MPRD_POLICY_V1");
        hasher.update(bytes);
        Hash32(hasher.finalize().into())
    }
}

fn verify_policy_hash_matches_expected(expected: &PolicyHash, policy_bytes: &[u8]) -> Result<()> {
    let computed = LocalPolicyStorage::compute_hash(policy_bytes);
    if computed == *expected {
        return Ok(());
    }
    Err(MprdError::ConfigError(format!(
        "Policy hash mismatch: expected {}, got {}",
        hex::encode(expected.0),
        hex::encode(computed.0)
    )))
}

impl PolicyStorage for LocalPolicyStorage {
    fn store(&self, policy_bytes: &[u8]) -> Result<PolicyHash> {
        let hash = Self::compute_hash(policy_bytes);
        let path = self.path_for(&hash);

        // Skip if already exists (content-addressed dedup)
        if path.exists() {
            return Ok(hash);
        }

        // Write to file
        let mut file = File::create(&path)
            .map_err(|e| MprdError::ConfigError(format!("Failed to create policy file: {}", e)))?;

        file.write_all(policy_bytes)
            .map_err(|e| MprdError::ConfigError(format!("Failed to write policy: {}", e)))?;

        // Update cache
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(hash.clone(), policy_bytes.to_vec());
        }

        Ok(hash)
    }

    fn retrieve(&self, hash: &PolicyHash) -> Result<Option<Vec<u8>>> {
        // Check cache first
        if let Ok(cache) = self.cache.read() {
            if let Some(bytes) = cache.get(hash) {
                return Ok(Some(bytes.clone()));
            }
        }

        // Read from file
        let path = self.path_for(hash);
        if !path.exists() {
            return Ok(None);
        }

        let mut file = File::open(&path)
            .map_err(|e| MprdError::ConfigError(format!("Failed to open policy file: {}", e)))?;

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| MprdError::ConfigError(format!("Failed to read policy: {}", e)))?;

        // Verify hash
        let computed = Self::compute_hash(&bytes);
        if computed != *hash {
            return Err(MprdError::ConfigError(format!(
                "Policy hash mismatch: expected {}, got {}",
                hex::encode(hash.0),
                hex::encode(computed.0)
            )));
        }

        // Update cache
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(hash.clone(), bytes.clone());
        }

        Ok(Some(bytes))
    }

    fn exists(&self, hash: &PolicyHash) -> Result<bool> {
        Ok(self.path_for(hash).exists())
    }

    fn list(&self) -> Result<Vec<PolicyHash>> {
        let mut hashes = Vec::new();

        let entries = fs::read_dir(&self.base_dir)
            .map_err(|e| MprdError::ConfigError(format!("Failed to read storage dir: {}", e)))?;

        for entry in entries {
            let entry = entry
                .map_err(|e| MprdError::ConfigError(format!("Failed to read entry: {}", e)))?;

            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if name_str.ends_with(".policy") {
                let hex_str = name_str.trim_end_matches(".policy");
                if let Ok(bytes) = hex::decode(hex_str) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        hashes.push(Hash32(arr));
                    }
                }
            }
        }

        Ok(hashes)
    }
}

// =============================================================================
// IPFS Storage
// =============================================================================

/// Configuration for IPFS storage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpfsConfig {
    /// IPFS API endpoint (e.g., "http://localhost:5001").
    pub api_url: String,

    /// Timeout in milliseconds.
    pub timeout_ms: u64,

    /// Pin files after adding.
    pub pin: bool,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            api_url: "http://localhost:5001".into(),
            timeout_ms: 30000,
            pin: true,
        }
    }
}

/// IPFS-backed policy storage.
///
/// Uses IPFS content addressing for immutable, distributed policy storage.
/// Note: IPFS CIDs don't match our SHA256 hashes, so we maintain a mapping.
pub struct IpfsPolicyStorage {
    config: IpfsConfig,
    client: reqwest::blocking::Client,
    /// Maps our policy hash to IPFS CID.
    hash_to_cid: Arc<RwLock<HashMap<PolicyHash, String>>>,
    /// Local fallback storage.
    local: LocalPolicyStorage,
}

impl IpfsPolicyStorage {
    /// Create a new IPFS storage with local fallback.
    pub fn new(config: IpfsConfig, local_fallback_dir: impl Into<PathBuf>) -> Result<Self> {
        egress::validate_outbound_url(&config.api_url)?;
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| MprdError::ConfigError(format!("Failed to create IPFS client: {}", e)))?;

        let local = LocalPolicyStorage::new(local_fallback_dir)?;

        Ok(Self {
            config,
            client,
            hash_to_cid: Arc::new(RwLock::new(HashMap::new())),
            local,
        })
    }

    /// Add content to IPFS and return the CID.
    fn ipfs_add(&self, bytes: &[u8]) -> Result<String> {
        let url = format!("{}/api/v0/add", self.config.api_url);

        // IPFS expects multipart form data
        let form = reqwest::blocking::multipart::Form::new().part(
            "file",
            reqwest::blocking::multipart::Part::bytes(bytes.to_vec()).file_name("policy"),
        );

        let response = self
            .client
            .post(&url)
            .multipart(form)
            .send()
            .map_err(|e| MprdError::ConfigError(format!("IPFS add failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(MprdError::ConfigError(format!(
                "IPFS add returned {}",
                response.status()
            )));
        }

        #[derive(Deserialize)]
        struct IpfsAddResponse {
            #[serde(rename = "Hash")]
            hash: String,
        }

        let resp: IpfsAddResponse = response
            .json()
            .map_err(|e| MprdError::ConfigError(format!("Failed to parse IPFS response: {}", e)))?;

        // Pin if configured
        if self.config.pin {
            let pin_url = format!("{}/api/v0/pin/add?arg={}", self.config.api_url, resp.hash);
            let _ = self.client.post(&pin_url).send();
        }

        Ok(resp.hash)
    }

    /// Get content from IPFS by CID.
    fn ipfs_cat(&self, cid: &str) -> Result<Vec<u8>> {
        let url = format!("{}/api/v0/cat?arg={}", self.config.api_url, cid);

        let response = self
            .client
            .post(&url)
            .send()
            .map_err(|e| MprdError::ConfigError(format!("IPFS cat failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(MprdError::ConfigError(format!(
                "IPFS cat returned {}",
                response.status()
            )));
        }

        response
            .bytes()
            .map(|b| b.to_vec())
            .map_err(|e| MprdError::ConfigError(format!("Failed to read IPFS content: {}", e)))
    }
}

impl PolicyStorage for IpfsPolicyStorage {
    fn store(&self, policy_bytes: &[u8]) -> Result<PolicyHash> {
        // Always store locally first
        let hash = self.local.store(policy_bytes)?;

        // Try to add to IPFS
        match self.ipfs_add(policy_bytes) {
            Ok(cid) => {
                if let Ok(mut mapping) = self.hash_to_cid.write() {
                    mapping.insert(hash.clone(), cid);
                }
            }
            Err(e) => {
                tracing::warn!("IPFS add failed, using local only: {}", e);
            }
        }

        Ok(hash)
    }

    fn retrieve(&self, hash: &PolicyHash) -> Result<Option<Vec<u8>>> {
        // Try IPFS first if we have a CID mapping
        if let Ok(mapping) = self.hash_to_cid.read() {
            if let Some(cid) = mapping.get(hash) {
                match self.ipfs_cat(cid) {
                    Ok(bytes) => {
                        if let Err(e) = verify_policy_hash_matches_expected(hash, &bytes) {
                            tracing::warn!(
                                "IPFS content hash mismatch; refusing IPFS bytes and falling back to local: {}",
                                e
                            );
                        } else {
                            return Ok(Some(bytes));
                        }
                    }
                    Err(e) => {
                        tracing::warn!("IPFS cat failed, falling back to local: {}", e);
                    }
                }
            }
        }

        // Fall back to local
        self.local.retrieve(hash)
    }

    fn exists(&self, hash: &PolicyHash) -> Result<bool> {
        // Check local (faster)
        if self.local.exists(hash)? {
            return Ok(true);
        }

        // Check IPFS mapping
        if let Ok(mapping) = self.hash_to_cid.read() {
            return Ok(mapping.contains_key(hash));
        }

        Ok(false)
    }

    fn list(&self) -> Result<Vec<PolicyHash>> {
        self.local.list()
    }
}

// =============================================================================
// In-Memory Storage (Testing)
// =============================================================================

/// In-memory storage for testing.
pub struct InMemoryPolicyStorage {
    policies: Arc<RwLock<HashMap<PolicyHash, Vec<u8>>>>,
}

impl InMemoryPolicyStorage {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryPolicyStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyStorage for InMemoryPolicyStorage {
    fn store(&self, policy_bytes: &[u8]) -> Result<PolicyHash> {
        let hash = LocalPolicyStorage::compute_hash(policy_bytes);

        // SECURITY: Propagate lock errors instead of silently ignoring
        let mut policies = self
            .policies
            .write()
            .map_err(|_| MprdError::ConfigError("Policy storage lock poisoned".into()))?;

        policies.insert(hash.clone(), policy_bytes.to_vec());
        Ok(hash)
    }

    fn retrieve(&self, hash: &PolicyHash) -> Result<Option<Vec<u8>>> {
        let policies = self
            .policies
            .read()
            .map_err(|_| MprdError::ConfigError("Policy storage lock poisoned".into()))?;
        Ok(policies.get(hash).cloned())
    }

    fn exists(&self, hash: &PolicyHash) -> Result<bool> {
        let policies = self
            .policies
            .read()
            .map_err(|_| MprdError::ConfigError("Policy storage lock poisoned".into()))?;
        Ok(policies.contains_key(hash))
    }

    fn list(&self) -> Result<Vec<PolicyHash>> {
        let policies = self
            .policies
            .read()
            .map_err(|_| MprdError::ConfigError("Policy storage lock poisoned".into()))?;
        Ok(policies.keys().cloned().collect())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_storage_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("mprd_storage_test_{}", std::process::id()));
        let storage = LocalPolicyStorage::new(&temp_dir).unwrap();

        let policy = b"test policy content";
        let hash = storage.store(policy).unwrap();

        let retrieved = storage.retrieve(&hash).unwrap().unwrap();
        assert_eq!(retrieved, policy);

        assert!(storage.exists(&hash).unwrap());

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn in_memory_storage_works() {
        let storage = InMemoryPolicyStorage::new();

        let policy = b"another test policy";
        let hash = storage.store(policy).unwrap();

        let retrieved = storage.retrieve(&hash).unwrap().unwrap();
        assert_eq!(retrieved, policy);

        let list = storage.list().unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn storage_is_content_addressed() {
        let storage = InMemoryPolicyStorage::new();

        let policy = b"same content";
        let hash1 = storage.store(policy).unwrap();
        let hash2 = storage.store(policy).unwrap();

        // Same content = same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn verify_policy_hash_matches_expected_fails_closed_on_mismatch() {
        let policy_a = b"policy-a";
        let policy_b = b"policy-b";

        let hash_a = LocalPolicyStorage::compute_hash(policy_a);
        let result = verify_policy_hash_matches_expected(&hash_a, policy_b);
        assert!(result.is_err());
    }
}
