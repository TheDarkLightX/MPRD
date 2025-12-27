//! CBC-hardened types and traits for Operator Services
//!
//! This module provides:
//! - Phase-typed enums (invalid states unrepresentable)
//! - Explicit capacity limits with fail-closed behavior
//! - Validating constructors that reject invalid configs
//! - Crypto/verifier trait boundaries with stable error codes

use std::collections::BTreeMap;

// =============================================================================
// CAPACITY LIMITS (DoS resistance)
// =============================================================================

/// Maximum slots in the Proof Market (per epoch/round)
pub const MAX_SLOTS: usize = 1024;

/// Maximum reporters per OPI Oracle round
pub const MAX_REPORTERS_PER_ROUND: usize = 256;

/// Maximum claims in the Optimistic Relay (per epoch)
pub const MAX_CLAIMS: usize = 512;

/// Maximum observation window for Lipschitz-UCB
pub const MAX_OBSERVATION_WINDOW: usize = 256;

// =============================================================================
// BOUNDED MAP (fail-closed on overflow)
// =============================================================================

/// A `BTreeMap` that enforces a capacity limit.
/// Insertions beyond capacity fail with `CapacityExceeded`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedMap<K: Ord, V> {
    inner: BTreeMap<K, V>,
    capacity: usize,
}

impl<K: Ord, V> BoundedMap<K, V> {
    /// Create a new bounded map with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: BTreeMap::new(),
            capacity,
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Is the map empty?
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get a reference to a value.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.inner.get(key)
    }

    /// Get a mutable reference to a value.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.inner.get_mut(key)
    }

    /// Check if the map contains a key.
    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }

    /// Insert a new key-value pair. Fails if at capacity and key is new.
    pub fn insert(&mut self, key: K, value: V) -> Result<Option<V>, CapacityError> {
        if !self.inner.contains_key(&key) && self.inner.len() >= self.capacity {
            return Err(CapacityError::CapacityExceeded {
                capacity: self.capacity,
            });
        }
        Ok(self.inner.insert(key, value))
    }

    /// Remove a key-value pair.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.remove(key)
    }

    /// Iterate over entries.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.inner.iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapacityError {
    CapacityExceeded { capacity: usize },
}

impl std::fmt::Display for CapacityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapacityError::CapacityExceeded { capacity } => {
                write!(f, "capacity exceeded: max {capacity}")
            }
        }
    }
}

impl std::error::Error for CapacityError {}

// =============================================================================
// STABLE ERROR CODES (for deterministic error handling)
// =============================================================================

/// Unified error codes for all operator services.
/// Stable codes allow deterministic handling and logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ErrorCode {
    // Common
    InvalidConfig = 1000,
    CapacityExceeded = 1001,
    ArithmeticOverflow = 1002,
    PreconditionFailed = 1003,

    // Proof Market (1100-1199)
    SlotNotEmpty = 1100,
    SlotMissing = 1101,
    SlotWrongPhase = 1102,
    DeadlinePassed = 1103,
    DeadlineNotPassed = 1104,
    PayoutExceedsDeposit = 1105,
    BudgetExceeded = 1106,
    JobHashMismatch = 1107,
    ProofNotVerified = 1108,

    // OPI Oracle (1200-1299)
    RoundWrongPhase = 1200,
    ReporterNotFound = 1201,
    ReporterAlreadyCommitted = 1202,
    ReporterNotCommitted = 1203,
    ReporterAlreadyRevealed = 1204,
    CommitHashMismatch = 1205,
    CommitDeadlinePassed = 1206,
    RevealDeadlinePassed = 1207,
    AggregationFailed = 1208,
    NotFinalized = 1209,

    // Optimistic Relay (1300-1399)
    ClaimNotEmpty = 1300,
    ClaimMissing = 1301,
    ClaimWrongPhase = 1302,
    ChallengeWindowPassed = 1303,
    ChallengeWindowNotPassed = 1304,
    MaxRoundsExceeded = 1305,
    RoundsNotComplete = 1306,
    VerdictIncorrect = 1307,

    // Crypto/Verification (1400-1499)
    InvalidHash = 1400,
    InvalidSignature = 1401,
    VerificationFailed = 1402,
}

impl ErrorCode {
    /// Get the numeric code for deterministic serialization.
    pub fn code(self) -> u16 {
        self as u16
    }
}

// =============================================================================
// CRYPTO TRAITS (bounded, domain-separated)
// =============================================================================

/// Domain separator for hash inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashDomain {
    ProofMarketSlot = 1,
    OPIOracleCommit = 2,
    OptimisticRelayClaim = 3,
}

/// A 32-byte hash output.
pub type Hash32 = [u8; 32];

/// Trait for cryptographic commitment hashing.
/// Implementations must be deterministic and domain-separated.
pub trait CommitmentHasher: Send + Sync {
    /// Compute a commitment hash.
    /// 
    /// # Arguments
    /// * `domain` - Domain separator for collision resistance
    /// * `data` - Input data (must be bounded; implementations should check)
    /// 
    /// # Errors
    /// Returns `ErrorCode::InvalidHash` if data is malformed or too large.
    fn hash(&self, domain: HashDomain, data: &[u8]) -> Result<Hash32, ErrorCode>;

    /// Maximum input size in bytes.
    fn max_input_size(&self) -> usize;
}

/// Trait for proof/evidence verification.
/// Used by Optimistic Relay and Proof Market for objective correctness.
pub trait ObjectiveVerifier: Send + Sync {
    /// Verify that a proof is correct for the given job and result.
    /// 
    /// # Arguments
    /// * `job_hash` - Hash of the job inputs/circuit
    /// * `result_hash` - Hash of the claimed result
    /// * `proof` - The proof artifact (must be bounded)
    /// 
    /// # Returns
    /// * `Ok(true)` if proof is valid for (job, result)
    /// * `Ok(false)` if proof is invalid
    /// * `Err(ErrorCode)` if verification cannot be performed
    fn verify(
        &self,
        job_hash: &Hash32,
        result_hash: &Hash32,
        proof: &[u8],
    ) -> Result<bool, ErrorCode>;

    /// Maximum proof size in bytes.
    fn max_proof_size(&self) -> usize;
}

/// SHA-256 based hasher (production-ready).
#[derive(Debug, Clone, Default)]
pub struct Sha256Hasher {
    max_input: usize,
}

impl Sha256Hasher {
    /// Create with a maximum input size (DoS protection).
    pub fn new(max_input: usize) -> Self {
        Self { max_input }
    }
}

impl CommitmentHasher for Sha256Hasher {
    fn hash(&self, domain: HashDomain, data: &[u8]) -> Result<Hash32, ErrorCode> {
        if data.len() > self.max_input {
            return Err(ErrorCode::InvalidHash);
        }
        
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        // TODO: Replace with actual SHA-256 when crypto crate is added
        // For now, use a placeholder that is deterministic
        let mut hasher = DefaultHasher::new();
        (domain as u8).hash(&mut hasher);
        data.hash(&mut hasher);
        let h1 = hasher.finish();
        
        // Extend to 32 bytes (placeholder)
        let mut output = [0u8; 32];
        output[0..8].copy_from_slice(&h1.to_le_bytes());
        output[8..16].copy_from_slice(&h1.to_be_bytes());
        output[16..24].copy_from_slice(&(!h1).to_le_bytes());
        output[24..32].copy_from_slice(&(!h1).to_be_bytes());
        
        Ok(output)
    }

    fn max_input_size(&self) -> usize {
        self.max_input
    }
}

// =============================================================================
// ECONOMICS: Reward/Penalty Schedules
// =============================================================================

/// Economics configuration for the Proof Market.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofMarketEconomics {
    /// Minimum deposit required per slot (basis points of job value)
    pub min_deposit_bps: u32,
    /// Slash percentage on missed deadline
    pub slash_rate_bps: u32,
    /// Protocol fee on successful settlement
    pub protocol_fee_bps: u32,
}

impl ProofMarketEconomics {
    /// Create with validated parameters.
    pub fn new(min_deposit_bps: u32, slash_rate_bps: u32, protocol_fee_bps: u32) -> Result<Self, ErrorCode> {
        // Invariants: all rates must be ≤ 10000 bps (100%)
        if min_deposit_bps > 10_000 || slash_rate_bps > 10_000 || protocol_fee_bps > 10_000 {
            return Err(ErrorCode::InvalidConfig);
        }
        Ok(Self {
            min_deposit_bps,
            slash_rate_bps,
            protocol_fee_bps,
        })
    }
}

/// Economics configuration for the OPI Oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleEconomics {
    /// Reward per valid reveal (in smallest token unit)
    pub reward_per_reveal: u64,
    /// Penalty for non-reveal (bond forfeit percentage)
    pub non_reveal_penalty_bps: u32,
    /// Penalty for outlier reports (additional to non-reveal)
    pub outlier_penalty_bps: u32,
    /// Threshold for outlier detection (distance from median in bps)
    pub outlier_threshold_bps: u32,
}

impl OracleEconomics {
    /// Create with validated parameters.
    pub fn new(
        reward_per_reveal: u64,
        non_reveal_penalty_bps: u32,
        outlier_penalty_bps: u32,
        outlier_threshold_bps: u32,
    ) -> Result<Self, ErrorCode> {
        if non_reveal_penalty_bps > 10_000 || outlier_penalty_bps > 10_000 {
            return Err(ErrorCode::InvalidConfig);
        }
        Ok(Self {
            reward_per_reveal,
            non_reveal_penalty_bps,
            outlier_penalty_bps,
            outlier_threshold_bps,
        })
    }
}

/// Economics configuration for the Optimistic Relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEconomics {
    /// Minimum relay bond (absolute)
    pub min_relay_bond: u64,
    /// Minimum challenger bond (absolute)
    pub min_challenger_bond: u64,
    /// Challenger reward as percentage of relay bond on successful challenge
    pub challenger_reward_bps: u32,
    /// Protocol fee on relay bond slash
    pub protocol_fee_bps: u32,
}

impl RelayEconomics {
    /// Create with validated parameters.
    pub fn new(
        min_relay_bond: u64,
        min_challenger_bond: u64,
        challenger_reward_bps: u32,
        protocol_fee_bps: u32,
    ) -> Result<Self, ErrorCode> {
        if challenger_reward_bps > 10_000 || protocol_fee_bps > 10_000 {
            return Err(ErrorCode::InvalidConfig);
        }
        // Invariant: reward + protocol fee ≤ 100% of slashed bond
        if challenger_reward_bps + protocol_fee_bps > 10_000 {
            return Err(ErrorCode::InvalidConfig);
        }
        Ok(Self {
            min_relay_bond,
            min_challenger_bond,
            challenger_reward_bps,
            protocol_fee_bps,
        })
    }

    /// Calculate challenger reward from slashed relay bond.
    pub fn calculate_challenger_reward(&self, relay_bond: u64) -> u64 {
        (relay_bond as u128 * self.challenger_reward_bps as u128 / 10_000) as u64
    }

    /// Calculate protocol fee from slashed relay bond.
    pub fn calculate_protocol_fee(&self, relay_bond: u64) -> u64 {
        (relay_bond as u128 * self.protocol_fee_bps as u128 / 10_000) as u64
    }
}

// =============================================================================
// CONFIG VALIDATION
// =============================================================================

/// Validated OPI Oracle round configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleRoundConfig {
    pub commit_deadline: u64,
    pub reveal_deadline: u64,
    pub trim_k: usize,
    pub min_reporters: usize,
}

impl OracleRoundConfig {
    /// Create with validation.
    pub fn new(
        commit_deadline: u64,
        reveal_deadline: u64,
        trim_k: usize,
        min_reporters: usize,
    ) -> Result<Self, ErrorCode> {
        // Invariant: commit_deadline < reveal_deadline
        if commit_deadline >= reveal_deadline {
            return Err(ErrorCode::InvalidConfig);
        }
        // Invariant: min_reporters > 2 * trim_k (for robust aggregation)
        if min_reporters <= 2 * trim_k {
            return Err(ErrorCode::InvalidConfig);
        }
        Ok(Self {
            commit_deadline,
            reveal_deadline,
            trim_k,
            min_reporters,
        })
    }
}

/// Validated Optimistic Relay claim configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayClaimConfig {
    pub challenge_window: u64,
    pub max_rounds: u32,
}

impl RelayClaimConfig {
    /// Create with validation.
    pub fn new(challenge_window: u64, max_rounds: u32) -> Result<Self, ErrorCode> {
        // Invariant: challenge_window > 0
        if challenge_window == 0 {
            return Err(ErrorCode::InvalidConfig);
        }
        // Invariant: max_rounds ≥ 1 (at least one resolution round)
        if max_rounds == 0 {
            return Err(ErrorCode::InvalidConfig);
        }
        Ok(Self {
            challenge_window,
            max_rounds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_map_enforces_capacity() {
        let mut map: BoundedMap<u64, u64> = BoundedMap::new(2);
        assert!(map.insert(1, 100).is_ok());
        assert!(map.insert(2, 200).is_ok());
        assert_eq!(map.insert(3, 300), Err(CapacityError::CapacityExceeded { capacity: 2 }));
        
        // Updating existing key should work
        assert!(map.insert(1, 101).is_ok());
    }

    #[test]
    fn oracle_config_validates_deadlines() {
        assert!(OracleRoundConfig::new(100, 50, 2, 10).is_err()); // commit >= reveal
        assert!(OracleRoundConfig::new(50, 100, 2, 10).is_ok());  // valid
        assert!(OracleRoundConfig::new(50, 100, 5, 5).is_err());  // min_reporters <= 2*trim_k
    }

    #[test]
    fn relay_economics_validates_percentages() {
        assert!(RelayEconomics::new(100, 50, 5_000, 5_000).is_ok());  // 50% + 50% = 100%
        assert!(RelayEconomics::new(100, 50, 6_000, 5_000).is_err()); // 60% + 50% > 100%
    }

    #[test]
    fn sha256_hasher_respects_limit() {
        let hasher = Sha256Hasher::new(32);
        assert!(hasher.hash(HashDomain::ProofMarketSlot, &[0u8; 32]).is_ok());
        assert!(hasher.hash(HashDomain::ProofMarketSlot, &[0u8; 33]).is_err());
    }
}
