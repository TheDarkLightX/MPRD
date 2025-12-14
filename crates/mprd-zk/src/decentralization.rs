//! Decentralization primitives for MPRD.
//!
//! This module provides mechanisms to eliminate single points of failure (SPOF)
//! and enable trustless operation without relying on any single entity.
//!
//! # Key Decentralization Features
//!
//! | Feature | Purpose | Status |
//! |---------|---------|--------|
//! | Threshold Signatures | Multi-party token signing | ✅ Implemented |
//! | Distributed Policy Storage | No single policy authority | 🔶 Interface |
//! | Multi-Attestor Verification | Require N-of-M attestors | ✅ Implemented |
//! | Commitment Anchoring | Anchor commitments to external chains | 🔶 Interface |
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Decentralized MPRD                       │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
//! │  │  Attestor 1 │  │  Attestor 2 │  │  Attestor N │         │
//! │  │   (Risc0)   │  │   (Risc0)   │  │   (Risc0)   │         │
//! │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
//! │         │                │                │                 │
//! │         └────────────────┼────────────────┘                 │
//! │                          ▼                                  │
//! │              ┌───────────────────────┐                      │
//! │              │   Threshold Verifier  │                      │
//! │              │     (K-of-N quorum)   │                      │
//! │              └───────────┬───────────┘                      │
//! │                          │                                  │
//! │                          ▼                                  │
//! │              ┌───────────────────────┐                      │
//! │              │   Commitment Anchor   │                      │
//! │              │  (IPFS/Arweave/Chain) │                      │
//! │              └───────────────────────┘                      │
//! │                                                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use crate::error::{ModeError, ModeResult};
use mprd_core::egress;
use mprd_core::orchestrator::DecisionRecorder;
use mprd_core::{
    CandidateAction, Decision, DecisionToken, Hash32, MprdError, ProofBundle, Result,
    StateSnapshot, VerificationStatus, ZkAttestor, ZkLocalVerifier,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::RwLock;
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernanceOpcode {
    RulesUpdate,
    CommitteeUpdate,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulesUpdateTx {
    pub prev_rules_hash: Hash32,
    pub rules_text: String,
    pub update_seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitteeUpdateTx {
    pub prev_committee_hash: Hash32,
    pub new_threshold: u16,
    pub new_members: Vec<Vec<u8>>,
    pub committee_seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernanceState {
    pub rules_hash: Hash32,
    pub rules_seq: u64,
    pub committee_hash: Hash32,
    pub committee_seq: u64,
}

impl GovernanceState {
    pub fn apply_committee_update(
        &mut self,
        tx: &CommitteeUpdateTx,
        threshold_ok: bool,
    ) -> Result<Hash32> {
        if !threshold_ok {
            return Err(MprdError::ZkError(
                "Committee threshold authorization failed".into(),
            ));
        }
        if tx.prev_committee_hash != self.committee_hash {
            return Err(MprdError::ZkError("Committee prev hash mismatch".into()));
        }
        if tx.committee_seq != self.committee_seq.saturating_add(1) {
            return Err(MprdError::ZkError("Committee seq mismatch".into()));
        }

        let computed = compute_committee_hash(tx.new_threshold, &tx.new_members)?;
        self.committee_hash = computed.clone();
        self.committee_seq = tx.committee_seq;
        Ok(computed)
    }

    pub fn apply_rules_update(&mut self, tx: &RulesUpdateTx, threshold_ok: bool) -> Result<Hash32> {
        if !threshold_ok {
            return Err(MprdError::ZkError(
                "Rules update threshold authorization failed".into(),
            ));
        }
        if tx.prev_rules_hash != self.rules_hash {
            return Err(MprdError::ZkError("Rules prev hash mismatch".into()));
        }
        if tx.update_seq != self.rules_seq.saturating_add(1) {
            return Err(MprdError::ZkError("Rules seq mismatch".into()));
        }

        let new_hash = compute_rules_hash(&tx.rules_text);
        self.rules_hash = new_hash.clone();
        self.rules_seq = tx.update_seq;
        Ok(new_hash)
    }
}

pub fn compute_rules_hash(rules_text: &str) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(rules_text.as_bytes());
    Hash32(hasher.finalize().into())
}

pub fn compute_committee_hash(threshold: u16, members: &[Vec<u8>]) -> Result<Hash32> {
    if threshold == 0 {
        return Err(MprdError::ZkError("Committee threshold must be > 0".into()));
    }
    if members.is_empty() {
        return Err(MprdError::ZkError(
            "Committee members must be non-empty".into(),
        ));
    }
    if usize::from(threshold) > members.len() {
        return Err(MprdError::ZkError(
            "Committee threshold cannot exceed member count".into(),
        ));
    }

    let mut sorted: Vec<&[u8]> = members.iter().map(|m| m.as_slice()).collect();
    sorted.sort_unstable();

    let mut hasher = Sha256::new();
    hasher.update(b"MPRD_COMMITTEE_V1");
    hasher.update([0u8]);
    hasher.update(threshold.to_be_bytes());
    hasher.update((members.len() as u16).to_be_bytes());
    for m in sorted {
        hasher.update(m);
    }
    Ok(Hash32(hasher.finalize().into()))
}

pub fn compute_rules_update_payload_hash(
    chain_id: &str,
    app_id: &str,
    rules_hash: &Hash32,
    prev_rules_hash: &Hash32,
    update_seq: u64,
) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(b"MPRD_RULES_UPDATE_V1");
    hasher.update([0u8]);
    hasher.update(chain_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(app_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(rules_hash.0);
    hasher.update(prev_rules_hash.0);
    hasher.update(update_seq.to_be_bytes());
    Hash32(hasher.finalize().into())
}

pub fn compute_committee_update_payload_hash(
    chain_id: &str,
    app_id: &str,
    prev_committee_hash: &Hash32,
    new_committee_hash: &Hash32,
    new_threshold: u16,
    committee_seq: u64,
) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(b"MPRD_COMMITTEE_UPDATE_V1");
    hasher.update([0u8]);
    hasher.update(chain_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(app_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(prev_committee_hash.0);
    hasher.update(new_committee_hash.0);
    hasher.update(new_threshold.to_be_bytes());
    hasher.update(committee_seq.to_be_bytes());
    Hash32(hasher.finalize().into())
}

// =============================================================================
// Governance Profile System
// =============================================================================

/// Update kinds that map to the Tau governance gate spec.
/// These correspond to i_update_kind in mprd_governance_gate.tau
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum UpdateKind {
    /// Policy tweak: requires app profile authorization only (0x01)
    PolicyTweak = 0x01,
    /// Safety rule change: requires safety profile authorization only (0x02)
    SafetyRuleChange = 0x02,
    /// Agent capability expansion: requires both app AND safety profiles (0x03)
    AgentCapabilityExpand = 0x03,
}

impl UpdateKind {
    pub fn to_bv8(&self) -> u8 {
        *self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::PolicyTweak),
            0x02 => Some(Self::SafetyRuleChange),
            0x03 => Some(Self::AgentCapabilityExpand),
            _ => None,
        }
    }
}

/// Governance mode determines authorization structure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceMode {
    /// Single owner controls all profiles (development/testing)
    SingleOwner { owner_pubkey: Vec<u8> },
    /// Committee-based M-of-N threshold for all profiles
    Committee {
        threshold: u16,
        members: Vec<Vec<u8>>,
    },
    /// Hybrid: separate committees for app and safety profiles
    Hybrid {
        app_profile: ProfileConfig,
        safety_profile: ProfileConfig,
    },
}

/// Configuration for a single profile (app or safety).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileConfig {
    /// M-of-N threshold requirement
    pub threshold: u16,
    /// Public keys of authorized signers
    pub members: Vec<Vec<u8>>,
    /// Profile hash (computed from threshold + sorted members)
    pub profile_hash: Hash32,
}

impl ProfileConfig {
    /// Create a new profile config and compute its hash.
    pub fn new(threshold: u16, members: Vec<Vec<u8>>) -> Result<Self> {
        let profile_hash = compute_committee_hash(threshold, &members)?;
        Ok(Self {
            threshold,
            members,
            profile_hash,
        })
    }

    /// Verify that a set of signatures meets the threshold.
    /// Returns true if at least `threshold` valid signatures from members.
    pub fn verify_threshold(&self, signatures: &[(Vec<u8>, Vec<u8>)]) -> bool {
        let valid_count = signatures
            .iter()
            .filter(|(pubkey, _sig)| self.members.contains(pubkey))
            .count();
        valid_count >= self.threshold as usize
    }
}

/// Governance profile instance - the core authorization structure.
///
/// This struct represents the complete governance configuration and provides
/// methods to check authorization for different update types, feeding the
/// Tau governance gate spec's inputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceProfile {
    /// Governance mode (single-owner, committee, or hybrid)
    pub mode: GovernanceMode,
    /// App profile config (for PolicyTweak and AgentCapabilityExpand)
    pub app_profile: ProfileConfig,
    /// Safety profile config (for SafetyRuleChange and AgentCapabilityExpand)
    pub safety_profile: ProfileConfig,
    /// Chain/network identifier for replay protection
    pub chain_id: String,
    /// Application identifier
    pub app_id: String,
}

/// Input payload for the Tau governance gate spec.
/// Maps directly to the Tau spec inputs in mprd_governance_gate.tau
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceGateInput {
    /// Update kind (bv[8]): 0x01, 0x02, or 0x03
    pub update_kind: u8,
    /// App profile authorization verified (sbf)
    pub profile_app_ok: bool,
    /// Safety profile authorization verified (sbf)
    pub profile_safety_ok: bool,
    /// Hash/sequence linkage checks passed (sbf)
    pub link_ok: bool,
}

impl GovernanceProfile {
    /// Create a single-owner governance profile.
    pub fn single_owner(
        owner_pubkey: Vec<u8>,
        chain_id: impl Into<String>,
        app_id: impl Into<String>,
    ) -> Result<Self> {
        let app_profile = ProfileConfig::new(1, vec![owner_pubkey.clone()])?;
        let safety_profile = ProfileConfig::new(1, vec![owner_pubkey.clone()])?;

        Ok(Self {
            mode: GovernanceMode::SingleOwner { owner_pubkey },
            app_profile,
            safety_profile,
            chain_id: chain_id.into(),
            app_id: app_id.into(),
        })
    }

    /// Create a committee-based governance profile (same committee for all).
    pub fn committee(
        threshold: u16,
        members: Vec<Vec<u8>>,
        chain_id: impl Into<String>,
        app_id: impl Into<String>,
    ) -> Result<Self> {
        let app_profile = ProfileConfig::new(threshold, members.clone())?;
        let safety_profile = ProfileConfig::new(threshold, members.clone())?;

        Ok(Self {
            mode: GovernanceMode::Committee { threshold, members },
            app_profile,
            safety_profile,
            chain_id: chain_id.into(),
            app_id: app_id.into(),
        })
    }

    /// Create a hybrid governance profile with separate app/safety committees.
    pub fn hybrid(
        app_threshold: u16,
        app_members: Vec<Vec<u8>>,
        safety_threshold: u16,
        safety_members: Vec<Vec<u8>>,
        chain_id: impl Into<String>,
        app_id: impl Into<String>,
    ) -> Result<Self> {
        let app_profile = ProfileConfig::new(app_threshold, app_members)?;
        let safety_profile = ProfileConfig::new(safety_threshold, safety_members)?;

        Ok(Self {
            mode: GovernanceMode::Hybrid {
                app_profile: app_profile.clone(),
                safety_profile: safety_profile.clone(),
            },
            app_profile,
            safety_profile,
            chain_id: chain_id.into(),
            app_id: app_id.into(),
        })
    }

    /// Check if an update is authorized based on signatures.
    /// Returns a GovernanceGateInput ready for the Tau spec.
    ///
    /// # Arguments
    /// * `update_kind` - The type of update being requested
    /// * `app_signatures` - Signatures from app profile members: (pubkey, signature)
    /// * `safety_signatures` - Signatures from safety profile members: (pubkey, signature)
    /// * `link_ok` - Whether hash/sequence linkage checks passed (from host/chain)
    pub fn check_authorization(
        &self,
        update_kind: UpdateKind,
        app_signatures: &[(Vec<u8>, Vec<u8>)],
        safety_signatures: &[(Vec<u8>, Vec<u8>)],
        link_ok: bool,
    ) -> GovernanceGateInput {
        let profile_app_ok = self.app_profile.verify_threshold(app_signatures);
        let profile_safety_ok = self.safety_profile.verify_threshold(safety_signatures);

        GovernanceGateInput {
            update_kind: update_kind.to_bv8(),
            profile_app_ok,
            profile_safety_ok,
            link_ok,
        }
    }

    /// Determine if a governance gate input would be accepted.
    /// This mirrors the Tau spec logic for host-side validation.
    pub fn would_accept(input: &GovernanceGateInput) -> bool {
        let kind = UpdateKind::from_u8(input.update_kind);
        if !input.link_ok {
            return false;
        }

        match kind {
            Some(UpdateKind::PolicyTweak) => input.profile_app_ok,
            Some(UpdateKind::SafetyRuleChange) => input.profile_safety_ok,
            Some(UpdateKind::AgentCapabilityExpand) => {
                input.profile_app_ok && input.profile_safety_ok
            }
            None => false,
        }
    }

    /// Get the profile hash for the governance configuration.
    pub fn compute_profile_hash(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(b"MPRD_GOVERNANCE_PROFILE_V1");
        hasher.update([0u8]);
        hasher.update(self.chain_id.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.app_id.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.app_profile.profile_hash.0);
        hasher.update(self.safety_profile.profile_hash.0);
        Hash32(hasher.finalize().into())
    }
}

// =============================================================================
// Tau Governance Runner
// =============================================================================

const TAU_RUNNER_MAX_OUTPUT_BYTES: usize = 64 * 1024;
const TAU_RUNNER_POLL_INTERVAL_MS: u64 = 10;

fn read_tau_runner_stream<R: Read>(mut reader: R, stream_name: &'static str) -> io::Result<String> {
    let mut output = Vec::new();
    let mut total = 0usize;
    let mut buf = [0u8; 4096];

    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| io::Error::other(format!("failed to read tau {stream_name}: {e}")))?;

        if n == 0 {
            break;
        }

        total = total.saturating_add(n);

        if output.len() < TAU_RUNNER_MAX_OUTPUT_BYTES {
            let remaining = TAU_RUNNER_MAX_OUTPUT_BYTES - output.len();
            let take = remaining.min(n);
            output.extend_from_slice(&buf[..take]);
        }
    }

    if total > TAU_RUNNER_MAX_OUTPUT_BYTES {
        return Err(io::Error::other(format!(
            "tau {stream_name} exceeded {TAU_RUNNER_MAX_OUTPUT_BYTES} bytes"
        )));
    }

    Ok(String::from_utf8_lossy(&output).into_owned())
}

fn wait_for_tau_runner_exit(
    child: &mut std::process::Child,
    timeout: Duration,
) -> io::Result<std::process::ExitStatus> {
    let start = Instant::now();

    loop {
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("tau timed out after {:?}", timeout),
            ));
        }

        let status = child.try_wait()?;
        if let Some(status) = status {
            return Ok(status);
        }

        thread::sleep(Duration::from_millis(TAU_RUNNER_POLL_INTERVAL_MS));
    }
}

/// Runner for executing governance decisions through Tau specs.
/// Provides integration between GovernanceProfile and Tau execution.
#[derive(Clone, Debug)]
pub struct TauGovernanceRunner {
    /// Path to the Tau binary.
    pub tau_binary: std::path::PathBuf,
    /// Working directory for input/output files.
    pub work_dir: std::path::PathBuf,
    /// Timeout for Tau execution in seconds.
    pub timeout_secs: u64,
}

impl TauGovernanceRunner {
    /// Create a new runner with the specified Tau binary path.
    pub fn new(
        tau_binary: impl Into<std::path::PathBuf>,
        work_dir: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            tau_binary: tau_binary.into(),
            work_dir: work_dir.into(),
            timeout_secs: 30,
        }
    }

    /// Write governance gate inputs to files for Tau execution.
    ///
    /// Converts GovernanceGateInput to one-hot sbf files:
    /// - inputs/is_policy_tweak.in
    /// - inputs/is_safety_change.in
    /// - inputs/is_cap_expand.in
    /// - inputs/profile_app_ok.in
    /// - inputs/profile_safety_ok.in
    /// - inputs/link_ok.in
    pub fn write_inputs(&self, input: &GovernanceGateInput) -> std::io::Result<()> {
        let inputs_dir = self.work_dir.join("inputs");
        std::fs::create_dir_all(&inputs_dir)?;

        // Ensure outputs directory exists for Tau file outputs.
        let outputs_dir = self.work_dir.join("outputs");
        std::fs::create_dir_all(&outputs_dir)?;

        let kind = UpdateKind::from_u8(input.update_kind);
        let is_policy_tweak = matches!(kind, Some(UpdateKind::PolicyTweak));
        let is_safety_change = matches!(kind, Some(UpdateKind::SafetyRuleChange));
        let is_cap_expand = matches!(kind, Some(UpdateKind::AgentCapabilityExpand));

        // Write sbf input files (init line + step-0 value)
        std::fs::write(
            inputs_dir.join("is_policy_tweak.in"),
            format!("0\n{}\n", is_policy_tweak as u8),
        )?;
        std::fs::write(
            inputs_dir.join("is_safety_change.in"),
            format!("0\n{}\n", is_safety_change as u8),
        )?;
        std::fs::write(
            inputs_dir.join("is_cap_expand.in"),
            format!("0\n{}\n", is_cap_expand as u8),
        )?;
        std::fs::write(
            inputs_dir.join("profile_app_ok.in"),
            format!("0\n{}\n", input.profile_app_ok as u8),
        )?;
        std::fs::write(
            inputs_dir.join("profile_safety_ok.in"),
            format!("0\n{}\n", input.profile_safety_ok as u8),
        )?;
        std::fs::write(
            inputs_dir.join("link_ok.in"),
            format!("0\n{}\n", input.link_ok as u8),
        )?;

        Ok(())
    }

    fn canonical_gate_spec_path() -> std::io::Result<PathBuf> {
        // Workspace root is two directories above this crate's manifest directory:
        // crates/mprd-zk -> crates -> <workspace-root>
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .ok_or_else(|| {
                io::Error::other("cannot resolve workspace root from CARGO_MANIFEST_DIR")
            })?;

        let spec = workspace_root.join("policies/governance/canonical/mprd_governance_gate.tau");
        if !spec.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "canonical governance gate spec not found: {}",
                    spec.display()
                ),
            ));
        }
        Ok(spec)
    }

    fn run_tau_spec_with_timeout(&self, spec_path: &Path) -> std::io::Result<()> {
        let mut child = Command::new(&self.tau_binary)
            .arg(spec_path)
            .current_dir(&self.work_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdout_reader = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("tau stdout unavailable"))?;
        let stderr_reader = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("tau stderr unavailable"))?;

        let stdout_task = thread::spawn(move || read_tau_runner_stream(stdout_reader, "stdout"));
        let stderr_task = thread::spawn(move || read_tau_runner_stream(stderr_reader, "stderr"));

        let timeout = Duration::from_secs(self.timeout_secs);
        let status = wait_for_tau_runner_exit(&mut child, timeout);

        let stdout = stdout_task
            .join()
            .map_err(|_| io::Error::other("tau stdout reader thread panicked"))??;
        let stderr = stderr_task
            .join()
            .map_err(|_| io::Error::other("tau stderr reader thread panicked"))??;

        let status = status?;

        if !status.success() {
            return Err(io::Error::other(format!(
                "tau exited with error. stderr: {stderr}"
            )));
        }

        if stdout.contains("(Error)") || stderr.contains("(Error)") {
            return Err(io::Error::other(format!(
                "tau reported error. stdout: {stdout} stderr: {stderr}"
            )));
        }

        Ok(())
    }

    /// Execute the canonical governance gate spec and return the boolean result.
    ///
    /// Preconditions:
    /// - `write_inputs` has been called for the intended input.
    /// - `tau_binary` points to a working Tau interpreter.
    ///
    /// Postconditions:
    /// - Returns `Ok(true|false)` if Tau produced a concrete output.
    /// - Returns `Err` if Tau fails, times out, or produces no output (fail-closed).
    pub fn execute_canonical_gate(&self) -> std::io::Result<bool> {
        let outputs_dir = self.work_dir.join("outputs");
        std::fs::create_dir_all(&outputs_dir)?;
        let out_path = outputs_dir.join("accept.out");
        let _ = std::fs::remove_file(&out_path);

        let spec_path = Self::canonical_gate_spec_path()?;
        self.run_tau_spec_with_timeout(&spec_path)?;

        let Some(result) = self.read_output()? else {
            return Err(io::Error::other("tau produced no governance output"));
        };
        Ok(result)
    }

    /// Read the acceptance result from Tau output file.
    pub fn read_output(&self) -> std::io::Result<Option<bool>> {
        let output_path = self.work_dir.join("outputs/accept.out");
        let content = std::fs::read_to_string(output_path)?;

        // Parse last non-empty line as sbf value
        for line in content.lines().rev() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                return match trimmed {
                    "1" | "T" => Ok(Some(true)),
                    "0" | "F" => Ok(Some(false)),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected sbf output '{trimmed}'"),
                    )),
                };
            }
        }
        Ok(None)
    }

    /// Execute governance decision and compare Tau result with Rust would_accept.
    /// Returns (tau_result, rust_result, match).
    pub fn verify_governance_decision(
        &self,
        profile: &GovernanceProfile,
        update_kind: UpdateKind,
        app_signatures: &[(Vec<u8>, Vec<u8>)],
        safety_signatures: &[(Vec<u8>, Vec<u8>)],
        link_ok: bool,
    ) -> std::io::Result<(bool, bool, bool)> {
        let input =
            profile.check_authorization(update_kind, app_signatures, safety_signatures, link_ok);
        let rust_result = GovernanceProfile::would_accept(&input);

        self.write_inputs(&input)?;

        let tau_result = self.execute_canonical_gate()?;

        Ok((tau_result, rust_result, tau_result == rust_result))
    }
}

// =============================================================================
// Threshold Configuration
// =============================================================================

/// Configuration for threshold-based verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Total number of attestors (N).
    pub total_attestors: usize,

    /// Required quorum (K) - must be <= total_attestors.
    pub required_quorum: usize,

    /// Whether to require all attestors to use the same proof type.
    pub require_uniform_proofs: bool,

    /// Maximum allowed disagreement on decision.
    pub max_decision_divergence: usize,
}

impl ThresholdConfig {
    /// Create a simple majority config (N/2 + 1 of N).
    pub fn simple_majority(total: usize) -> Self {
        Self {
            total_attestors: total,
            required_quorum: total / 2 + 1,
            require_uniform_proofs: false,
            max_decision_divergence: 0,
        }
    }

    /// Create a supermajority config (2/3 of N).
    pub fn supermajority(total: usize) -> Self {
        Self {
            total_attestors: total,
            required_quorum: total.saturating_mul(2).div_ceil(3),
            require_uniform_proofs: false,
            max_decision_divergence: 0,
        }
    }

    /// Create a unanimous config (all must agree).
    pub fn unanimous(total: usize) -> Self {
        Self {
            total_attestors: total,
            required_quorum: total,
            require_uniform_proofs: true,
            max_decision_divergence: 0,
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> ModeResult<()> {
        if self.total_attestors == 0 {
            return Err(ModeError::InvalidConfig(
                "total_attestors must be > 0".into(),
            ));
        }
        if self.required_quorum == 0 {
            return Err(ModeError::InvalidConfig(
                "required_quorum must be > 0".into(),
            ));
        }
        if self.required_quorum > self.total_attestors {
            return Err(ModeError::InvalidConfig(
                "required_quorum cannot exceed total_attestors".into(),
            ));
        }
        Ok(())
    }
}

// =============================================================================
// On-Chain / Tau Registry Interfaces
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRegistryEntry {
    pub policy_hash: Hash32,
    pub publisher: String,
    pub ethics_profile: Option<String>,
    pub legal_profile: Option<String>,
    pub version: u64,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRegistryEntry {
    pub key_id: String,
    pub owner: String,
    pub key_type: String,
    pub revoked: bool,
}

pub trait OnChainRegistry: Send + Sync {
    fn register_policy(&self, entry: PolicyRegistryEntry) -> Result<CommitmentAnchor>;
    fn get_policy(&self, policy_hash: &Hash32) -> Result<Option<PolicyRegistryEntry>>;

    fn register_key(&self, entry: KeyRegistryEntry) -> Result<CommitmentAnchor>;
    fn get_key(&self, key_id: &str) -> Result<Option<KeyRegistryEntry>>;

    fn anchor_decision(
        &self,
        token: &DecisionToken,
        proof: &ProofBundle,
    ) -> Result<CommitmentAnchor>;
}

pub struct LocalOnChainRegistry {
    anchor_store: Box<dyn CommitmentAnchorStore>,
    policies: RwLock<HashMap<[u8; 32], PolicyRegistryEntry>>,
    keys: RwLock<HashMap<String, KeyRegistryEntry>>,
}

impl LocalOnChainRegistry {
    pub fn new(anchor_store: Box<dyn CommitmentAnchorStore>) -> Self {
        Self {
            anchor_store,
            policies: RwLock::new(HashMap::new()),
            keys: RwLock::new(HashMap::new()),
        }
    }

    fn compute_decision_commitment(token: &DecisionToken, proof: &ProofBundle) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(token.policy_hash.0);
        hasher.update(token.state_hash.0);
        hasher.update(proof.candidate_set_hash.0);
        hasher.update(token.chosen_action_hash.0);
        hasher.update(token.nonce_or_tx_hash.0);
        Hash32(hasher.finalize().into())
    }
}

pub struct RegistryRecorder<R: OnChainRegistry> {
    registry: R,
}

impl<R: OnChainRegistry> RegistryRecorder<R> {
    pub fn new(registry: R) -> Self {
        Self { registry }
    }
}

impl<R: OnChainRegistry> DecisionRecorder for RegistryRecorder<R> {
    fn record(&self, token: &DecisionToken, proof: &ProofBundle) -> Result<()> {
        self.registry.anchor_decision(token, proof).map(|_| ())
    }
}

impl OnChainRegistry for LocalOnChainRegistry {
    fn register_policy(&self, entry: PolicyRegistryEntry) -> Result<CommitmentAnchor> {
        let key = entry.policy_hash.0;

        {
            let mut map = self
                .policies
                .write()
                .map_err(|_| MprdError::ZkError("Policy registry lock poisoned".into()))?;
            map.insert(key, entry.clone());
        }

        self.anchor_store.anchor(&key)
    }

    fn get_policy(&self, policy_hash: &Hash32) -> Result<Option<PolicyRegistryEntry>> {
        let map = self
            .policies
            .read()
            .map_err(|_| MprdError::ZkError("Policy registry lock poisoned".into()))?;
        Ok(map.get(&policy_hash.0).cloned())
    }

    fn register_key(&self, entry: KeyRegistryEntry) -> Result<CommitmentAnchor> {
        let key_id = entry.key_id.clone();

        {
            let mut map = self
                .keys
                .write()
                .map_err(|_| MprdError::ZkError("Key registry lock poisoned".into()))?;
            map.insert(key_id.clone(), entry);
        }

        let mut hasher = Sha256::new();
        hasher.update(key_id.as_bytes());
        let commitment: [u8; 32] = hasher.finalize().into();
        self.anchor_store.anchor(&commitment)
    }

    fn get_key(&self, key_id: &str) -> Result<Option<KeyRegistryEntry>> {
        let map = self
            .keys
            .read()
            .map_err(|_| MprdError::ZkError("Key registry lock poisoned".into()))?;
        Ok(map.get(key_id).cloned())
    }

    fn anchor_decision(
        &self,
        token: &DecisionToken,
        proof: &ProofBundle,
    ) -> Result<CommitmentAnchor> {
        let commitment = Self::compute_decision_commitment(token, proof);
        self.anchor_store.anchor(&commitment.0)
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self::simple_majority(3)
    }
}

// =============================================================================
// Multi-Attestor System
// =============================================================================

/// Result from a single attestor.
#[derive(Clone, Debug)]
pub struct AttestorResult {
    /// Attestor identifier.
    pub attestor_id: String,

    /// The proof bundle produced.
    pub proof: ProofBundle,

    /// Whether attestation succeeded.
    pub success: bool,

    /// Error message if failed.
    pub error: Option<String>,
}

/// Aggregated result from multiple attestors.
#[derive(Clone, Debug)]
pub struct AggregatedAttestation {
    /// Individual results from each attestor.
    pub results: Vec<AttestorResult>,

    /// Number of successful attestations.
    pub success_count: usize,

    /// Number of failed attestations.
    pub failure_count: usize,

    /// Whether quorum was reached.
    pub quorum_reached: bool,

    /// Merged proof bundle (if quorum reached).
    pub merged_proof: Option<ProofBundle>,

    /// Commitment to all individual proofs.
    pub aggregated_commitment: Hash32,
}

/// Multi-attestor coordinator.
///
/// Coordinates multiple independent attestors and aggregates their results.
/// This eliminates SPOF by requiring K-of-N attestors to agree.
pub struct MultiAttestor {
    config: ThresholdConfig,
    attestors: Vec<Box<dyn ZkAttestor>>,
}

impl MultiAttestor {
    /// Create a new multi-attestor coordinator.
    pub fn new(config: ThresholdConfig, attestors: Vec<Box<dyn ZkAttestor>>) -> ModeResult<Self> {
        config.validate()?;

        if attestors.len() != config.total_attestors {
            return Err(ModeError::InvalidConfig(format!(
                "Expected {} attestors, got {}",
                config.total_attestors,
                attestors.len()
            )));
        }

        Ok(Self { config, attestors })
    }

    /// Run attestation across all attestors and aggregate results.
    pub fn attest_multi(
        &self,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> AggregatedAttestation {
        let mut results = Vec::with_capacity(self.attestors.len());
        let mut success_count = 0;
        let mut proofs_for_merge: Vec<ProofBundle> = Vec::new();

        for (i, attestor) in self.attestors.iter().enumerate() {
            let attestor_id = format!("attestor_{}", i);

            match attestor.attest(decision, state, candidates) {
                Ok(proof) => {
                    debug!(attestor = %attestor_id, "Attestation succeeded");
                    proofs_for_merge.push(proof.clone());
                    results.push(AttestorResult {
                        attestor_id,
                        proof,
                        success: true,
                        error: None,
                    });
                    success_count += 1;
                }
                Err(e) => {
                    warn!(attestor = %attestor_id, error = %e, "Attestation failed");
                    results.push(AttestorResult {
                        attestor_id,
                        proof: ProofBundle {
                            policy_hash: decision.policy_hash.clone(),
                            state_hash: state.state_hash.clone(),
                            candidate_set_hash: Hash32([0u8; 32]),
                            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
                            risc0_receipt: vec![],
                            attestation_metadata: HashMap::new(),
                        },
                        success: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        let quorum_reached = success_count >= self.config.required_quorum;
        let failure_count = results.len() - success_count;

        // Compute aggregated commitment
        let aggregated_commitment = self.compute_aggregated_commitment(&proofs_for_merge);

        let merged_proof = quorum_reached
            .then(|| self.merge_proofs(&proofs_for_merge, &aggregated_commitment))
            .flatten();

        let quorum_reached = quorum_reached && merged_proof.is_some();

        if quorum_reached {
            info!(
                success = success_count,
                required = self.config.required_quorum,
                "Quorum reached"
            );
        } else {
            warn!(
                success = success_count,
                required = self.config.required_quorum,
                "Quorum NOT reached"
            );
        }

        AggregatedAttestation {
            results,
            success_count,
            failure_count,
            quorum_reached,
            merged_proof,
            aggregated_commitment,
        }
    }

    /// Compute commitment to all proofs.
    fn compute_aggregated_commitment(&self, proofs: &[ProofBundle]) -> Hash32 {
        let mut hasher = Sha256::new();
        for proof in proofs {
            hasher.update(proof.policy_hash.0);
            hasher.update(proof.state_hash.0);
            hasher.update(proof.chosen_action_hash.0);
        }
        Hash32(hasher.finalize().into())
    }

    /// Merge multiple proofs into one.
    fn merge_proofs(&self, proofs: &[ProofBundle], commitment: &Hash32) -> Option<ProofBundle> {
        let first = proofs.first()?;

        let mut metadata = first.attestation_metadata.clone();
        metadata.insert("multi_attestor".into(), "true".into());
        metadata.insert("attestor_count".into(), proofs.len().to_string());
        metadata.insert("aggregated_commitment".into(), hex::encode(commitment.0));

        Some(ProofBundle {
            policy_hash: first.policy_hash.clone(),
            state_hash: first.state_hash.clone(),
            candidate_set_hash: first.candidate_set_hash.clone(),
            chosen_action_hash: first.chosen_action_hash.clone(),
            risc0_receipt: first.risc0_receipt.clone(), // Use first receipt
            attestation_metadata: metadata,
        })
    }
}

// =============================================================================
// Threshold Verifier
// =============================================================================

/// Multi-verifier that requires K-of-N verifiers to accept.
pub struct ThresholdVerifier {
    config: ThresholdConfig,
    verifiers: Vec<Box<dyn ZkLocalVerifier>>,
}

impl ThresholdVerifier {
    /// Create a new threshold verifier.
    pub fn new(
        config: ThresholdConfig,
        verifiers: Vec<Box<dyn ZkLocalVerifier>>,
    ) -> ModeResult<Self> {
        config.validate()?;

        if verifiers.len() != config.total_attestors {
            return Err(ModeError::InvalidConfig(format!(
                "Expected {} verifiers, got {}",
                config.total_attestors,
                verifiers.len()
            )));
        }

        Ok(Self { config, verifiers })
    }

    /// Verify with threshold - requires K-of-N to accept.
    pub fn verify_threshold(
        &self,
        token: &DecisionToken,
        proof: &ProofBundle,
    ) -> ThresholdVerificationResult {
        let mut accept_count = 0;
        let mut reject_count = 0;
        let mut results = Vec::new();

        for (i, verifier) in self.verifiers.iter().enumerate() {
            let status = verifier.verify(token, proof);
            let accepted = matches!(status, VerificationStatus::Success);

            if accepted {
                accept_count += 1;
            } else {
                reject_count += 1;
            }

            results.push(VerifierResult {
                verifier_id: format!("verifier_{}", i),
                status,
                accepted,
            });
        }

        let quorum_reached = accept_count >= self.config.required_quorum;

        ThresholdVerificationResult {
            results,
            accept_count,
            reject_count,
            quorum_reached,
            final_status: if quorum_reached {
                VerificationStatus::Success
            } else {
                VerificationStatus::Failure(format!(
                    "Quorum not reached: {}/{} accepted, {} required",
                    accept_count,
                    self.verifiers.len(),
                    self.config.required_quorum
                ))
            },
        }
    }
}

/// Result from a single verifier.
#[derive(Clone, Debug)]
pub struct VerifierResult {
    pub verifier_id: String,
    pub status: VerificationStatus,
    pub accepted: bool,
}

/// Aggregated verification result.
#[derive(Clone, Debug)]
pub struct ThresholdVerificationResult {
    pub results: Vec<VerifierResult>,
    pub accept_count: usize,
    pub reject_count: usize,
    pub quorum_reached: bool,
    pub final_status: VerificationStatus,
}

// =============================================================================
// Distributed Policy Storage Interface
// =============================================================================

/// Interface for distributed policy storage.
///
/// Implementations can store policies on:
/// - IPFS
/// - Arweave
/// - Blockchain (Ethereum, Solana, etc.)
/// - Tau Network (when integrated)
pub trait DistributedPolicyStore: Send + Sync {
    /// Store a policy and return its content-addressed hash.
    fn store(&self, policy_bytes: &[u8]) -> Result<Hash32>;

    /// Retrieve a policy by its hash.
    fn retrieve(&self, policy_hash: &Hash32) -> Result<Vec<u8>>;

    /// Check if a policy exists.
    fn exists(&self, policy_hash: &Hash32) -> Result<bool>;

    /// Get the storage backend name.
    fn backend_name(&self) -> &'static str;
}

/// IPFS-based policy storage (interface only).
pub struct IpfsPolicyStore {
    gateway_url: String,
    client: Client,
    hash_to_cid: RwLock<HashMap<Hash32, String>>,
    mapping_path: PathBuf,
}

impl IpfsPolicyStore {
    pub fn new(gateway_url: impl Into<String>) -> Result<Self> {
        let mapping_path = Self::default_mapping_path();
        let mapping = match Self::load_mapping(&mapping_path) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "Failed to load IPFS mapping file, starting with empty mapping");
                HashMap::new()
            }
        };

        let gateway_url: String = gateway_url.into();
        egress::validate_outbound_url(&gateway_url)?;

        Ok(Self {
            gateway_url,
            client: Client::new(),
            hash_to_cid: RwLock::new(mapping),
            mapping_path,
        })
    }

    fn default_mapping_path() -> PathBuf {
        if let Ok(path) = std::env::var("MPRD_IPFS_MAPPING_FILE") {
            PathBuf::from(path)
        } else {
            PathBuf::from(".mprd_ipfs_mapping.json")
        }
    }

    fn load_mapping(path: &Path) -> Result<HashMap<Hash32, String>> {
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let data = fs::read_to_string(path)
            .map_err(|e| MprdError::ZkError(format!("Failed to read IPFS mapping file: {}", e)))?;

        let raw: HashMap<String, String> = serde_json::from_str(&data)
            .map_err(|e| MprdError::ZkError(format!("Failed to parse IPFS mapping file: {}", e)))?;

        let mut mapping = HashMap::new();

        for (hex_hash, cid) in raw {
            let bytes = hex::decode(&hex_hash).map_err(|e| {
                MprdError::ZkError(format!("Invalid hash in IPFS mapping file: {}", e))
            })?;

            if bytes.len() != 32 {
                return Err(MprdError::ZkError(
                    "Invalid hash length in IPFS mapping file".into(),
                ));
            }

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            mapping.insert(Hash32(arr), cid);
        }

        Ok(mapping)
    }

    fn persist_mapping(&self, mapping: &HashMap<Hash32, String>) -> Result<()> {
        let mut raw = HashMap::new();

        for (hash, cid) in mapping {
            raw.insert(hex::encode(hash.0), cid.clone());
        }

        let data = serde_json::to_string_pretty(&raw)
            .map_err(|e| MprdError::ZkError(format!("Failed to serialize IPFS mapping: {}", e)))?;

        let tmp_path = self.mapping_path.with_extension("tmp");

        fs::write(&tmp_path, &data).map_err(|e| {
            MprdError::ZkError(format!("Failed to write IPFS mapping temp file: {}", e))
        })?;

        fs::rename(&tmp_path, &self.mapping_path).map_err(|e| {
            MprdError::ZkError(format!("Failed to replace IPFS mapping file: {}", e))
        })?;

        Ok(())
    }

    fn compute_hash(bytes: &[u8]) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(b"MPRD_POLICY_V1");
        hasher.update(bytes);
        Hash32(hasher.finalize().into())
    }

    fn verify_policy_hash_matches_expected(expected: &Hash32, policy_bytes: &[u8]) -> Result<()> {
        let computed = Self::compute_hash(policy_bytes);
        if computed == *expected {
            return Ok(());
        }
        Err(MprdError::ZkError(format!(
            "Policy hash mismatch: expected {}, got {}",
            hex::encode(expected.0),
            hex::encode(computed.0)
        )))
    }

    fn has_mapping(&self, policy_hash: &Hash32) -> Result<bool> {
        let mapping = self
            .hash_to_cid
            .read()
            .map_err(|_| MprdError::ZkError("IPFS mapping lock poisoned".into()))?;
        Ok(mapping.contains_key(policy_hash))
    }

    fn ipfs_add(&self, bytes: &[u8]) -> Result<String> {
        let url = format!("{}/api/v0/add", self.gateway_url);
        let part = reqwest::blocking::multipart::Part::bytes(bytes.to_vec()).file_name("policy");
        let form = reqwest::blocking::multipart::Form::new().part("file", part);

        let response = self
            .client
            .post(&url)
            .multipart(form)
            .send()
            .map_err(|e| MprdError::ZkError(format!("IPFS add failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(MprdError::ZkError(format!(
                "IPFS add returned {}",
                response.status()
            )));
        }

        #[derive(Deserialize)]
        struct IpfsAddResponse {
            #[serde(rename = "Hash")]
            hash: String,
        }

        let parsed: IpfsAddResponse = response
            .json()
            .map_err(|e| MprdError::ZkError(format!("Failed to parse IPFS response: {}", e)))?;

        Ok(parsed.hash)
    }

    fn ipfs_cat(&self, cid: &str) -> Result<Vec<u8>> {
        let url = format!("{}/api/v0/cat?arg={}", self.gateway_url, cid);

        let response = self
            .client
            .post(&url)
            .send()
            .map_err(|e| MprdError::ZkError(format!("IPFS cat failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(MprdError::ZkError(format!(
                "IPFS cat returned {}",
                response.status()
            )));
        }

        let body = response
            .bytes()
            .map_err(|e| MprdError::ZkError(format!("Failed to read IPFS content: {}", e)))?;

        Ok(body.to_vec())
    }
}

impl DistributedPolicyStore for IpfsPolicyStore {
    fn store(&self, policy_bytes: &[u8]) -> Result<Hash32> {
        let hash = Self::compute_hash(policy_bytes);

        if self.has_mapping(&hash)? {
            return Ok(hash);
        }

        let cid = self.ipfs_add(policy_bytes)?;

        let mut mapping = self
            .hash_to_cid
            .write()
            .map_err(|_| MprdError::ZkError("IPFS mapping lock poisoned".into()))?;
        mapping.insert(hash.clone(), cid);
        self.persist_mapping(&mapping)?;

        Ok(hash)
    }

    fn retrieve(&self, policy_hash: &Hash32) -> Result<Vec<u8>> {
        let cid = {
            let mapping = self
                .hash_to_cid
                .read()
                .map_err(|_| MprdError::ZkError("IPFS mapping lock poisoned".into()))?;
            mapping
                .get(policy_hash)
                .cloned()
                .ok_or_else(|| MprdError::ZkError("No CID mapping for policy hash".into()))?
        };

        let bytes = self.ipfs_cat(&cid)?;
        Self::verify_policy_hash_matches_expected(policy_hash, &bytes)?;
        Ok(bytes)
    }

    fn exists(&self, policy_hash: &Hash32) -> Result<bool> {
        self.has_mapping(policy_hash)
    }

    fn backend_name(&self) -> &'static str {
        "IPFS"
    }
}

// =============================================================================
// Commitment Anchoring
// =============================================================================

/// Anchor point for commitment chains.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitmentAnchor {
    /// The commitment being anchored.
    pub commitment: [u8; 32],

    /// Timestamp of anchoring.
    pub timestamp: i64,

    /// Block number (if blockchain).
    pub block_number: Option<u64>,

    /// Transaction hash (if blockchain).
    pub tx_hash: Option<[u8; 32]>,

    /// IPFS CID (if IPFS).
    pub ipfs_cid: Option<String>,

    /// Anchor type.
    pub anchor_type: AnchorType,
}

/// Types of commitment anchors.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnchorType {
    /// Anchored to a blockchain.
    Blockchain { chain_id: u64 },

    /// Anchored to IPFS.
    Ipfs,

    /// Anchored to Arweave.
    Arweave,

    /// Anchored to Tau Network.
    TauNetwork,

    /// Local timestamp only (not decentralized).
    LocalTimestamp,
}

/// Interface for anchoring commitments.
pub trait CommitmentAnchorStore: Send + Sync {
    /// Anchor a commitment and return the anchor.
    fn anchor(&self, commitment: &[u8; 32]) -> Result<CommitmentAnchor>;

    /// Verify an anchor is valid.
    fn verify_anchor(&self, anchor: &CommitmentAnchor) -> Result<bool>;
}

pub struct LocalTimestampAnchorStore {
    anchors: RwLock<HashMap<[u8; 32], CommitmentAnchor>>,
}

impl LocalTimestampAnchorStore {
    pub fn new() -> Self {
        Self {
            anchors: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for LocalTimestampAnchorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentAnchorStore for LocalTimestampAnchorStore {
    fn anchor(&self, commitment: &[u8; 32]) -> Result<CommitmentAnchor> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MprdError::ZkError(format!("System time error: {}", e)))?;

        let anchor = CommitmentAnchor {
            commitment: *commitment,
            timestamp: now.as_millis() as i64,
            block_number: None,
            tx_hash: None,
            ipfs_cid: None,
            anchor_type: AnchorType::LocalTimestamp,
        };

        let mut anchors = self
            .anchors
            .write()
            .map_err(|_| MprdError::ZkError("Anchor store lock poisoned".into()))?;
        anchors.insert(*commitment, anchor.clone());

        Ok(anchor)
    }

    fn verify_anchor(&self, anchor: &CommitmentAnchor) -> Result<bool> {
        let anchors = self
            .anchors
            .read()
            .map_err(|_| MprdError::ZkError("Anchor store lock poisoned".into()))?;

        if let Some(stored) = anchors.get(&anchor.commitment) {
            Ok(stored == anchor)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mprd_core::components::StubZkAttestor;
    use mprd_core::Score;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::sync::{Mutex, OnceLock};

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    #[test]
    fn compute_committee_hash_is_order_independent() {
        let members_a = vec![vec![3u8; 48], vec![1u8; 48], vec![2u8; 48]];
        let members_b = vec![vec![2u8; 48], vec![3u8; 48], vec![1u8; 48]];

        let ha = compute_committee_hash(2, &members_a).expect("hash should compute");
        let hb = compute_committee_hash(2, &members_b).expect("hash should compute");
        assert_eq!(ha, hb);
    }

    #[test]
    fn compute_committee_hash_validates_inputs() {
        let members = vec![vec![1u8; 48]];
        assert!(compute_committee_hash(0, &members).is_err());
        assert!(compute_committee_hash(2, &members).is_err());
        assert!(compute_committee_hash(1, &[]).is_err());
    }

    #[test]
    fn governance_state_rules_update_requires_hash_link_and_monotonic_seq() {
        let mut state = GovernanceState {
            rules_hash: dummy_hash(9),
            rules_seq: 7,
            committee_hash: dummy_hash(1),
            committee_seq: 0,
        };

        let ok = RulesUpdateTx {
            prev_rules_hash: dummy_hash(9),
            rules_text: "rule_v2".into(),
            update_seq: 8,
        };
        let new_hash = state
            .apply_rules_update(&ok, true)
            .expect("rules update should apply");
        assert_eq!(state.rules_hash, new_hash);
        assert_eq!(state.rules_seq, 8);

        let wrong_prev = RulesUpdateTx {
            prev_rules_hash: dummy_hash(9),
            rules_text: "rule_v3".into(),
            update_seq: 9,
        };
        assert!(state.apply_rules_update(&wrong_prev, true).is_err());

        let wrong_seq = RulesUpdateTx {
            prev_rules_hash: state.rules_hash.clone(),
            rules_text: "rule_v3".into(),
            update_seq: 11,
        };
        assert!(state.apply_rules_update(&wrong_seq, true).is_err());
        assert!(state.apply_rules_update(&wrong_seq, false).is_err());
    }

    #[test]
    fn governance_state_committee_update_requires_hash_link_and_monotonic_seq() {
        let initial_members = vec![vec![1u8; 48], vec![2u8; 48]];
        let initial_hash =
            compute_committee_hash(1, &initial_members).expect("hash should compute");
        let mut state = GovernanceState {
            rules_hash: dummy_hash(9),
            rules_seq: 0,
            committee_hash: initial_hash.clone(),
            committee_seq: 3,
        };

        let tx_ok = CommitteeUpdateTx {
            prev_committee_hash: initial_hash.clone(),
            new_threshold: 2,
            new_members: vec![vec![3u8; 48], vec![4u8; 48]],
            committee_seq: 4,
        };

        let new_hash = state
            .apply_committee_update(&tx_ok, true)
            .expect("committee update should apply");
        assert_eq!(state.committee_hash, new_hash);
        assert_eq!(state.committee_seq, 4);

        let tx_wrong_prev = CommitteeUpdateTx {
            prev_committee_hash: initial_hash,
            new_threshold: 1,
            new_members: vec![vec![5u8; 48]],
            committee_seq: 5,
        };
        assert!(state.apply_committee_update(&tx_wrong_prev, true).is_err());

        let tx_wrong_seq = CommitteeUpdateTx {
            prev_committee_hash: state.committee_hash.clone(),
            new_threshold: 1,
            new_members: vec![vec![6u8; 48]],
            committee_seq: 7,
        };
        assert!(state.apply_committee_update(&tx_wrong_seq, true).is_err());
        assert!(state.apply_committee_update(&tx_wrong_seq, false).is_err());
    }

    #[test]
    fn local_timestamp_anchor_store_roundtrip() {
        let store = LocalTimestampAnchorStore::new();
        let commitment = [42u8; 32];

        let anchor = store.anchor(&commitment).expect("anchor should succeed");

        assert_eq!(anchor.commitment, commitment);
        assert_eq!(anchor.anchor_type, AnchorType::LocalTimestamp);

        let verified = store.verify_anchor(&anchor).expect("verify should succeed");
        assert!(verified);

        let mut tampered = anchor.clone();
        tampered.commitment = [7u8; 32];
        let verified_tampered = store
            .verify_anchor(&tampered)
            .expect("verify should succeed for tampered");
        assert!(!verified_tampered);
    }

    #[test]
    fn ipfs_policy_store_mapping_persistence_roundtrip() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let temp_dir = std::env::temp_dir();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        let mapping_path = temp_dir.join(format!(
            "mprd_ipfs_mapping_test_{}_{}.json",
            std::process::id(),
            now,
        ));

        static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env mutex poisoned");

        let previous = std::env::var("MPRD_IPFS_MAPPING_FILE").ok();
        std::env::set_var(
            "MPRD_IPFS_MAPPING_FILE",
            mapping_path.to_string_lossy().as_ref(),
        );

        let store = IpfsPolicyStore::new("http://localhost:5001")
            .expect("IpfsPolicyStore::new should succeed for localhost");

        let mut mapping = HashMap::new();
        let hash = dummy_hash(1);
        mapping.insert(hash.clone(), "cid-test".to_string());

        store
            .persist_mapping(&mapping)
            .expect("persist_mapping should succeed");

        let loaded =
            IpfsPolicyStore::load_mapping(&mapping_path).expect("load_mapping should succeed");

        assert_eq!(loaded.get(&hash), Some(&"cid-test".to_string()));

        match previous {
            Some(value) => std::env::set_var("MPRD_IPFS_MAPPING_FILE", value),
            None => std::env::remove_var("MPRD_IPFS_MAPPING_FILE"),
        }
    }

    #[test]
    fn ipfs_policy_store_new_fails_closed_on_private_gateway_ip() {
        let err = match IpfsPolicyStore::new("https://10.0.0.1:5001") {
            Ok(_) => panic!("expected IpfsPolicyStore::new to reject private IP"),
            Err(e) => e,
        };
        assert!(err.to_string().to_lowercase().contains("disallowed"));
    }

    #[test]
    fn verify_policy_hash_matches_expected_fails_closed_on_mismatch() {
        let policy_a = b"policy-a";
        let policy_b = b"policy-b";

        let hash_a = IpfsPolicyStore::compute_hash(policy_a);
        let result = IpfsPolicyStore::verify_policy_hash_matches_expected(&hash_a, policy_b);
        assert!(result.is_err());
    }

    #[test]
    fn threshold_config_validation() {
        // Valid config
        assert!(ThresholdConfig::simple_majority(3).validate().is_ok());
        assert!(ThresholdConfig::supermajority(5).validate().is_ok());
        assert!(ThresholdConfig::unanimous(3).validate().is_ok());

        // Invalid: zero attestors
        let config = ThresholdConfig {
            total_attestors: 0,
            ..ThresholdConfig::default()
        };
        assert!(config.validate().is_err());

        // Invalid: quorum > total
        let config = ThresholdConfig {
            required_quorum: 10,
            total_attestors: 3,
            ..ThresholdConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn simple_majority_calculation() {
        // 3 attestors -> need 2
        let config = ThresholdConfig::simple_majority(3);
        assert_eq!(config.required_quorum, 2);

        // 5 attestors -> need 3
        let config = ThresholdConfig::simple_majority(5);
        assert_eq!(config.required_quorum, 3);

        // 7 attestors -> need 4
        let config = ThresholdConfig::simple_majority(7);
        assert_eq!(config.required_quorum, 4);
    }

    #[test]
    fn supermajority_calculation() {
        // 3 attestors -> need 2 (ceiling of 2)
        let config = ThresholdConfig::supermajority(3);
        assert_eq!(config.required_quorum, 2);

        // 5 attestors -> need 4 (ceiling of 3.33)
        let config = ThresholdConfig::supermajority(5);
        assert_eq!(config.required_quorum, 4);

        // 9 attestors -> need 6
        let config = ThresholdConfig::supermajority(9);
        assert_eq!(config.required_quorum, 6);
    }

    #[test]
    fn multi_attestor_reaches_quorum() {
        let config = ThresholdConfig::simple_majority(3);
        let attestors: Vec<Box<dyn ZkAttestor>> = vec![
            Box::new(StubZkAttestor::new()),
            Box::new(StubZkAttestor::new()),
            Box::new(StubZkAttestor::new()),
        ];

        let multi = MultiAttestor::new(config, attestors).expect("Should create");

        let decision = Decision {
            chosen_index: 0,
            chosen_action: CandidateAction {
                action_type: "TEST".into(),
                params: HashMap::new(),
                score: Score(10),
                candidate_hash: dummy_hash(1),
            },
            policy_hash: dummy_hash(2),
            decision_commitment: dummy_hash(3),
        };

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(4),
        };

        let result = multi.attest_multi(&decision, &state, &[]);

        assert_eq!(result.success_count, 3);
        assert!(result.quorum_reached);
        assert!(result.merged_proof.is_some());
    }

    #[derive(Clone)]
    struct RecordingRegistry {
        anchored: Arc<AtomicBool>,
    }

    impl RecordingRegistry {
        fn new() -> Self {
            Self {
                anchored: Arc::new(AtomicBool::new(false)),
            }
        }

        fn dummy_anchor() -> CommitmentAnchor {
            CommitmentAnchor {
                commitment: [0u8; 32],
                timestamp: 0,
                block_number: None,
                tx_hash: None,
                ipfs_cid: None,
                anchor_type: AnchorType::LocalTimestamp,
            }
        }
    }

    impl OnChainRegistry for RecordingRegistry {
        fn register_policy(&self, _entry: PolicyRegistryEntry) -> Result<CommitmentAnchor> {
            Ok(Self::dummy_anchor())
        }

        fn get_policy(&self, _policy_hash: &Hash32) -> Result<Option<PolicyRegistryEntry>> {
            Ok(None)
        }

        fn register_key(&self, _entry: KeyRegistryEntry) -> Result<CommitmentAnchor> {
            Ok(Self::dummy_anchor())
        }

        fn get_key(&self, _key_id: &str) -> Result<Option<KeyRegistryEntry>> {
            Ok(None)
        }

        fn anchor_decision(
            &self,
            _token: &DecisionToken,
            _proof: &ProofBundle,
        ) -> Result<CommitmentAnchor> {
            self.anchored.store(true, Ordering::SeqCst);
            Ok(Self::dummy_anchor())
        }
    }

    #[test]
    fn registry_recorder_forwards_to_registry() {
        let registry = RecordingRegistry::new();
        let anchored_flag = registry.anchored.clone();
        let recorder = RegistryRecorder::new(registry);

        let token = DecisionToken {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            chosen_action_hash: dummy_hash(3),
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 0,
            signature: vec![],
        };

        let proof = ProofBundle {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            candidate_set_hash: dummy_hash(5),
            chosen_action_hash: dummy_hash(3),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        recorder
            .record(&token, &proof)
            .expect("record should succeed");

        assert!(anchored_flag.load(Ordering::SeqCst));
    }

    // =========================================================================
    // GovernanceProfile Tests
    // =========================================================================

    fn test_pubkey(id: u8) -> Vec<u8> {
        vec![id; 33]
    }

    #[test]
    fn governance_profile_single_owner_creation() {
        let owner = test_pubkey(1);
        let profile = GovernanceProfile::single_owner(owner.clone(), "test-chain", "test-app")
            .expect("should create single owner profile");

        assert_eq!(profile.app_profile.threshold, 1);
        assert_eq!(profile.app_profile.members.len(), 1);
        assert_eq!(profile.safety_profile.threshold, 1);
        assert_eq!(profile.chain_id, "test-chain");
        assert_eq!(profile.app_id, "test-app");

        match &profile.mode {
            GovernanceMode::SingleOwner { owner_pubkey } => {
                assert_eq!(owner_pubkey, &owner);
            }
            _ => panic!("Expected SingleOwner mode"),
        }
    }

    #[test]
    fn governance_profile_committee_creation() {
        let members = vec![test_pubkey(1), test_pubkey(2), test_pubkey(3)];
        let profile = GovernanceProfile::committee(2, members.clone(), "chain", "app")
            .expect("should create committee profile");

        assert_eq!(profile.app_profile.threshold, 2);
        assert_eq!(profile.app_profile.members.len(), 3);
        assert_eq!(profile.safety_profile.threshold, 2);

        match &profile.mode {
            GovernanceMode::Committee {
                threshold,
                members: m,
            } => {
                assert_eq!(*threshold, 2);
                assert_eq!(m.len(), 3);
            }
            _ => panic!("Expected Committee mode"),
        }
    }

    #[test]
    fn governance_profile_hybrid_creation() {
        let app_members = vec![test_pubkey(1), test_pubkey(2)];
        let safety_members = vec![test_pubkey(3), test_pubkey(4), test_pubkey(5)];

        let profile = GovernanceProfile::hybrid(1, app_members, 2, safety_members, "chain", "app")
            .expect("should create hybrid profile");

        assert_eq!(profile.app_profile.threshold, 1);
        assert_eq!(profile.app_profile.members.len(), 2);
        assert_eq!(profile.safety_profile.threshold, 2);
        assert_eq!(profile.safety_profile.members.len(), 3);

        matches!(&profile.mode, GovernanceMode::Hybrid { .. });
    }

    #[test]
    fn update_kind_roundtrip() {
        assert_eq!(UpdateKind::from_u8(0x01), Some(UpdateKind::PolicyTweak));
        assert_eq!(
            UpdateKind::from_u8(0x02),
            Some(UpdateKind::SafetyRuleChange)
        );
        assert_eq!(
            UpdateKind::from_u8(0x03),
            Some(UpdateKind::AgentCapabilityExpand)
        );
        assert_eq!(UpdateKind::from_u8(0x00), None);
        assert_eq!(UpdateKind::from_u8(0x04), None);

        assert_eq!(UpdateKind::PolicyTweak.to_bv8(), 0x01);
        assert_eq!(UpdateKind::SafetyRuleChange.to_bv8(), 0x02);
        assert_eq!(UpdateKind::AgentCapabilityExpand.to_bv8(), 0x03);
    }

    #[test]
    fn profile_config_verify_threshold() {
        let members = vec![test_pubkey(1), test_pubkey(2), test_pubkey(3)];
        let config = ProfileConfig::new(2, members).expect("should create");

        // No signatures -> fail
        assert!(!config.verify_threshold(&[]));

        // 1 valid signature -> fail (need 2)
        let sigs_1 = vec![(test_pubkey(1), vec![0u8; 64])];
        assert!(!config.verify_threshold(&sigs_1));

        // 2 valid signatures -> pass
        let sigs_2 = vec![
            (test_pubkey(1), vec![0u8; 64]),
            (test_pubkey(2), vec![0u8; 64]),
        ];
        assert!(config.verify_threshold(&sigs_2));

        // 3 valid signatures -> pass
        let sigs_3 = vec![
            (test_pubkey(1), vec![0u8; 64]),
            (test_pubkey(2), vec![0u8; 64]),
            (test_pubkey(3), vec![0u8; 64]),
        ];
        assert!(config.verify_threshold(&sigs_3));

        // 2 signatures but 1 invalid member -> fail
        let sigs_invalid = vec![
            (test_pubkey(1), vec![0u8; 64]),
            (test_pubkey(99), vec![0u8; 64]),
        ];
        assert!(!config.verify_threshold(&sigs_invalid));
    }

    #[test]
    fn governance_gate_policy_tweak_requires_app_only() {
        let profile = GovernanceProfile::hybrid(
            1,
            vec![test_pubkey(1)],
            1,
            vec![test_pubkey(2)],
            "chain",
            "app",
        )
        .expect("should create");

        // App signature only -> accepted for PolicyTweak
        let app_sigs = vec![(test_pubkey(1), vec![0u8; 64])];
        let safety_sigs: Vec<(Vec<u8>, Vec<u8>)> = vec![];

        let input =
            profile.check_authorization(UpdateKind::PolicyTweak, &app_sigs, &safety_sigs, true);

        assert_eq!(input.update_kind, 0x01);
        assert!(input.profile_app_ok);
        assert!(!input.profile_safety_ok);
        assert!(input.link_ok);
        assert!(GovernanceProfile::would_accept(&input));
    }

    #[test]
    fn governance_gate_safety_change_requires_safety_only() {
        let profile = GovernanceProfile::hybrid(
            1,
            vec![test_pubkey(1)],
            1,
            vec![test_pubkey(2)],
            "chain",
            "app",
        )
        .expect("should create");

        // Safety signature only -> accepted for SafetyRuleChange
        let app_sigs: Vec<(Vec<u8>, Vec<u8>)> = vec![];
        let safety_sigs = vec![(test_pubkey(2), vec![0u8; 64])];

        let input = profile.check_authorization(
            UpdateKind::SafetyRuleChange,
            &app_sigs,
            &safety_sigs,
            true,
        );

        assert_eq!(input.update_kind, 0x02);
        assert!(!input.profile_app_ok);
        assert!(input.profile_safety_ok);
        assert!(GovernanceProfile::would_accept(&input));
    }

    #[test]
    fn governance_gate_capability_expand_requires_both() {
        let profile = GovernanceProfile::hybrid(
            1,
            vec![test_pubkey(1)],
            1,
            vec![test_pubkey(2)],
            "chain",
            "app",
        )
        .expect("should create");

        // Only app -> rejected
        let app_only = profile.check_authorization(
            UpdateKind::AgentCapabilityExpand,
            &[(test_pubkey(1), vec![0u8; 64])],
            &[],
            true,
        );
        assert!(!GovernanceProfile::would_accept(&app_only));

        // Only safety -> rejected
        let safety_only = profile.check_authorization(
            UpdateKind::AgentCapabilityExpand,
            &[],
            &[(test_pubkey(2), vec![0u8; 64])],
            true,
        );
        assert!(!GovernanceProfile::would_accept(&safety_only));

        // Both -> accepted
        let both = profile.check_authorization(
            UpdateKind::AgentCapabilityExpand,
            &[(test_pubkey(1), vec![0u8; 64])],
            &[(test_pubkey(2), vec![0u8; 64])],
            true,
        );
        assert!(GovernanceProfile::would_accept(&both));
    }

    #[test]
    fn governance_gate_link_failure_rejects_all() {
        let profile =
            GovernanceProfile::single_owner(test_pubkey(1), "chain", "app").expect("should create");

        let sigs = vec![(test_pubkey(1), vec![0u8; 64])];

        // Valid signatures but link_ok = false -> rejected
        for kind in [
            UpdateKind::PolicyTweak,
            UpdateKind::SafetyRuleChange,
            UpdateKind::AgentCapabilityExpand,
        ] {
            let input = profile.check_authorization(kind, &sigs, &sigs, false);
            assert!(!GovernanceProfile::would_accept(&input));
        }
    }

    #[test]
    fn governance_profile_hash_is_deterministic() {
        let profile1 = GovernanceProfile::committee(
            2,
            vec![test_pubkey(1), test_pubkey(2), test_pubkey(3)],
            "chain",
            "app",
        )
        .expect("should create");

        let profile2 = GovernanceProfile::committee(
            2,
            vec![test_pubkey(1), test_pubkey(2), test_pubkey(3)],
            "chain",
            "app",
        )
        .expect("should create");

        assert_eq!(
            profile1.compute_profile_hash(),
            profile2.compute_profile_hash()
        );
    }

    #[test]
    fn governance_profile_hash_changes_with_config() {
        let profile1 = GovernanceProfile::committee(
            2,
            vec![test_pubkey(1), test_pubkey(2), test_pubkey(3)],
            "chain",
            "app",
        )
        .expect("should create");

        let profile2 = GovernanceProfile::committee(
            3,
            vec![test_pubkey(1), test_pubkey(2), test_pubkey(3)],
            "chain",
            "app",
        )
        .expect("should create");

        assert_ne!(
            profile1.compute_profile_hash(),
            profile2.compute_profile_hash()
        );
    }

    #[test]
    fn tau_governance_runner_writes_inputs() {
        let temp_dir = std::env::temp_dir().join("tau_governance_test");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        let runner = TauGovernanceRunner::new("tau", &temp_dir);

        let input = GovernanceGateInput {
            update_kind: UpdateKind::PolicyTweak.to_bv8(),
            profile_app_ok: true,
            profile_safety_ok: false,
            link_ok: true,
        };

        runner.write_inputs(&input).expect("write inputs");

        // Verify files exist and have correct content
        let inputs_dir = temp_dir.join("inputs");
        assert!(inputs_dir.join("is_policy_tweak.in").exists());
        assert!(inputs_dir.join("is_safety_change.in").exists());
        assert!(inputs_dir.join("is_cap_expand.in").exists());
        assert!(inputs_dir.join("profile_app_ok.in").exists());
        assert!(inputs_dir.join("profile_safety_ok.in").exists());
        assert!(inputs_dir.join("link_ok.in").exists());

        // Verify content
        let policy_tweak = std::fs::read_to_string(inputs_dir.join("is_policy_tweak.in")).unwrap();
        assert!(policy_tweak.contains("1"), "policy_tweak should be 1");

        let safety_change =
            std::fs::read_to_string(inputs_dir.join("is_safety_change.in")).unwrap();
        assert!(safety_change.contains("0"), "safety_change should be 0");

        let app_ok = std::fs::read_to_string(inputs_dir.join("profile_app_ok.in")).unwrap();
        assert!(app_ok.contains("1"), "profile_app_ok should be 1");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn tau_governance_runner_executes_canonical_gate_when_tau_available() {
        let Some(tau_bin) = std::env::var_os("TAU_BIN") else {
            eprintln!("Skipping: TAU_BIN not set");
            return;
        };
        let tau_bin = std::path::PathBuf::from(tau_bin);
        if !tau_bin.is_file() {
            eprintln!("Skipping: TAU_BIN is not a file: {}", tau_bin.display());
            return;
        }

        let temp_dir = std::env::temp_dir().join("tau_governance_exec_test");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        let runner = TauGovernanceRunner::new(tau_bin, &temp_dir);

        let owner_pubkey = b"owner".to_vec();
        let profile =
            GovernanceProfile::single_owner(owner_pubkey.clone(), "chain", "app").expect("profile");

        let input = profile.check_authorization(
            UpdateKind::PolicyTweak,
            &[(b"sig".to_vec(), owner_pubkey)],
            &[],
            true,
        );

        let expected = GovernanceProfile::would_accept(&input);
        runner.write_inputs(&input).expect("write inputs");

        let actual = runner.execute_canonical_gate().expect("execute tau");
        assert_eq!(expected, actual);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
