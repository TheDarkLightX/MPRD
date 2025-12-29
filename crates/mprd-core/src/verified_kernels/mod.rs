//! Verified kernels - formally verified state machines from ESSO models.
//!
//! Each kernel is generated from an ESSO-IR model using CGS v3.0 codegen.
//! These kernels enforce CBC (Correct-By-Construction) properties:
//! - Invalid states are unrepresentable
//! - All transitions check pre/post invariants
//! - Fail-closed on any domain violation
//!
//! Synthesis-as-Spec: For models with holes, synth.json defines the grammar
//! and CGS synthesizes verified solutions.

#[cfg(kani)]
pub mod kani_harnesses;


// Artifact/commit kernels
pub mod artifact_commit_consistency_gate;

// Autopilot
pub mod autopilot_controller;

// BCR staking
pub mod bcr_staking;

// Decision token security kernels
pub mod decision_token_anti_replay_race;
pub mod decision_token_timestamp_freshness;

// Drip payroll
pub mod drip_payroll;

// Executor kernels
pub mod executor_action_preimage_binding;
pub mod executor_circuit_breaker;

// Fee distribution
pub mod fee_distribution;

// Mining kernels
pub mod mprd_difficulty_adjustment;
pub mod mprd_emission_schedule;
pub mod mprd_operator_mining_round;
pub mod mprd_proof_market_slot;
pub mod mprd_reward_pool;
pub mod mprd_work_submission;
pub mod mprd_work_verification;

// Tokenomics v6 kernels
pub mod mprd_v6_auction_escrow_carry;
pub mod mprd_v6_fee_lanes_bcr_caps;
pub mod mprd_v6_stake_penalty_shares;

// Oracle kernels
pub mod opi_oracle_round;
pub mod optimistic_relay_claim;

// Reserve/staking kernels
pub mod rate_limited_withdrawals;
pub mod reserve_management;
pub mod reverse_auction;
pub mod slashing_escrow;

// Selector kernels
pub mod selector_canonical_tiebreak;
pub mod selector_fail_closed_required_limits;

// Security kernels
pub mod tau_attestation_replay_guard;

// Policy governance kernels (high priority security)
pub mod nonce_manager_lifecycle;
pub mod policy_algebra_operators;
pub mod policy_registry_gate;

// Tokenomics
pub mod tokenomics_ceo_menu;

// UI kernels
pub mod ui_mode_adaptive_gates;
pub mod ui_trust_anchor_fingerprints_only;

