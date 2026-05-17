//! Production deployment wiring checks.
//!
//! This command validates that a deployment bundle is self-consistent and fail-closed:
//! - signed registry checkpoint verifies under a verifier-trusted key
//! - signed guest image manifest verifies under its verifier-trusted key
//! - every authorized policy has a local policy artifact file (content-addressed by policy_hash)
//! - every authorized policy's exec kind/version resolves to an image_id in the manifest

use crate::config_model::MprdConfigFile;
use anyhow::{Context, Result};
use mprd_core::{Hash32, PolicyRef, TokenVerifyingKey};
use mprd_risc0_shared::{
    decode_compiled_tau_policy_v1, policy_exec_kind_host_trusted_id_v0, policy_exec_kind_mpb_id_v1,
    policy_exec_kind_tau_compiled_id_v1, policy_exec_version_id_v1, policy_source_kind_tau_id_v1,
    tau_compiled_policy_hash_v1, Id32,
};
use mprd_zk::policy_artifacts::decode_mpb_policy_artifact_bytes_v1;
use mprd_zk::policy_fetch::{DirPolicyArtifactStore, PolicyArtifactStore};
use mprd_zk::registry_state::{
    AuthorizedPolicyV1, RegistryStateProvider, RegistryStateV1, SignedRegistryStateV1,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;

pub const STRICT_GOVERNED_SOURCE_EXIT_CODE: i32 = 2;
pub const STRICT_SOURCE_ARTIFACT_WITNESS_EXIT_CODE: i32 = 3;
const GENERIC_BUNDLE_FAILURE_EXIT_CODE: i32 = 1;
const STRICT_GOVERNED_SOURCE_ISSUE_UNKNOWN_DECLARED_EXEC_KIND: &str = "unknown_declared_exec_kind";
const STRICT_GOVERNED_SOURCE_ISSUE_TAU_DECLARED_MAPPING_MISSING: &str =
    "tau_declared_mapping_missing";
const STRICT_GOVERNED_SOURCE_ISSUE_POLICY_NOT_TAU_GOVERNED: &str = "policy_not_tau_governed";
const STRICT_GOVERNED_SOURCE_ISSUE_INTERNAL_ERROR: &str = "strict_governed_source_internal_error";
const STRICT_GOVERNED_SOURCE_RESPONSE_MATRIX_SCHEMA_V1: &str =
    "mprd/deploy-check-bundle-strict-governed-source-response-matrix/v1";
const STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_UNKNOWN_DECLARED_EXEC_KIND: &str =
    "unknown_declared_exec_kind";
const STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_MAPPING_MISSING: &str =
    "source_artifact_mapping_missing";
const STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_ARTIFACT_VALIDATION_MISSING: &str =
    "source_artifact_validation_missing";
const STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_INTERNAL_ERROR: &str =
    "strict_source_artifact_witness_internal_error";
const STRICT_SOURCE_ARTIFACT_WITNESS_RESPONSE_MATRIX_SCHEMA_V1: &str =
    "mprd/deploy-check-bundle-strict-source-artifact-witness-response-matrix/v1";
const STRICT_SELECTOR_ALIAS_MATRIX_SCHEMA_V1: &str =
    "mprd/deploy-check-bundle-strict-selector-alias-matrix/v1";
const PRODUCTION_RELEASE_REPORT_SCHEMA_V1: &str = "mprd/deploy-verify-release/v1";
const PRODUCTION_RELEASE_ISSUE_HOST_TRUSTED: &str = "host_trusted_v0_release_route";
const PRODUCTION_RELEASE_ISSUE_UNSUPPORTED_EXEC_KIND: &str = "unsupported_production_exec_kind";
const PRODUCTION_RELEASE_ISSUE_MISSING_IMAGE_ID: &str = "missing_image_id";
const PRODUCTION_RELEASE_ISSUE_ALL_ZERO_IMAGE_ID: &str = "all_zero_image_id";
const PRODUCTION_RELEASE_ISSUE_PLACEHOLDER_METHODS: &str = "placeholder_risc0_methods";
const PRODUCTION_RELEASE_ISSUE_MISSING_SOURCE_MAPPING: &str = "missing_policy_source_mapping";
const PRODUCTION_RELEASE_ISSUE_CONFIG_LOCAL_MODE: &str = "production_config_local_mode";
const PRODUCTION_RELEASE_ISSUE_CONFIG_PLACEHOLDER_IMAGE_ID: &str =
    "production_config_placeholder_image_id";
const PRODUCTION_RELEASE_ISSUE_ONCHAIN_FINALITY_UNSUPPORTED: &str =
    "production_config_onchain_finality_unsupported";
const PRODUCTION_RELEASE_ISSUE_CONFIG_MISSING_NONCE_STORE: &str =
    "production_config_missing_nonce_store";
const PRODUCTION_RELEASE_ISSUE_CONFIG_LOWTRUST_REDIS_REQUIRED: &str =
    "production_config_lowtrust_redis_required";

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum BundleCheckError {
    #[error("missing policy artifact file for policy_hash={policy_hash_hex}")]
    MissingPolicyArtifact { policy_hash_hex: String },
    #[error("production release check failed: issue_kind={issue_kind} first_issue={first_issue}")]
    ProductionReleaseViolation {
        issue_kind: String,
        first_issue: String,
    },
    #[error(
        "strict governed-source check failed: declared_exec_kinds={declared_exec_kinds_csv} issue_kind={issue_kind} first_issue={first_issue} strict_failure_digest={strict_failure_digest_hex}"
    )]
    StrictGovernedSourceViolation {
        declared_exec_kinds_csv: String,
        issue_kind: String,
        first_issue: String,
        strict_failure_digest_hex: String,
    },
    #[error(
        "strict source-artifact-witness check failed: declared_exec_kinds={declared_exec_kinds_csv} issue_kind={issue_kind} first_issue={first_issue} strict_failure_digest={strict_failure_digest_hex}"
    )]
    StrictSourceArtifactWitnessViolation {
        declared_exec_kinds_csv: String,
        issue_kind: String,
        first_issue: String,
        strict_failure_digest_hex: String,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
struct PolicySourceGovernanceSummary {
    tau_governed_mapped: usize,
    other_mapped: usize,
    unmapped: usize,
}

impl PolicySourceGovernanceSummary {
    fn observe(&mut self, authorized_policy: &AuthorizedPolicyV1) {
        match source_governance_label(authorized_policy) {
            "TauGovernedMapped" => self.tau_governed_mapped += 1,
            "OtherMapped" => self.other_mapped += 1,
            "Unmapped" => self.unmapped += 1,
            _ => unreachable!("source_governance_label is closed over known labels"),
        }
    }
}

fn summarize_policy_source_governance(
    authorized_policies: &[AuthorizedPolicyV1],
) -> PolicySourceGovernanceSummary {
    let mut summary = PolicySourceGovernanceSummary::default();
    for authorized_policy in authorized_policies {
        summary.observe(authorized_policy);
    }
    summary
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct BundlePolicyReport {
    policy_hash_hex: String,
    policy_exec_kind: String,
    strict_selector_aliases: Vec<String>,
    policy_exec_version_hex: String,
    source_governance: String,
    source_intent_classification: String,
    source_boundary_classification: String,
    policy_source_kind_hex: Option<String>,
    policy_source_hash_hex: Option<String>,
    artifact_hash_validated: bool,
    source_artifact_witness_state: String,
    artifact_validation: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct BundleCheckReport {
    policy_epoch: u64,
    registry_root_hex: String,
    validated_policy_count: usize,
    skipped_policy_count: usize,
    total_policy_count: usize,
    source_governance: PolicySourceGovernanceSummary,
    policy_artifacts_dir: String,
    policies: Vec<BundlePolicyReport>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct ProductionReleasePolicyReport {
    policy_hash_hex: String,
    policy_exec_kind: String,
    policy_exec_version_hex: String,
    image_id_hex: String,
    source_governance: String,
    artifact_validation: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct ProductionReleaseReport {
    report_schema: &'static str,
    policy_epoch: u64,
    registry_root_hex: String,
    production_policy_count: usize,
    policies: Vec<ProductionReleasePolicyReport>,
}

const NORMALIZED_BUNDLE_CHECK_REPORT_SCHEMA_V1: &str = "mprd/deploy-check-bundle-normalized/v1";
const STRICT_GOVERNED_SOURCE_FAILURE_REPORT_SCHEMA_V1: &str =
    "mprd/deploy-check-bundle-strict-governed-source-failure/v1";
const STRICT_SOURCE_ARTIFACT_WITNESS_FAILURE_REPORT_SCHEMA_V1: &str =
    "mprd/deploy-check-bundle-strict-source-artifact-witness-failure/v1";

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct NormalizedBundleCheckReport {
    report_schema: &'static str,
    policy_epoch: u64,
    registry_root_hex: String,
    validated_policy_count: usize,
    skipped_policy_count: usize,
    total_policy_count: usize,
    source_governance: PolicySourceGovernanceSummary,
    policies: Vec<BundlePolicyReport>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct StrictGovernedSourceFailureReport {
    report_schema: &'static str,
    normalized_bundle_digest_hex: String,
    declared_governed_exec_kinds: Vec<String>,
    issue_kind: String,
    classification: String,
    required_response: String,
    first_issue: String,
    unknown_declared_exec_kinds: Vec<String>,
    failing_policies: Vec<BundlePolicyReport>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct StrictSourceArtifactWitnessFailureReport {
    report_schema: &'static str,
    normalized_bundle_digest_hex: String,
    declared_artifact_witness_exec_kinds: Vec<String>,
    issue_kind: String,
    classification: String,
    required_response: String,
    first_issue: String,
    unknown_declared_exec_kinds: Vec<String>,
    failing_policies: Vec<BundlePolicyReport>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
struct StrictGovernedSourceResponseRule {
    issue_kind: &'static str,
    exit_code: i32,
    classification: &'static str,
    required_response: &'static str,
    machine_witness_formats: &'static [&'static str],
    human_surface: &'static str,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct StrictGovernedSourceResponseMatrix {
    report_schema: &'static str,
    rejection_exit_code: i32,
    generic_bundle_failure_exit_code: i32,
    rules: Vec<StrictGovernedSourceResponseRule>,
    generic_failure_rule: StrictGovernedSourceGenericFailureRule,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct StrictSourceArtifactWitnessResponseMatrix {
    report_schema: &'static str,
    rejection_exit_code: i32,
    generic_bundle_failure_exit_code: i32,
    rules: Vec<StrictSourceArtifactWitnessResponseRule>,
    generic_failure_rule: StrictSourceArtifactWitnessGenericFailureRule,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
struct StrictGovernedSourceGenericFailureRule {
    error_class: &'static str,
    exit_code: i32,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
struct StrictSourceArtifactWitnessResponseRule {
    issue_kind: &'static str,
    exit_code: i32,
    classification: &'static str,
    required_response: &'static str,
    machine_witness_formats: &'static [&'static str],
    human_surface: &'static str,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
struct StrictSourceArtifactWitnessGenericFailureRule {
    error_class: &'static str,
    exit_code: i32,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct StrictSelectorAliasFamily {
    exec_kind_label: String,
    canonical_exec_kind_hex: String,
    selector_aliases: Vec<String>,
    accepted_by_surfaces: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct StrictSelectorAliasMatrix {
    report_schema: &'static str,
    built_in_only: bool,
    selector_match_rule: &'static str,
    custom_exec_kind_rule: &'static str,
    families: Vec<StrictSelectorAliasFamily>,
}

const STRICT_GOVERNED_SOURCE_RESPONSE_RULES: [StrictGovernedSourceResponseRule; 3] = [
    StrictGovernedSourceResponseRule {
        issue_kind: STRICT_GOVERNED_SOURCE_ISSUE_UNKNOWN_DECLARED_EXEC_KIND,
        exit_code: STRICT_GOVERNED_SOURCE_EXIT_CODE,
        classification: "operator_input_invalid",
        required_response: "reject_bundle_and_fix_declared_exec_kind",
        machine_witness_formats: &["json", "digest"],
        human_surface: "stderr",
    },
    StrictGovernedSourceResponseRule {
        issue_kind: STRICT_GOVERNED_SOURCE_ISSUE_TAU_DECLARED_MAPPING_MISSING,
        exit_code: STRICT_GOVERNED_SOURCE_EXIT_CODE,
        classification: "governed_source_mapping_missing",
        required_response: "reject_bundle_and_publish_tau_mapping",
        machine_witness_formats: &["json", "digest"],
        human_surface: "stderr",
    },
    StrictGovernedSourceResponseRule {
        issue_kind: STRICT_GOVERNED_SOURCE_ISSUE_POLICY_NOT_TAU_GOVERNED,
        exit_code: STRICT_GOVERNED_SOURCE_EXIT_CODE,
        classification: "governed_source_violation",
        required_response: "reject_bundle_and_fix_policy_mapping_or_declaration",
        machine_witness_formats: &["json", "digest"],
        human_surface: "stderr",
    },
];

const STRICT_SOURCE_ARTIFACT_WITNESS_RESPONSE_RULES: [StrictSourceArtifactWitnessResponseRule; 3] = [
    StrictSourceArtifactWitnessResponseRule {
        issue_kind: STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_UNKNOWN_DECLARED_EXEC_KIND,
        exit_code: STRICT_SOURCE_ARTIFACT_WITNESS_EXIT_CODE,
        classification: "operator_input_invalid",
        required_response: "reject_bundle_and_fix_declared_exec_kind",
        machine_witness_formats: &["json", "digest"],
        human_surface: "stderr",
    },
    StrictSourceArtifactWitnessResponseRule {
        issue_kind: STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_MAPPING_MISSING,
        exit_code: STRICT_SOURCE_ARTIFACT_WITNESS_EXIT_CODE,
        classification: "source_artifact_mapping_missing",
        required_response: "reject_bundle_and_publish_source_mapping",
        machine_witness_formats: &["json", "digest"],
        human_surface: "stderr",
    },
    StrictSourceArtifactWitnessResponseRule {
        issue_kind: STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_ARTIFACT_VALIDATION_MISSING,
        exit_code: STRICT_SOURCE_ARTIFACT_WITNESS_EXIT_CODE,
        classification: "source_artifact_validation_missing",
        required_response: "reject_bundle_and_publish_validated_artifact",
        machine_witness_formats: &["json", "digest"],
        human_surface: "stderr",
    },
];

fn strict_governed_source_response_rule(
    issue_kind: &str,
) -> Option<&'static StrictGovernedSourceResponseRule> {
    STRICT_GOVERNED_SOURCE_RESPONSE_RULES
        .iter()
        .find(|rule| rule.issue_kind == issue_kind)
}

fn strict_source_artifact_witness_response_rule(
    issue_kind: &str,
) -> Option<&'static StrictSourceArtifactWitnessResponseRule> {
    STRICT_SOURCE_ARTIFACT_WITNESS_RESPONSE_RULES
        .iter()
        .find(|rule| rule.issue_kind == issue_kind)
}

fn strict_governed_source_response_matrix() -> StrictGovernedSourceResponseMatrix {
    StrictGovernedSourceResponseMatrix {
        report_schema: STRICT_GOVERNED_SOURCE_RESPONSE_MATRIX_SCHEMA_V1,
        rejection_exit_code: STRICT_GOVERNED_SOURCE_EXIT_CODE,
        generic_bundle_failure_exit_code: GENERIC_BUNDLE_FAILURE_EXIT_CODE,
        rules: STRICT_GOVERNED_SOURCE_RESPONSE_RULES.to_vec(),
        generic_failure_rule: StrictGovernedSourceGenericFailureRule {
            error_class: "bundle_validation_failure",
            exit_code: GENERIC_BUNDLE_FAILURE_EXIT_CODE,
        },
    }
}

fn strict_source_artifact_witness_response_matrix() -> StrictSourceArtifactWitnessResponseMatrix {
    StrictSourceArtifactWitnessResponseMatrix {
        report_schema: STRICT_SOURCE_ARTIFACT_WITNESS_RESPONSE_MATRIX_SCHEMA_V1,
        rejection_exit_code: STRICT_SOURCE_ARTIFACT_WITNESS_EXIT_CODE,
        generic_bundle_failure_exit_code: GENERIC_BUNDLE_FAILURE_EXIT_CODE,
        rules: STRICT_SOURCE_ARTIFACT_WITNESS_RESPONSE_RULES.to_vec(),
        generic_failure_rule: StrictSourceArtifactWitnessGenericFailureRule {
            error_class: "bundle_validation_failure",
            exit_code: GENERIC_BUNDLE_FAILURE_EXIT_CODE,
        },
    }
}

fn strict_selector_alias_matrix() -> StrictSelectorAliasMatrix {
    let accepted_by_surfaces = vec![
        "strict_governed_source".to_string(),
        "strict_source_artifact_witness".to_string(),
    ];
    let mut families = vec![
        StrictSelectorAliasFamily {
            exec_kind_label: "mpb_v1".into(),
            canonical_exec_kind_hex: hex::encode(policy_exec_kind_mpb_id_v1()),
            selector_aliases: policy_exec_kind_aliases_from_label("mpb_v1"),
            accepted_by_surfaces: accepted_by_surfaces.clone(),
        },
        StrictSelectorAliasFamily {
            exec_kind_label: "tau_compiled_v1".into(),
            canonical_exec_kind_hex: hex::encode(policy_exec_kind_tau_compiled_id_v1()),
            selector_aliases: policy_exec_kind_aliases_from_label("tau_compiled_v1"),
            accepted_by_surfaces,
        },
    ];
    families.sort_by(|a, b| a.exec_kind_label.cmp(&b.exec_kind_label));
    StrictSelectorAliasMatrix {
        report_schema: STRICT_SELECTOR_ALIAS_MATRIX_SCHEMA_V1,
        built_in_only: true,
        selector_match_rule:
            "declared exec kind matches any per-policy strict_selector_aliases entry",
        custom_exec_kind_rule:
            "non-built-in selectors are recognized only when present in bundle policy rows",
        families,
    }
}

fn policy_source_mapping_present(authorized_policy: &AuthorizedPolicyV1) -> bool {
    authorized_policy.policy_source_kind_id.is_some()
        && authorized_policy.policy_source_hash.is_some()
}

fn policy_source_kind_is_tau(authorized_policy: &AuthorizedPolicyV1) -> bool {
    authorized_policy
        .policy_source_kind_id
        .as_ref()
        .map(|kind| *kind == policy_source_kind_tau_id_v1())
        .unwrap_or(false)
}

fn policy_exec_kind_is_tau_compiled(authorized_policy: &AuthorizedPolicyV1) -> bool {
    authorized_policy.policy_exec_kind_id == policy_exec_kind_tau_compiled_id_v1()
}

fn source_governance_label(authorized_policy: &AuthorizedPolicyV1) -> &'static str {
    match (
        authorized_policy.policy_source_kind_id.as_ref(),
        authorized_policy.policy_source_hash.as_ref(),
    ) {
        (Some(kind), Some(_)) if *kind == policy_source_kind_tau_id_v1() => "TauGovernedMapped",
        (Some(_), Some(_)) => "OtherMapped",
        _ => "Unmapped",
    }
}

fn source_intent_classification_label(authorized_policy: &AuthorizedPolicyV1) -> &'static str {
    if policy_source_kind_is_tau(authorized_policy)
        || policy_exec_kind_is_tau_compiled(authorized_policy)
    {
        "TauDeclared"
    } else if authorized_policy.policy_source_kind_id.is_some() {
        "OtherDeclared"
    } else {
        "Undeclared"
    }
}

fn source_boundary_classification_label(authorized_policy: &AuthorizedPolicyV1) -> &'static str {
    match source_governance_label(authorized_policy) {
        "TauGovernedMapped" => "TauGovernedMapped",
        "OtherMapped" => "OtherMapped",
        "Unmapped" if policy_exec_kind_is_tau_compiled(authorized_policy) => {
            "TauCompiledCarrierUnmapped"
        }
        "Unmapped" => "OtherCarrierUnmapped",
        _ => unreachable!("source_governance_label is closed over known labels"),
    }
}

fn is_all_zero_id(id: &Id32) -> bool {
    *id == [0u8; 32]
}

fn policy_exec_kind_label_from_parts(exec_kind_id: &Id32, exec_version_id: &Id32) -> String {
    if *exec_kind_id == policy_exec_kind_host_trusted_id_v0() {
        "host_trusted_v0".to_string()
    } else if *exec_kind_id == policy_exec_kind_mpb_id_v1()
        && *exec_version_id == policy_exec_version_id_v1()
    {
        "mpb_v1".to_string()
    } else if *exec_kind_id == policy_exec_kind_tau_compiled_id_v1()
        && *exec_version_id == policy_exec_version_id_v1()
    {
        "tau_compiled_v1".to_string()
    } else {
        hex::encode(exec_kind_id)
    }
}

fn policy_exec_kind_label(authorized_policy: &AuthorizedPolicyV1) -> String {
    policy_exec_kind_label_from_parts(
        &authorized_policy.policy_exec_kind_id,
        &authorized_policy.policy_exec_version_id,
    )
}

fn build_bundle_policy_report(
    authorized_policy: &AuthorizedPolicyV1,
    artifact_validation: &str,
) -> BundlePolicyReport {
    let artifact_hash_validated = artifact_validation == "validated";
    let policy_exec_kind = policy_exec_kind_label(authorized_policy);
    BundlePolicyReport {
        policy_hash_hex: hex::encode(authorized_policy.policy_hash.0),
        strict_selector_aliases: policy_exec_kind_aliases_from_label(&policy_exec_kind),
        policy_exec_kind,
        policy_exec_version_hex: hex::encode(authorized_policy.policy_exec_version_id),
        source_governance: source_governance_label(authorized_policy).into(),
        source_intent_classification: source_intent_classification_label(authorized_policy).into(),
        source_boundary_classification: source_boundary_classification_label(authorized_policy)
            .into(),
        policy_source_kind_hex: authorized_policy.policy_source_kind_id.map(hex::encode),
        policy_source_hash_hex: authorized_policy
            .policy_source_hash
            .as_ref()
            .map(|hash| hex::encode(hash.0)),
        artifact_hash_validated,
        source_artifact_witness_state: source_artifact_witness_state_label(
            authorized_policy,
            artifact_hash_validated,
        )
        .into(),
        artifact_validation: artifact_validation.into(),
    }
}

fn source_artifact_witness_state_label(
    authorized_policy: &AuthorizedPolicyV1,
    artifact_hash_validated: bool,
) -> &'static str {
    if !policy_source_mapping_present(authorized_policy) {
        "BlockedMissingSourceMapping"
    } else if artifact_hash_validated {
        "Ready"
    } else {
        "BlockedArtifactValidation"
    }
}

fn sort_bundle_policy_reports(policies: &mut [BundlePolicyReport]) {
    // Keep deploy output stable even if registry entries arrive in a different order.
    policies.sort_by(|a, b| {
        a.policy_hash_hex
            .cmp(&b.policy_hash_hex)
            .then_with(|| a.policy_exec_kind.cmp(&b.policy_exec_kind))
            .then_with(|| a.policy_exec_version_hex.cmp(&b.policy_exec_version_hex))
    });
}

fn load_verified_registry_state(
    registry_state_path: PathBuf,
    registry_key_hex: String,
    manifest_key_hex: Option<String>,
) -> Result<RegistryStateV1> {
    let registry_vk =
        TokenVerifyingKey::from_hex(&registry_key_hex).context("Invalid --registry-key-hex")?;
    let manifest_vk = match manifest_key_hex.as_deref() {
        None => registry_vk.clone(),
        Some(hex) => TokenVerifyingKey::from_hex(hex).context("Invalid --manifest-key-hex")?,
    };

    let json = fs::read_to_string(&registry_state_path).with_context(|| {
        format!(
            "Failed to read registry_state file: {}",
            registry_state_path.display()
        )
    })?;
    let signed: SignedRegistryStateV1 =
        serde_json::from_str(&json).context("Failed to parse registry_state JSON")?;

    let provider = Arc::new(
        mprd_zk::registry_state::SignedStaticRegistryStateProvider::new(signed, registry_vk),
    );
    let state = RegistryStateProvider::get(provider.as_ref())
        .context("Failed to verify signed registry_state")?;

    state
        .verify_manifest(&manifest_vk)
        .context("Failed to verify signed guest image manifest")?;
    Ok(state)
}

fn build_bundle_check_report(
    registry_state_path: PathBuf,
    registry_key_hex: String,
    manifest_key_hex: Option<String>,
    policy_artifacts_dir: PathBuf,
) -> Result<BundleCheckReport> {
    let state =
        load_verified_registry_state(registry_state_path, registry_key_hex, manifest_key_hex)?;

    let policy_ref = PolicyRef {
        policy_epoch: state.policy_epoch,
        registry_root: state.registry_root,
    };

    let store = DirPolicyArtifactStore::new(&policy_artifacts_dir);
    let mut validated_policy_count = 0usize;
    let mut skipped_policy_count = 0usize;
    let source_governance = summarize_policy_source_governance(&state.authorized_policies);
    let mut policies = Vec::with_capacity(state.authorized_policies.len());

    for authorized_policy in &state.authorized_policies {
        state
            .guest_image_manifest
            .image_id_for(
                &authorized_policy.policy_exec_kind_id,
                &authorized_policy.policy_exec_version_id,
            )
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "manifest missing image_id for exec kind/version (policy_hash={})",
                    hex::encode(authorized_policy.policy_hash.0)
                )
            })?;

        let artifact_validation = match authorized_policy.policy_exec_kind_id {
            kind if kind == policy_exec_kind_mpb_id_v1()
                && authorized_policy.policy_exec_version_id == policy_exec_version_id_v1() =>
            {
                validate_mpb_policy_artifact(&store, &policy_ref, authorized_policy)?;
                validated_policy_count += 1;
                "validated"
            }
            kind if kind == policy_exec_kind_tau_compiled_id_v1()
                && authorized_policy.policy_exec_version_id == policy_exec_version_id_v1() =>
            {
                validate_tau_compiled_policy_artifact(&store, &policy_ref, authorized_policy)?;
                validated_policy_count += 1;
                "validated"
            }
            _ => {
                skipped_policy_count += 1;
                "skipped"
            }
        };

        policies.push(build_bundle_policy_report(
            authorized_policy,
            artifact_validation,
        ));
    }
    sort_bundle_policy_reports(&mut policies);

    Ok(BundleCheckReport {
        policy_epoch: policy_ref.policy_epoch,
        registry_root_hex: hex::encode(policy_ref.registry_root.0),
        validated_policy_count,
        skipped_policy_count,
        total_policy_count: state.authorized_policies.len(),
        source_governance,
        policy_artifacts_dir: policy_artifacts_dir.display().to_string(),
        policies,
    })
}

fn print_bundle_check_report_human(report: &BundleCheckReport) {
    println!("✅ Bundle check passed");
    println!("   policy_epoch:  {}", report.policy_epoch);
    println!("   registry_root: {}", report.registry_root_hex);
    println!(
        "   policies: {} validated, {} skipped, {} total",
        report.validated_policy_count, report.skipped_policy_count, report.total_policy_count
    );
    println!(
        "   source_governance: tau_governed_mapped={}, other_mapped={}, unmapped={}",
        report.source_governance.tau_governed_mapped,
        report.source_governance.other_mapped,
        report.source_governance.unmapped
    );
    println!("   policy_source_rows:");
    for policy in &report.policies {
        println!(
            "      {} source={} intent={} boundary={} exec_kind={} artifact={} witness={}",
            policy.policy_hash_hex,
            policy.source_governance,
            policy.source_intent_classification,
            policy.source_boundary_classification,
            policy.policy_exec_kind,
            policy.artifact_validation,
            policy.source_artifact_witness_state
        );
    }
    println!("   policy_artifacts_dir: {}", report.policy_artifacts_dir);
}

fn format_bundle_check_report_json(report: &BundleCheckReport) -> Result<String> {
    serde_json::to_string_pretty(report).context("Failed to serialize bundle report")
}

fn normalized_bundle_check_report(report: &BundleCheckReport) -> NormalizedBundleCheckReport {
    NormalizedBundleCheckReport {
        report_schema: NORMALIZED_BUNDLE_CHECK_REPORT_SCHEMA_V1,
        policy_epoch: report.policy_epoch,
        registry_root_hex: report.registry_root_hex.clone(),
        validated_policy_count: report.validated_policy_count,
        skipped_policy_count: report.skipped_policy_count,
        total_policy_count: report.total_policy_count,
        source_governance: report.source_governance,
        policies: report.policies.clone(),
    }
}

fn format_normalized_bundle_check_report_json(report: &BundleCheckReport) -> Result<String> {
    serde_json::to_string_pretty(&normalized_bundle_check_report(report))
        .context("Failed to serialize normalized bundle report")
}

fn format_bundle_check_report_digest(report: &BundleCheckReport) -> Result<String> {
    let normalized_json = format_normalized_bundle_check_report_json(report)?;
    let mut hasher = Sha256::new();
    hasher.update(normalized_json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn production_release_violation(
    issue_kind: &'static str,
    first_issue: impl Into<String>,
) -> anyhow::Error {
    BundleCheckError::ProductionReleaseViolation {
        issue_kind: issue_kind.into(),
        first_issue: first_issue.into(),
    }
    .into()
}

fn production_release_exec_kind_label(
    authorized_policy: &AuthorizedPolicyV1,
) -> Result<&'static str> {
    let policy_hash_hex = hex::encode(authorized_policy.policy_hash.0);
    if authorized_policy.policy_exec_kind_id == policy_exec_kind_host_trusted_id_v0() {
        return Err(production_release_violation(
            PRODUCTION_RELEASE_ISSUE_HOST_TRUSTED,
            format!(
                "policy_hash={policy_hash_hex} exec_kind=host_trusted_v0 is demo/dev-only and is not a production release route"
            ),
        ));
    }

    if authorized_policy.policy_exec_kind_id == policy_exec_kind_mpb_id_v1()
        && authorized_policy.policy_exec_version_id == policy_exec_version_id_v1()
    {
        return Ok("mpb_v1");
    }

    if authorized_policy.policy_exec_kind_id == policy_exec_kind_tau_compiled_id_v1()
        && authorized_policy.policy_exec_version_id == policy_exec_version_id_v1()
    {
        return Ok("tau_compiled_v1");
    }

    Err(production_release_violation(
        PRODUCTION_RELEASE_ISSUE_UNSUPPORTED_EXEC_KIND,
        format!(
            "policy_hash={} exec_kind={} exec_version={} is not in production allowlist (mpb_v1,tau_compiled_v1)",
            policy_hash_hex,
            hex::encode(authorized_policy.policy_exec_kind_id),
            hex::encode(authorized_policy.policy_exec_version_id)
        ),
    ))
}

fn sort_production_release_policy_reports(policies: &mut [ProductionReleasePolicyReport]) {
    policies.sort_by(|a, b| {
        a.policy_hash_hex
            .cmp(&b.policy_hash_hex)
            .then_with(|| a.policy_exec_kind.cmp(&b.policy_exec_kind))
            .then_with(|| a.policy_exec_version_hex.cmp(&b.policy_exec_version_hex))
    });
}

fn build_production_release_report(
    registry_state_path: PathBuf,
    registry_key_hex: String,
    manifest_key_hex: Option<String>,
    policy_artifacts_dir: PathBuf,
) -> Result<ProductionReleaseReport> {
    let state =
        load_verified_registry_state(registry_state_path, registry_key_hex, manifest_key_hex)?;
    let policy_ref = PolicyRef {
        policy_epoch: state.policy_epoch,
        registry_root: state.registry_root,
    };
    let store = DirPolicyArtifactStore::new(&policy_artifacts_dir);
    let mut policies = Vec::with_capacity(state.authorized_policies.len());

    for authorized_policy in &state.authorized_policies {
        let exec_kind = production_release_exec_kind_label(authorized_policy)?;
        let policy_hash_hex = hex::encode(authorized_policy.policy_hash.0);

        let image_id = state
            .guest_image_manifest
            .image_id_for(
                &authorized_policy.policy_exec_kind_id,
                &authorized_policy.policy_exec_version_id,
            )
            .ok_or_else(|| {
                production_release_violation(
                    PRODUCTION_RELEASE_ISSUE_MISSING_IMAGE_ID,
                    format!("policy_hash={policy_hash_hex} exec_kind={exec_kind} missing manifest image_id"),
                )
            })?;

        if is_all_zero_id(&image_id) {
            return Err(production_release_violation(
                PRODUCTION_RELEASE_ISSUE_ALL_ZERO_IMAGE_ID,
                format!("policy_hash={policy_hash_hex} exec_kind={exec_kind} image_id is all-zero"),
            ));
        }

        if !policy_source_mapping_present(authorized_policy) {
            return Err(production_release_violation(
                PRODUCTION_RELEASE_ISSUE_MISSING_SOURCE_MAPPING,
                format!(
                    "policy_hash={policy_hash_hex} exec_kind={exec_kind} missing policy_source_kind_id/policy_source_hash mapping required for production release"
                ),
            ));
        }

        let artifact_validation = match exec_kind {
            "mpb_v1" => {
                validate_mpb_policy_artifact(&store, &policy_ref, authorized_policy)?;
                "validated"
            }
            "tau_compiled_v1" => {
                validate_tau_compiled_policy_artifact(&store, &policy_ref, authorized_policy)?;
                "validated"
            }
            _ => unreachable!("production_release_exec_kind_label restricts release exec kinds"),
        };

        policies.push(ProductionReleasePolicyReport {
            policy_hash_hex,
            policy_exec_kind: exec_kind.into(),
            policy_exec_version_hex: hex::encode(authorized_policy.policy_exec_version_id),
            image_id_hex: hex::encode(image_id),
            source_governance: source_governance_label(authorized_policy).into(),
            artifact_validation: artifact_validation.into(),
        });
    }

    sort_production_release_policy_reports(&mut policies);
    Ok(ProductionReleaseReport {
        report_schema: PRODUCTION_RELEASE_REPORT_SCHEMA_V1,
        policy_epoch: policy_ref.policy_epoch,
        registry_root_hex: hex::encode(policy_ref.registry_root.0),
        production_policy_count: policies.len(),
        policies,
    })
}

fn config_hex_image_id_is_placeholder(image_id_hex: &str) -> bool {
    let image_id_hex = image_id_hex.trim();
    image_id_hex.len() == 64 && image_id_hex.chars().all(|c| c == '0')
}

fn config_executor_type_requires_onchain_finality(executor_type: &str) -> bool {
    let normalized: String = executor_type
        .trim()
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "onchain"
            | "chain"
            | "evm"
            | "ethereum"
            | "eth"
            | "solana"
            | "sui"
            | "aptos"
            | "cosmos"
            | "starknet"
            | "polygon"
            | "arbitrum"
            | "optimism"
            | "base"
    )
}

fn config_has_persistent_nonce_store(config: &MprdConfigFile) -> bool {
    config
        .anti_replay
        .as_ref()
        .and_then(|anti_replay| anti_replay.nonce_store_dir.as_ref())
        .is_some_and(|path| !path.to_string_lossy().trim().is_empty())
}

fn normalize_config_label(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .collect::<String>()
        .to_ascii_lowercase()
}

fn config_is_low_trust(config: &MprdConfigFile) -> bool {
    config
        .trust_mode
        .as_deref()
        .is_some_and(|mode| normalize_config_label(mode) == "lowtrust")
        || normalize_config_label(&config.mode) == "lowtrust"
        || config.low_trust.is_some()
}

fn config_has_lowtrust_redis_nonce_store(config: &MprdConfigFile) -> bool {
    let Some(low_trust) = config.low_trust.as_ref() else {
        return false;
    };
    let redis_backend = low_trust
        .nonce_store_backend
        .as_deref()
        .is_some_and(|backend| normalize_config_label(backend) == "redis");
    let redis_url_present = low_trust
        .redis_url
        .as_deref()
        .is_some_and(|url| !url.trim().is_empty());
    redis_backend && redis_url_present
}

fn validate_optional_production_release_config(config_path: Option<PathBuf>) -> Result<()> {
    let Some(config_path) = config_path else {
        return Ok(());
    };

    let config_json = fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;
    let config: MprdConfigFile =
        serde_json::from_str(&config_json).context("Failed to parse config JSON")?;

    if config.mode.eq_ignore_ascii_case("local") {
        return Err(production_release_violation(
            PRODUCTION_RELEASE_ISSUE_CONFIG_LOCAL_MODE,
            format!(
                "config={} mode=local is demo-only and cannot be used for production release verification",
                config_path.display()
            ),
        ));
    }

    if config_executor_type_requires_onchain_finality(&config.execution.executor_type) {
        return Err(production_release_violation(
            PRODUCTION_RELEASE_ISSUE_ONCHAIN_FINALITY_UNSUPPORTED,
            format!(
                "config={} execution.executor_type={} requires a promoted per-chain finality, nonce-scope, retry, and replay spec before production release verification",
                config_path.display(),
                config.execution.executor_type
            ),
        ));
    }

    if config_is_low_trust(&config) {
        if !config_has_lowtrust_redis_nonce_store(&config) {
            return Err(production_release_violation(
                PRODUCTION_RELEASE_ISSUE_CONFIG_LOWTRUST_REDIS_REQUIRED,
                format!(
                    "config={} low-trust production requires low_trust.nonce_store_backend=redis and non-empty low_trust.redis_url",
                    config_path.display()
                ),
            ));
        }
    } else if !config_has_persistent_nonce_store(&config) {
        return Err(production_release_violation(
            PRODUCTION_RELEASE_ISSUE_CONFIG_MISSING_NONCE_STORE,
            format!(
                "config={} anti_replay.nonce_store_dir is required for production persistent anti-replay",
                config_path.display()
            ),
        ));
    }

    if config
        .risc0_image_id
        .as_deref()
        .is_some_and(config_hex_image_id_is_placeholder)
    {
        return Err(production_release_violation(
            PRODUCTION_RELEASE_ISSUE_CONFIG_PLACEHOLDER_IMAGE_ID,
            format!(
                "config={} risc0_image_id is all-zero placeholder; production release verification requires registry manifest routing with non-placeholder image IDs",
                config_path.display()
            ),
        ));
    }

    Ok(())
}

fn print_production_release_report_human(report: &ProductionReleaseReport) {
    println!("Production release check passed");
    println!("   policy_epoch:  {}", report.policy_epoch);
    println!("   registry_root: {}", report.registry_root_hex);
    println!("   production_policies: {}", report.production_policy_count);
    println!("   release_routes:");
    for policy in &report.policies {
        println!(
            "      {} exec_kind={} image_id={} source={} artifact={}",
            policy.policy_hash_hex,
            policy.policy_exec_kind,
            policy.image_id_hex,
            policy.source_governance,
            policy.artifact_validation
        );
    }
}

fn format_production_release_report_json(report: &ProductionReleaseReport) -> Result<String> {
    serde_json::to_string_pretty(report).context("Failed to serialize production release report")
}

fn format_production_release_report_digest(report: &ProductionReleaseReport) -> Result<String> {
    let json = format_production_release_report_json(report)?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn ensure_release_methods_embedded(
    report: &ProductionReleaseReport,
    mpb_methods_embedded: bool,
    tau_compiled_methods_embedded: bool,
) -> Result<()> {
    if report
        .policies
        .iter()
        .any(|policy| policy.policy_exec_kind == "mpb_v1")
        && !mpb_methods_embedded
    {
        return Err(production_release_violation(
            PRODUCTION_RELEASE_ISSUE_PLACEHOLDER_METHODS,
            "exec_kind=mpb_v1 local Risc0 methods are placeholders; rebuild without RISC0_SKIP_BUILD=1 and require embedded methods for production release",
        ));
    }

    if report
        .policies
        .iter()
        .any(|policy| policy.policy_exec_kind == "tau_compiled_v1")
        && !tau_compiled_methods_embedded
    {
        return Err(production_release_violation(
            PRODUCTION_RELEASE_ISSUE_PLACEHOLDER_METHODS,
            "exec_kind=tau_compiled_v1 local Risc0 methods are placeholders; rebuild without RISC0_SKIP_BUILD=1 and require embedded methods for production release",
        ));
    }

    Ok(())
}

fn normalize_exec_kind_label(exec_kind: &str) -> String {
    exec_kind.trim().to_ascii_lowercase()
}

fn built_in_exec_kind_id_hex_alias(exec_kind: &str) -> Option<String> {
    match normalize_exec_kind_label(exec_kind).as_str() {
        "mpb_v1" => Some(hex::encode(policy_exec_kind_mpb_id_v1())),
        "tau_compiled_v1" => Some(hex::encode(policy_exec_kind_tau_compiled_id_v1())),
        _ => None,
    }
}

fn policy_exec_kind_aliases_from_label(exec_kind: &str) -> Vec<String> {
    let normalized_exec_kind = normalize_exec_kind_label(exec_kind);
    let mut aliases = vec![normalized_exec_kind.clone()];
    if let Some(exec_kind_id_hex) = built_in_exec_kind_id_hex_alias(&normalized_exec_kind) {
        if exec_kind_id_hex != normalized_exec_kind {
            aliases.push(exec_kind_id_hex);
        }
    }
    aliases
}

fn policy_exec_kind_aliases(policy: &BundlePolicyReport) -> Vec<String> {
    policy.strict_selector_aliases.clone()
}

fn known_report_exec_kind_aliases(report: &BundleCheckReport) -> BTreeSet<String> {
    report
        .policies
        .iter()
        .flat_map(policy_exec_kind_aliases)
        .collect()
}

fn policy_matches_declared_exec_kind(
    policy: &BundlePolicyReport,
    declared_exec_kind_set: &BTreeSet<String>,
) -> bool {
    policy_exec_kind_aliases(policy)
        .into_iter()
        .any(|alias| declared_exec_kind_set.contains(&alias))
}

#[cfg(test)]
fn strict_governed_source_response_matrix_value() -> serde_json::Value {
    serde_json::to_value(strict_governed_source_response_matrix())
        .expect("strict governed-source response matrix serializes")
}

#[cfg(test)]
fn strict_source_artifact_witness_response_matrix_value() -> serde_json::Value {
    serde_json::to_value(strict_source_artifact_witness_response_matrix())
        .expect("strict source-artifact-witness response matrix serializes")
}

#[cfg(test)]
fn strict_selector_alias_matrix_value() -> serde_json::Value {
    serde_json::to_value(strict_selector_alias_matrix())
        .expect("strict selector alias matrix serializes")
}

fn format_strict_governed_source_response_matrix_json() -> Result<String> {
    serde_json::to_string_pretty(&strict_governed_source_response_matrix())
        .context("Failed to serialize strict governed-source response matrix")
}

fn format_strict_governed_source_response_matrix_digest() -> Result<String> {
    let json = format_strict_governed_source_response_matrix_json()?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn format_strict_source_artifact_witness_response_matrix_json() -> Result<String> {
    serde_json::to_string_pretty(&strict_source_artifact_witness_response_matrix())
        .context("Failed to serialize strict source-artifact-witness response matrix")
}

fn format_strict_source_artifact_witness_response_matrix_digest() -> Result<String> {
    let json = format_strict_source_artifact_witness_response_matrix_json()?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn format_strict_selector_alias_matrix_json() -> Result<String> {
    serde_json::to_string_pretty(&strict_selector_alias_matrix())
        .context("Failed to serialize strict selector alias matrix")
}

fn format_strict_selector_alias_matrix_digest() -> Result<String> {
    let json = format_strict_selector_alias_matrix_json()?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn print_strict_governed_source_response_matrix_human() {
    let matrix = strict_governed_source_response_matrix();
    println!("Strict governed-source response matrix");
    println!(
        "  rejection_exit_code={} generic_bundle_failure_exit_code={}",
        matrix.rejection_exit_code, matrix.generic_bundle_failure_exit_code
    );
    for rule in matrix.rules {
        println!(
            "  issue_kind={} classification={} response={} exit_code={} machine_formats={} human_surface={}",
            rule.issue_kind,
            rule.classification,
            rule.required_response,
            rule.exit_code,
            rule.machine_witness_formats.join(","),
            rule.human_surface
        );
    }
}

fn print_strict_source_artifact_witness_response_matrix_human() {
    let matrix = strict_source_artifact_witness_response_matrix();
    println!("Strict source-artifact-witness response matrix");
    println!(
        "  rejection_exit_code={} generic_bundle_failure_exit_code={}",
        matrix.rejection_exit_code, matrix.generic_bundle_failure_exit_code
    );
    for rule in matrix.rules {
        println!(
            "  issue_kind={} classification={} response={} exit_code={} machine_formats={} human_surface={}",
            rule.issue_kind,
            rule.classification,
            rule.required_response,
            rule.exit_code,
            rule.machine_witness_formats.join(","),
            rule.human_surface
        );
    }
}

fn print_strict_selector_alias_matrix_human() {
    let matrix = strict_selector_alias_matrix();
    println!("Strict selector alias matrix");
    println!("  built_in_only={}", matrix.built_in_only);
    println!("  selector_match_rule={}", matrix.selector_match_rule);
    println!("  custom_exec_kind_rule={}", matrix.custom_exec_kind_rule);
    for family in matrix.families {
        println!(
            "  exec_kind={} canonical_hex={} aliases={} surfaces={}",
            family.exec_kind_label,
            family.canonical_exec_kind_hex,
            family.selector_aliases.join(","),
            family.accepted_by_surfaces.join(",")
        );
    }
}

pub fn emit_strict_governed_source_response_matrix(format: &str) -> Result<()> {
    match format {
        "human" => print_strict_governed_source_response_matrix_human(),
        "json" => println!("{}", format_strict_governed_source_response_matrix_json()?),
        "digest" => println!(
            "{}",
            format_strict_governed_source_response_matrix_digest()?
        ),
        other => anyhow::bail!("unsupported deploy strict response-matrix format: {other}"),
    }
    Ok(())
}

pub fn emit_strict_source_artifact_witness_response_matrix(format: &str) -> Result<()> {
    match format {
        "human" => print_strict_source_artifact_witness_response_matrix_human(),
        "json" => println!(
            "{}",
            format_strict_source_artifact_witness_response_matrix_json()?
        ),
        "digest" => println!(
            "{}",
            format_strict_source_artifact_witness_response_matrix_digest()?
        ),
        other => anyhow::bail!(
            "unsupported deploy strict source-artifact-witness response-matrix format: {other}"
        ),
    }
    Ok(())
}

pub fn emit_strict_selector_alias_matrix(format: &str) -> Result<()> {
    match format {
        "human" => print_strict_selector_alias_matrix_human(),
        "json" => println!("{}", format_strict_selector_alias_matrix_json()?),
        "digest" => println!("{}", format_strict_selector_alias_matrix_digest()?),
        other => anyhow::bail!("unsupported deploy strict selector-alias matrix format: {other}"),
    }
    Ok(())
}

fn declared_strict_governed_source_exec_kinds(strict_exec_kinds: &[String]) -> Vec<String> {
    strict_exec_kinds
        .iter()
        .map(|exec_kind| normalize_exec_kind_label(exec_kind))
        .filter(|exec_kind| !exec_kind.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn build_strict_governed_source_failure_report(
    report: &BundleCheckReport,
    strict_exec_kinds: &[String],
) -> Result<Option<StrictGovernedSourceFailureReport>> {
    let declared_governed_exec_kinds =
        declared_strict_governed_source_exec_kinds(strict_exec_kinds);
    if declared_governed_exec_kinds.is_empty() {
        return Ok(None);
    }

    let known_exec_kinds = known_report_exec_kind_aliases(report);
    let declared_exec_kind_set: BTreeSet<String> =
        declared_governed_exec_kinds.iter().cloned().collect();
    let unknown_declared_exec_kinds: Vec<String> = declared_governed_exec_kinds
        .iter()
        .filter(|exec_kind| !known_exec_kinds.contains(*exec_kind))
        .cloned()
        .collect();
    let failing_policies: Vec<BundlePolicyReport> = report
        .policies
        .iter()
        .filter(|policy| {
            policy_matches_declared_exec_kind(policy, &declared_exec_kind_set)
                && policy.source_governance != "TauGovernedMapped"
        })
        .cloned()
        .collect();

    if unknown_declared_exec_kinds.is_empty() && failing_policies.is_empty() {
        return Ok(None);
    }

    let (response_rule, first_issue) = if let Some(first_unknown) =
        unknown_declared_exec_kinds.first()
    {
        (
            strict_governed_source_response_rule(
                STRICT_GOVERNED_SOURCE_ISSUE_UNKNOWN_DECLARED_EXEC_KIND,
            )
            .expect("strict response rule for unknown declared exec kind"),
            format!("exec_kind={first_unknown}"),
        )
    } else if let Some(first_policy) = failing_policies.first() {
        let issue_kind = if first_policy.source_governance == "Unmapped"
            && first_policy.source_intent_classification == "TauDeclared"
            && first_policy.source_boundary_classification == "TauCompiledCarrierUnmapped"
        {
            STRICT_GOVERNED_SOURCE_ISSUE_TAU_DECLARED_MAPPING_MISSING
        } else {
            STRICT_GOVERNED_SOURCE_ISSUE_POLICY_NOT_TAU_GOVERNED
        };
        (
                strict_governed_source_response_rule(issue_kind)
                    .expect("strict response rule for failing governed-source policy"),
                format!(
                    "policy_hash={} exec_kind={} source_governance={} source_intent={} source_boundary={}",
                    first_policy.policy_hash_hex,
                    first_policy.policy_exec_kind,
                    first_policy.source_governance,
                    first_policy.source_intent_classification,
                    first_policy.source_boundary_classification
                ),
            )
    } else {
        anyhow::bail!(
            "{}: no failure details after strict governed-source mismatch",
            STRICT_GOVERNED_SOURCE_ISSUE_INTERNAL_ERROR
        )
    };

    Ok(Some(StrictGovernedSourceFailureReport {
        report_schema: STRICT_GOVERNED_SOURCE_FAILURE_REPORT_SCHEMA_V1,
        normalized_bundle_digest_hex: format_bundle_check_report_digest(report)?,
        declared_governed_exec_kinds,
        issue_kind: response_rule.issue_kind.to_string(),
        classification: response_rule.classification.to_string(),
        required_response: response_rule.required_response.to_string(),
        first_issue,
        unknown_declared_exec_kinds,
        failing_policies,
    }))
}

fn build_strict_source_artifact_witness_failure_report(
    report: &BundleCheckReport,
    strict_exec_kinds: &[String],
) -> Result<Option<StrictSourceArtifactWitnessFailureReport>> {
    let declared_artifact_witness_exec_kinds =
        declared_strict_governed_source_exec_kinds(strict_exec_kinds);
    if declared_artifact_witness_exec_kinds.is_empty() {
        return Ok(None);
    }

    let known_exec_kinds = known_report_exec_kind_aliases(report);
    let declared_exec_kind_set: BTreeSet<String> = declared_artifact_witness_exec_kinds
        .iter()
        .cloned()
        .collect();
    let unknown_declared_exec_kinds: Vec<String> = declared_artifact_witness_exec_kinds
        .iter()
        .filter(|exec_kind| !known_exec_kinds.contains(*exec_kind))
        .cloned()
        .collect();
    let failing_policies: Vec<BundlePolicyReport> = report
        .policies
        .iter()
        .filter(|policy| {
            policy_matches_declared_exec_kind(policy, &declared_exec_kind_set)
                && policy.source_artifact_witness_state != "Ready"
        })
        .cloned()
        .collect();

    if unknown_declared_exec_kinds.is_empty() && failing_policies.is_empty() {
        return Ok(None);
    }

    let (response_rule, first_issue) = if let Some(first_unknown) =
        unknown_declared_exec_kinds.first()
    {
        (
            strict_source_artifact_witness_response_rule(
                STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_UNKNOWN_DECLARED_EXEC_KIND,
            )
            .expect("strict response rule for unknown artifact-witness exec kind"),
            format!("exec_kind={first_unknown}"),
        )
    } else if let Some(first_policy) = failing_policies.first() {
        let issue_kind = match first_policy.source_artifact_witness_state.as_str() {
            "BlockedMissingSourceMapping" => STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_MAPPING_MISSING,
            "BlockedArtifactValidation" => {
                STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_ARTIFACT_VALIDATION_MISSING
            }
            other => anyhow::bail!(
                "{}: unexpected source_artifact_witness_state={other}",
                STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_INTERNAL_ERROR
            ),
        };
        (
            strict_source_artifact_witness_response_rule(issue_kind)
                .expect("strict response rule for failing source-artifact-witness policy"),
            format!(
                "policy_hash={} exec_kind={} source_governance={} source_intent={} source_boundary={} artifact={} witness={}",
                first_policy.policy_hash_hex,
                first_policy.policy_exec_kind,
                first_policy.source_governance,
                first_policy.source_intent_classification,
                first_policy.source_boundary_classification,
                first_policy.artifact_validation,
                first_policy.source_artifact_witness_state
            ),
        )
    } else {
        anyhow::bail!(
            "{}: no failure details after strict source-artifact-witness mismatch",
            STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_INTERNAL_ERROR
        )
    };

    Ok(Some(StrictSourceArtifactWitnessFailureReport {
        report_schema: STRICT_SOURCE_ARTIFACT_WITNESS_FAILURE_REPORT_SCHEMA_V1,
        normalized_bundle_digest_hex: format_bundle_check_report_digest(report)?,
        declared_artifact_witness_exec_kinds,
        issue_kind: response_rule.issue_kind.to_string(),
        classification: response_rule.classification.to_string(),
        required_response: response_rule.required_response.to_string(),
        first_issue,
        unknown_declared_exec_kinds,
        failing_policies,
    }))
}

fn format_strict_governed_source_failure_report_json(
    report: &StrictGovernedSourceFailureReport,
) -> Result<String> {
    serde_json::to_string_pretty(report)
        .context("Failed to serialize strict governed-source failure report")
}

fn format_strict_source_artifact_witness_failure_report_json(
    report: &StrictSourceArtifactWitnessFailureReport,
) -> Result<String> {
    serde_json::to_string_pretty(report)
        .context("Failed to serialize strict source-artifact-witness failure report")
}

fn format_strict_governed_source_failure_digest(
    report: &StrictGovernedSourceFailureReport,
) -> Result<String> {
    let json = format_strict_governed_source_failure_report_json(report)?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn format_strict_source_artifact_witness_failure_digest(
    report: &StrictSourceArtifactWitnessFailureReport,
) -> Result<String> {
    let json = format_strict_source_artifact_witness_failure_report_json(report)?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn strict_governed_source_violation_error(
    report: &StrictGovernedSourceFailureReport,
) -> Result<BundleCheckError> {
    Ok(BundleCheckError::StrictGovernedSourceViolation {
        declared_exec_kinds_csv: report.declared_governed_exec_kinds.join(","),
        issue_kind: report.issue_kind.clone(),
        first_issue: report.first_issue.clone(),
        strict_failure_digest_hex: format_strict_governed_source_failure_digest(report)?,
    })
}

fn strict_source_artifact_witness_violation_error(
    report: &StrictSourceArtifactWitnessFailureReport,
) -> Result<BundleCheckError> {
    Ok(BundleCheckError::StrictSourceArtifactWitnessViolation {
        declared_exec_kinds_csv: report.declared_artifact_witness_exec_kinds.join(","),
        issue_kind: report.issue_kind.clone(),
        first_issue: report.first_issue.clone(),
        strict_failure_digest_hex: format_strict_source_artifact_witness_failure_digest(report)?,
    })
}

pub fn suggested_exit_code(err: &anyhow::Error) -> Option<i32> {
    match err.downcast_ref::<BundleCheckError>() {
        Some(BundleCheckError::StrictGovernedSourceViolation { .. }) => {
            Some(STRICT_GOVERNED_SOURCE_EXIT_CODE)
        }
        Some(BundleCheckError::StrictSourceArtifactWitnessViolation { .. }) => {
            Some(STRICT_SOURCE_ARTIFACT_WITNESS_EXIT_CODE)
        }
        _ => None,
    }
}

#[cfg(test)]
fn enforce_strict_governed_source(
    report: &BundleCheckReport,
    strict_exec_kinds: &[String],
) -> Result<()> {
    let Some(failure_report) =
        build_strict_governed_source_failure_report(report, strict_exec_kinds)?
    else {
        return Ok(());
    };

    Err(strict_governed_source_violation_error(&failure_report)?.into())
}

#[cfg(test)]
fn enforce_strict_source_artifact_witness(
    report: &BundleCheckReport,
    strict_exec_kinds: &[String],
) -> Result<()> {
    let Some(failure_report) =
        build_strict_source_artifact_witness_failure_report(report, strict_exec_kinds)?
    else {
        return Ok(());
    };

    Err(strict_source_artifact_witness_violation_error(&failure_report)?.into())
}

fn emit_strict_governed_source_failure(
    failure_report: &StrictGovernedSourceFailureReport,
    failure_format: &str,
) -> Result<()> {
    match failure_format {
        "human" => Err(strict_governed_source_violation_error(failure_report)?.into()),
        "json" => {
            return write_stdout_and_exit(
                &format_strict_governed_source_failure_report_json(failure_report)?,
                STRICT_GOVERNED_SOURCE_EXIT_CODE,
            )
        }
        "digest" => {
            return write_stdout_and_exit(
                &format_strict_governed_source_failure_digest(failure_report)?,
                STRICT_GOVERNED_SOURCE_EXIT_CODE,
            )
        }
        other => anyhow::bail!("unsupported deploy strict-failure format: {other}"),
    }
}

fn emit_strict_source_artifact_witness_failure(
    failure_report: &StrictSourceArtifactWitnessFailureReport,
    failure_format: &str,
) -> Result<()> {
    match failure_format {
        "human" => Err(strict_source_artifact_witness_violation_error(failure_report)?.into()),
        "json" => {
            return write_stdout_and_exit(
                &format_strict_source_artifact_witness_failure_report_json(failure_report)?,
                STRICT_SOURCE_ARTIFACT_WITNESS_EXIT_CODE,
            )
        }
        "digest" => {
            return write_stdout_and_exit(
                &format_strict_source_artifact_witness_failure_digest(failure_report)?,
                STRICT_SOURCE_ARTIFACT_WITNESS_EXIT_CODE,
            )
        }
        other => anyhow::bail!(
            "unsupported deploy strict source-artifact-witness failure format: {other}"
        ),
    }
}

fn write_stdout_and_exit(payload: &str, exit_code: i32) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(payload.as_bytes())
        .context("Failed to write strict deploy failure witness")?;
    stdout
        .write_all(b"\n")
        .context("Failed to terminate strict deploy failure witness")?;
    stdout
        .flush()
        .context("Failed to flush strict deploy failure witness")?;
    std::process::exit(exit_code);
}

fn enforce_strict_bundle_contracts(
    report: &BundleCheckReport,
    strict_governed_source: &[String],
    strict_governed_source_failure_format: &str,
    strict_source_artifact_witness: &[String],
    strict_source_artifact_witness_failure_format: &str,
) -> Result<()> {
    // Governed-source is the antecedent contract: artifact-witness strictness only makes sense
    // after the declared exec kind is already admitted as Tau-governed on the selected surface.
    if let Some(failure_report) =
        build_strict_governed_source_failure_report(report, strict_governed_source)?
    {
        return emit_strict_governed_source_failure(
            &failure_report,
            strict_governed_source_failure_format,
        );
    }
    if let Some(failure_report) =
        build_strict_source_artifact_witness_failure_report(report, strict_source_artifact_witness)?
    {
        return emit_strict_source_artifact_witness_failure(
            &failure_report,
            strict_source_artifact_witness_failure_format,
        );
    }

    Ok(())
}

pub fn check_bundle(
    registry_state_path: PathBuf,
    registry_key_hex: String,
    manifest_key_hex: Option<String>,
    policy_artifacts_dir: PathBuf,
    format: &str,
    strict_governed_source: &[String],
    strict_governed_source_failure_format: &str,
    strict_source_artifact_witness: &[String],
    strict_source_artifact_witness_failure_format: &str,
) -> Result<()> {
    let report = build_bundle_check_report(
        registry_state_path,
        registry_key_hex,
        manifest_key_hex,
        policy_artifacts_dir,
    )?;
    enforce_strict_bundle_contracts(
        &report,
        strict_governed_source,
        strict_governed_source_failure_format,
        strict_source_artifact_witness,
        strict_source_artifact_witness_failure_format,
    )?;

    match format {
        "human" => print_bundle_check_report_human(&report),
        "json" => println!("{}", format_bundle_check_report_json(&report)?),
        "normalized-json" => println!("{}", format_normalized_bundle_check_report_json(&report)?),
        "digest" => println!("{}", format_bundle_check_report_digest(&report)?),
        other => {
            anyhow::bail!("unsupported deploy check-bundle format: {other}");
        }
    }
    Ok(())
}

pub(crate) fn check_bundle_quiet(
    registry_state_path: PathBuf,
    registry_key_hex: String,
    manifest_key_hex: Option<String>,
    policy_artifacts_dir: PathBuf,
) -> Result<()> {
    let report = build_bundle_check_report(
        registry_state_path,
        registry_key_hex,
        manifest_key_hex,
        policy_artifacts_dir,
    )?;
    enforce_strict_bundle_contracts(&report, &[], "human", &[], "human")
}

pub fn verify_release(
    registry_state_path: PathBuf,
    registry_key_hex: String,
    manifest_key_hex: Option<String>,
    policy_artifacts_dir: PathBuf,
    config_path: Option<PathBuf>,
    format: &str,
) -> Result<()> {
    validate_optional_production_release_config(config_path)?;
    let report = build_production_release_report(
        registry_state_path,
        registry_key_hex,
        manifest_key_hex,
        policy_artifacts_dir,
    )?;
    ensure_release_methods_embedded(
        &report,
        mprd_risc0_methods::mprd_mpb_guest_is_embedded(),
        mprd_risc0_methods::mprd_tau_compiled_guest_is_embedded(),
    )?;

    match format {
        "human" => print_production_release_report_human(&report),
        "json" => println!("{}", format_production_release_report_json(&report)?),
        "digest" => println!("{}", format_production_release_report_digest(&report)?),
        other => {
            anyhow::bail!("unsupported deploy verify-release format: {other}");
        }
    }
    Ok(())
}

fn validate_mpb_policy_artifact(
    store: &DirPolicyArtifactStore,
    _policy_ref: &PolicyRef,
    ap: &AuthorizedPolicyV1,
) -> Result<()> {
    let bytes = store
        .get(&ap.policy_hash)
        .context("Failed to read policy artifact store")?
        .ok_or_else(|| BundleCheckError::MissingPolicyArtifact {
            policy_hash_hex: hex::encode(ap.policy_hash.0),
        })?;

    let artifact = decode_mpb_policy_artifact_bytes_v1(&bytes)
        .context("invalid mpb-v1 policy artifact bytes")?;

    let refs: Vec<(&[u8], u8)> = artifact
        .variables
        .iter()
        .map(|(name, reg)| (name.as_bytes(), *reg))
        .collect();
    let computed = Hash32(mprd_mpb::policy_hash_v1(&artifact.bytecode, &refs));
    if computed != ap.policy_hash {
        anyhow::bail!(
            "mpb policy_hash mismatch (artifact tamper) policy_hash={}",
            hex::encode(ap.policy_hash.0)
        );
    }
    Ok(())
}

fn validate_tau_compiled_policy_artifact(
    store: &DirPolicyArtifactStore,
    _policy_ref: &PolicyRef,
    ap: &AuthorizedPolicyV1,
) -> Result<()> {
    let bytes = store
        .get(&ap.policy_hash)
        .context("Failed to read policy artifact store")?
        .ok_or_else(|| BundleCheckError::MissingPolicyArtifact {
            policy_hash_hex: hex::encode(ap.policy_hash.0),
        })?;

    let computed = Hash32(tau_compiled_policy_hash_v1(&bytes));
    if computed != ap.policy_hash {
        anyhow::bail!(
            "tau_compiled policy_hash mismatch (artifact tamper) policy_hash={}",
            hex::encode(ap.policy_hash.0)
        );
    }

    decode_compiled_tau_policy_v1(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid compiled Tau policy bytes: {e:?}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mprd_core::TokenSigningKey;
    use mprd_risc0_shared::{policy_exec_kind_host_trusted_id_v0, policy_source_kind_tau_id_v1};
    use mprd_zk::manifest::{GuestImageEntryV1, GuestImageManifestV1};
    use mprd_zk::registry_state::{AuthorizedPolicyV1, RegistryStateV1, SignedRegistryStateV1};
    use std::path::Path;

    fn tmpdir(prefix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("{prefix}-{}-{}", std::process::id(), now));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    fn encode_mpb_artifact(bytecode: &[u8], vars: &[(&str, u8)]) -> Vec<u8> {
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

    fn encode_minimal_compiled_tau_policy_bytes() -> Vec<u8> {
        // Same layout as `mprd_risc0_shared::decode_compiled_tau_policy_v1`.
        let mut out = Vec::new();
        out.extend_from_slice(&1u32.to_le_bytes()); // version
        out.extend_from_slice(&1u32.to_le_bytes()); // predicate_count
        out.extend_from_slice(&0u32.to_le_bytes()); // predicate_idx
        out.push(4u8); // Equals
                       // left operand
        out.push(2u8); // Constant
        out.extend_from_slice(&[0u8; 32]);
        out.push(0u8); // U64
        out.extend_from_slice(&1u64.to_le_bytes());
        // right operand
        out.push(2u8);
        out.extend_from_slice(&[0u8; 32]);
        out.push(0u8);
        out.extend_from_slice(&1u64.to_le_bytes());
        // gate_count
        out.extend_from_slice(&1u32.to_le_bytes());
        // gate: PredicateInput -> wire 0
        out.push(3u8);
        out.extend_from_slice(&0u32.to_le_bytes()); // out_wire
        out.extend_from_slice(&0u32.to_le_bytes()); // in1 (pred idx)
        out.extend_from_slice(&0u32.to_le_bytes()); // in2
                                                    // output_wire
        out.extend_from_slice(&0u32.to_le_bytes());
        // temporal_fields count
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    fn write_signed_registry_state(
        bundle_dir: &Path,
        registry_signer: &TokenSigningKey,
        state: RegistryStateV1,
    ) -> PathBuf {
        let signed = SignedRegistryStateV1::sign(registry_signer, 456, state).unwrap();
        let registry_state_path = bundle_dir.join("registry_state.json");
        write_file(
            &registry_state_path,
            serde_json::to_string_pretty(&signed).unwrap().as_bytes(),
        );
        registry_state_path
    }

    fn write_release_mpb_artifact(artifacts_dir: &Path) -> Hash32 {
        let mpb_bytecode = vec![0xFF];
        let mpb_vars = [("a", 0u8)];
        let mpb_bytes = encode_mpb_artifact(&mpb_bytecode, &[("a", 0)]);
        let refs: Vec<(&[u8], u8)> = mpb_vars.iter().map(|(n, r)| (n.as_bytes(), *r)).collect();
        let mpb_policy_hash = Hash32(mprd_mpb::policy_hash_v1(&mpb_bytecode, &refs));
        write_file(
            &artifacts_dir.join(hex::encode(mpb_policy_hash.0)),
            &mpb_bytes,
        );
        mpb_policy_hash
    }

    fn write_release_config(
        bundle_dir: &Path,
        name: &str,
        mode: &str,
        risc0_image_id: Option<String>,
        executor_type: Option<&str>,
        drop_nonce_store: bool,
        trust_mode: Option<&str>,
        low_trust: Option<crate::config_model::LowTrustConfig>,
    ) -> PathBuf {
        let mut config = MprdConfigFile::default();
        config.mode = mode.into();
        config.trust_mode = trust_mode.map(str::to_string);
        config.risc0_image_id = risc0_image_id;
        if let Some(executor_type) = executor_type {
            config.execution.executor_type = executor_type.into();
        }
        if drop_nonce_store {
            config.anti_replay = None;
        }
        config.low_trust = low_trust;
        let path = bundle_dir.join(name);
        write_file(
            &path,
            serde_json::to_string_pretty(&config).unwrap().as_bytes(),
        );
        path
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum ProductionReleaseBoundaryMutation {
        ValidSeed,
        HostTrustedRoute,
        UnsupportedExecKind,
        MissingManifestImageId,
        AllZeroManifestImageId,
        MissingPolicySourceMapping,
        MissingPolicyArtifact,
        InvalidMpbArtifactBytes,
        MpbArtifactHashMismatch,
        PlaceholderMpbMethods,
        LocalModeConfig,
        PlaceholderConfigImageId,
        OnChainExecutorConfig,
        MissingNonceStoreConfig,
        LowTrustMissingRedisConfig,
        WrongManifestKey,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ProductionReleaseBoundaryOutcome {
        mutation: ProductionReleaseBoundaryMutation,
        outcome_label: String,
        path_id: String,
    }

    fn production_release_boundary_path_id(
        mutation: ProductionReleaseBoundaryMutation,
        outcome_label: &str,
        detail: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{mutation:?}\n{outcome_label}\n{detail}").as_bytes());
        hex::encode(hasher.finalize())[..16].into()
    }

    fn classify_production_release_boundary_error(err: &anyhow::Error) -> String {
        if let Some(BundleCheckError::ProductionReleaseViolation { issue_kind, .. }) =
            err.downcast_ref::<BundleCheckError>()
        {
            return issue_kind.clone();
        }
        if err
            .downcast_ref::<BundleCheckError>()
            .is_some_and(|e| matches!(e, BundleCheckError::MissingPolicyArtifact { .. }))
        {
            return "missing_policy_artifact".into();
        }

        let chain = format!("{err:#}");
        if chain.contains("manifest image_id must not be all-zero") {
            return PRODUCTION_RELEASE_ISSUE_ALL_ZERO_IMAGE_ID.into();
        }
        if chain.contains("invalid mpb-v1 policy artifact bytes") {
            return "invalid_mpb_artifact_bytes".into();
        }
        if chain.contains("mpb policy_hash mismatch") {
            return "mpb_artifact_hash_mismatch".into();
        }
        if chain.contains("signature verification failed") || chain.contains("manifest") {
            return "manifest_verification_failed".into();
        }
        "unexpected_release_boundary_error".into()
    }

    fn run_production_release_boundary_case(
        mutation: ProductionReleaseBoundaryMutation,
    ) -> ProductionReleaseBoundaryOutcome {
        let artifacts_dir = tmpdir("mprd-release-boundary-artifacts");
        let bundle_dir = tmpdir("mprd-release-boundary-bundle");

        let registry_signer = TokenSigningKey::from_seed(&[241u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[242u8; 32]);
        let wrong_manifest_signer = TokenSigningKey::from_seed(&[243u8; 32]);
        let registry_vk_hex = hex::encode(registry_signer.verifying_key().to_bytes());
        let manifest_vk_hex = match mutation {
            ProductionReleaseBoundaryMutation::WrongManifestKey => {
                hex::encode(wrong_manifest_signer.verifying_key().to_bytes())
            }
            _ => hex::encode(manifest_signer.verifying_key().to_bytes()),
        };

        let mpb_policy_hash = write_release_mpb_artifact(&artifacts_dir);
        let artifact_path = artifacts_dir.join(hex::encode(mpb_policy_hash.0));
        match mutation {
            ProductionReleaseBoundaryMutation::MissingPolicyArtifact => {
                std::fs::remove_file(&artifact_path).unwrap();
            }
            ProductionReleaseBoundaryMutation::InvalidMpbArtifactBytes => {
                write_file(&artifact_path, b"not-an-mpb-artifact");
            }
            ProductionReleaseBoundaryMutation::MpbArtifactHashMismatch => {
                let tampered = encode_mpb_artifact(&[0xFE], &[("a", 0)]);
                write_file(&artifact_path, &tampered);
            }
            _ => {}
        }

        let policy_exec_kind_id = match mutation {
            ProductionReleaseBoundaryMutation::HostTrustedRoute => {
                policy_exec_kind_host_trusted_id_v0()
            }
            ProductionReleaseBoundaryMutation::UnsupportedExecKind => [0xA5; 32],
            _ => policy_exec_kind_mpb_id_v1(),
        };
        let manifest_exec_kind_id = match mutation {
            ProductionReleaseBoundaryMutation::HostTrustedRoute => {
                policy_exec_kind_host_trusted_id_v0()
            }
            ProductionReleaseBoundaryMutation::UnsupportedExecKind => [0xA5; 32],
            _ => policy_exec_kind_mpb_id_v1(),
        };
        let manifest = match mutation {
            ProductionReleaseBoundaryMutation::MissingManifestImageId => {
                GuestImageManifestV1::sign(&manifest_signer, 123, vec![]).unwrap()
            }
            _ => GuestImageManifestV1::sign(
                &manifest_signer,
                123,
                vec![GuestImageEntryV1 {
                    policy_exec_kind_id: manifest_exec_kind_id,
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    image_id: if mutation
                        == ProductionReleaseBoundaryMutation::AllZeroManifestImageId
                    {
                        [0u8; 32]
                    } else {
                        [9u8; 32]
                    },
                }],
            )
            .unwrap(),
        };

        let source_mapping_present =
            mutation != ProductionReleaseBoundaryMutation::MissingPolicySourceMapping;
        let state = RegistryStateV1 {
            policy_epoch: 26,
            registry_root: Hash32([0x26; 32]),
            authorized_policies: vec![AuthorizedPolicyV1 {
                policy_hash: mpb_policy_hash,
                policy_exec_kind_id,
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: source_mapping_present.then(policy_source_kind_tau_id_v1),
                policy_source_hash: source_mapping_present.then_some(Hash32([0x48; 32])),
            }],
            guest_image_manifest: manifest,
        };
        let registry_state_path = write_signed_registry_state(&bundle_dir, &registry_signer, state);

        let config_path = match mutation {
            ProductionReleaseBoundaryMutation::LocalModeConfig => Some(write_release_config(
                &bundle_dir,
                "local-config.json",
                "local",
                Some(hex::encode([9u8; 32])),
                None,
                false,
                None,
                None,
            )),
            ProductionReleaseBoundaryMutation::PlaceholderConfigImageId => {
                Some(write_release_config(
                    &bundle_dir,
                    "placeholder-config.json",
                    "trustless",
                    Some("0".repeat(64)),
                    None,
                    false,
                    None,
                    None,
                ))
            }
            ProductionReleaseBoundaryMutation::OnChainExecutorConfig => Some(write_release_config(
                &bundle_dir,
                "onchain-config.json",
                "trustless",
                Some(hex::encode([9u8; 32])),
                Some("evm"),
                false,
                None,
                None,
            )),
            ProductionReleaseBoundaryMutation::MissingNonceStoreConfig => {
                Some(write_release_config(
                    &bundle_dir,
                    "missing-nonce-config.json",
                    "trustless",
                    Some(hex::encode([9u8; 32])),
                    None,
                    true,
                    None,
                    None,
                ))
            }
            ProductionReleaseBoundaryMutation::LowTrustMissingRedisConfig => {
                Some(write_release_config(
                    &bundle_dir,
                    "lowtrust-missing-redis-config.json",
                    "trustless",
                    Some(hex::encode([9u8; 32])),
                    None,
                    false,
                    Some("low_trust"),
                    Some(crate::config_model::LowTrustConfig {
                        nonce_store_backend: Some("shared_fs".into()),
                        redis_url: None,
                        redis_key_prefix: Some("mprd:nonce:v1".into()),
                        redis_timeout_ms: Some(250),
                    }),
                ))
            }
            _ => None,
        };
        let mpb_methods_embedded =
            mutation != ProductionReleaseBoundaryMutation::PlaceholderMpbMethods;

        let result = validate_optional_production_release_config(config_path)
            .and_then(|_| {
                build_production_release_report(
                    registry_state_path,
                    registry_vk_hex,
                    Some(manifest_vk_hex),
                    artifacts_dir,
                )
            })
            .and_then(|report| {
                ensure_release_methods_embedded(&report, mpb_methods_embedded, true)
            });

        match result {
            Ok(()) => {
                let outcome_label = "ok".to_string();
                ProductionReleaseBoundaryOutcome {
                    mutation,
                    path_id: production_release_boundary_path_id(mutation, &outcome_label, "ok"),
                    outcome_label,
                }
            }
            Err(err) => {
                let outcome_label = classify_production_release_boundary_error(&err);
                let detail = format!("{err:#}");
                ProductionReleaseBoundaryOutcome {
                    mutation,
                    path_id: production_release_boundary_path_id(mutation, &outcome_label, &detail),
                    outcome_label,
                }
            }
        }
    }

    #[test]
    fn summarize_policy_source_governance_counts_classifications() {
        let policies = vec![
            AuthorizedPolicyV1 {
                policy_hash: Hash32([1u8; 32]),
                policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: Some(policy_source_kind_tau_id_v1()),
                policy_source_hash: Some(Hash32([2u8; 32])),
            },
            AuthorizedPolicyV1 {
                policy_hash: Hash32([3u8; 32]),
                policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: Some([0x44; 32]),
                policy_source_hash: Some(Hash32([4u8; 32])),
            },
            AuthorizedPolicyV1 {
                policy_hash: Hash32([5u8; 32]),
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: None,
                policy_source_hash: None,
            },
        ];

        assert_eq!(
            summarize_policy_source_governance(&policies),
            PolicySourceGovernanceSummary {
                tau_governed_mapped: 1,
                other_mapped: 1,
                unmapped: 1,
            }
        );
    }

    #[test]
    fn build_bundle_policy_report_distinguishes_tau_compiled_unmapped_boundary() {
        let policy = AuthorizedPolicyV1 {
            policy_hash: Hash32([9u8; 32]),
            policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            policy_source_kind_id: None,
            policy_source_hash: None,
        };

        let report = build_bundle_policy_report(&policy, "validated");
        assert_eq!(report.source_governance, "Unmapped");
        assert_eq!(report.source_intent_classification, "TauDeclared");
        assert_eq!(
            report.source_boundary_classification,
            "TauCompiledCarrierUnmapped"
        );
        assert_eq!(
            report.strict_selector_aliases,
            policy_exec_kind_aliases_from_label("tau_compiled_v1")
        );
        assert!(report.artifact_hash_validated);
        assert_eq!(
            report.source_artifact_witness_state,
            "BlockedMissingSourceMapping"
        );
    }

    #[test]
    fn build_bundle_policy_report_marks_mapped_validated_witness_ready() {
        let policy = AuthorizedPolicyV1 {
            policy_hash: Hash32([10u8; 32]),
            policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            policy_source_kind_id: Some(policy_source_kind_tau_id_v1()),
            policy_source_hash: Some(Hash32([11u8; 32])),
        };

        let report = build_bundle_policy_report(&policy, "validated");
        assert!(report.artifact_hash_validated);
        assert_eq!(report.source_governance, "TauGovernedMapped");
        assert_eq!(report.source_intent_classification, "TauDeclared");
        assert_eq!(
            report.strict_selector_aliases,
            policy_exec_kind_aliases_from_label("tau_compiled_v1")
        );
        assert_eq!(report.source_artifact_witness_state, "Ready");
    }

    #[test]
    fn build_bundle_check_report_includes_per_policy_classification_rows() {
        let artifacts_dir = tmpdir("mprd-artifacts-report");
        let bundle_dir = tmpdir("mprd-bundle-report");

        let registry_signer = TokenSigningKey::from_seed(&[215u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[216u8; 32]);
        let registry_vk_hex = hex::encode(registry_signer.verifying_key().to_bytes());
        let manifest_vk_hex = hex::encode(manifest_signer.verifying_key().to_bytes());

        let tau_bytes = encode_minimal_compiled_tau_policy_bytes();
        let tau_policy_hash = Hash32(tau_compiled_policy_hash_v1(&tau_bytes));
        write_file(
            &artifacts_dir.join(hex::encode(tau_policy_hash.0)),
            &tau_bytes,
        );
        let skipped_tau_hash = Hash32([21u8; 32]);
        let skipped_unmapped_hash = Hash32([24u8; 32]);
        let skipped_tau_exec_kind = [0x11; 32];
        let skipped_unmapped_exec_kind = [0x99; 32];

        let manifest = GuestImageManifestV1::sign(
            &manifest_signer,
            123,
            vec![
                GuestImageEntryV1 {
                    policy_exec_kind_id: skipped_tau_exec_kind,
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    image_id: [7u8; 32],
                },
                GuestImageEntryV1 {
                    policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    image_id: [8u8; 32],
                },
                GuestImageEntryV1 {
                    policy_exec_kind_id: skipped_unmapped_exec_kind,
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    image_id: [9u8; 32],
                },
            ],
        )
        .unwrap();

        let policies = vec![
            AuthorizedPolicyV1 {
                policy_hash: skipped_tau_hash,
                policy_exec_kind_id: skipped_tau_exec_kind,
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: Some(policy_source_kind_tau_id_v1()),
                policy_source_hash: Some(Hash32([22u8; 32])),
            },
            AuthorizedPolicyV1 {
                policy_hash: tau_policy_hash,
                policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: Some([0x33; 32]),
                policy_source_hash: Some(Hash32([23u8; 32])),
            },
            AuthorizedPolicyV1 {
                policy_hash: skipped_unmapped_hash,
                policy_exec_kind_id: skipped_unmapped_exec_kind,
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: None,
                policy_source_hash: None,
            },
        ];

        let state = RegistryStateV1 {
            policy_epoch: 3,
            registry_root: Hash32([7u8; 32]),
            authorized_policies: policies,
            guest_image_manifest: manifest,
        };
        let signed = SignedRegistryStateV1::sign(&registry_signer, 456, state).unwrap();
        let registry_state_path = bundle_dir.join("registry_state.json");
        write_file(
            &registry_state_path,
            serde_json::to_string_pretty(&signed).unwrap().as_bytes(),
        );

        let report = build_bundle_check_report(
            registry_state_path,
            registry_vk_hex,
            Some(manifest_vk_hex),
            artifacts_dir,
        )
        .unwrap();

        assert_eq!(report.source_governance.tau_governed_mapped, 1);
        assert_eq!(report.source_governance.other_mapped, 1);
        assert_eq!(report.source_governance.unmapped, 1);
        assert_eq!(report.validated_policy_count, 1);
        assert_eq!(report.skipped_policy_count, 2);
        assert_eq!(report.policies.len(), 3);
        assert!(report.policies.iter().any(|policy| policy.policy_hash_hex
            == hex::encode(skipped_tau_hash.0)
            && policy.strict_selector_aliases
                == policy_exec_kind_aliases_from_label(&hex::encode(skipped_tau_exec_kind))
            && policy.source_governance == "TauGovernedMapped"
            && policy.source_intent_classification == "TauDeclared"
            && policy.source_boundary_classification == "TauGovernedMapped"
            && !policy.artifact_hash_validated
            && policy.source_artifact_witness_state == "BlockedArtifactValidation"
            && policy.artifact_validation == "skipped"));
        assert!(report.policies.iter().any(|policy| policy.policy_hash_hex
            == hex::encode(tau_policy_hash.0)
            && policy.strict_selector_aliases
                == policy_exec_kind_aliases_from_label("tau_compiled_v1")
            && policy.source_governance == "OtherMapped"
            && policy.source_intent_classification == "OtherDeclared"
            && policy.source_boundary_classification == "OtherMapped"
            && policy.artifact_hash_validated
            && policy.source_artifact_witness_state == "Ready"
            && policy.artifact_validation == "validated"));
        assert!(report.policies.iter().any(|policy| policy.policy_hash_hex
            == hex::encode(skipped_unmapped_hash.0)
            && policy.strict_selector_aliases
                == policy_exec_kind_aliases_from_label(&hex::encode(skipped_unmapped_exec_kind))
            && policy.source_governance == "Unmapped"
            && policy.source_intent_classification == "Undeclared"
            && policy.source_boundary_classification == "OtherCarrierUnmapped"
            && !policy.artifact_hash_validated
            && policy.source_artifact_witness_state == "BlockedMissingSourceMapping"
            && policy.artifact_validation == "skipped"));
    }

    #[test]
    fn bundle_check_report_json_includes_policy_rows() {
        let report = sample_bundle_check_report("/tmp/example");

        let json = format_bundle_check_report_json(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["source_governance"]["tau_governed_mapped"], 1);
        assert_eq!(
            parsed["policies"][0]["source_governance"],
            "TauGovernedMapped"
        );
        assert_eq!(
            parsed["policies"][0]["source_intent_classification"],
            "TauDeclared"
        );
        assert_eq!(
            parsed["policies"][0]["source_boundary_classification"],
            "TauGovernedMapped"
        );
        assert_eq!(
            parsed["policies"][0]["strict_selector_aliases"],
            serde_json::json!(policy_exec_kind_aliases_from_label("tau_compiled_v1"))
        );
        assert_eq!(parsed["policies"][0]["artifact_hash_validated"], true);
        assert_eq!(
            parsed["policies"][0]["source_artifact_witness_state"],
            "Ready"
        );
        assert_eq!(parsed["policies"][1]["artifact_validation"], "skipped");
        assert_eq!(
            parsed["policies"][1]["strict_selector_aliases"],
            serde_json::json!(policy_exec_kind_aliases_from_label("deadbeef"))
        );
        assert_eq!(
            parsed["policies"][1]["source_artifact_witness_state"],
            "BlockedMissingSourceMapping"
        );
        assert_eq!(parsed["policy_artifacts_dir"], "/tmp/example");
    }

    #[test]
    fn normalized_bundle_check_report_json_omits_local_path_and_keeps_policy_rows() {
        let report = sample_bundle_check_report("/tmp/fixture-a");

        let json = format_normalized_bundle_check_report_json(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["report_schema"],
            NORMALIZED_BUNDLE_CHECK_REPORT_SCHEMA_V1
        );
        assert!(parsed.get("policy_artifacts_dir").is_none());
        assert_eq!(parsed["source_governance"]["tau_governed_mapped"], 1);
        assert_eq!(
            parsed["policies"][0]["source_governance"],
            "TauGovernedMapped"
        );
        assert_eq!(
            parsed["policies"][0]["source_intent_classification"],
            "TauDeclared"
        );
        assert_eq!(
            parsed["policies"][0]["strict_selector_aliases"],
            serde_json::json!(policy_exec_kind_aliases_from_label("tau_compiled_v1"))
        );
        assert_eq!(
            parsed["policies"][0]["source_artifact_witness_state"],
            "Ready"
        );
        assert_eq!(
            parsed["policies"][1]["source_boundary_classification"],
            "OtherCarrierUnmapped"
        );
        assert_eq!(
            parsed["policies"][1]["strict_selector_aliases"],
            serde_json::json!(policy_exec_kind_aliases_from_label("deadbeef"))
        );
        assert_eq!(
            parsed["policies"][1]["source_artifact_witness_state"],
            "BlockedMissingSourceMapping"
        );
        assert_eq!(parsed["policies"][1]["artifact_validation"], "skipped");
    }

    #[test]
    fn bundle_check_report_digest_ignores_local_artifacts_dir() {
        let report_a = sample_bundle_check_report("/tmp/fixture-a");
        let report_b = sample_bundle_check_report("/tmp/fixture-b");

        assert_eq!(
            format_normalized_bundle_check_report_json(&report_a).unwrap(),
            format_normalized_bundle_check_report_json(&report_b).unwrap()
        );
        assert_eq!(
            format_bundle_check_report_digest(&report_a).unwrap(),
            format_bundle_check_report_digest(&report_b).unwrap()
        );
    }

    #[test]
    fn strict_governed_source_accepts_declared_tau_governed_exec_kind() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        enforce_strict_governed_source(&report, &[hex::encode([0x81u8; 32])]).unwrap();
    }

    #[test]
    fn strict_governed_source_builtin_tau_hex_alias_is_not_treated_as_unknown() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let failure_report = build_strict_governed_source_failure_report(
            &report,
            &[hex::encode(policy_exec_kind_tau_compiled_id_v1())],
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            failure_report.issue_kind,
            STRICT_GOVERNED_SOURCE_ISSUE_POLICY_NOT_TAU_GOVERNED
        );
        assert!(failure_report.unknown_declared_exec_kinds.is_empty());
        assert_eq!(failure_report.failing_policies.len(), 1);
        assert_eq!(
            failure_report.failing_policies[0].policy_exec_kind,
            "tau_compiled_v1"
        );
    }

    #[test]
    fn strict_governed_source_builtin_mpb_hex_alias_is_not_treated_as_unknown() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let failure_report = build_strict_governed_source_failure_report(
            &report,
            &[hex::encode(policy_exec_kind_mpb_id_v1())],
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            failure_report.issue_kind,
            STRICT_GOVERNED_SOURCE_ISSUE_POLICY_NOT_TAU_GOVERNED
        );
        assert!(failure_report.unknown_declared_exec_kinds.is_empty());
        assert_eq!(failure_report.failing_policies.len(), 1);
        assert_eq!(
            failure_report.failing_policies[0].policy_exec_kind,
            "mpb_v1"
        );
    }

    #[test]
    fn strict_governed_source_fails_on_non_tau_governed_declared_exec_kind() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let expected_digest = format_strict_governed_source_failure_digest(
            &build_strict_governed_source_failure_report(&report, &["tau_compiled_v1".into()])
                .unwrap()
                .unwrap(),
        )
        .unwrap();

        let err = enforce_strict_governed_source(&report, &["tau_compiled_v1".into()]).unwrap_err();
        assert_eq!(
            err.downcast_ref::<BundleCheckError>(),
            Some(&BundleCheckError::StrictGovernedSourceViolation {
                declared_exec_kinds_csv: "tau_compiled_v1".into(),
                issue_kind: STRICT_GOVERNED_SOURCE_ISSUE_POLICY_NOT_TAU_GOVERNED.into(),
                first_issue: format!(
                    "policy_hash={} exec_kind=tau_compiled_v1 source_governance=OtherMapped source_intent=OtherDeclared source_boundary=OtherMapped",
                    "11".repeat(32)
                ),
                strict_failure_digest_hex: expected_digest,
            })
        );
    }

    #[test]
    fn strict_governed_source_fails_closed_on_unknown_declared_exec_kind() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let expected_digest = format_strict_governed_source_failure_digest(
            &build_strict_governed_source_failure_report(&report, &["unknown_v1".into()])
                .unwrap()
                .unwrap(),
        )
        .unwrap();

        let err = enforce_strict_governed_source(&report, &["unknown_v1".into()]).unwrap_err();
        assert_eq!(
            err.downcast_ref::<BundleCheckError>(),
            Some(&BundleCheckError::StrictGovernedSourceViolation {
                declared_exec_kinds_csv: "unknown_v1".into(),
                issue_kind: STRICT_GOVERNED_SOURCE_ISSUE_UNKNOWN_DECLARED_EXEC_KIND.into(),
                first_issue: "exec_kind=unknown_v1".into(),
                strict_failure_digest_hex: expected_digest,
            })
        );
    }

    #[test]
    fn strict_governed_source_failure_digest_ignores_local_artifacts_dir() {
        let report_a = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let report_b = strict_governed_source_sample_bundle_check_report("/tmp/fixture-b");
        let strict_exec_kinds = vec!["tau_compiled_v1".into()];

        let failure_report_a =
            build_strict_governed_source_failure_report(&report_a, &strict_exec_kinds)
                .unwrap()
                .unwrap();
        let failure_report_b =
            build_strict_governed_source_failure_report(&report_b, &strict_exec_kinds)
                .unwrap()
                .unwrap();
        assert_eq!(failure_report_a, failure_report_b);
        assert_eq!(
            format_strict_governed_source_failure_digest(&failure_report_a).unwrap(),
            format_strict_governed_source_failure_digest(&failure_report_b).unwrap()
        );
    }

    #[test]
    fn strict_governed_source_failure_report_json_includes_issue_fields() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let failure_report =
            build_strict_governed_source_failure_report(&report, &["tau_compiled_v1".into()])
                .unwrap()
                .unwrap();

        let json = format_strict_governed_source_failure_report_json(&failure_report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["report_schema"],
            STRICT_GOVERNED_SOURCE_FAILURE_REPORT_SCHEMA_V1
        );
        assert_eq!(
            parsed["issue_kind"],
            STRICT_GOVERNED_SOURCE_ISSUE_POLICY_NOT_TAU_GOVERNED
        );
        assert_eq!(parsed["classification"], "governed_source_violation");
        assert_eq!(
            parsed["required_response"],
            "reject_bundle_and_fix_policy_mapping_or_declaration"
        );
        assert_eq!(
            parsed["first_issue"],
            format!(
                "policy_hash={} exec_kind=tau_compiled_v1 source_governance=OtherMapped source_intent=OtherDeclared source_boundary=OtherMapped",
                "11".repeat(32)
            )
        );
        assert_eq!(
            parsed["failing_policies"][0]["source_intent_classification"],
            "OtherDeclared"
        );
        assert_eq!(
            parsed["failing_policies"][0]["source_boundary_classification"],
            "OtherMapped"
        );
    }

    #[test]
    fn strict_governed_source_violation_suggests_special_exit_code() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let err = enforce_strict_governed_source(&report, &["tau_compiled_v1".into()]).unwrap_err();
        assert_eq!(
            suggested_exit_code(&err),
            Some(STRICT_GOVERNED_SOURCE_EXIT_CODE)
        );
    }

    #[test]
    fn missing_policy_artifact_does_not_use_strict_exit_code() {
        let err = BundleCheckError::MissingPolicyArtifact {
            policy_hash_hex: "11".repeat(32),
        };
        let anyhow_err = anyhow::Error::from(err);
        assert_eq!(suggested_exit_code(&anyhow_err), None);
    }

    #[test]
    fn strict_governed_source_response_matrix_artifact_matches_code_contract() {
        let artifact_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../internal/shapeforge/mprd/evidence/strict_governed_source_response_matrix.json",
        );
        let artifact_json = fs::read_to_string(&artifact_path).unwrap_or_else(|err| {
            panic!("failed to read {}: {err}", artifact_path.display());
        });
        let artifact_value: serde_json::Value = serde_json::from_str(&artifact_json).unwrap();

        assert_eq!(
            artifact_value,
            strict_governed_source_response_matrix_value()
        );
    }

    #[test]
    fn strict_source_artifact_witness_accepts_declared_ready_exec_kind() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        enforce_strict_source_artifact_witness(&report, &["tau_compiled_v1".into()]).unwrap();
    }

    #[test]
    fn strict_source_artifact_witness_accepts_builtin_tau_hex_alias() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        enforce_strict_source_artifact_witness(
            &report,
            &[hex::encode(policy_exec_kind_tau_compiled_id_v1())],
        )
        .unwrap();
    }

    #[test]
    fn strict_source_artifact_witness_fails_on_blocked_artifact_validation() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let exec_kind = hex::encode([0x81u8; 32]);
        let expected_digest = format_strict_source_artifact_witness_failure_digest(
            &build_strict_source_artifact_witness_failure_report(&report, &[exec_kind.clone()])
                .unwrap()
                .unwrap(),
        )
        .unwrap();

        let err = enforce_strict_source_artifact_witness(&report, &[exec_kind]).unwrap_err();
        assert_eq!(
            err.downcast_ref::<BundleCheckError>(),
            Some(&BundleCheckError::StrictSourceArtifactWitnessViolation {
                declared_exec_kinds_csv: hex::encode([0x81u8; 32]),
                issue_kind: STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_ARTIFACT_VALIDATION_MISSING
                    .into(),
                first_issue: format!(
                    "policy_hash={} exec_kind={} source_governance=TauGovernedMapped source_intent=TauDeclared source_boundary=TauGovernedMapped artifact=skipped witness=BlockedArtifactValidation",
                    "22".repeat(32),
                    hex::encode([0x81u8; 32])
                ),
                strict_failure_digest_hex: expected_digest,
            })
        );
    }

    #[test]
    fn strict_source_artifact_witness_fails_on_blocked_missing_mapping() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let expected_digest = format_strict_source_artifact_witness_failure_digest(
            &build_strict_source_artifact_witness_failure_report(&report, &["mpb_v1".into()])
                .unwrap()
                .unwrap(),
        )
        .unwrap();

        let err = enforce_strict_source_artifact_witness(&report, &["mpb_v1".into()]).unwrap_err();
        assert_eq!(
            err.downcast_ref::<BundleCheckError>(),
            Some(&BundleCheckError::StrictSourceArtifactWitnessViolation {
                declared_exec_kinds_csv: "mpb_v1".into(),
                issue_kind: STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_MAPPING_MISSING.into(),
                first_issue: format!(
                    "policy_hash={} exec_kind=mpb_v1 source_governance=Unmapped source_intent=Undeclared source_boundary=OtherCarrierUnmapped artifact=validated witness=BlockedMissingSourceMapping",
                    "33".repeat(32)
                ),
                strict_failure_digest_hex: expected_digest,
            })
        );
    }

    #[test]
    fn strict_source_artifact_witness_builtin_mpb_hex_alias_is_not_treated_as_unknown() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let failure_report = build_strict_source_artifact_witness_failure_report(
            &report,
            &[hex::encode(policy_exec_kind_mpb_id_v1())],
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            failure_report.issue_kind,
            STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_MAPPING_MISSING
        );
        assert!(failure_report.unknown_declared_exec_kinds.is_empty());
        assert_eq!(failure_report.failing_policies.len(), 1);
        assert_eq!(
            failure_report.failing_policies[0].policy_exec_kind,
            "mpb_v1"
        );
    }

    #[test]
    fn strict_source_artifact_witness_fails_closed_on_unknown_declared_exec_kind() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let expected_digest = format_strict_source_artifact_witness_failure_digest(
            &build_strict_source_artifact_witness_failure_report(&report, &["unknown_v1".into()])
                .unwrap()
                .unwrap(),
        )
        .unwrap();

        let err =
            enforce_strict_source_artifact_witness(&report, &["unknown_v1".into()]).unwrap_err();
        assert_eq!(
            err.downcast_ref::<BundleCheckError>(),
            Some(&BundleCheckError::StrictSourceArtifactWitnessViolation {
                declared_exec_kinds_csv: "unknown_v1".into(),
                issue_kind: STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_UNKNOWN_DECLARED_EXEC_KIND.into(),
                first_issue: "exec_kind=unknown_v1".into(),
                strict_failure_digest_hex: expected_digest,
            })
        );
    }

    #[test]
    fn strict_source_artifact_witness_failure_digest_ignores_local_artifacts_dir() {
        let report_a = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let report_b = strict_governed_source_sample_bundle_check_report("/tmp/fixture-b");
        let strict_exec_kinds = vec!["mpb_v1".into()];

        let failure_report_a =
            build_strict_source_artifact_witness_failure_report(&report_a, &strict_exec_kinds)
                .unwrap()
                .unwrap();
        let failure_report_b =
            build_strict_source_artifact_witness_failure_report(&report_b, &strict_exec_kinds)
                .unwrap()
                .unwrap();
        assert_eq!(failure_report_a, failure_report_b);
        assert_eq!(
            format_strict_source_artifact_witness_failure_digest(&failure_report_a).unwrap(),
            format_strict_source_artifact_witness_failure_digest(&failure_report_b).unwrap()
        );
    }

    #[test]
    fn strict_source_artifact_witness_failure_report_json_includes_issue_fields() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let failure_report = build_strict_source_artifact_witness_failure_report(
            &report,
            &[hex::encode([0x81u8; 32])],
        )
        .unwrap()
        .unwrap();

        let json =
            format_strict_source_artifact_witness_failure_report_json(&failure_report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["report_schema"],
            STRICT_SOURCE_ARTIFACT_WITNESS_FAILURE_REPORT_SCHEMA_V1
        );
        assert_eq!(
            parsed["issue_kind"],
            STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_ARTIFACT_VALIDATION_MISSING
        );
        assert_eq!(
            parsed["classification"],
            "source_artifact_validation_missing"
        );
        assert_eq!(
            parsed["required_response"],
            "reject_bundle_and_publish_validated_artifact"
        );
        assert_eq!(
            parsed["failing_policies"][0]["source_artifact_witness_state"],
            "BlockedArtifactValidation"
        );
        assert_eq!(
            parsed["failing_policies"][0]["artifact_validation"],
            "skipped"
        );
    }

    #[test]
    fn strict_source_artifact_witness_violation_suggests_special_exit_code() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let err = enforce_strict_source_artifact_witness(&report, &["mpb_v1".into()]).unwrap_err();
        assert_eq!(
            suggested_exit_code(&err),
            Some(STRICT_SOURCE_ARTIFACT_WITNESS_EXIT_CODE)
        );
    }

    #[test]
    fn combined_strict_contracts_prioritize_governed_source_when_both_fail() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let err = enforce_strict_bundle_contracts(
            &report,
            &["mpb_v1".into()],
            "human",
            &["mpb_v1".into()],
            "human",
        )
        .unwrap_err();
        assert_eq!(
            err.downcast_ref::<BundleCheckError>(),
            Some(&BundleCheckError::StrictGovernedSourceViolation {
                declared_exec_kinds_csv: "mpb_v1".into(),
                issue_kind: STRICT_GOVERNED_SOURCE_ISSUE_POLICY_NOT_TAU_GOVERNED.into(),
                first_issue: format!(
                    "policy_hash={} exec_kind=mpb_v1 source_governance=Unmapped source_intent=Undeclared source_boundary=OtherCarrierUnmapped",
                    "33".repeat(32)
                ),
                strict_failure_digest_hex: format_strict_governed_source_failure_digest(
                    &build_strict_governed_source_failure_report(&report, &["mpb_v1".into()])
                        .unwrap()
                        .unwrap()
                )
                .unwrap(),
            })
        );
    }

    #[test]
    fn combined_strict_contracts_reach_source_artifact_after_governed_source_passes() {
        let report = strict_governed_source_sample_bundle_check_report("/tmp/fixture-a");
        let exec_kind = hex::encode([0x81u8; 32]);
        let err = enforce_strict_bundle_contracts(
            &report,
            &[exec_kind.clone()],
            "human",
            &[exec_kind.clone()],
            "human",
        )
        .unwrap_err();
        assert_eq!(
            err.downcast_ref::<BundleCheckError>(),
            Some(&BundleCheckError::StrictSourceArtifactWitnessViolation {
                declared_exec_kinds_csv: exec_kind.clone(),
                issue_kind: STRICT_SOURCE_ARTIFACT_WITNESS_ISSUE_ARTIFACT_VALIDATION_MISSING
                    .into(),
                first_issue: format!(
                    "policy_hash={} exec_kind={} source_governance=TauGovernedMapped source_intent=TauDeclared source_boundary=TauGovernedMapped artifact=skipped witness=BlockedArtifactValidation",
                    "22".repeat(32),
                    exec_kind
                ),
                strict_failure_digest_hex: format_strict_source_artifact_witness_failure_digest(
                    &build_strict_source_artifact_witness_failure_report(
                        &report,
                        &[hex::encode([0x81u8; 32])]
                    )
                    .unwrap()
                    .unwrap()
                )
                .unwrap(),
            })
        );
    }

    #[test]
    fn strict_source_artifact_witness_response_matrix_artifact_matches_code_contract() {
        let artifact_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../internal/shapeforge/mprd/evidence/strict_source_artifact_witness_response_matrix.json",
        );
        let artifact_json = fs::read_to_string(&artifact_path).unwrap_or_else(|err| {
            panic!("failed to read {}: {err}", artifact_path.display());
        });
        let artifact_value: serde_json::Value = serde_json::from_str(&artifact_json).unwrap();

        assert_eq!(
            artifact_value,
            strict_source_artifact_witness_response_matrix_value()
        );
    }

    #[test]
    fn strict_selector_alias_matrix_artifact_matches_code_contract() {
        let artifact_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../internal/shapeforge/mprd/evidence/strict_selector_alias_matrix.json");
        let artifact_json = fs::read_to_string(&artifact_path).unwrap_or_else(|err| {
            panic!("failed to read {}: {err}", artifact_path.display());
        });
        let artifact_value: serde_json::Value = serde_json::from_str(&artifact_json).unwrap();

        assert_eq!(artifact_value, strict_selector_alias_matrix_value());
    }

    fn sample_bundle_check_report(policy_artifacts_dir: &str) -> BundleCheckReport {
        BundleCheckReport {
            policy_epoch: 5,
            registry_root_hex: "aa".repeat(32),
            validated_policy_count: 1,
            skipped_policy_count: 1,
            total_policy_count: 2,
            source_governance: PolicySourceGovernanceSummary {
                tau_governed_mapped: 1,
                other_mapped: 0,
                unmapped: 1,
            },
            policies: vec![
                BundlePolicyReport {
                    policy_hash_hex: "11".repeat(32),
                    policy_exec_kind: "tau_compiled_v1".into(),
                    strict_selector_aliases: policy_exec_kind_aliases_from_label("tau_compiled_v1"),
                    policy_exec_version_hex: "22".repeat(32),
                    source_governance: "TauGovernedMapped".into(),
                    source_intent_classification: "TauDeclared".into(),
                    source_boundary_classification: "TauGovernedMapped".into(),
                    policy_source_kind_hex: Some(hex::encode(policy_source_kind_tau_id_v1())),
                    policy_source_hash_hex: Some("33".repeat(32)),
                    artifact_hash_validated: true,
                    source_artifact_witness_state: "Ready".into(),
                    artifact_validation: "validated".into(),
                },
                BundlePolicyReport {
                    policy_hash_hex: "44".repeat(32),
                    policy_exec_kind: "deadbeef".into(),
                    strict_selector_aliases: policy_exec_kind_aliases_from_label("deadbeef"),
                    policy_exec_version_hex: "55".repeat(32),
                    source_governance: "Unmapped".into(),
                    source_intent_classification: "Undeclared".into(),
                    source_boundary_classification: "OtherCarrierUnmapped".into(),
                    policy_source_kind_hex: None,
                    policy_source_hash_hex: None,
                    artifact_hash_validated: false,
                    source_artifact_witness_state: "BlockedMissingSourceMapping".into(),
                    artifact_validation: "skipped".into(),
                },
            ],
            policy_artifacts_dir: policy_artifacts_dir.into(),
        }
    }

    fn strict_governed_source_sample_bundle_check_report(
        policy_artifacts_dir: &str,
    ) -> BundleCheckReport {
        BundleCheckReport {
            policy_epoch: 8,
            registry_root_hex: "bb".repeat(32),
            validated_policy_count: 2,
            skipped_policy_count: 1,
            total_policy_count: 3,
            source_governance: PolicySourceGovernanceSummary {
                tau_governed_mapped: 1,
                other_mapped: 1,
                unmapped: 1,
            },
            policies: vec![
                BundlePolicyReport {
                    policy_hash_hex: "11".repeat(32),
                    policy_exec_kind: "tau_compiled_v1".into(),
                    strict_selector_aliases: policy_exec_kind_aliases_from_label("tau_compiled_v1"),
                    policy_exec_version_hex: "22".repeat(32),
                    source_governance: "OtherMapped".into(),
                    source_intent_classification: "OtherDeclared".into(),
                    source_boundary_classification: "OtherMapped".into(),
                    policy_source_kind_hex: Some(hex::encode([0x77u8; 32])),
                    policy_source_hash_hex: Some("33".repeat(32)),
                    artifact_hash_validated: true,
                    source_artifact_witness_state: "Ready".into(),
                    artifact_validation: "validated".into(),
                },
                BundlePolicyReport {
                    policy_hash_hex: "22".repeat(32),
                    policy_exec_kind: hex::encode([0x81u8; 32]),
                    strict_selector_aliases: policy_exec_kind_aliases_from_label(&hex::encode(
                        [0x81u8; 32],
                    )),
                    policy_exec_version_hex: "44".repeat(32),
                    source_governance: "TauGovernedMapped".into(),
                    source_intent_classification: "TauDeclared".into(),
                    source_boundary_classification: "TauGovernedMapped".into(),
                    policy_source_kind_hex: Some(hex::encode(policy_source_kind_tau_id_v1())),
                    policy_source_hash_hex: Some("55".repeat(32)),
                    artifact_hash_validated: false,
                    source_artifact_witness_state: "BlockedArtifactValidation".into(),
                    artifact_validation: "skipped".into(),
                },
                BundlePolicyReport {
                    policy_hash_hex: "33".repeat(32),
                    policy_exec_kind: "mpb_v1".into(),
                    strict_selector_aliases: policy_exec_kind_aliases_from_label("mpb_v1"),
                    policy_exec_version_hex: "66".repeat(32),
                    source_governance: "Unmapped".into(),
                    source_intent_classification: "Undeclared".into(),
                    source_boundary_classification: "OtherCarrierUnmapped".into(),
                    policy_source_kind_hex: None,
                    policy_source_hash_hex: None,
                    artifact_hash_validated: true,
                    source_artifact_witness_state: "BlockedMissingSourceMapping".into(),
                    artifact_validation: "validated".into(),
                },
            ],
            policy_artifacts_dir: policy_artifacts_dir.into(),
        }
    }

    #[test]
    fn build_bundle_check_report_sorts_policy_rows_by_policy_hash() {
        let artifacts_dir = tmpdir("mprd-artifacts-sorted-report");
        let bundle_dir = tmpdir("mprd-bundle-sorted-report");

        let registry_signer = TokenSigningKey::from_seed(&[217u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[218u8; 32]);
        let registry_vk_hex = hex::encode(registry_signer.verifying_key().to_bytes());
        let manifest_vk_hex = hex::encode(manifest_signer.verifying_key().to_bytes());

        let exec_kind_a = [0x81; 32];
        let exec_kind_b = [0x82; 32];
        let exec_kind_c = [0x83; 32];
        let policy_hash_a = Hash32([0x30; 32]);
        let policy_hash_b = Hash32([0x10; 32]);
        let policy_hash_c = Hash32([0x20; 32]);

        let manifest = GuestImageManifestV1::sign(
            &manifest_signer,
            123,
            vec![
                GuestImageEntryV1 {
                    policy_exec_kind_id: exec_kind_a,
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    image_id: [1u8; 32],
                },
                GuestImageEntryV1 {
                    policy_exec_kind_id: exec_kind_b,
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    image_id: [2u8; 32],
                },
                GuestImageEntryV1 {
                    policy_exec_kind_id: exec_kind_c,
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    image_id: [3u8; 32],
                },
            ],
        )
        .unwrap();

        let state = RegistryStateV1 {
            policy_epoch: 9,
            registry_root: Hash32([0x77; 32]),
            authorized_policies: vec![
                AuthorizedPolicyV1 {
                    policy_hash: policy_hash_a,
                    policy_exec_kind_id: exec_kind_a,
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    policy_source_kind_id: None,
                    policy_source_hash: None,
                },
                AuthorizedPolicyV1 {
                    policy_hash: policy_hash_b,
                    policy_exec_kind_id: exec_kind_b,
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    policy_source_kind_id: Some(policy_source_kind_tau_id_v1()),
                    policy_source_hash: Some(Hash32([0x41; 32])),
                },
                AuthorizedPolicyV1 {
                    policy_hash: policy_hash_c,
                    policy_exec_kind_id: exec_kind_c,
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    policy_source_kind_id: Some([0x55; 32]),
                    policy_source_hash: Some(Hash32([0x42; 32])),
                },
            ],
            guest_image_manifest: manifest,
        };
        let signed = SignedRegistryStateV1::sign(&registry_signer, 456, state).unwrap();
        let registry_state_path = bundle_dir.join("registry_state.json");
        write_file(
            &registry_state_path,
            serde_json::to_string_pretty(&signed).unwrap().as_bytes(),
        );

        let report = build_bundle_check_report(
            registry_state_path,
            registry_vk_hex,
            Some(manifest_vk_hex),
            artifacts_dir,
        )
        .unwrap();

        let actual_hashes: Vec<_> = report
            .policies
            .iter()
            .map(|policy| policy.policy_hash_hex.clone())
            .collect();
        assert_eq!(
            actual_hashes,
            vec![
                hex::encode(policy_hash_b.0),
                hex::encode(policy_hash_c.0),
                hex::encode(policy_hash_a.0),
            ]
        );
    }

    #[test]
    fn check_bundle_accepts_valid_minimal_bundle() {
        let artifacts_dir = tmpdir("mprd-artifacts");
        let bundle_dir = tmpdir("mprd-bundle");

        let registry_signer = TokenSigningKey::from_seed(&[211u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[212u8; 32]);
        let registry_vk_hex = hex::encode(registry_signer.verifying_key().to_bytes());
        let manifest_vk_hex = hex::encode(manifest_signer.verifying_key().to_bytes());

        // MPB artifact
        let mpb_bytecode = vec![0xFF];
        let mpb_vars = [("a", 0u8)];
        let mpb_bytes = encode_mpb_artifact(&mpb_bytecode, &[("a", 0)]);
        let refs: Vec<(&[u8], u8)> = mpb_vars.iter().map(|(n, r)| (n.as_bytes(), *r)).collect();
        let mpb_policy_hash = Hash32(mprd_mpb::policy_hash_v1(&mpb_bytecode, &refs));
        write_file(
            &artifacts_dir.join(hex::encode(mpb_policy_hash.0)),
            &mpb_bytes,
        );

        // Tau-compiled artifact
        let tau_bytes = encode_minimal_compiled_tau_policy_bytes();
        let tau_policy_hash = Hash32(tau_compiled_policy_hash_v1(&tau_bytes));
        // keep: `tau_policy_hash` is used below; no need to keep the hex string here.
        write_file(
            &artifacts_dir.join(hex::encode(tau_policy_hash.0)),
            &tau_bytes,
        );

        // Signed manifest
        let manifest = GuestImageManifestV1::sign(
            &manifest_signer,
            123,
            vec![
                GuestImageEntryV1 {
                    policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    image_id: [9u8; 32],
                },
                GuestImageEntryV1 {
                    policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    image_id: [8u8; 32],
                },
            ],
        )
        .unwrap();

        let mut policies = vec![
            AuthorizedPolicyV1 {
                policy_hash: mpb_policy_hash,
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: None,
                policy_source_hash: None,
            },
            AuthorizedPolicyV1 {
                policy_hash: tau_policy_hash,
                policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: None,
                policy_source_hash: None,
            },
        ];
        policies.sort_by(|a, b| a.policy_hash.0.cmp(&b.policy_hash.0));

        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: Hash32([7u8; 32]),
            authorized_policies: policies,
            guest_image_manifest: manifest,
        };
        let signed = SignedRegistryStateV1::sign(&registry_signer, 456, state).unwrap();
        let registry_state_path = bundle_dir.join("registry_state.json");
        write_file(
            &registry_state_path,
            serde_json::to_string_pretty(&signed).unwrap().as_bytes(),
        );

        check_bundle(
            registry_state_path,
            registry_vk_hex,
            Some(manifest_vk_hex),
            artifacts_dir,
            "human",
            &[],
            "human",
            &[],
            "human",
        )
        .unwrap();
    }

    #[test]
    fn production_release_accepts_valid_signed_mpb_registry_manifest_pair() {
        let artifacts_dir = tmpdir("mprd-release-artifacts");
        let bundle_dir = tmpdir("mprd-release-bundle");

        let registry_signer = TokenSigningKey::from_seed(&[231u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[232u8; 32]);
        let registry_vk_hex = hex::encode(registry_signer.verifying_key().to_bytes());
        let manifest_vk_hex = hex::encode(manifest_signer.verifying_key().to_bytes());
        let mpb_policy_hash = write_release_mpb_artifact(&artifacts_dir);

        let manifest = GuestImageManifestV1::sign(
            &manifest_signer,
            123,
            vec![GuestImageEntryV1 {
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                image_id: [9u8; 32],
            }],
        )
        .unwrap();

        let state = RegistryStateV1 {
            policy_epoch: 21,
            registry_root: Hash32([0x21; 32]),
            authorized_policies: vec![AuthorizedPolicyV1 {
                policy_hash: mpb_policy_hash,
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: Some(policy_source_kind_tau_id_v1()),
                policy_source_hash: Some(Hash32([0x31; 32])),
            }],
            guest_image_manifest: manifest,
        };
        let registry_state_path = write_signed_registry_state(&bundle_dir, &registry_signer, state);

        let report = build_production_release_report(
            registry_state_path,
            registry_vk_hex,
            Some(manifest_vk_hex),
            artifacts_dir,
        )
        .unwrap();

        assert_eq!(report.report_schema, PRODUCTION_RELEASE_REPORT_SCHEMA_V1);
        assert_eq!(report.production_policy_count, 1);
        assert_eq!(report.policies[0].policy_exec_kind, "mpb_v1");
        assert_eq!(report.policies[0].image_id_hex, hex::encode([9u8; 32]));
        assert_eq!(report.policies[0].artifact_validation, "validated");
    }

    #[test]
    fn production_release_methods_gate_rejects_placeholder_mpb_methods() {
        let report = ProductionReleaseReport {
            report_schema: PRODUCTION_RELEASE_REPORT_SCHEMA_V1,
            policy_epoch: 21,
            registry_root_hex: "11".repeat(32),
            production_policy_count: 1,
            policies: vec![ProductionReleasePolicyReport {
                policy_hash_hex: "22".repeat(32),
                policy_exec_kind: "mpb_v1".into(),
                policy_exec_version_hex: hex::encode(policy_exec_version_id_v1()),
                image_id_hex: "33".repeat(32),
                source_governance: "TauGovernedMapped".into(),
                artifact_validation: "validated".into(),
            }],
        };

        let err = ensure_release_methods_embedded(&report, false, true).unwrap_err();
        assert_eq!(
            err.downcast_ref::<BundleCheckError>(),
            Some(&BundleCheckError::ProductionReleaseViolation {
                issue_kind: PRODUCTION_RELEASE_ISSUE_PLACEHOLDER_METHODS.into(),
                first_issue: "exec_kind=mpb_v1 local Risc0 methods are placeholders; rebuild without RISC0_SKIP_BUILD=1 and require embedded methods for production release".into(),
            })
        );
    }

    #[test]
    fn production_release_onchain_executor_alias_boundary_is_fail_closed() {
        for executor_type in ["noop", "http", "file", "webhook", "event-mirror"] {
            assert!(
                !config_executor_type_requires_onchain_finality(executor_type),
                "non-chain executor_type={executor_type} must not require a chain finality spec"
            );
        }

        for executor_type in [
            "onchain", "on_chain", "on-chain", "EVM", "ethereum", "eth", "solana", "sui", "aptos",
            "cosmos", "starknet", "polygon", "arbitrum", "optimism", "base",
        ] {
            assert!(
                config_executor_type_requires_onchain_finality(executor_type),
                "chain executor_type={executor_type} must require a promoted finality spec"
            );
        }
    }

    #[test]
    fn production_release_nonce_store_boundary_is_fail_closed() {
        let mut config = MprdConfigFile::default();
        config.anti_replay = Some(crate::config_model::AntiReplayConfig {
            nonce_store_dir: Some(PathBuf::from("anti_replay")),
        });
        assert!(config_has_persistent_nonce_store(&config));

        config.anti_replay = Some(crate::config_model::AntiReplayConfig {
            nonce_store_dir: Some(PathBuf::from("  ")),
        });
        assert!(!config_has_persistent_nonce_store(&config));

        config.anti_replay = Some(crate::config_model::AntiReplayConfig {
            nonce_store_dir: None,
        });
        assert!(!config_has_persistent_nonce_store(&config));

        config.anti_replay = None;
        assert!(!config_has_persistent_nonce_store(&config));
    }

    #[test]
    fn production_release_lowtrust_redis_boundary_is_fail_closed() {
        let mut config = MprdConfigFile::default();
        assert!(!config_is_low_trust(&config));
        assert!(!config_has_lowtrust_redis_nonce_store(&config));

        config.trust_mode = Some("low_trust".into());
        assert!(config_is_low_trust(&config));
        assert!(!config_has_lowtrust_redis_nonce_store(&config));

        config.low_trust = Some(crate::config_model::LowTrustConfig {
            nonce_store_backend: Some("shared_fs".into()),
            redis_url: Some("redis://127.0.0.1:6379".into()),
            redis_key_prefix: Some("mprd:nonce:v1".into()),
            redis_timeout_ms: Some(250),
        });
        assert!(!config_has_lowtrust_redis_nonce_store(&config));

        config.low_trust = Some(crate::config_model::LowTrustConfig {
            nonce_store_backend: Some("redis".into()),
            redis_url: Some("   ".into()),
            redis_key_prefix: Some("mprd:nonce:v1".into()),
            redis_timeout_ms: Some(250),
        });
        assert!(!config_has_lowtrust_redis_nonce_store(&config));

        config.low_trust = Some(crate::config_model::LowTrustConfig {
            nonce_store_backend: Some("redis".into()),
            redis_url: Some("redis://127.0.0.1:6379".into()),
            redis_key_prefix: Some("mprd:nonce:v1".into()),
            redis_timeout_ms: Some(250),
        });
        assert!(config_has_lowtrust_redis_nonce_store(&config));
    }

    #[test]
    fn production_release_accepts_lowtrust_redis_config_boundary() {
        let bundle_dir = tmpdir("mprd-release-lowtrust-config");
        let config_path = write_release_config(
            &bundle_dir,
            "lowtrust-redis-config.json",
            "trustless",
            Some(hex::encode([9u8; 32])),
            None,
            false,
            Some("low_trust"),
            Some(crate::config_model::LowTrustConfig {
                nonce_store_backend: Some("redis".into()),
                redis_url: Some("redis://127.0.0.1:6379".into()),
                redis_key_prefix: Some("mprd:nonce:v1".into()),
                redis_timeout_ms: Some(250),
            }),
        );

        validate_optional_production_release_config(Some(config_path)).unwrap();
        let _ = std::fs::remove_dir_all(bundle_dir);
    }

    #[test]
    fn production_release_boundary_concolic_atlas_covers_distinct_reject_paths() {
        let cases = [
            (
                ProductionReleaseBoundaryMutation::ValidSeed,
                "ok",
                "structure-preserving valid seed must remain accepted",
            ),
            (
                ProductionReleaseBoundaryMutation::HostTrustedRoute,
                PRODUCTION_RELEASE_ISSUE_HOST_TRUSTED,
                "demo/dev host-trusted route must be rejected before manifest/artifact trust",
            ),
            (
                ProductionReleaseBoundaryMutation::UnsupportedExecKind,
                PRODUCTION_RELEASE_ISSUE_UNSUPPORTED_EXEC_KIND,
                "unknown exec kind must stay outside production allowlist",
            ),
            (
                ProductionReleaseBoundaryMutation::MissingManifestImageId,
                PRODUCTION_RELEASE_ISSUE_MISSING_IMAGE_ID,
                "registry policy without manifest image route must reject",
            ),
            (
                ProductionReleaseBoundaryMutation::AllZeroManifestImageId,
                PRODUCTION_RELEASE_ISSUE_ALL_ZERO_IMAGE_ID,
                "tampered signed state with all-zero manifest route must reject",
            ),
            (
                ProductionReleaseBoundaryMutation::MissingPolicySourceMapping,
                PRODUCTION_RELEASE_ISSUE_MISSING_SOURCE_MAPPING,
                "production route needs source-to-artifact mapping",
            ),
            (
                ProductionReleaseBoundaryMutation::MissingPolicyArtifact,
                "missing_policy_artifact",
                "mapped policy without local content-addressed artifact must reject",
            ),
            (
                ProductionReleaseBoundaryMutation::InvalidMpbArtifactBytes,
                "invalid_mpb_artifact_bytes",
                "artifact file with malformed MPB bytes must reject",
            ),
            (
                ProductionReleaseBoundaryMutation::MpbArtifactHashMismatch,
                "mpb_artifact_hash_mismatch",
                "validly shaped but content-mismatched artifact must reject",
            ),
            (
                ProductionReleaseBoundaryMutation::PlaceholderMpbMethods,
                PRODUCTION_RELEASE_ISSUE_PLACEHOLDER_METHODS,
                "valid bundle with local placeholder methods must reject",
            ),
            (
                ProductionReleaseBoundaryMutation::LocalModeConfig,
                PRODUCTION_RELEASE_ISSUE_CONFIG_LOCAL_MODE,
                "local config must reject before bundle acceptance",
            ),
            (
                ProductionReleaseBoundaryMutation::PlaceholderConfigImageId,
                PRODUCTION_RELEASE_ISSUE_CONFIG_PLACEHOLDER_IMAGE_ID,
                "all-zero configured image ID must reject before bundle acceptance",
            ),
            (
                ProductionReleaseBoundaryMutation::OnChainExecutorConfig,
                PRODUCTION_RELEASE_ISSUE_ONCHAIN_FINALITY_UNSUPPORTED,
                "on-chain executor aliases must reject until per-chain finality and nonce semantics are promoted",
            ),
            (
                ProductionReleaseBoundaryMutation::MissingNonceStoreConfig,
                PRODUCTION_RELEASE_ISSUE_CONFIG_MISSING_NONCE_STORE,
                "production config must name a persistent anti-replay nonce store",
            ),
            (
                ProductionReleaseBoundaryMutation::LowTrustMissingRedisConfig,
                PRODUCTION_RELEASE_ISSUE_CONFIG_LOWTRUST_REDIS_REQUIRED,
                "low-trust production config must use Redis nonce coordination",
            ),
            (
                ProductionReleaseBoundaryMutation::WrongManifestKey,
                "manifest_verification_failed",
                "wrong manifest verifying key must reject",
            ),
        ];

        let mut labels = BTreeSet::new();
        let mut path_ids = BTreeSet::new();
        for (mutation, expected_label, reason) in cases {
            let outcome = run_production_release_boundary_case(mutation);
            assert_eq!(
                outcome.outcome_label, expected_label,
                "mutation={mutation:?} reason={reason} path_id={}",
                outcome.path_id
            );
            labels.insert(outcome.outcome_label);
            path_ids.insert(outcome.path_id);
        }

        assert_eq!(labels.len(), cases.len());
        assert_eq!(path_ids.len(), cases.len());
        assert!(labels.contains("ok"));
        assert!(labels.contains(PRODUCTION_RELEASE_ISSUE_HOST_TRUSTED));
        assert!(labels.contains(PRODUCTION_RELEASE_ISSUE_UNSUPPORTED_EXEC_KIND));
        assert!(labels.contains(PRODUCTION_RELEASE_ISSUE_MISSING_IMAGE_ID));
        assert!(labels.contains(PRODUCTION_RELEASE_ISSUE_ALL_ZERO_IMAGE_ID));
        assert!(labels.contains(PRODUCTION_RELEASE_ISSUE_MISSING_SOURCE_MAPPING));
        assert!(labels.contains("missing_policy_artifact"));
        assert!(labels.contains("invalid_mpb_artifact_bytes"));
        assert!(labels.contains("mpb_artifact_hash_mismatch"));
        assert!(labels.contains(PRODUCTION_RELEASE_ISSUE_PLACEHOLDER_METHODS));
        assert!(labels.contains(PRODUCTION_RELEASE_ISSUE_CONFIG_LOCAL_MODE));
        assert!(labels.contains(PRODUCTION_RELEASE_ISSUE_CONFIG_PLACEHOLDER_IMAGE_ID));
        assert!(labels.contains(PRODUCTION_RELEASE_ISSUE_ONCHAIN_FINALITY_UNSUPPORTED));
        assert!(labels.contains(PRODUCTION_RELEASE_ISSUE_CONFIG_MISSING_NONCE_STORE));
        assert!(labels.contains(PRODUCTION_RELEASE_ISSUE_CONFIG_LOWTRUST_REDIS_REQUIRED));
        assert!(labels.contains("manifest_verification_failed"));
    }

    #[test]
    fn production_release_rejects_host_trusted_v0() {
        let artifacts_dir = tmpdir("mprd-release-host-artifacts");
        let bundle_dir = tmpdir("mprd-release-host-bundle");

        let registry_signer = TokenSigningKey::from_seed(&[233u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[234u8; 32]);
        let registry_vk_hex = hex::encode(registry_signer.verifying_key().to_bytes());
        let manifest_vk_hex = hex::encode(manifest_signer.verifying_key().to_bytes());

        let manifest = GuestImageManifestV1::sign(
            &manifest_signer,
            123,
            vec![GuestImageEntryV1 {
                policy_exec_kind_id: policy_exec_kind_host_trusted_id_v0(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                image_id: [7u8; 32],
            }],
        )
        .unwrap();

        let state = RegistryStateV1 {
            policy_epoch: 22,
            registry_root: Hash32([0x22; 32]),
            authorized_policies: vec![AuthorizedPolicyV1 {
                policy_hash: Hash32([0x44; 32]),
                policy_exec_kind_id: policy_exec_kind_host_trusted_id_v0(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: Some(policy_source_kind_tau_id_v1()),
                policy_source_hash: Some(Hash32([0x45; 32])),
            }],
            guest_image_manifest: manifest,
        };
        let registry_state_path = write_signed_registry_state(&bundle_dir, &registry_signer, state);

        let err = build_production_release_report(
            registry_state_path,
            registry_vk_hex,
            Some(manifest_vk_hex),
            artifacts_dir,
        )
        .unwrap_err();
        assert_eq!(
            err.downcast_ref::<BundleCheckError>(),
            Some(&BundleCheckError::ProductionReleaseViolation {
                issue_kind: PRODUCTION_RELEASE_ISSUE_HOST_TRUSTED.into(),
                first_issue: format!(
                    "policy_hash={} exec_kind=host_trusted_v0 is demo/dev-only and is not a production release route",
                    hex::encode([0x44u8; 32])
                ),
            })
        );
    }

    #[test]
    fn production_release_rejects_missing_image_id() {
        let artifacts_dir = tmpdir("mprd-release-missing-image-artifacts");
        let bundle_dir = tmpdir("mprd-release-missing-image-bundle");

        let registry_signer = TokenSigningKey::from_seed(&[235u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[236u8; 32]);
        let registry_vk_hex = hex::encode(registry_signer.verifying_key().to_bytes());
        let manifest_vk_hex = hex::encode(manifest_signer.verifying_key().to_bytes());
        let mpb_policy_hash = write_release_mpb_artifact(&artifacts_dir);

        let manifest = GuestImageManifestV1::sign(&manifest_signer, 123, vec![]).unwrap();
        let state = RegistryStateV1 {
            policy_epoch: 23,
            registry_root: Hash32([0x23; 32]),
            authorized_policies: vec![AuthorizedPolicyV1 {
                policy_hash: mpb_policy_hash,
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: Some(policy_source_kind_tau_id_v1()),
                policy_source_hash: Some(Hash32([0x46; 32])),
            }],
            guest_image_manifest: manifest,
        };
        let registry_state_path = write_signed_registry_state(&bundle_dir, &registry_signer, state);

        let err = build_production_release_report(
            registry_state_path,
            registry_vk_hex,
            Some(manifest_vk_hex),
            artifacts_dir,
        )
        .unwrap_err();
        assert_eq!(
            err.downcast_ref::<BundleCheckError>(),
            Some(&BundleCheckError::ProductionReleaseViolation {
                issue_kind: PRODUCTION_RELEASE_ISSUE_MISSING_IMAGE_ID.into(),
                first_issue: format!(
                    "policy_hash={} exec_kind=mpb_v1 missing manifest image_id",
                    hex::encode(mpb_policy_hash.0)
                ),
            })
        );
    }

    #[test]
    fn production_release_rejects_all_zero_image_id() {
        let artifacts_dir = tmpdir("mprd-release-zero-image-artifacts");
        let bundle_dir = tmpdir("mprd-release-zero-image-bundle");

        let registry_signer = TokenSigningKey::from_seed(&[237u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[238u8; 32]);
        let registry_vk_hex = hex::encode(registry_signer.verifying_key().to_bytes());
        let manifest_vk_hex = hex::encode(manifest_signer.verifying_key().to_bytes());
        let mpb_policy_hash = write_release_mpb_artifact(&artifacts_dir);

        let manifest = GuestImageManifestV1::sign(
            &manifest_signer,
            123,
            vec![GuestImageEntryV1 {
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                image_id: [0u8; 32],
            }],
        )
        .unwrap();

        let signed = SignedRegistryStateV1::sign(
            &registry_signer,
            456,
            RegistryStateV1 {
                policy_epoch: 24,
                registry_root: Hash32([0x24; 32]),
                authorized_policies: vec![AuthorizedPolicyV1 {
                    policy_hash: mpb_policy_hash,
                    policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    policy_source_kind_id: Some(policy_source_kind_tau_id_v1()),
                    policy_source_hash: Some(Hash32([0x47; 32])),
                }],
                guest_image_manifest: manifest,
            },
        )
        .unwrap();
        let registry_state_path = bundle_dir.join("registry_state.json");
        write_file(
            &registry_state_path,
            serde_json::to_string_pretty(&signed).unwrap().as_bytes(),
        );

        let err = build_production_release_report(
            registry_state_path,
            registry_vk_hex,
            Some(manifest_vk_hex),
            artifacts_dir,
        )
        .unwrap_err();
        let err_chain = format!("{err:#}");
        assert!(
            err_chain.contains(PRODUCTION_RELEASE_ISSUE_ALL_ZERO_IMAGE_ID)
                && err_chain.contains("image_id is all-zero"),
            "unexpected error: {err_chain}"
        );
    }

    #[test]
    fn production_release_rejects_missing_policy_source_mapping() {
        let artifacts_dir = tmpdir("mprd-release-missing-source-artifacts");
        let bundle_dir = tmpdir("mprd-release-missing-source-bundle");

        let registry_signer = TokenSigningKey::from_seed(&[239u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[240u8; 32]);
        let registry_vk_hex = hex::encode(registry_signer.verifying_key().to_bytes());
        let manifest_vk_hex = hex::encode(manifest_signer.verifying_key().to_bytes());
        let mpb_policy_hash = write_release_mpb_artifact(&artifacts_dir);

        let manifest = GuestImageManifestV1::sign(
            &manifest_signer,
            123,
            vec![GuestImageEntryV1 {
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                image_id: [9u8; 32],
            }],
        )
        .unwrap();
        let state = RegistryStateV1 {
            policy_epoch: 25,
            registry_root: Hash32([0x25; 32]),
            authorized_policies: vec![AuthorizedPolicyV1 {
                policy_hash: mpb_policy_hash,
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: None,
                policy_source_hash: None,
            }],
            guest_image_manifest: manifest,
        };
        let registry_state_path = write_signed_registry_state(&bundle_dir, &registry_signer, state);

        let err = build_production_release_report(
            registry_state_path,
            registry_vk_hex,
            Some(manifest_vk_hex),
            artifacts_dir,
        )
        .unwrap_err();
        assert_eq!(
            err.downcast_ref::<BundleCheckError>(),
            Some(&BundleCheckError::ProductionReleaseViolation {
                issue_kind: PRODUCTION_RELEASE_ISSUE_MISSING_SOURCE_MAPPING.into(),
                first_issue: format!(
                    "policy_hash={} exec_kind=mpb_v1 missing policy_source_kind_id/policy_source_hash mapping required for production release",
                    hex::encode(mpb_policy_hash.0)
                ),
            })
        );
    }

    #[test]
    fn check_bundle_fails_closed_on_missing_policy_artifact() {
        let artifacts_dir = tmpdir("mprd-artifacts-missing");
        let bundle_dir = tmpdir("mprd-bundle-missing");

        let registry_signer = TokenSigningKey::from_seed(&[213u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[214u8; 32]);
        let registry_vk_hex = hex::encode(registry_signer.verifying_key().to_bytes());
        let manifest_vk_hex = hex::encode(manifest_signer.verifying_key().to_bytes());

        let tau_bytes = encode_minimal_compiled_tau_policy_bytes();
        let tau_policy_hash = Hash32(tau_compiled_policy_hash_v1(&tau_bytes));
        let tau_policy_hash_hex = hex::encode(tau_policy_hash.0);

        let manifest = GuestImageManifestV1::sign(
            &manifest_signer,
            123,
            vec![GuestImageEntryV1 {
                policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                image_id: [8u8; 32],
            }],
        )
        .unwrap();

        let policies = vec![AuthorizedPolicyV1 {
            policy_hash: tau_policy_hash,
            policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            policy_source_kind_id: None,
            policy_source_hash: None,
        }];

        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: Hash32([7u8; 32]),
            authorized_policies: policies,
            guest_image_manifest: manifest,
        };
        let signed = SignedRegistryStateV1::sign(&registry_signer, 456, state).unwrap();
        let registry_state_path = bundle_dir.join("registry_state.json");
        write_file(
            &registry_state_path,
            serde_json::to_string_pretty(&signed).unwrap().as_bytes(),
        );

        let err = check_bundle(
            registry_state_path,
            registry_vk_hex,
            Some(manifest_vk_hex),
            artifacts_dir,
            "human",
            &[],
            "human",
            &[],
            "human",
        )
        .unwrap_err();
        assert_eq!(
            err.downcast_ref::<BundleCheckError>(),
            Some(&BundleCheckError::MissingPolicyArtifact {
                policy_hash_hex: tau_policy_hash_hex,
            })
        );
    }
}
