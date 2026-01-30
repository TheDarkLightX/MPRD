use crate::{MprdError, Result};

use super::{CanonicalPolicy, PolicyExpr, PolicyLimits};

/// A curated policy template (“menu item”) expressed in Policy Algebra.
///
/// These entries are **suggestions**: they are intended to be emitted to Tau (or embedded as
/// Policy Algebra bytes) and then audited/certified like any other gate.
#[derive(Clone, Copy)]
pub struct PolicyMenuEntry {
    pub id: &'static str,
    pub category: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub suggested_output_name: &'static str,
    build_fn: fn(PolicyLimits) -> Result<PolicyExpr>,
}

impl PolicyMenuEntry {
    pub fn build(&self, limits: PolicyLimits) -> Result<PolicyExpr> {
        (self.build_fn)(limits)
    }

    pub fn canonical(&self, limits: PolicyLimits) -> Result<CanonicalPolicy> {
        CanonicalPolicy::new(self.build(limits)?, limits)
    }
}

fn build_governance_gate_onehot_suggested(limits: PolicyLimits) -> Result<PolicyExpr> {
    // Mirrors `policies/governance/canonical/mprd_governance_gate.tau` structure, but remains
    // fail-closed in Policy Algebra by requiring an explicit host-checked rail:
    // `governance_update_kind_invalid` must be present and false.
    //
    // Why: expressing “exactly one of (a,b,c)” in the current algebra requires `Not(Atom)` which
    // is not fail-closed under missing signals. We therefore keep the gate positive and enforce
    // one-hot at the boundary (host), under a veto signal.
    let is_policy_tweak = PolicyExpr::atom("is_policy_tweak", limits)?;
    let is_safety_change = PolicyExpr::atom("is_safety_change", limits)?;
    let is_cap_expand = PolicyExpr::atom("is_cap_expand", limits)?;
    let profile_app_ok = PolicyExpr::atom("profile_app_ok", limits)?;
    let profile_safety_ok = PolicyExpr::atom("profile_safety_ok", limits)?;
    let link_ok = PolicyExpr::atom("link_ok", limits)?;

    // Host must compute one-hot validity (or any equivalent invariant) and provide it.
    // DenyIf semantics: missing/true => veto.
    let onehot_invalid = PolicyExpr::deny_if("governance_update_kind_invalid", limits)?;

    let tweak = PolicyExpr::all(vec![is_policy_tweak, profile_app_ok.clone()], limits)?;
    let safety = PolicyExpr::all(vec![is_safety_change, profile_safety_ok.clone()], limits)?;
    let cap = PolicyExpr::all(
        vec![is_cap_expand, profile_app_ok, profile_safety_ok],
        limits,
    )?;

    let kind_gate = PolicyExpr::any(vec![tweak, safety, cap], limits)?;

    PolicyExpr::all(vec![link_ok, kind_gate, onehot_invalid], limits)
}

fn build_tokenomics_v6_action_gate_fast(limits: PolicyLimits) -> Result<PolicyExpr> {
    // Mirrors the structure of `policies/tokenomics/canonical/mprd_tokenomics_v6_action_gate.tau`.
    // All atoms are positive rails; missing signals deny (fail-closed).
    let link_ok = PolicyExpr::atom("link_ok", limits)?;
    let actor_is_target_ok = PolicyExpr::atom("actor_is_target_ok", limits)?;
    let control_auth_ok = PolicyExpr::atom("control_auth_ok", limits)?;
    let epoch_phase_ok = PolicyExpr::atom("epoch_phase_ok", limits)?;
    let action_preconds_ok = PolicyExpr::atom("action_preconds_ok", limits)?;
    let action_one_hot_ok = PolicyExpr::atom("action_one_hot_ok", limits)?;
    let service_tx_auth_ok = PolicyExpr::atom("service_tx_auth_ok", limits)?;
    let credit_agrs_replay_ok = PolicyExpr::atom("credit_agrs_replay_ok", limits)?;

    // One-hot action flags (decoded by host from ActionV6).
    let is_admit_operator = PolicyExpr::atom("is_admit_operator", limits)?;
    let is_credit_agrs = PolicyExpr::atom("is_credit_agrs", limits)?;
    let is_set_opi = PolicyExpr::atom("is_set_opi", limits)?;
    let is_set_bounds = PolicyExpr::atom("is_set_bounds", limits)?;
    let is_stake_start = PolicyExpr::atom("is_stake_start", limits)?;
    let is_stake_end = PolicyExpr::atom("is_stake_end", limits)?;
    let is_accrue_bcr_drip = PolicyExpr::atom("is_accrue_bcr_drip", limits)?;
    let is_apply_service_tx = PolicyExpr::atom("is_apply_service_tx", limits)?;
    let is_auction_reveal = PolicyExpr::atom("is_auction_reveal", limits)?;
    let is_finalize_epoch = PolicyExpr::atom("is_finalize_epoch", limits)?;
    let is_settle_ops_payroll = PolicyExpr::atom("is_settle_ops_payroll", limits)?;
    let is_settle_auction = PolicyExpr::atom("is_settle_auction", limits)?;
    let is_advance_epoch = PolicyExpr::atom("is_advance_epoch", limits)?;

    // Sanity rail: at least one action flag must be true.
    let any_action = PolicyExpr::any(
        vec![
            is_admit_operator.clone(),
            is_credit_agrs.clone(),
            is_set_opi.clone(),
            is_set_bounds.clone(),
            is_stake_start.clone(),
            is_stake_end.clone(),
            is_accrue_bcr_drip.clone(),
            is_apply_service_tx.clone(),
            is_auction_reveal.clone(),
            is_finalize_epoch.clone(),
            is_settle_ops_payroll.clone(),
            is_settle_auction.clone(),
            is_advance_epoch.clone(),
        ],
        limits,
    )?;

    // LOW-IMPACT / SELF-AUTH actions (operator-scoped)
    let self_auth = PolicyExpr::all(
        vec![
            PolicyExpr::any(
                vec![is_stake_start, is_stake_end, is_auction_reveal],
                limits,
            )?,
            actor_is_target_ok,
        ],
        limits,
    )?;

    // SERVICE TX application
    let service_tx = PolicyExpr::all(vec![is_apply_service_tx, service_tx_auth_ok], limits)?;

    // EPOCH TRANSITION actions (controller-only)
    let epoch_transition = PolicyExpr::all(
        vec![
            PolicyExpr::any(
                vec![
                    is_accrue_bcr_drip,
                    is_finalize_epoch,
                    is_settle_ops_payroll,
                    is_settle_auction,
                    is_advance_epoch,
                ],
                limits,
            )?,
            control_auth_ok.clone(),
        ],
        limits,
    )?;

    // ADMIN actions (controller-only). CreditAgrs also requires replay protection.
    let admin_basic = PolicyExpr::all(
        vec![
            PolicyExpr::any(vec![is_admit_operator, is_set_opi, is_set_bounds], limits)?,
            control_auth_ok.clone(),
        ],
        limits,
    )?;
    let admin_credit_agrs = PolicyExpr::all(
        vec![is_credit_agrs, control_auth_ok, credit_agrs_replay_ok],
        limits,
    )?;
    let admin = PolicyExpr::any(vec![admin_basic, admin_credit_agrs], limits)?;

    let category_gate =
        PolicyExpr::any(vec![self_auth, service_tx, epoch_transition, admin], limits)?;

    PolicyExpr::all(
        vec![
            link_ok,
            action_preconds_ok,
            epoch_phase_ok,
            action_one_hot_ok,
            any_action,
            category_gate,
        ],
        limits,
    )
}

fn build_tokenomics_v6_pid_update_gate(limits: PolicyLimits) -> Result<PolicyExpr> {
    // Mirrors `policies/tokenomics/canonical/mprd_tokenomics_v6_pid_update_gate.tau` structure:
    // all checks are host-computed sbf rails; Tau/PolicyAlgebra combines them.
    let link_ok = PolicyExpr::atom("link_ok", limits)?;
    let control_auth_ok = PolicyExpr::atom("control_auth_ok", limits)?;
    let params_version_ok = PolicyExpr::atom("params_version_ok", limits)?;
    let update_window_ok = PolicyExpr::atom("update_window_ok", limits)?;

    let burn_in_range_ok = PolicyExpr::atom("burn_in_range_ok", limits)?;
    let auction_in_range_ok = PolicyExpr::atom("auction_in_range_ok", limits)?;
    let drip_in_range_ok = PolicyExpr::atom("drip_in_range_ok", limits)?;
    let burn_step_ok = PolicyExpr::atom("burn_step_ok", limits)?;
    let auction_step_ok = PolicyExpr::atom("auction_step_ok", limits)?;
    let drip_step_ok = PolicyExpr::atom("drip_step_ok", limits)?;
    let split_ok = PolicyExpr::atom("split_ok", limits)?;

    PolicyExpr::all(
        vec![
            link_ok,
            control_auth_ok,
            params_version_ok,
            update_window_ok,
            burn_in_range_ok,
            auction_in_range_ok,
            drip_in_range_ok,
            burn_step_ok,
            auction_step_ok,
            drip_step_ok,
            split_ok,
        ],
        limits,
    )
}

fn build_governance_committee_quorum_1of3(limits: PolicyLimits) -> Result<PolicyExpr> {
    let v0 = PolicyExpr::atom("vote_0", limits)?;
    let v1 = PolicyExpr::atom("vote_1", limits)?;
    let v2 = PolicyExpr::atom("vote_2", limits)?;
    PolicyExpr::any(vec![v0, v1, v2], limits)
}

fn build_governance_committee_quorum_2of3(limits: PolicyLimits) -> Result<PolicyExpr> {
    let v0 = PolicyExpr::atom("vote_0", limits)?;
    let v1 = PolicyExpr::atom("vote_1", limits)?;
    let v2 = PolicyExpr::atom("vote_2", limits)?;
    // NOTE: We intentionally avoid `Threshold(2, [...])` here because `emit_tau_gate_v2` currently only supports
    // `k==0` or `k==n`.
    at_least_k(vec![v0, v1, v2], 2, limits)
}

fn build_governance_committee_quorum_3of3(limits: PolicyLimits) -> Result<PolicyExpr> {
    let v0 = PolicyExpr::atom("vote_0", limits)?;
    let v1 = PolicyExpr::atom("vote_1", limits)?;
    let v2 = PolicyExpr::atom("vote_2", limits)?;
    PolicyExpr::all(vec![v0, v1, v2], limits)
}

fn build_governance_committee_quorum_2of5(limits: PolicyLimits) -> Result<PolicyExpr> {
    let votes = vec![
        PolicyExpr::atom("vote_0", limits)?,
        PolicyExpr::atom("vote_1", limits)?,
        PolicyExpr::atom("vote_2", limits)?,
        PolicyExpr::atom("vote_3", limits)?,
        PolicyExpr::atom("vote_4", limits)?,
    ];
    at_least_k(votes, 2, limits)
}

fn build_governance_committee_quorum_3of5(limits: PolicyLimits) -> Result<PolicyExpr> {
    let votes = vec![
        PolicyExpr::atom("vote_0", limits)?,
        PolicyExpr::atom("vote_1", limits)?,
        PolicyExpr::atom("vote_2", limits)?,
        PolicyExpr::atom("vote_3", limits)?,
        PolicyExpr::atom("vote_4", limits)?,
    ];
    at_least_k(votes, 3, limits)
}

fn build_governance_escalation_ladder_suggested(limits: PolicyLimits) -> Result<PolicyExpr> {
    // Mirrors `policies/governance/canonical/mprd_escalation.tau` but uses only sbf rails:
    // host decodes tier to one-hot flags and supplies a veto rail if invalid.
    let link_ok = PolicyExpr::atom("link_ok", limits)?;
    let is_tier_1 = PolicyExpr::atom("is_tier_1", limits)?;
    let is_tier_2 = PolicyExpr::atom("is_tier_2", limits)?;
    let is_tier_3 = PolicyExpr::atom("is_tier_3", limits)?;
    let timelock_ok = PolicyExpr::atom("timelock_ok", limits)?;

    let v0 = PolicyExpr::atom("vote_0", limits)?;
    let v1 = PolicyExpr::atom("vote_1", limits)?;
    let v2 = PolicyExpr::atom("vote_2", limits)?;
    let at_least_1 = PolicyExpr::any(vec![v0.clone(), v1.clone(), v2.clone()], limits)?;
    let at_least_2 = at_least_k(vec![v0.clone(), v1.clone(), v2.clone()], 2, limits)?;
    let all_3 = PolicyExpr::all(vec![v0, v1, v2], limits)?;

    // Host rail: tier must be valid and one-hot.
    let tier_invalid = PolicyExpr::deny_if("tier_invalid", limits)?;

    let accepted = PolicyExpr::any(
        vec![
            PolicyExpr::all(vec![is_tier_1, at_least_1], limits)?,
            PolicyExpr::all(vec![is_tier_2, at_least_2], limits)?,
            PolicyExpr::all(vec![is_tier_3, all_3, timelock_ok], limits)?,
        ],
        limits,
    )?;

    PolicyExpr::all(vec![link_ok, accepted, tier_invalid], limits)
}

fn build_ceo_setpoint_change_gate_suggested(limits: PolicyLimits) -> Result<PolicyExpr> {
    // Suggested high-level gate for setpoint/policy parameter changes (generic).
    // Intended usage: host computes each boolean rail and feeds Policy Algebra/Tau.
    let link_ok = PolicyExpr::atom("link_ok", limits)?;
    let opi_healthy_ok = PolicyExpr::atom("opi_healthy_ok", limits)?;
    let reserve_runway_ok = PolicyExpr::atom("reserve_runway_ok", limits)?;
    let cooldown_elapsed_ok = PolicyExpr::atom("cooldown_elapsed_ok", limits)?;
    let emergency_freeze = PolicyExpr::deny_if("emergency_freeze", limits)?;

    PolicyExpr::all(
        vec![
            link_ok,
            opi_healthy_ok,
            reserve_runway_ok,
            cooldown_elapsed_ok,
            emergency_freeze,
        ],
        limits,
    )
}

fn build_deploy_registry_receipt_gate_suggested(limits: PolicyLimits) -> Result<PolicyExpr> {
    // Suggested deployment/verification gate for proof-carrying artifacts.
    // Intended usage: host computes each boolean rail and feeds Policy Algebra/Tau.
    let registry_checkpoint_ok = PolicyExpr::atom("registry_checkpoint_ok", limits)?;
    let policy_hash_authorized_ok = PolicyExpr::atom("policy_hash_authorized_ok", limits)?;
    let artifact_bundle_ok = PolicyExpr::atom("artifact_bundle_ok", limits)?;
    let receipt_verified_ok = PolicyExpr::atom("receipt_verified_ok", limits)?;
    let emergency_freeze = PolicyExpr::deny_if("emergency_freeze", limits)?;

    PolicyExpr::all(
        vec![
            registry_checkpoint_ok,
            policy_hash_authorized_ok,
            artifact_bundle_ok,
            receipt_verified_ok,
            emergency_freeze,
        ],
        limits,
    )
}

fn at_least_k(children: Vec<PolicyExpr>, k: usize, limits: PolicyLimits) -> Result<PolicyExpr> {
    if k == 0 {
        return Ok(PolicyExpr::True);
    }
    if children.is_empty() {
        return Err(MprdError::InvalidInput("at_least_k: empty children".into()));
    }
    if k > children.len() {
        return Err(MprdError::InvalidInput(format!(
            "at_least_k: k too large ({k} > n={})",
            children.len()
        )));
    }
    if k == 1 {
        return PolicyExpr::any(children, limits);
    }
    if k == children.len() {
        return PolicyExpr::all(children, limits);
    }

    // Tau emission does not currently support `Threshold(k,n)` except trivial cases. Expand into
    // DNF using only `All`/`Any`: OR over all k-sized conjunctions (deterministic lexicographic
    // combination order). Fail closed if it would exceed the configured child limit.
    let n = children.len();
    let term_count = n_choose_k(n, k).ok_or_else(|| {
        MprdError::InvalidInput(format!("at_least_k: nCk overflow (n={n}, k={k})"))
    })?;
    if term_count > limits.max_children {
        return Err(MprdError::InvalidInput(format!(
            "at_least_k: would require {term_count} terms (n={n},k={k}) > max_children={}",
            limits.max_children
        )));
    }

    fn rec(
        children: &[PolicyExpr],
        k: usize,
        start: usize,
        idxs: &mut Vec<usize>,
        limits: PolicyLimits,
        out_terms: &mut Vec<PolicyExpr>,
    ) -> Result<()> {
        if idxs.len() == k {
            let mut term = Vec::with_capacity(k);
            for &i in idxs.iter() {
                term.push(children[i].clone());
            }
            out_terms.push(PolicyExpr::all(term, limits)?);
            return Ok(());
        }

        // Remaining picks: k - idxs.len(). We can stop earlier to preserve lexicographic order.
        let remaining = k - idxs.len();
        for i in start..=(children.len() - remaining) {
            idxs.push(i);
            rec(children, k, i + 1, idxs, limits, out_terms)?;
            idxs.pop();
        }
        Ok(())
    }

    let mut idxs = Vec::with_capacity(k);
    let mut terms = Vec::with_capacity(term_count);
    rec(&children, k, 0, &mut idxs, limits, &mut terms)?;
    PolicyExpr::any(terms, limits)
}

fn n_choose_k(n: usize, k: usize) -> Option<usize> {
    // Simple exact binomial coefficient with overflow detection.
    let k = k.min(n - k);
    let mut num: u128 = 1;
    let mut den: u128 = 1;
    for i in 0..k {
        num = num.checked_mul((n - i) as u128)?;
        den = den.checked_mul((i + 1) as u128)?;
    }
    let v = num.checked_div(den)?;
    usize::try_from(v).ok()
}

static ENTRIES_V1: [PolicyMenuEntry; 11] = [
    PolicyMenuEntry {
        id: "governance_gate_onehot_suggested",
        category: "governance",
        title: "Governance Gate (one-hot, host rail)",
        description: "Suggested governance gate that mirrors the canonical one-hot structure, with a fail-closed host-provided veto rail for one-hot validity.",
        suggested_output_name: "accept",
        build_fn: build_governance_gate_onehot_suggested,
    },
    PolicyMenuEntry {
        id: "tokenomics_v6_action_gate_fast",
        category: "tokenomics",
        title: "Tokenomics v6 Action Gate (fast)",
        description: "Fail-closed authorization gate for Tokenomics v6 actions (mirrors canonical fast Tau gate).",
        suggested_output_name: "allow",
        build_fn: build_tokenomics_v6_action_gate_fast,
    },
    PolicyMenuEntry {
        id: "tokenomics_v6_pid_update_gate",
        category: "tokenomics",
        title: "Tokenomics v6 PID Update Gate",
        description: "Fail-closed gate for PID/controller parameter updates (mirrors canonical Tau gate; host computes bounds/step/split rails).",
        suggested_output_name: "accept",
        build_fn: build_tokenomics_v6_pid_update_gate,
    },
    PolicyMenuEntry {
        id: "governance_committee_quorum_1of3",
        category: "governance",
        title: "Governance Committee Quorum (1-of-3)",
        description: "At least 1 of 3 votes is required (vote_0|vote_1|vote_2).",
        suggested_output_name: "passed",
        build_fn: build_governance_committee_quorum_1of3,
    },
    PolicyMenuEntry {
        id: "governance_committee_quorum_2of3",
        category: "governance",
        title: "Governance Committee Quorum (2-of-3)",
        description:
            "At least 2 of 3 votes is required ((vote_0&vote_1)|(vote_0&vote_2)|(vote_1&vote_2)).",
        suggested_output_name: "passed",
        build_fn: build_governance_committee_quorum_2of3,
    },
    PolicyMenuEntry {
        id: "governance_committee_quorum_3of3",
        category: "governance",
        title: "Governance Committee Quorum (3-of-3)",
        description: "Unanimous 3-of-3 quorum is required (vote_0 & vote_1 & vote_2).",
        suggested_output_name: "passed",
        build_fn: build_governance_committee_quorum_3of3,
    },
    PolicyMenuEntry {
        id: "governance_committee_quorum_2of5",
        category: "governance",
        title: "Governance Committee Quorum (2-of-5)",
        description: "At least 2 of 5 votes is required (2-of-5, Tau-emittable DNF expansion).",
        suggested_output_name: "passed",
        build_fn: build_governance_committee_quorum_2of5,
    },
    PolicyMenuEntry {
        id: "governance_committee_quorum_3of5",
        category: "governance",
        title: "Governance Committee Quorum (3-of-5)",
        description: "At least 3 of 5 votes is required (3-of-5, Tau-emittable DNF expansion).",
        suggested_output_name: "passed",
        build_fn: build_governance_committee_quorum_3of5,
    },
    PolicyMenuEntry {
        id: "governance_escalation_ladder_suggested",
        category: "governance",
        title: "Governance Escalation Ladder (tiered quorum + timelock)",
        description: "Tiered approval: tier1=1-of-3, tier2=2-of-3, tier3=3-of-3+timelock_ok. Host supplies tier one-hot and vetoes via tier_invalid.",
        suggested_output_name: "accepted",
        build_fn: build_governance_escalation_ladder_suggested,
    },
    PolicyMenuEntry {
        id: "ceo_setpoint_change_gate_suggested",
        category: "ceo",
        title: "CEO Setpoint Change Gate (suggested)",
        description: "Suggested high-level gate for parameter/setpoint changes: link_ok & opi_healthy_ok & reserve_runway_ok & cooldown_elapsed_ok, vetoed by emergency_freeze.",
        suggested_output_name: "allow",
        build_fn: build_ceo_setpoint_change_gate_suggested,
    },
    PolicyMenuEntry {
        id: "deploy_registry_receipt_gate_suggested",
        category: "infra",
        title: "Deploy/Verify Gate (registry + receipt)",
        description: "Suggested gate for proof-carrying artifact execution: registry_checkpoint_ok & policy_hash_authorized_ok & artifact_bundle_ok & receipt_verified_ok, vetoed by emergency_freeze.",
        suggested_output_name: "allow",
        build_fn: build_deploy_registry_receipt_gate_suggested,
    },
];

pub fn policy_menu_entries_v1() -> &'static [PolicyMenuEntry] {
    &ENTRIES_V1
}

pub fn policy_menu_entry_v1(id: &str) -> Option<&'static PolicyMenuEntry> {
    ENTRIES_V1.iter().find(|e| e.id == id)
}

pub fn policy_menu_canonical_v1(id: &str, limits: PolicyLimits) -> Result<CanonicalPolicy> {
    let Some(e) = policy_menu_entry_v1(id) else {
        return Err(MprdError::InvalidInput(format!(
            "unknown policy menu id: {id}"
        )));
    };
    e.canonical(limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_algebra::{
        emit_tau_gate_v2, parse_emitted_tau_gate_allow_expr_v1,
        policy_equiv_robdd_policy_vs_tau_bits,
    };

    #[test]
    fn menu_entries_emit_tau_and_roundtrip_equiv_via_robdd() {
        let limits = PolicyLimits::DEFAULT;
        for e in policy_menu_entries_v1() {
            let expr = e.build(limits).expect("menu build");
            let tau = emit_tau_gate_v2(&expr, e.suggested_output_name, limits).expect("emit tau");
            let tau_bits =
                parse_emitted_tau_gate_allow_expr_v1(&tau, e.suggested_output_name, limits)
                    .expect("parse emitted tau");
            let r = policy_equiv_robdd_policy_vs_tau_bits(&expr, &tau_bits, limits)
                .expect("robdd equiv");
            assert!(
                r.equivalent,
                "menu entry {} did not roundtrip; counterexample: {:?}",
                e.id, r.counterexample
            );
        }
    }
}
