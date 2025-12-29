//! CEGIS loop hardening for MPRD.
//!
//! Context: Model Proposes, Rules Decide. A proposer emits candidate actions; a verifier
//! deterministically evaluates `Allowed(policy, state, action)` and returns a trace suitable
//! for regression and operator UX.

use crate::hash;
use crate::policy_algebra::{self, PolicyExpr, PolicyLimits, PolicyOutcomeKind, PolicyTrace};
use crate::tokenomics_v6::types::{ActionId, EpochId, Step};
use crate::{Hash32, MprdError, Result};
use std::collections::BTreeMap;
use std::time::Instant;
use thiserror::Error;

/// Replayable input state for CEGIS verification.
///
/// This type is intentionally small and IO-free. Higher layers should validate/normalize
/// untrusted inputs before constructing a `State`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    state_hash: Hash32,
    timestamp_epoch: EpochId,
    signals: BTreeMap<String, bool>,
}

impl State {
    /// Construct a deterministic CEGIS state.
    ///
    /// `state_hash` is derived from `signals` using a canonical encoding.
    pub fn new(timestamp_epoch: EpochId, signals: BTreeMap<String, bool>) -> Self {
        let state_hash = hash_cegis_state_v1(&signals);
        Self {
            state_hash,
            timestamp_epoch,
            signals,
        }
    }

    pub fn state_hash(&self) -> Hash32 {
        self.state_hash
    }

    pub fn timestamp_epoch(&self) -> EpochId {
        self.timestamp_epoch
    }

    pub fn signals(&self) -> &BTreeMap<String, bool> {
        &self.signals
    }
}

/// Canonical hashing for `State` signals.
fn hash_cegis_state_v1(signals: &BTreeMap<String, bool>) -> Hash32 {
    const DOMAIN: &[u8] = b"MPRD_CEGIS_STATE_V1";
    let mut buf = Vec::new();
    buf.extend_from_slice(&(signals.len() as u32).to_le_bytes());
    for (k, v) in signals {
        buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
        buf.extend_from_slice(k.as_bytes());
        buf.push(if *v { 1 } else { 0 });
    }
    hash::sha256_domain(DOMAIN, &buf)
}

/// CEGIS action type.
pub type Action = ActionId;

/// Counterexample returned by the verifier when a proposal is denied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counterexample {
    pub policy_hash: Hash32,
    pub state_hash: Hash32,
    pub action: ActionId,
    pub trace: PolicyTrace,
    pub failed_atom: Option<String>,
    pub timestamp_epoch: EpochId,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProposerMetrics {
    pub proposals_total: u64,
    pub proposals_valid: u64,
    pub proposals_invalid: u64,
    pub counterexamples_captured: u64,
    pub time_to_first_valid_ms: Option<u64>,
}

/// An IO-free proposer that can incorporate prior counterexamples.
pub trait Proposer {
    fn propose(&mut self, state: &State, counterexamples: &[Counterexample]) -> Result<Action>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyResult {
    pub outcome: PolicyOutcomeKind,
    pub trace: PolicyTrace,
    pub failed_atom: Option<String>,
}

impl VerifyResult {
    pub fn allowed(&self) -> bool {
        matches!(self.outcome, PolicyOutcomeKind::Allow)
    }
}

/// Deterministic local verifier for `Allowed(policy, state, action)`.
pub trait Verifier {
    fn policy_hash(&self) -> Hash32;

    fn verify(&self, state: &State, action: Action) -> Result<VerifyResult>;

    fn replay_trace(&self, state: &State, action: Action) -> Result<PolicyTrace> {
        Ok(self.verify(state, action)?.trace)
    }
}

#[derive(Debug, Error)]
pub enum CegisDenied {
    #[error("CEGIS exhausted after {attempts} invalid proposals (max_counterexamples={max_counterexamples})")]
    Exhausted {
        attempts: u64,
        max_counterexamples: usize,
        policy_hash: Hash32,
        state_hash: Hash32,
    },

    #[error("CEGIS proposer failed: {0}")]
    ProposerFailed(MprdError),

    #[error("CEGIS verifier failed: {0}")]
    VerifierFailed(MprdError),
}

pub struct CegisLoop<P: Proposer, V: Verifier> {
    proposer: P,
    verifier: V,
    metrics: ProposerMetrics,
    counterexamples: Vec<Counterexample>,
    max_counterexamples: usize,
}

impl<P: Proposer, V: Verifier> CegisLoop<P, V> {
    pub fn new(proposer: P, verifier: V, max_counterexamples: usize) -> Result<Self> {
        if max_counterexamples == 0 {
            return Err(MprdError::InvalidInput(
                "max_counterexamples must be > 0".into(),
            ));
        }
        Ok(Self {
            proposer,
            verifier,
            metrics: ProposerMetrics::default(),
            counterexamples: Vec::new(),
            max_counterexamples,
        })
    }

    pub fn metrics(&self) -> &ProposerMetrics {
        &self.metrics
    }

    pub fn counterexamples(&self) -> &[Counterexample] {
        &self.counterexamples
    }

    pub fn run(&mut self, state: &State) -> std::result::Result<Action, CegisDenied> {
        let start = Instant::now();
        loop {
            let action = self
                .proposer
                .propose(state, &self.counterexamples)
                .map_err(CegisDenied::ProposerFailed)?;
            self.metrics.proposals_total = self.metrics.proposals_total.saturating_add(1);

            let vr = self
                .verifier
                .verify(state, action)
                .map_err(CegisDenied::VerifierFailed)?;

            if vr.allowed() {
                self.metrics.proposals_valid = self.metrics.proposals_valid.saturating_add(1);
                if self.metrics.time_to_first_valid_ms.is_none() {
                    self.metrics.time_to_first_valid_ms =
                        Some(start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
                }
                return Ok(action);
            }

            self.metrics.proposals_invalid = self.metrics.proposals_invalid.saturating_add(1);

            let policy_hash = self.verifier.policy_hash();
            let cx = Counterexample {
                policy_hash,
                state_hash: state.state_hash(),
                action,
                trace: vr.trace,
                failed_atom: vr.failed_atom,
                timestamp_epoch: state.timestamp_epoch(),
            };

            let cx = self.minimize_counterexample(state, cx)?;
            self.capture_counterexample(cx);

            if (self.metrics.counterexamples_captured as usize) >= self.max_counterexamples {
                return Err(CegisDenied::Exhausted {
                    attempts: self.metrics.proposals_total,
                    max_counterexamples: self.max_counterexamples,
                    policy_hash,
                    state_hash: state.state_hash(),
                });
            }
        }
    }

    fn capture_counterexample(&mut self, cx: Counterexample) {
        self.metrics.counterexamples_captured =
            self.metrics.counterexamples_captured.saturating_add(1);
        self.counterexamples.push(cx);
        if self.counterexamples.len() > self.max_counterexamples {
            self.counterexamples.truncate(self.max_counterexamples);
        }
    }

    fn minimize_counterexample(
        &self,
        state: &State,
        original: Counterexample,
    ) -> std::result::Result<Counterexample, CegisDenied> {
        // Search the finite action space for a "smaller" action that triggers the same failure
        // fingerprint (failed atom + first failing reason code).
        let want_fp = failure_fingerprint(&original.trace, original.failed_atom.as_deref());

        let mut best: Option<(u8, u8, Counterexample)> = None; // (effort, idx, cx)
        for action in ActionId::iter() {
            let vr = self
                .verifier
                .verify(state, action)
                .map_err(CegisDenied::VerifierFailed)?;
            if vr.allowed() {
                continue;
            }

            let fp = failure_fingerprint(&vr.trace, vr.failed_atom.as_deref());
            if fp != want_fp {
                continue;
            }

            let effort = control_effort(action);
            let idx = action.index();
            let cx = Counterexample {
                policy_hash: original.policy_hash,
                state_hash: original.state_hash,
                action,
                trace: vr.trace,
                failed_atom: vr.failed_atom,
                timestamp_epoch: original.timestamp_epoch,
            };
            match best {
                None => best = Some((effort, idx, cx)),
                Some((b_eff, b_idx, _)) if (effort, idx) < (b_eff, b_idx) => {
                    best = Some((effort, idx, cx))
                }
                Some(_) => {}
            }
        }

        Ok(best.map(|(_, _, cx)| cx).unwrap_or(original))
    }
}

fn control_effort(action: ActionId) -> u8 {
    let d = action.to_delta();
    let mut effort = 0u8;
    if d.db != Step::Zero {
        effort = effort.saturating_add(1);
    }
    if d.da != Step::Zero {
        effort = effort.saturating_add(1);
    }
    if d.dd != Step::Zero {
        effort = effort.saturating_add(1);
    }
    effort
}

fn failure_fingerprint<'a>(
    trace: &PolicyTrace,
    failed_atom: Option<&'a str>,
) -> (Option<&'a str>, Option<policy_algebra::TraceReasonCode>) {
    let mut reason: Option<policy_algebra::TraceReasonCode> = None;
    for e in trace.entries() {
        use policy_algebra::TraceReasonCode::*;
        match e.reason {
            DenySignalFalse | DenyMissingSignal | DenyVetoSignalTrue | DenyVetoMissingSignal => {
                reason = Some(e.reason);
                break;
            }
            _ => {}
        }
    }
    (failed_atom, reason)
}

/// Policy-algebra-backed verifier over `State` signals and `ActionId` features.
///
/// Action-derived atoms (if used by the policy) are provided under the following names
/// (matching `PolicyAtom`'s `[a-z0-9_]+` charset):
/// - `action_noop`
/// - `action_db_neg|zero|pos`
/// - `action_da_neg|zero|pos`
/// - `action_dd_neg|zero|pos`
pub struct PolicyAlgebraVerifier {
    policy: policy_algebra::CanonicalPolicy,
    limits: PolicyLimits,
    node_hash_to_atom: BTreeMap<Hash32, String>,
}

impl PolicyAlgebraVerifier {
    pub fn new(policy: policy_algebra::CanonicalPolicy, limits: PolicyLimits) -> Result<Self> {
        limits.validate()?;
        let node_hash_to_atom = build_node_hash_to_atom_map(policy.expr(), limits)?;
        Ok(Self {
            policy,
            limits,
            node_hash_to_atom,
        })
    }

    fn signal_for(
        &self,
        state: &State,
        action: ActionId,
        atom: &policy_algebra::PolicyAtom,
    ) -> Option<bool> {
        // State-provided signals.
        if let Some(v) = state.signals.get(atom.as_str()).copied() {
            return Some(v);
        }

        // Action-derived signals (deterministic).
        match atom.as_str() {
            "action_noop" => Some(action == ActionId::NOOP),
            "action_db_neg" => Some(action.to_delta().db == Step::Neg),
            "action_db_zero" => Some(action.to_delta().db == Step::Zero),
            "action_db_pos" => Some(action.to_delta().db == Step::Pos),
            "action_da_neg" => Some(action.to_delta().da == Step::Neg),
            "action_da_zero" => Some(action.to_delta().da == Step::Zero),
            "action_da_pos" => Some(action.to_delta().da == Step::Pos),
            "action_dd_neg" => Some(action.to_delta().dd == Step::Neg),
            "action_dd_zero" => Some(action.to_delta().dd == Step::Zero),
            "action_dd_pos" => Some(action.to_delta().dd == Step::Pos),
            _ => None,
        }
    }

    fn derive_failed_atom(&self, trace: &PolicyTrace) -> Option<String> {
        for e in trace.entries() {
            use policy_algebra::TraceReasonCode::*;
            match e.reason {
                DenySignalFalse
                | DenyMissingSignal
                | DenyVetoSignalTrue
                | DenyVetoMissingSignal => {
                    if let Some(atom) = self.node_hash_to_atom.get(&e.node_hash) {
                        return Some(atom.clone());
                    }
                }
                _ => {}
            }
        }
        None
    }
}

impl Verifier for PolicyAlgebraVerifier {
    fn policy_hash(&self) -> Hash32 {
        self.policy.hash_v1()
    }

    fn verify(&self, state: &State, action: Action) -> Result<VerifyResult> {
        struct Ctx<'a> {
            v: &'a PolicyAlgebraVerifier,
            s: &'a State,
            a: ActionId,
        }

        impl policy_algebra::EvalContext for Ctx<'_> {
            fn signal(&self, atom: &policy_algebra::PolicyAtom) -> Option<bool> {
                self.v.signal_for(self.s, self.a, atom)
            }
        }

        let ctx = Ctx {
            v: self,
            s: state,
            a: action,
        };
        let r = policy_algebra::evaluate(self.policy.expr(), &ctx, self.limits)?;
        let failed_atom = if r.allowed() {
            None
        } else {
            self.derive_failed_atom(&r.trace)
        };

        Ok(VerifyResult {
            outcome: r.outcome,
            trace: r.trace,
            failed_atom,
        })
    }
}

fn build_node_hash_to_atom_map(
    expr: &PolicyExpr,
    limits: PolicyLimits,
) -> Result<BTreeMap<Hash32, String>> {
    use policy_algebra::PolicyExpr::*;

    fn walk(
        expr: &PolicyExpr,
        limits: PolicyLimits,
        out: &mut BTreeMap<Hash32, String>,
    ) -> Result<()> {
        match expr {
            Atom(a) => {
                out.insert(policy_algebra::policy_hash_v1(expr), a.as_str().to_string());
                Ok(())
            }
            DenyIf(a) => {
                out.insert(policy_algebra::policy_hash_v1(expr), a.as_str().to_string());
                Ok(())
            }
            Not(p) => walk(p, limits, out),
            All(children) | Any(children) => {
                for ch in children {
                    walk(ch, limits, out)?;
                }
                Ok(())
            }
            Threshold { children, .. } => {
                for ch in children {
                    walk(ch, limits, out)?;
                }
                Ok(())
            }
            True | False => Ok(()),
        }
    }

    limits.validate()?;
    let mut out = BTreeMap::new();
    walk(expr, limits, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_algebra::{CanonicalPolicy, PolicyExpr};

    struct SequenceProposer {
        actions: Vec<ActionId>,
        idx: usize,
    }

    impl Proposer for SequenceProposer {
        fn propose(&mut self, _state: &State, _cxs: &[Counterexample]) -> Result<Action> {
            let a = self
                .actions
                .get(self.idx)
                .copied()
                .ok_or_else(|| MprdError::InvalidInput("proposer ran out of actions".into()))?;
            self.idx = self.idx.saturating_add(1);
            Ok(a)
        }
    }

    #[test]
    fn cegis_finds_first_allowed_and_records_metrics() {
        let limits = PolicyLimits::DEFAULT;
        let expr = PolicyExpr::any(
            vec![
                PolicyExpr::True,
                PolicyExpr::deny_if("action_db_pos", limits).unwrap(),
            ],
            limits,
        )
        .unwrap();
        let canon = CanonicalPolicy::new(expr, limits).unwrap();
        let verifier = PolicyAlgebraVerifier::new(canon, limits).unwrap();

        let state = State::new(EpochId(1), BTreeMap::new());
        let deny = ActionId::from_delta(&crate::tokenomics_v6::types::Delta {
            db: Step::Pos,
            da: Step::Zero,
            dd: Step::Zero,
        });
        let allow = ActionId::NOOP;

        let proposer = SequenceProposer {
            actions: vec![deny, allow],
            idx: 0,
        };
        let mut loop_ = CegisLoop::new(proposer, verifier, 8).unwrap();
        let chosen = loop_.run(&state).expect("should find allowed action");
        assert_eq!(chosen, allow);
        assert_eq!(loop_.metrics.proposals_total, 2);
        assert_eq!(loop_.metrics.proposals_valid, 1);
        assert_eq!(loop_.metrics.proposals_invalid, 1);
        assert_eq!(loop_.metrics.counterexamples_captured, 1);
        assert!(loop_.metrics.time_to_first_valid_ms.is_some());
        assert_eq!(loop_.counterexamples.len(), 1);
        assert_eq!(
            loop_.counterexamples[0].failed_atom.as_deref(),
            Some("action_db_pos")
        );
    }

    #[test]
    fn minimization_picks_lower_effort_action_for_same_failure() {
        let limits = PolicyLimits::DEFAULT;
        let expr = PolicyExpr::any(
            vec![
                PolicyExpr::True,
                PolicyExpr::deny_if("action_dd_pos", limits).unwrap(),
            ],
            limits,
        )
        .unwrap();
        let canon = CanonicalPolicy::new(expr, limits).unwrap();
        let verifier = PolicyAlgebraVerifier::new(canon, limits).unwrap();
        let state = State::new(EpochId(1), BTreeMap::new());

        // Start with a higher-effort action (db=pos, dd=pos). Minimization should select
        // the simpler (dd=pos only).
        let high_eff = ActionId::from_delta(&crate::tokenomics_v6::types::Delta {
            db: Step::Pos,
            da: Step::Zero,
            dd: Step::Pos,
        });
        let proposer = SequenceProposer {
            actions: vec![high_eff, ActionId::NOOP],
            idx: 0,
        };
        let mut loop_ = CegisLoop::new(proposer, verifier, 4).unwrap();
        let _ = loop_.run(&state).expect("find noop allowed");

        let cx = &loop_.counterexamples[0];
        assert_eq!(cx.failed_atom.as_deref(), Some("action_dd_pos"));
        assert_eq!(control_effort(cx.action), 1);
    }

    #[test]
    fn replay_is_deterministic_for_policy_state_action() {
        let limits = PolicyLimits::DEFAULT;
        let expr = PolicyExpr::deny_if("action_noop", limits).unwrap();
        let canon = CanonicalPolicy::new(expr, limits).unwrap();
        let verifier = PolicyAlgebraVerifier::new(canon, limits).unwrap();
        let state = State::new(EpochId(7), BTreeMap::new());
        let action = ActionId::NOOP;

        let t1 = verifier.replay_trace(&state, action).unwrap();
        let t2 = verifier.replay_trace(&state, action).unwrap();
        assert_eq!(t1, t2);
    }
}
