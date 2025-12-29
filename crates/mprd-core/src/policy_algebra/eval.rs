use std::collections::BTreeSet;

use crate::{Hash32, MprdError, Result};
use crate::verified_kernels::policy_algebra_operators;

use super::ast::{PolicyAtom, PolicyExpr, PolicyLimits, PolicyOutcomeKind};
use super::hash::policy_hash_v1;
use super::trace::{PolicyTrace, TraceEntry, TraceReasonCode};

/// Evaluation context for policy algebra signals.
///
/// `None` means the signal is missing (fail-closed).
pub trait EvalContext {
    fn signal(&self, atom: &PolicyAtom) -> Option<bool>;
}

/// Result of evaluating a policy under some context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEvalResult {
    pub outcome: PolicyOutcomeKind,
    pub trace: PolicyTrace,
}

impl PolicyEvalResult {
    pub fn allowed(&self) -> bool {
        matches!(self.outcome, PolicyOutcomeKind::Allow)
    }
}

fn deny_if_set(expr: &PolicyExpr, out: &mut BTreeSet<PolicyAtom>) {
    match expr {
        PolicyExpr::DenyIf(a) => {
            out.insert(a.clone());
        }
        PolicyExpr::Not(p) => deny_if_set(p, out),
        PolicyExpr::All(children) | PolicyExpr::Any(children) => {
            for ch in children {
                deny_if_set(ch, out);
            }
        }
        PolicyExpr::Threshold { children, .. } => {
            for ch in children {
                deny_if_set(ch, out);
            }
        }
        PolicyExpr::True | PolicyExpr::False | PolicyExpr::Atom(_) => {}
    }
}

fn push_trace(
    trace: &mut PolicyTrace,
    limits: PolicyLimits,
    node_hash: Hash32,
    outcome: PolicyOutcomeKind,
    reason: TraceReasonCode,
) -> Result<()> {
    trace.push_bounded(
        TraceEntry {
            node_hash,
            outcome,
            reason,
        },
        limits.max_trace_nodes,
    )
}

/// Evaluate a canonical policy expression.
///
/// Semantics summary (veto-first, fail-closed):
/// - All `DenyIf(atom)` nodes anywhere in the policy act as *global veto guards*.
///   They are evaluated first (in deterministic order) and if any is true/missing → DenyVeto.
/// - The remaining policy is evaluated with `DenyIf(_)` treated as `Neutral`.
/// - Missing signals deny (fail-closed).
pub fn evaluate(
    expr: &PolicyExpr,
    ctx: &impl EvalContext,
    limits: PolicyLimits,
) -> Result<PolicyEvalResult> {
    limits.validate()?;
    if expr.node_count() > limits.max_nodes {
        return Err(MprdError::InvalidInput(format!(
            "policy too large for evaluation (nodes={} max_nodes={})",
            expr.node_count(),
            limits.max_nodes
        )));
    }

    let mut trace = PolicyTrace::new();

    // CBC: use the verified policy_algebra_operators kernel as a bounded evaluation budget.
    // This is intentionally orthogonal to the policy semantics (DenyIf, 3-valued outcomes).
    #[derive(Debug)]
    struct KernelBudget {
        state: policy_algebra_operators::State,
    }

    impl KernelBudget {
        fn new() -> Self {
            Self {
                state: policy_algebra_operators::State::init(),
            }
        }

        fn step(&mut self, cmd: policy_algebra_operators::Command) -> Result<()> {
            let (st, _) = policy_algebra_operators::step(&self.state, cmd).map_err(|e| {
                MprdError::BoundedValueExceeded(format!("policy_algebra_operators budget exceeded: {e}"))
            })?;
            self.state = st;
            Ok(())
        }

        fn enter_composite(&mut self) -> Result<()> {
            self.step(policy_algebra_operators::Command::PushComposite)
        }

        fn leave_composite(&mut self) -> Result<()> {
            self.step(policy_algebra_operators::Command::PopComposite)
        }

        fn charge_not(&mut self) -> Result<()> {
            // Use a deterministic dummy input; we only want the bounded counter semantics.
            self.step(policy_algebra_operators::Command::EvalNot { sub_result: false })
        }

        fn charge_and(&mut self) -> Result<()> {
            self.step(policy_algebra_operators::Command::EvalAnd {
                left_result: true,
                right_result: true,
            })
        }

        fn charge_or(&mut self) -> Result<()> {
            self.step(policy_algebra_operators::Command::EvalOr {
                left_result: false,
                right_result: false,
            })
        }
    }

    let mut budget = KernelBudget::new();

    // Phase 1: evaluate veto guards globally.
    let mut deny_if_atoms: BTreeSet<PolicyAtom> = BTreeSet::new();
    deny_if_set(expr, &mut deny_if_atoms);

    for atom in deny_if_atoms {
        let node = PolicyExpr::DenyIf(atom.clone());
        let node_hash = policy_hash_v1(&node);
        match ctx.signal(&atom) {
            None => {
                push_trace(
                    &mut trace,
                    limits,
                    node_hash,
                    PolicyOutcomeKind::DenyVeto,
                    TraceReasonCode::DenyVetoMissingSignal,
                )?;
                return Ok(PolicyEvalResult {
                    outcome: PolicyOutcomeKind::DenyVeto,
                    trace,
                });
            }
            Some(true) => {
                push_trace(
                    &mut trace,
                    limits,
                    node_hash,
                    PolicyOutcomeKind::DenyVeto,
                    TraceReasonCode::DenyVetoSignalTrue,
                )?;
                return Ok(PolicyEvalResult {
                    outcome: PolicyOutcomeKind::DenyVeto,
                    trace,
                });
            }
            Some(false) => {
                push_trace(
                    &mut trace,
                    limits,
                    node_hash,
                    PolicyOutcomeKind::Neutral,
                    TraceReasonCode::NeutralVetoNotTriggered,
                )?;
            }
        }
    }

    // Phase 2: evaluate the policy normally, treating DenyIf as Neutral.
    fn eval_node(
        expr: &PolicyExpr,
        ctx: &impl EvalContext,
        limits: PolicyLimits,
        trace: &mut PolicyTrace,
        budget: &mut KernelBudget,
    ) -> Result<PolicyOutcomeKind> {
        let node_hash = policy_hash_v1(expr);

        let out = match expr {
            PolicyExpr::True => PolicyOutcomeKind::Allow,
            PolicyExpr::False => PolicyOutcomeKind::DenySoft,
            PolicyExpr::Atom(a) => match ctx.signal(a) {
                None => PolicyOutcomeKind::DenySoft,
                Some(true) => PolicyOutcomeKind::Allow,
                Some(false) => PolicyOutcomeKind::DenySoft,
            },
            PolicyExpr::DenyIf(_) => PolicyOutcomeKind::Neutral,
            PolicyExpr::Not(p) => {
                budget.enter_composite()?;
                budget.charge_not()?;
                let out = match eval_node(p, ctx, limits, trace, budget)? {
                    PolicyOutcomeKind::Allow => PolicyOutcomeKind::DenySoft,
                    PolicyOutcomeKind::DenySoft => PolicyOutcomeKind::Allow,
                    PolicyOutcomeKind::DenyVeto => PolicyOutcomeKind::Allow,
                    PolicyOutcomeKind::Neutral => PolicyOutcomeKind::Neutral,
                };
                budget.leave_composite()?;
                out
            }
            PolicyExpr::All(children) => {
                budget.enter_composite()?;
                budget.charge_and()?;
                let mut saw_any = false;
                let mut local_out = PolicyOutcomeKind::Allow;
                for ch in children {
                    saw_any = true;
                    match eval_node(ch, ctx, limits, trace, budget)? {
                        PolicyOutcomeKind::Allow | PolicyOutcomeKind::Neutral => {}
                        PolicyOutcomeKind::DenySoft => {
                            local_out = PolicyOutcomeKind::DenySoft;
                            break;
                        }
                        PolicyOutcomeKind::DenyVeto => {
                            local_out = PolicyOutcomeKind::DenyVeto;
                            break;
                        }
                    }
                }
                if !saw_any {
                    local_out = PolicyOutcomeKind::Allow;
                }
                budget.leave_composite()?;
                local_out
            }
            PolicyExpr::Any(children) => {
                budget.enter_composite()?;
                budget.charge_or()?;
                let mut any_allow = false;
                let mut veto = false;
                for ch in children {
                    match eval_node(ch, ctx, limits, trace, budget)? {
                        PolicyOutcomeKind::Allow => {
                            any_allow = true;
                            break;
                        }
                        PolicyOutcomeKind::DenyVeto => {
                            veto = true;
                            break;
                        }
                        PolicyOutcomeKind::DenySoft | PolicyOutcomeKind::Neutral => {}
                    }
                }
                let out = if veto {
                    PolicyOutcomeKind::DenyVeto
                } else if any_allow {
                    PolicyOutcomeKind::Allow
                } else {
                    PolicyOutcomeKind::DenySoft
                };
                budget.leave_composite()?;
                out
            }
            PolicyExpr::Threshold { k, children } => {
                budget.enter_composite()?;
                budget.charge_and()?;
                if *k == 0 {
                    budget.leave_composite()?;
                    PolicyOutcomeKind::Allow
                } else {
                    let mut allow_count: usize = 0;
                    let mut veto = false;
                    for ch in children {
                        match eval_node(ch, ctx, limits, trace, budget)? {
                            PolicyOutcomeKind::Allow => {
                                allow_count = allow_count.saturating_add(1);
                            }
                            PolicyOutcomeKind::DenyVeto => {
                                veto = true;
                                break;
                            }
                            PolicyOutcomeKind::DenySoft | PolicyOutcomeKind::Neutral => {}
                        }
                    }
                    let out = if veto {
                        PolicyOutcomeKind::DenyVeto
                    } else if allow_count >= (*k as usize) {
                        PolicyOutcomeKind::Allow
                    } else {
                        PolicyOutcomeKind::DenySoft
                    };
                    budget.leave_composite()?;
                    out
                }
            }
        };

        let reason = match expr {
            PolicyExpr::True => TraceReasonCode::Allow,
            PolicyExpr::False => TraceReasonCode::DenyUnknown,
            PolicyExpr::Atom(a) => match ctx.signal(a) {
                None => TraceReasonCode::DenyMissingSignal,
                Some(true) => TraceReasonCode::Allow,
                Some(false) => TraceReasonCode::DenySignalFalse,
            },
            PolicyExpr::DenyIf(_) => TraceReasonCode::NeutralVetoNotTriggered,
            PolicyExpr::Any(_) => match out {
                PolicyOutcomeKind::Allow => TraceReasonCode::Allow,
                _ => TraceReasonCode::DenyAnyNoAllow,
            },
            PolicyExpr::Threshold { .. } => match out {
                PolicyOutcomeKind::Allow => TraceReasonCode::Allow,
                _ => TraceReasonCode::DenyThresholdNotMet,
            },
            PolicyExpr::All(_) | PolicyExpr::Not(_) => match out {
                PolicyOutcomeKind::Allow => TraceReasonCode::Allow,
                _ => TraceReasonCode::DenyUnknown,
            },
        };

        push_trace(trace, limits, node_hash, out, reason)?;
        Ok(out)
    }

    let outcome = eval_node(expr, ctx, limits, &mut trace, &mut budget)?;
    Ok(PolicyEvalResult { outcome, trace })
}
