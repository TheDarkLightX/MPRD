use crate::{MprdError, Result};

use super::{
    ActionOutcomeV6, ActionV6, AllowAllGateV6, InvariantCounterexampleV6, InvariantIdV6,
    InvariantViolationV6, ParamsV6, RuntimeBoundsV6, TokenomicsV6,
};

/// Run a v6 action trace and return the first invariant counterexample (if any).
///
/// Invariants checked:
/// - "no mutation on error" (state hash must not change if `apply` returns `Err`)
/// - `TokenomicsV6::check_invariants_v1` after every successful action
/// - transition-level conservation checks for specific outcomes (e.g., payroll)
pub fn first_invariant_counterexample_v1(
    params: ParamsV6,
    bounds: RuntimeBoundsV6,
    actions: &[ActionV6],
) -> Result<Option<InvariantCounterexampleV6>> {
    let mut eng = TokenomicsV6::new_with_bounds(params, bounds)?;
    let gate = AllowAllGateV6;

    for (i, a) in actions.iter().cloned().enumerate() {
        let before_hash = eng.state_hash_v1();
        let r = eng.apply(&gate, a.clone());

        match r {
            Err(e) => {
                let after_hash = eng.state_hash_v1();
                if after_hash != before_hash {
                    return Ok(Some(InvariantCounterexampleV6 {
                        violation: InvariantViolationV6::new(
                            InvariantIdV6::NoMutationOnError,
                            format!("action returned Err but state hash changed: {e}"),
                        ),
                        at_step: i,
                        state_hash: after_hash,
                        actions: actions[..=i].to_vec(),
                    }));
                }
                continue;
            }
            Ok(outcome) => {
                if let Some(v) = check_transition_invariants(&a, &outcome) {
                    return Ok(Some(InvariantCounterexampleV6 {
                        violation: v,
                        at_step: i,
                        state_hash: eng.state_hash_v1(),
                        actions: actions[..=i].to_vec(),
                    }));
                }
                if let Err(v) = eng.check_invariants_v1() {
                    return Ok(Some(InvariantCounterexampleV6 {
                        violation: v,
                        at_step: i,
                        state_hash: eng.state_hash_v1(),
                        actions: actions[..=i].to_vec(),
                    }));
                }
            }
        }
    }

    Ok(None)
}

fn check_transition_invariants(
    action: &ActionV6,
    outcome: &ActionOutcomeV6,
) -> Option<InvariantViolationV6> {
    match (action, outcome) {
        (ActionV6::SettleOpsPayroll, ActionOutcomeV6::SettleOpsPayroll(o)) => {
            let pool = o.ops_payroll_pool.get() as u128;
            let paid = o.payout_total.get() as u128;
            let carry = o.carry_to_reserve.get() as u128;
            if paid + carry != pool {
                return Some(InvariantViolationV6::new(
                    InvariantIdV6::RewardConserve,
                    format!(
                        "reward conservation broken: payout_total({}) + carry_to_reserve({}) != ops_payroll_pool({})",
                        o.payout_total.get(),
                        o.carry_to_reserve.get(),
                        o.ops_payroll_pool.get()
                    ),
                ));
            }
        }
        _ => {}
    }
    None
}

/// Minimize an invariant counterexample by removing actions while preserving the same invariant id.
///
/// This is a deterministic delta-debugging (ddmin) pass over the action list.
pub fn minimize_counterexample_v1(
    params: ParamsV6,
    bounds: RuntimeBoundsV6,
    ce: &InvariantCounterexampleV6,
) -> Result<InvariantCounterexampleV6> {
    let want = ce.violation.id;

    // Always start from the smallest prefix that actually triggers the violation.
    let mut cur = ce.actions.clone();
    let Some(first) = first_invariant_counterexample_v1(params.clone(), bounds, &cur)? else {
        return Err(MprdError::ExecutionError(
            "minimize_counterexample_v1: provided trace does not reproduce".into(),
        ));
    };
    if first.violation.id != want {
        return Err(MprdError::ExecutionError(
            "minimize_counterexample_v1: provided trace reproduces a different invariant".into(),
        ));
    }
    cur = first.actions.clone();

    // ddmin: remove chunks while preserving failure.
    let mut n = 2usize;
    while cur.len() >= 2 {
        let len = cur.len();
        let chunk = (len + n - 1) / n;
        let mut reduced = false;

        for start in (0..len).step_by(chunk) {
            let end = (start + chunk).min(len);
            if start == 0 && end == len {
                continue;
            }
            let mut cand = Vec::with_capacity(len - (end - start));
            cand.extend_from_slice(&cur[..start]);
            cand.extend_from_slice(&cur[end..]);

            let Some(r) = first_invariant_counterexample_v1(params.clone(), bounds, &cand)? else {
                continue;
            };
            if r.violation.id != want {
                continue;
            }

            cur = r.actions.clone();
            n = n.saturating_sub(1).max(2);
            reduced = true;
            break;
        }

        if reduced {
            continue;
        }
        if n >= len {
            break;
        }
        n = (n * 2).min(len);
    }

    let Some(out) = first_invariant_counterexample_v1(params, bounds, &cur)? else {
        return Err(MprdError::ExecutionError(
            "minimize_counterexample_v1: lost counterexample during minimization".into(),
        ));
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ltlf;
    use crate::tokenomics_v6::types::Bps;
    use crate::tokenomics_v6::{Agrs, Bcr, EpochId, OperatorId, ServiceTx};
    use crate::Hash32;
    use std::hash::{Hash, Hasher};

    fn params() -> ParamsV6 {
        ParamsV6::new(
            Bps::new(7_000).unwrap(),
            Bps::new(3_000).unwrap(),
            Bps::new(1_500).unwrap(),
            Bps::new(500).unwrap(),
            Bps::new(10).unwrap(),
            Bps::new(2_000).unwrap(),
            Bps::new(2_000).unwrap(),
            Agrs::new(150_000),
            Agrs::new(25_000),
            Agrs::new(5_000_000),
            50_000_000,
            14,
        )
        .unwrap()
    }

    fn oid(b: u8) -> OperatorId {
        OperatorId(Hash32([b; 32]))
    }

    #[test]
    fn invariant_rail_ignores_invalid_actions_that_do_not_mutate() {
        let p = params();
        let bounds = RuntimeBoundsV6::default();

        // Stake start without admission should fail-closed and NOT mutate.
        let actions = vec![ActionV6::StakeStart {
            operator: oid(1),
            stake_amount: Agrs::new(1),
            lock_epochs: 10,
            nonce: Hash32([9; 32]),
        }];

        let ce = first_invariant_counterexample_v1(p, bounds, &actions).unwrap();
        assert!(ce.is_none());
    }

    #[test]
    fn invariant_rail_accepts_basic_happy_path() {
        let p = params();
        let bounds = RuntimeBoundsV6::default();
        let a = oid(1);
        let b = oid(2);

        let actions = vec![
            ActionV6::AdmitOperator { operator: a },
            ActionV6::AdmitOperator { operator: b },
            ActionV6::CreditAgrs {
                operator: a,
                amt: Agrs::new(1_000_000),
            },
            ActionV6::StakeStart {
                operator: a,
                stake_amount: Agrs::new(100_000),
                lock_epochs: 30,
                nonce: Hash32([1; 32]),
            },
            ActionV6::AccrueBcrDrip,
            ActionV6::ApplyServiceTx(ServiceTx {
                payer: a,
                servicer: b,
                base_fee_agrs: Agrs::new(10_000),
                tip_agrs: Agrs::new(100),
                offset_request_bcr: Bcr::new(0),
                work_units: 1_000,
                nonce: Hash32([7; 32]),
            }),
            ActionV6::FinalizeEpoch,
            ActionV6::SettleOpsPayroll,
            ActionV6::SettleAuction,
            ActionV6::AdvanceEpoch {
                next_epoch: EpochId(1),
            },
        ];

        let ce = first_invariant_counterexample_v1(p, bounds, &actions).unwrap();
        assert!(ce.is_none());
    }

    #[test]
    fn ltlf_tokenomics_v6_epoch_lifecycle_bmc() {
        // This demonstrates how the public LTLf+BMC tooling can verify *temporal* tokenomics properties:
        // ordering and phase constraints that span multiple actions.
        //
        // Reference framing: "environment choices" (attempting actions out-of-order) are modeled as
        // nondeterminism; the property must hold for all traces within a bounded horizon.

        fn v(name: &str) -> ltlf::Valuation {
            let mut out = ltlf::Valuation::new();
            out.insert(name.to_string());
            out
        }

        // Seed an engine state so epoch close/settlements are reachable (not vacuously failing).
        let p = params();
        let bounds = RuntimeBoundsV6::default();
        let a = oid(1);
        let b = oid(2);

        let mut eng = TokenomicsV6::new_with_bounds(p, bounds).expect("engine");
        let gate = AllowAllGateV6;
        eng.apply(&gate, ActionV6::AdmitOperator { operator: a })
            .expect("admit a");
        eng.apply(&gate, ActionV6::AdmitOperator { operator: b })
            .expect("admit b");
        eng.apply(
            &gate,
            ActionV6::CreditAgrs {
                operator: a,
                amt: Agrs::new(1_000_000),
            },
        )
        .expect("credit");
        eng.apply(
            &gate,
            ActionV6::ApplyServiceTx(ServiceTx {
                payer: a,
                servicer: b,
                base_fee_agrs: Agrs::new(10_000),
                tip_agrs: Agrs::new(100),
                offset_request_bcr: Bcr::new(0),
                work_units: 1_000,
                nonce: Hash32([7; 32]),
            }),
        )
        .expect("service tx");

        #[derive(Clone)]
        struct Tok {
            eng: TokenomicsV6,
            id: Hash32,
        }

        impl Tok {
            fn new(eng: TokenomicsV6) -> Self {
                let id = eng.state_hash_v1();
                Self { eng, id }
            }
        }

        impl PartialEq for Tok {
            fn eq(&self, other: &Self) -> bool {
                self.id == other.id
            }
        }
        impl Eq for Tok {}
        impl Hash for Tok {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.id.hash(state)
            }
        }

        // Small action set: enough to cover the epoch lifecycle ordering.
        // (Trying these out of order is our "environment adversary".)
        let action_set: Vec<(ActionV6, &'static str)> = vec![
            (ActionV6::SettleOpsPayroll, "ok_settle_payroll"),
            (ActionV6::SettleAuction, "ok_settle_auction"),
            (
                ActionV6::AdvanceEpoch {
                    next_epoch: EpochId(1),
                },
                "ok_advance",
            ),
        ];

        // Temporal safety spec (within this bounded run where we end on the first successful advance):
        // - advance cannot happen before both settlements (enforced via precedence)
        // - no mutation on error
        let spec = ltlf::Formula::and(vec![
            ltlf::Formula::precedence("ok_settle_payroll", "ok_advance"),
            ltlf::Formula::precedence("ok_settle_auction", "ok_advance"),
            ltlf::Formula::always(ltlf::Formula::not_atom("mutated_on_err")),
        ]);

        let init = Tok::new(eng);

        let ce = ltlf::bmc_find_violation(spec, init, 8, |s| {
            let mut out: Vec<(ltlf::Valuation, Tok, bool)> = Vec::new();

            // Allow early termination so we check all prefixes up to the bound.
            out.push((ltlf::Valuation::new(), s.clone(), true));

            for (a, ok_atom) in &action_set {
                let mut eng2 = s.eng.clone();
                let before = eng2.state_hash_v1();
                let res = eng2.apply(&gate, a.clone());
                match res {
                    Ok(_) => {
                        // Success atom, plus an attempt label for debugging.
                        let mut val = v(ok_atom);
                        val.extend(v("attempt"));
                        let next = Tok::new(eng2);
                        // Treat a successful epoch advance as an end-of-trace boundary for this check.
                        let is_end = ok_atom == &"ok_advance";
                        out.push((val, next, is_end));
                    }
                    Err(_) => {
                        // On error, preserve the post-state (to catch mutation-on-error bugs) and emit a flag if mutated.
                        let after = eng2.state_hash_v1();
                        let mut val = v("err");
                        if after != before {
                            val.extend(v("mutated_on_err"));
                        }
                        out.push((val, Tok::new(eng2), false));
                    }
                }
            }
            out
        });

        assert!(
            ce.is_none(),
            "tokenomics_v6 lifecycle temporal spec violated; counterexample trace: {:?}",
            ce.map(|x| x.trace)
        );
    }

    #[test]
    fn ltlf_tokenomics_v6_epoch_close_forbids_open_actions_bmc() {
        // Strengthen tokenomics verification with *temporal* properties that invariants don't express cleanly:
        // - Per-epoch "at most once" actions (drip)
        // - After epoch close (budgets finalized via settlement), "epoch open" actions must never succeed
        //
        // This is checked via bounded nondeterministic exploration (explicit-state), returning a concrete
        // counterexample trace if violated.

        fn atom(name: &str) -> ltlf::Valuation {
            let mut out = ltlf::Valuation::new();
            out.insert(name.to_string());
            out
        }

        let p = params();
        let bounds = RuntimeBoundsV6::default();
        let a = oid(1);
        let b = oid(2);

        let mut eng = TokenomicsV6::new_with_bounds(p, bounds).expect("engine");
        let gate = AllowAllGateV6;
        eng.apply(&gate, ActionV6::AdmitOperator { operator: a })
            .expect("admit a");
        eng.apply(&gate, ActionV6::AdmitOperator { operator: b })
            .expect("admit b");
        eng.apply(
            &gate,
            ActionV6::CreditAgrs {
                operator: a,
                amt: Agrs::new(1_000_000),
            },
        )
        .expect("credit");
        // Seed one stake so drip has a meaningful effect.
        eng.apply(
            &gate,
            ActionV6::StakeStart {
                operator: a,
                stake_amount: Agrs::new(100_000),
                lock_epochs: 30,
                nonce: Hash32([42; 32]),
            },
        )
        .expect("stake");

        let tx = ServiceTx {
            payer: a,
            servicer: b,
            base_fee_agrs: Agrs::new(10_000),
            tip_agrs: Agrs::new(100),
            offset_request_bcr: Bcr::new(0),
            work_units: 1_000,
            nonce: Hash32([7; 32]),
        };

        #[derive(Clone)]
        struct Tok {
            eng: TokenomicsV6,
            id: Hash32,
        }

        impl Tok {
            fn new(eng: TokenomicsV6) -> Self {
                let id = eng.state_hash_v1();
                Self { eng, id }
            }
        }

        impl PartialEq for Tok {
            fn eq(&self, other: &Self) -> bool {
                self.id == other.id
            }
        }
        impl Eq for Tok {}
        impl Hash for Tok {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.id.hash(state)
            }
        }

        // Action set includes:
        // - epoch-open actions: drip, service tx
        // - epoch-close actions: settlements, advance
        let action_set: Vec<(ActionV6, &'static str)> = vec![
            (ActionV6::AccrueBcrDrip, "ok_drip"),
            (ActionV6::ApplyServiceTx(tx), "ok_service"),
            (ActionV6::SettleOpsPayroll, "ok_settle_payroll"),
            (ActionV6::SettleAuction, "ok_settle_auction"),
            (
                ActionV6::AdvanceEpoch {
                    next_epoch: EpochId(1),
                },
                "ok_advance",
            ),
        ];

        // Temporal spec:
        // - advance requires both settlements (order only, not necessarily immediate)
        // - drip is at-most-once per epoch (no second ok_drip before ok_advance)
        // - after either settlement succeeds (epoch is closed), epoch-open actions must never succeed
        // - no mutation on error
        let spec = ltlf::Formula::and(vec![
            ltlf::Formula::precedence("ok_settle_payroll", "ok_advance"),
            ltlf::Formula::precedence("ok_settle_auction", "ok_advance"),
            // Drip at most once per epoch: ok_drip -> Xw(ok_advance R !ok_drip)
            ltlf::Formula::always(ltlf::Formula::or(vec![
                ltlf::Formula::not_atom("ok_drip"),
                ltlf::Formula::weak_next(ltlf::Formula::release(
                    ltlf::Formula::atom("ok_advance"),
                    ltlf::Formula::not_atom("ok_drip"),
                )),
            ])),
            // Once payroll settlement succeeds, no more successful drip/service in that epoch.
            ltlf::Formula::always(ltlf::Formula::or(vec![
                ltlf::Formula::not_atom("ok_settle_payroll"),
                ltlf::Formula::always(ltlf::Formula::not_atom("ok_drip")),
            ])),
            ltlf::Formula::always(ltlf::Formula::or(vec![
                ltlf::Formula::not_atom("ok_settle_payroll"),
                ltlf::Formula::always(ltlf::Formula::not_atom("ok_service")),
            ])),
            // Once auction settlement succeeds, no more successful drip/service in that epoch.
            ltlf::Formula::always(ltlf::Formula::or(vec![
                ltlf::Formula::not_atom("ok_settle_auction"),
                ltlf::Formula::always(ltlf::Formula::not_atom("ok_drip")),
            ])),
            ltlf::Formula::always(ltlf::Formula::or(vec![
                ltlf::Formula::not_atom("ok_settle_auction"),
                ltlf::Formula::always(ltlf::Formula::not_atom("ok_service")),
            ])),
            ltlf::Formula::always(ltlf::Formula::not_atom("mutated_on_err")),
        ]);

        let init = Tok::new(eng);

        let ce = ltlf::bmc_find_violation(spec, init, 10, |s| {
            let mut out: Vec<(ltlf::Valuation, Tok, bool)> = Vec::new();

            // Allow early termination to check all prefixes.
            out.push((ltlf::Valuation::new(), s.clone(), true));

            for (a, ok_atom) in &action_set {
                let mut eng2 = s.eng.clone();
                let before = eng2.state_hash_v1();
                let res = eng2.apply(&gate, a.clone());
                match res {
                    Ok(_) => {
                        let mut val = atom("attempt");
                        val.extend(atom(ok_atom));
                        let next = Tok::new(eng2);
                        let is_end = ok_atom == &"ok_advance";
                        out.push((val, next, is_end));
                    }
                    Err(_) => {
                        let after = eng2.state_hash_v1();
                        let mut val = atom("err");
                        if after != before {
                            val.extend(atom("mutated_on_err"));
                        }
                        out.push((val, Tok::new(eng2), false));
                    }
                }
            }
            out
        });

        assert!(
            ce.is_none(),
            "tokenomics_v6 epoch-close temporal spec violated; counterexample trace: {:?}",
            ce.map(|x| x.trace)
        );
    }
}
