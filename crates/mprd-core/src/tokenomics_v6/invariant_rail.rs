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
    use crate::tokenomics_v6::types::Bps;
    use crate::tokenomics_v6::{Agrs, Bcr, EpochId, OperatorId, ServiceTx};
    use crate::Hash32;

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
}
