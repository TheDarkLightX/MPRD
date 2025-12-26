//! Tokenomics utilities (v6).

use anyhow::{Context, Result};

use mprd_core::tokenomics_v6::{
    first_invariant_counterexample_v1, minimize_counterexample_v1, propose_v6, ActionV6, Agrs,
    AgrsPerBcr, Bcr, Bps, EpochId, OperatorId, ParamsV6, PidBpsConfig, PidBpsGains, ServiceTx,
    StakeId, TokenomicsPidConfigV6, TokenomicsPidStateV6, TokenomicsV6,
};
use mprd_core::Hash32;

#[derive(Clone, Debug, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct PidProposeOutputV6 {
    pub new_burn_surplus_bps: u16,
    pub new_auction_surplus_bps: u16,
    pub new_drip_rate_bps: u16,
}

pub fn pid_propose_v6(
    cur_burn_surplus_bps: u16,
    cur_auction_surplus_bps: u16,
    cur_drip_rate_bps: u16,
    burn_setpoint_bps: u16,
    burn_measured_bps: u16,
    auction_setpoint_bps: u16,
    auction_measured_bps: u16,
    drip_setpoint_bps: u16,
    drip_measured_bps: u16,
    format: String,
) -> Result<()> {
    let bps = |v: u16| -> Result<Bps> { Bps::new(v).context("invalid bps") };

    // Default actuator safety rails per `internal/specs/mprd_operator_tokenomics.md` §9.5.
    let burn_cfg = PidBpsConfig {
        min_bps: bps(5000)?,
        max_bps: bps(9500)?,
        step_limit_bps: 100,
        i_min: -50_000,
        i_max: 50_000,
    };
    let auction_cfg = PidBpsConfig {
        min_bps: bps(500)?,
        max_bps: bps(5000)?,
        step_limit_bps: 100,
        i_min: -50_000,
        i_max: 50_000,
    };
    let drip_cfg = PidBpsConfig {
        min_bps: bps(5)?,
        max_bps: bps(100)?,
        step_limit_bps: 5,
        i_min: -50_000,
        i_max: 50_000,
    };

    // Simple defaults: proportional-only. Deployments can tune gains over time.
    let cfg = TokenomicsPidConfigV6 {
        burn: (
            PidBpsGains {
                kp: 1,
                ki: 0,
                kd: 0,
            },
            burn_cfg,
        ),
        auction: (
            PidBpsGains {
                kp: 1,
                ki: 0,
                kd: 0,
            },
            auction_cfg,
        ),
        drip: (
            PidBpsGains {
                kp: 1,
                ki: 0,
                kd: 0,
            },
            drip_cfg,
        ),
    };

    let (proposal, _state) = propose_v6(
        cfg,
        TokenomicsPidStateV6::default(),
        bps(cur_burn_surplus_bps)?,
        bps(cur_auction_surplus_bps)?,
        bps(cur_drip_rate_bps)?,
        bps(burn_setpoint_bps)?,
        bps(burn_measured_bps)?,
        bps(auction_setpoint_bps)?,
        bps(auction_measured_bps)?,
        bps(drip_setpoint_bps)?,
        bps(drip_measured_bps)?,
    )?;

    let out = PidProposeOutputV6 {
        new_burn_surplus_bps: proposal.new_burn_surplus_bps.get(),
        new_auction_surplus_bps: proposal.new_auction_surplus_bps.get(),
        new_drip_rate_bps: proposal.new_drip_rate_bps.get(),
    };

    match format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        "human" => {
            println!("PID proposal (v6)");
            println!();
            println!("  burn_surplus_bps   = {}", out.new_burn_surplus_bps);
            println!("  auction_surplus_bps= {}", out.new_auction_surplus_bps);
            println!("  drip_rate_bps      = {}", out.new_drip_rate_bps);
        }
        _ => anyhow::bail!("unknown format: {format} (expected 'human' or 'json')"),
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        // Avoid the all-zero state.
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn gen_range(&mut self, upper: u64) -> u64 {
        if upper == 0 {
            return 0;
        }
        self.next_u64() % upper
    }

    fn gen_hash32(&mut self) -> Hash32 {
        let mut out = [0u8; 32];
        for chunk in out.chunks_exact_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        Hash32(out)
    }
}

fn default_params_v6() -> ParamsV6 {
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

fn operator_id(i: u32) -> OperatorId {
    OperatorId(Hash32([u8::try_from((i % 255) + 1).unwrap_or(1); 32]))
}

fn generate_trace_v6(seed: u64, steps: u32, operators: u32) -> Result<Vec<ActionV6>> {
    let params = default_params_v6();
    let mut eng = TokenomicsV6::new(params.clone());
    let mut rng = XorShift64::new(seed);

    let mut actions: Vec<ActionV6> = Vec::new();
    let mut admitted: Vec<OperatorId> = Vec::new();
    let mut stakes: std::collections::BTreeMap<OperatorId, Vec<StakeId>> =
        std::collections::BTreeMap::new();
    let mut epoch_finalized = false;
    let mut payroll_settled = false;
    let mut auction_settled = false;

    // Bootstrap: admit + fund operators so deeper actions are reachable.
    for i in 0..operators {
        let oid = operator_id(i);
        admitted.push(oid);
        stakes.insert(oid, Vec::new());

        let admit = ActionV6::AdmitOperator { operator: oid };
        let _ = eng.apply(&mprd_core::tokenomics_v6::AllowAllGateV6, admit.clone());
        actions.push(admit);

        let credit = ActionV6::CreditAgrs {
            operator: oid,
            amt: Agrs::new(1_000_000),
        };
        let _ = eng.apply(&mprd_core::tokenomics_v6::AllowAllGateV6, credit.clone());
        actions.push(credit);
    }

    for _ in 0..steps {
        if admitted.is_empty() {
            break;
        }

        // Pick an action kind.
        let pick = rng.gen_range(10);
        let a = match pick {
            0 => {
                // StakeStart
                let oid = admitted[rng.gen_range(admitted.len() as u64) as usize];
                let bal = eng.agrs_balance(oid).unwrap_or(Agrs::ZERO).get();
                if bal == 0 {
                    continue;
                }
                let stake_amount = (bal / 4).max(1);
                let lock_epochs = (rng.gen_range(365) + 1) as u16;
                ActionV6::StakeStart {
                    operator: oid,
                    stake_amount: Agrs::new(stake_amount),
                    lock_epochs,
                    nonce: rng.gen_hash32(),
                }
            }
            1 => {
                // StakeEnd (if possible)
                let oid = admitted[rng.gen_range(admitted.len() as u64) as usize];
                let Some(list) = stakes.get(&oid) else {
                    continue;
                };
                let Some(&sid) = list.last() else { continue };
                ActionV6::StakeEnd {
                    operator: oid,
                    stake_id: sid,
                }
            }
            2 => ActionV6::AccrueBcrDrip,
            3 => {
                // ApplyServiceTx
                let payer = admitted[rng.gen_range(admitted.len() as u64) as usize];
                let mut servicer = admitted[rng.gen_range(admitted.len() as u64) as usize];
                if servicer == payer && admitted.len() > 1 {
                    servicer = admitted[(rng.gen_range((admitted.len() - 1) as u64) as usize + 1)
                        % admitted.len()];
                }
                let base_fee = (rng.gen_range(50_000) + 1).min(50_000);
                let tip = rng.gen_range(1_000);

                let payer_bcr = eng.bcr_balance(payer).unwrap_or(Bcr::ZERO).get();
                let tx_cap_u128 = (base_fee as u128)
                    * (params.max_offset_per_tx_bps().get() as u128)
                    / 10_000u128;
                let tx_cap = u64::try_from(tx_cap_u128).unwrap_or(0);
                let offset_req = payer_bcr.min(tx_cap);

                ActionV6::ApplyServiceTx(ServiceTx {
                    payer,
                    servicer,
                    base_fee_agrs: Agrs::new(base_fee),
                    tip_agrs: Agrs::new(tip),
                    offset_request_bcr: Bcr::new(offset_req),
                    work_units: rng.gen_range(10_000),
                    nonce: rng.gen_hash32(),
                })
            }
            4 => {
                // AuctionReveal (if possible)
                let oid = admitted[rng.gen_range(admitted.len() as u64) as usize];
                let bcr = eng.bcr_balance(oid).unwrap_or(Bcr::ZERO).get();
                if bcr == 0 {
                    continue;
                }
                let qty = (rng.gen_range(bcr) + 1).min(bcr);
                let min_price = rng.gen_range(10) + 1;
                ActionV6::AuctionReveal {
                    operator: oid,
                    qty_bcr: Bcr::new(qty),
                    min_price: AgrsPerBcr::new(min_price),
                    nonce: rng.gen_hash32(),
                }
            }
            5 => ActionV6::FinalizeEpoch,
            6 => ActionV6::SettleOpsPayroll,
            7 => ActionV6::SettleAuction,
            8 => {
                // AdvanceEpoch to next epoch id (monotone)
                let next = EpochId(eng.epoch().0.saturating_add(1));
                ActionV6::AdvanceEpoch { next_epoch: next }
            }
            _ => {
                // Occasionally update OPI to exercise payroll weighting.
                let oid = admitted[rng.gen_range(admitted.len() as u64) as usize];
                let opi = (rng.gen_range(10_000 + 1) as u16).min(10_000);
                ActionV6::SetOpi {
                    operator: oid,
                    opi_bps: Bps::new(opi).unwrap(),
                }
            }
        };

        // Apply and observe (to track stake ids and epoch state).
        let out = eng.apply(&mprd_core::tokenomics_v6::AllowAllGateV6, a.clone());
        match (&a, &out) {
            (ActionV6::FinalizeEpoch, Ok(_)) => epoch_finalized = true,
            (ActionV6::SettleOpsPayroll, Ok(_)) => payroll_settled = true,
            (ActionV6::SettleAuction, Ok(_)) => auction_settled = true,
            (ActionV6::AdvanceEpoch { .. }, Ok(_)) => {
                epoch_finalized = false;
                payroll_settled = false;
                auction_settled = false;
                // Stakes remain; but any locked payouts may have unlocked.
            }
            (
                ActionV6::StakeStart {
                    operator, nonce, ..
                },
                Ok(mprd_core::tokenomics_v6::ActionOutcomeV6::StakeStart(o)),
            ) => {
                // Record stake id for potential end.
                stakes.entry(*operator).or_default().push(o.stake_id);
                let _ = nonce;
            }
            (ActionV6::StakeEnd { operator, stake_id }, Ok(_)) => {
                if let Some(list) = stakes.get_mut(operator) {
                    list.retain(|x| x != stake_id);
                }
            }
            _ => {}
        }

        actions.push(a);

        // Avoid generating actions that are guaranteed to fail forever in this epoch state.
        if epoch_finalized && payroll_settled && auction_settled {
            // Bias toward advancing once settled.
            let adv = ActionV6::AdvanceEpoch {
                next_epoch: EpochId(eng.epoch().0.saturating_add(1)),
            };
            let _ = eng.apply(&mprd_core::tokenomics_v6::AllowAllGateV6, adv.clone());
            actions.push(adv);
            epoch_finalized = false;
            payroll_settled = false;
            auction_settled = false;
        }
    }

    Ok(actions)
}

pub fn fuzz_invariants_v6(seed: u64, steps: u32, iters: u32, operators: u32) -> Result<()> {
    let params = default_params_v6();
    let bounds = mprd_core::tokenomics_v6::RuntimeBoundsV6::default();

    for i in 0..iters {
        let run_seed = seed ^ (0x9E37_79B9_7F4A_7C15u64.wrapping_mul(i as u64 + 1));
        let trace = generate_trace_v6(run_seed, steps, operators)?;

        let Some(ce) = first_invariant_counterexample_v1(params.clone(), bounds, &trace)
            .context("Failed to run invariant check")?
        else {
            continue;
        };

        let min = minimize_counterexample_v1(params.clone(), bounds, &ce)
            .context("Failed to minimize invariant counterexample")?;

        println!("{}", min.short());
        println!();
        println!("Minimal trace ({} actions):", min.actions.len());
        for (idx, a) in min.actions.iter().enumerate() {
            println!("  {:03}: {:?}", idx, a);
        }
        return Ok(());
    }

    println!(
        "No invariant violations found (iters={iters}, steps={steps}, operators={operators})."
    );
    Ok(())
}
