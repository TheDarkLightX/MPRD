//! Tokenomics utilities (v6).

use anyhow::{Context, Result};

use mprd_core::tokenomics_v6::{
    propose_v6, Bps, PidBpsConfig, PidBpsGains, TokenomicsPidConfigV6, TokenomicsPidStateV6,
};

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
    let bps = |v: u16| Bps::new(v).context("invalid bps")?;

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

