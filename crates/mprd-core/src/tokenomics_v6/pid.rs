use crate::{MprdError, Result};

use super::types::{Bps, BPS_U16};

/// PID gains for a bps-valued actuator.
///
/// All arithmetic is integer and deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PidBpsGains {
    pub kp: i64,
    pub ki: i64,
    pub kd: i64,
}

/// PID internal state (integrator + previous error).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PidBpsState {
    pub e_prev: i64,
    pub i_acc: i64,
}

impl Default for PidBpsState {
    fn default() -> Self {
        Self { e_prev: 0, i_acc: 0 }
    }
}

/// Safety rails for a PID-controlled bps actuator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PidBpsConfig {
    pub min_bps: Bps,
    pub max_bps: Bps,
    pub step_limit_bps: u16,
    pub i_min: i64,
    pub i_max: i64,
}

impl PidBpsConfig {
    pub fn validate(self) -> Result<()> {
        if self.min_bps.get() > self.max_bps.get() {
            return Err(MprdError::InvalidInput(
                "pid config invalid: min_bps > max_bps".into(),
            ));
        }
        if self.step_limit_bps > BPS_U16 {
            return Err(MprdError::InvalidInput(
                "pid config invalid: step_limit_bps out of range".into(),
            ));
        }
        if self.i_min > self.i_max {
            return Err(MprdError::InvalidInput("pid config invalid: i_min > i_max".into()));
        }
        Ok(())
    }
}

/// Deterministic PID step for a bps parameter.
///
/// Contract:
/// - Enforces absolute bounds `[min_bps, max_bps]`
/// - Enforces per-step limit `|Δ| <= step_limit_bps`
/// - Anti-windup via integrator clamping
pub fn pid_step_bps(
    current: Bps,
    setpoint: Bps,
    measured: Bps,
    gains: PidBpsGains,
    cfg: PidBpsConfig,
    state: PidBpsState,
) -> Result<(Bps, PidBpsState)> {
    cfg.validate()?;

    let e = (setpoint.get() as i64) - (measured.get() as i64);
    let d = e - state.e_prev;

    // Integrator update with anti-windup clamp.
    let i_unclamped = state
        .i_acc
        .checked_add(e)
        .ok_or_else(|| MprdError::BoundedValueExceeded("pid integrator overflow".into()))?;
    let i = i_unclamped.clamp(cfg.i_min, cfg.i_max);

    // PID output (delta in bps).
    let u_pid = (gains.kp as i128)
        .checked_mul(e as i128)
        .and_then(|x| x.checked_add((gains.ki as i128).checked_mul(i as i128)?))
        .and_then(|x| x.checked_add((gains.kd as i128).checked_mul(d as i128)?))
        .ok_or_else(|| MprdError::BoundedValueExceeded("pid output overflow".into()))?;

    // Clamp delta to step limit.
    let step = cfg.step_limit_bps as i128;
    let delta = u_pid.clamp(-step, step);

    // Apply delta and clamp to absolute bounds.
    let cur = current.get() as i128;
    let proposed = cur
        .checked_add(delta)
        .ok_or_else(|| MprdError::BoundedValueExceeded("pid apply overflow".into()))?;
    let min = cfg.min_bps.get() as i128;
    let max = cfg.max_bps.get() as i128;
    let next = proposed.clamp(min, max);

    let next_u16 = u16::try_from(next).map_err(|_| {
        MprdError::BoundedValueExceeded("pid next bps does not fit u16".into())
    })?;

    Ok((
        Bps::new(next_u16)?,
        PidBpsState { e_prev: e, i_acc: i },
    ))
}

/// v6 PID proposal over the primary adjustable tokenomics knobs.
///
/// This does not mutate the engine; it produces a *proposal* that can be
/// policy-checked (Tau) and then applied by a higher-layer controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenomicsPidProposalV6 {
    pub new_burn_surplus_bps: Bps,
    pub new_auction_surplus_bps: Bps,
    pub new_drip_rate_bps: Bps,
}

/// Minimal PID controller state for v6 adjustable knobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenomicsPidStateV6 {
    pub burn: PidBpsState,
    pub auction: PidBpsState,
    pub drip: PidBpsState,
}

impl Default for TokenomicsPidStateV6 {
    fn default() -> Self {
        Self {
            burn: PidBpsState::default(),
            auction: PidBpsState::default(),
            drip: PidBpsState::default(),
        }
    }
}

/// Stateless PID config for v6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenomicsPidConfigV6 {
    pub burn: (PidBpsGains, PidBpsConfig),
    pub auction: (PidBpsGains, PidBpsConfig),
    pub drip: (PidBpsGains, PidBpsConfig),
}

impl TokenomicsPidConfigV6 {
    pub fn validate(self) -> Result<()> {
        self.burn.1.validate()?;
        self.auction.1.validate()?;
        self.drip.1.validate()?;
        Ok(())
    }
}

/// Compute a bounded PID proposal for v6 knobs.
///
/// Additional invariant enforced here (CBC): `burn + auction <= 10_000`.
#[allow(clippy::too_many_arguments)]
pub fn propose_v6(
    cfg: TokenomicsPidConfigV6,
    state: TokenomicsPidStateV6,
    cur_burn: Bps,
    cur_auction: Bps,
    cur_drip: Bps,
    burn_setpoint: Bps,
    burn_measured: Bps,
    auction_setpoint: Bps,
    auction_measured: Bps,
    drip_setpoint: Bps,
    drip_measured: Bps,
) -> Result<(TokenomicsPidProposalV6, TokenomicsPidStateV6)> {
    cfg.validate()?;

    let (burn_next, burn_state) = pid_step_bps(
        cur_burn,
        burn_setpoint,
        burn_measured,
        cfg.burn.0,
        cfg.burn.1,
        state.burn,
    )?;

    let (auction_next, auction_state) = pid_step_bps(
        cur_auction,
        auction_setpoint,
        auction_measured,
        cfg.auction.0,
        cfg.auction.1,
        state.auction,
    )?;

    let (drip_next, drip_state) = pid_step_bps(
        cur_drip,
        drip_setpoint,
        drip_measured,
        cfg.drip.0,
        cfg.drip.1,
        state.drip,
    )?;

    // Enforce v6 split invariant (fail-safe): burn + auction <= 10_000.
    let mut burn_final = burn_next.get() as u32;
    let mut auction_final = auction_next.get() as u32;
    if burn_final.saturating_add(auction_final) > (BPS_U16 as u32) {
        // Prefer to preserve burn and shrink auction first.
        auction_final = (BPS_U16 as u32).saturating_sub(burn_final);
        if burn_final > (BPS_U16 as u32) {
            burn_final = BPS_U16 as u32;
            auction_final = 0;
        }
    }

    Ok((
        TokenomicsPidProposalV6 {
            new_burn_surplus_bps: Bps::new(burn_final as u16)?,
            new_auction_surplus_bps: Bps::new(auction_final as u16)?,
            new_drip_rate_bps: drip_next,
        },
        TokenomicsPidStateV6 {
            burn: burn_state,
            auction: auction_state,
            drip: drip_state,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_step_respects_bounds_and_step_limit() {
        let gains = PidBpsGains {
            kp: 1,
            ki: 0,
            kd: 0,
        };
        let cfg = PidBpsConfig {
            min_bps: Bps::new(5).unwrap(),
            max_bps: Bps::new(100).unwrap(),
            step_limit_bps: 10,
            i_min: -1_000,
            i_max: 1_000,
        };
        let state = PidBpsState::default();

        let (next, _st) = pid_step_bps(
            Bps::new(50).unwrap(),
            Bps::new(100).unwrap(),
            Bps::new(0).unwrap(),
            gains,
            cfg,
            state,
        )
        .unwrap();

        // Error = 100, delta would be 100, but step limit clamps to +10.
        assert_eq!(next.get(), 60);
    }

    #[test]
    fn v6_proposal_enforces_split_cap() {
        let cfg = TokenomicsPidConfigV6 {
            burn: (
                PidBpsGains {
                    kp: 1,
                    ki: 0,
                    kd: 0,
                },
                PidBpsConfig {
                    min_bps: Bps::new(0).unwrap(),
                    max_bps: Bps::new(10_000).unwrap(),
                    step_limit_bps: 10_000,
                    i_min: -1_000,
                    i_max: 1_000,
                },
            ),
            auction: (
                PidBpsGains {
                    kp: 1,
                    ki: 0,
                    kd: 0,
                },
                PidBpsConfig {
                    min_bps: Bps::new(0).unwrap(),
                    max_bps: Bps::new(10_000).unwrap(),
                    step_limit_bps: 10_000,
                    i_min: -1_000,
                    i_max: 1_000,
                },
            ),
            drip: (
                PidBpsGains {
                    kp: 0,
                    ki: 0,
                    kd: 0,
                },
                PidBpsConfig {
                    min_bps: Bps::new(0).unwrap(),
                    max_bps: Bps::new(10_000).unwrap(),
                    step_limit_bps: 10_000,
                    i_min: -1_000,
                    i_max: 1_000,
                },
            ),
        };

        let (p, _st) = propose_v6(
            cfg,
            TokenomicsPidStateV6::default(),
            Bps::new(9000).unwrap(),
            Bps::new(9000).unwrap(),
            Bps::new(10).unwrap(),
            Bps::new(10_000).unwrap(),
            Bps::new(0).unwrap(),
            Bps::new(10_000).unwrap(),
            Bps::new(0).unwrap(),
            Bps::new(0).unwrap(),
            Bps::new(0).unwrap(),
        )
        .unwrap();

        assert!(p.new_burn_surplus_bps.get() as u32 + p.new_auction_surplus_bps.get() as u32 <= 10_000);
    }
}

