use crate::{hash, Hash32, MprdError, Result};

pub const BPS_U16: u16 = 10_000;
pub const BPS_U64: u64 = 10_000;

/// Basis points in `[0, 10_000]` (correct-by-construction).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bps(u16);

impl Bps {
    pub const ZERO: Bps = Bps(0);
    pub const MAX: Bps = Bps(BPS_U16);

    /// Constructs a bounded bps value.
    ///
    /// Preconditions:
    /// - `v <= 10_000` (else returns an error; fail-closed).
    ///
    /// Postconditions:
    /// - `self.get()` is always in `[0, 10_000]` and can be used without re-checking.
    pub fn new(v: u16) -> Result<Bps> {
        if v <= BPS_U16 {
            Ok(Bps(v))
        } else {
            Err(MprdError::InvalidInput(format!(
                "bps out of range: {v} > {BPS_U16}"
            )))
        }
    }

    pub fn get(self) -> u16 {
        self.0
    }

    pub fn as_u64(self) -> u64 {
        self.0 as u64
    }
}

impl TryFrom<u16> for Bps {
    type Error = MprdError;
    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        Bps::new(value)
    }
}

/// AGRS amount (Tau Net compute token).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Agrs(u64);

impl Agrs {
    pub const ZERO: Agrs = Agrs(0);

    pub fn new(v: u64) -> Agrs {
        Agrs(v)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

/// BCR amount (Burn Credits).
///
/// v6 has two rails:
/// - **Utility rail:** BCR can be spent to offset *base fees*; by definition `1 BCR` offsets `1 AGRS`
///   (subject to per-tx/per-epoch caps). This is a compute/fee-discount primitive, not a redemption promise.
/// - **Liquidity rail:** BCR can be sold via the opt-in auction; the `AGRS per BCR` price is market-set
///   by the clearing mechanism.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bcr(u64);

impl Bcr {
    pub const ZERO: Bcr = Bcr(0);

    pub fn new(v: u64) -> Bcr {
        Bcr(v)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

/// S-Shares amount (HEX-like stake shares; not governance).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Shares(u64);

impl Shares {
    pub const ZERO: Shares = Shares(0);

    pub fn new(v: u64) -> Shares {
        Shares(v)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

/// Price: AGRS per 1 BCR (integer, in smallest AGRS units).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgrsPerBcr(u64);

impl AgrsPerBcr {
    pub fn new(v: u64) -> AgrsPerBcr {
        AgrsPerBcr(v)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperatorId(pub Hash32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpochId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StakeId(pub Hash32);

impl StakeId {
    pub const DOMAIN_V1: &'static [u8] = b"MPRD_TOKENOMICS_V6_STAKE_ID_V1";

    /// Deterministically derives a stake identifier.
    ///
    /// Rationale: stake IDs are content-addressed (domain-separated hash) so callers don't
    /// have to coordinate a global counter; uniqueness comes from `(operator, epoch, nonce)`.
    pub fn derive(operator: OperatorId, epoch: u64, nonce: Hash32) -> StakeId {
        let mut bytes = Vec::with_capacity(Self::DOMAIN_V1.len() + 32 + 8 + 32);
        bytes.extend_from_slice(Self::DOMAIN_V1);
        bytes.extend_from_slice(&operator.0 .0);
        bytes.extend_from_slice(&epoch.to_le_bytes());
        bytes.extend_from_slice(&nonce.0);
        StakeId(hash::sha256(&bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StakeStatus {
    Active,
    Ended,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakeStartOutcome {
    pub stake_id: StakeId,
    pub shares_minted: Shares,
}

/// v6 policy parameters (validated once at construction).
///
/// These values are POLICY-SET (e.g., at genesis / upgrade) and are not market outputs.
/// Market-determined values (tips, auction clearing price) enter as transaction/bid inputs.
///
/// CBC contract: once constructed, the engine treats these as trusted invariants.
#[derive(Clone, Debug)]
pub struct ParamsV6 {
    burn_surplus_bps: Bps,
    auction_surplus_bps: Bps,

    ops_pay_bps: Bps,
    overhead_bps: Bps,

    drip_rate_bps: Bps,
    max_offset_per_tx_bps: Bps,
    max_offset_per_epoch_bps: Bps,

    ops_floor_fixed_agrs: Agrs,
    reserve_target_agrs: Agrs,
    carry_cap_agrs: Agrs,

    share_rate_k: u64,
    payout_lock_epochs: u16,
}

impl ParamsV6 {
    /// Creates a new v6 parameter bundle.
    ///
    /// Preconditions (enforced):
    /// - `burn_surplus_bps + auction_surplus_bps <= 10_000` (can't allocate more than 100%).
    /// - `share_rate_k > 0` (share-rate ratchet must be well-defined).
    /// - `payout_lock_epochs > 0` (auction payouts must have an unlock epoch).
    pub fn new(
        burn_surplus_bps: Bps,
        auction_surplus_bps: Bps,
        ops_pay_bps: Bps,
        overhead_bps: Bps,
        drip_rate_bps: Bps,
        max_offset_per_tx_bps: Bps,
        max_offset_per_epoch_bps: Bps,
        ops_floor_fixed_agrs: Agrs,
        reserve_target_agrs: Agrs,
        carry_cap_agrs: Agrs,
        share_rate_k: u64,
        payout_lock_epochs: u16,
    ) -> Result<ParamsV6> {
        let split = burn_surplus_bps.as_u64() + auction_surplus_bps.as_u64();
        if split > BPS_U64 {
            return Err(MprdError::InvalidInput(
                "burn_surplus_bps + auction_surplus_bps must be <= 10_000".into(),
            ));
        }
        if share_rate_k == 0 {
            return Err(MprdError::InvalidInput("share_rate_k must be > 0".into()));
        }
        if payout_lock_epochs == 0 {
            return Err(MprdError::InvalidInput(
                "payout_lock_epochs must be > 0".into(),
            ));
        }
        Ok(ParamsV6 {
            burn_surplus_bps,
            auction_surplus_bps,
            ops_pay_bps,
            overhead_bps,
            drip_rate_bps,
            max_offset_per_tx_bps,
            max_offset_per_epoch_bps,
            ops_floor_fixed_agrs,
            reserve_target_agrs,
            carry_cap_agrs,
            share_rate_k,
            payout_lock_epochs,
        })
    }

    /// POLICY-SET (genesis): surplus fraction that is burned directly.
    ///
    /// Rationale: explicit value-capture lane (scarcity) that does not depend on auction demand.
    pub fn burn_surplus_bps(&self) -> Bps {
        self.burn_surplus_bps
    }

    /// POLICY-SET (genesis): surplus fraction routed to the BCR reverse auction budget.
    ///
    /// Rationale: turns “fees not burned” into a deterministic payout lane for BCR sellers.
    pub fn auction_surplus_bps(&self) -> Bps {
        self.auction_surplus_bps
    }

    /// POLICY-SET (genesis): percentage-based ops floor from net protocol fees.
    ///
    /// Rationale: ensures a minimum operator funding rail when revenue is healthy, while
    /// still bounding spend by `F_net`.
    pub fn ops_pay_bps(&self) -> Bps {
        self.ops_pay_bps
    }

    /// POLICY-SET (genesis): ops-budget slice reserved for protocol overhead (not payroll).
    ///
    /// Rationale: funds shared infra / safety operations without diluting tip-based cashflow.
    pub fn overhead_bps(&self) -> Bps {
        self.overhead_bps
    }

    /// POLICY-SET (genesis): per-epoch BCR drip rate as bps of staked AGRS.
    ///
    /// Rationale: deterministic staking incentive that mints offset/auctionable credit over time.
    pub fn drip_rate_bps(&self) -> Bps {
        self.drip_rate_bps
    }

    /// POLICY-SET (genesis): per-transaction maximum BCR offset, as bps of the base fee.
    ///
    /// Rationale: offsets can only discount protocol revenue (base fee), never the tip lane;
    /// this cap prevents “free base fee” transactions and preserves budget signal.
    pub fn max_offset_per_tx_bps(&self) -> Bps {
        self.max_offset_per_tx_bps
    }

    /// POLICY-SET (genesis): per-epoch maximum total offsets, as bps of base-fee gross.
    ///
    /// Rationale: limits how much protocol revenue can be offset in aggregate, preventing a
    /// single epoch from draining ops/reserve/burn/auction budgets via offsets.
    pub fn max_offset_per_epoch_bps(&self) -> Bps {
        self.max_offset_per_epoch_bps
    }

    /// POLICY-SET (genesis): absolute ops budget floor per epoch (in AGRS).
    ///
    /// Rationale: keeps a minimal payroll lane alive during low-fee periods to avoid a
    /// “death spiral” where service degrades because fees are temporarily low.
    pub fn ops_floor_fixed_agrs(&self) -> Agrs {
        self.ops_floor_fixed_agrs
    }

    /// POLICY-SET (genesis): maximum reserve intake per epoch (in AGRS).
    ///
    /// Rationale: smooths reserve growth and leaves remaining net fees available for
    /// the burn/auction/unallocated lanes.
    pub fn reserve_target_agrs(&self) -> Agrs {
        self.reserve_target_agrs
    }

    /// POLICY-SET (genesis): maximum auction carry-forward per epoch (in AGRS).
    ///
    /// Rationale: carry prevents “dust loss” when budget doesn't clear, while the cap
    /// prevents indefinite hoarding; excess beyond the cap is burned.
    pub fn carry_cap_agrs(&self) -> Agrs {
        self.carry_cap_agrs
    }

    /// POLICY-SET (genesis): share-rate ratchet scaling constant `K` (> 0).
    ///
    /// Rationale: makes shares harder to mint as `total_shares_issued` grows, rewarding
    /// earlier/longer stakes and preventing runaway share inflation.
    pub fn share_rate_k(&self) -> u64 {
        self.share_rate_k
    }

    /// POLICY-SET (genesis): number of epochs auction payouts remain locked.
    ///
    /// Rationale: enforces a deterministic settlement delay for the auction payout lane and
    /// reduces immediate sell-pressure reflexivity from freshly paid-out AGRS.
    pub fn payout_lock_epochs(&self) -> u16 {
        self.payout_lock_epochs
    }
}
