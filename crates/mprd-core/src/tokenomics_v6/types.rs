use crate::{hash, Hash32, MprdError, Result};
use thiserror::Error;

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

// =============================================================================
// Algorithmic CEO: CBC Lattice Types (Safe Menu Graph)
// =============================================================================
//
// These types represent the state space for the Algorithmic CEO's setpoint
// decisions. All invariants are enforced at construction time, making invalid
// states unrepresentable.
//
// Coordinate system (normalized to step sizes):
//   BurnPct:    units ∈ [0,45]  → bps ∈ [5000, 9500], step 100
//   AuctionPct: units ∈ [5,50]  → bps ∈ [500, 5000], step 100
//   DripStep:   units ∈ [1,20]  → bps ∈ [5, 100], step 5
//
// See: internal/specs/mprd_ceo_menu_graph_proofs.lean

/// Burn surplus percentage in lattice units.
/// - units ∈ [0, 45] → bps ∈ [5000, 9500] (step 100)
/// - CBC: construction fails if out of range
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BurnPct(u8);

impl BurnPct {
    pub const MIN_UNITS: u8 = 0;
    pub const MAX_UNITS: u8 = 45;
    pub const MIN_BPS: u16 = 5000;
    pub const MAX_BPS: u16 = 9500;
    pub const STEP_BPS: u16 = 100;

    /// Constructs a BurnPct from lattice units.
    ///
    /// Preconditions:
    /// - `units <= 45`
    ///
    /// Postconditions:
    /// - `to_bps()` returns value in [5000, 9500]
    pub fn new(units: u8) -> Result<Self> {
        if units <= Self::MAX_UNITS {
            Ok(Self(units))
        } else {
            Err(MprdError::InvalidInput(format!(
                "BurnPct units {units} exceeds max {}",
                Self::MAX_UNITS
            )))
        }
    }

    pub fn units(self) -> u8 {
        self.0
    }

    pub fn to_bps(self) -> Bps {
        // Safe: 5000 + 45*100 = 9500 <= 10000
        Bps(Self::MIN_BPS + self.0 as u16 * Self::STEP_BPS)
    }

    /// Apply a step delta, returning None if result would be out of bounds.
    pub fn apply_step(self, delta: Step) -> Option<Self> {
        let new_units = match delta {
            Step::Neg => self.0.checked_sub(1)?,
            Step::Zero => self.0,
            Step::Pos => {
                let u = self.0.checked_add(1)?;
                if u > Self::MAX_UNITS {
                    return None;
                }
                u
            }
        };
        Some(Self(new_units))
    }
}

/// Auction surplus percentage in lattice units.
/// - units ∈ [5, 50] → bps ∈ [500, 5000] (step 100)
/// - CBC: construction fails if out of range
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuctionPct(u8);

impl AuctionPct {
    pub const MIN_UNITS: u8 = 5;
    pub const MAX_UNITS: u8 = 50;
    pub const MIN_BPS: u16 = 500;
    pub const MAX_BPS: u16 = 5000;
    pub const STEP_BPS: u16 = 100;

    /// Constructs an AuctionPct from lattice units.
    ///
    /// Preconditions:
    /// - `units >= 5 && units <= 50`
    ///
    /// Postconditions:
    /// - `to_bps()` returns value in [500, 5000]
    pub fn new(units: u8) -> Result<Self> {
        if (Self::MIN_UNITS..=Self::MAX_UNITS).contains(&units) {
            Ok(Self(units))
        } else {
            Err(MprdError::InvalidInput(format!(
                "AuctionPct units {units} not in [{}, {}]",
                Self::MIN_UNITS,
                Self::MAX_UNITS
            )))
        }
    }

    pub fn units(self) -> u8 {
        self.0
    }

    pub fn to_bps(self) -> Bps {
        // Safe: 50*100 = 5000 <= 10000
        Bps(self.0 as u16 * Self::STEP_BPS)
    }

    /// Apply a step delta, returning None if result would be out of bounds.
    pub fn apply_step(self, delta: Step) -> Option<Self> {
        let new_units = match delta {
            Step::Neg => {
                let u = self.0.checked_sub(1)?;
                if u < Self::MIN_UNITS {
                    return None;
                }
                u
            }
            Step::Zero => self.0,
            Step::Pos => {
                let u = self.0.checked_add(1)?;
                if u > Self::MAX_UNITS {
                    return None;
                }
                u
            }
        };
        Some(Self(new_units))
    }
}

/// Drip rate in lattice units.
/// - units ∈ [1, 20] → bps ∈ [5, 100] (step 5)
/// - CBC: construction fails if out of range
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DripStep(u8);

impl DripStep {
    pub const MIN_UNITS: u8 = 1;
    pub const MAX_UNITS: u8 = 20;
    pub const MIN_BPS: u16 = 5;
    pub const MAX_BPS: u16 = 100;
    pub const STEP_BPS: u16 = 5;

    /// Constructs a DripStep from lattice units.
    ///
    /// Preconditions:
    /// - `units >= 1 && units <= 20`
    ///
    /// Postconditions:
    /// - `to_bps()` returns value in [5, 100]
    pub fn new(units: u8) -> Result<Self> {
        if (Self::MIN_UNITS..=Self::MAX_UNITS).contains(&units) {
            Ok(Self(units))
        } else {
            Err(MprdError::InvalidInput(format!(
                "DripStep units {units} not in [{}, {}]",
                Self::MIN_UNITS,
                Self::MAX_UNITS
            )))
        }
    }

    pub fn units(self) -> u8 {
        self.0
    }

    pub fn to_bps(self) -> Bps {
        // Safe: 20*5 = 100 <= 10000
        Bps(self.0 as u16 * Self::STEP_BPS)
    }

    /// Apply a step delta, returning None if result would be out of bounds.
    pub fn apply_step(self, delta: Step) -> Option<Self> {
        let new_units = match delta {
            Step::Neg => {
                let u = self.0.checked_sub(1)?;
                if u < Self::MIN_UNITS {
                    return None;
                }
                u
            }
            Step::Zero => self.0,
            Step::Pos => {
                let u = self.0.checked_add(1)?;
                if u > Self::MAX_UNITS {
                    return None;
                }
                u
            }
        };
        Some(Self(new_units))
    }
}

/// Step direction for lattice transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    Neg,
    Zero,
    Pos,
}

/// Domain errors for the Algorithmic CEO safe menu lattice.
///
/// These errors are intended for boundary validation and must be stable enough for tests
/// to match on variants (avoid stringly-typed error handling).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum DomainError {
    #[error("split cap exceeded: burn {burn_bps} + auction {auction_bps} > {cap_bps}")]
    SplitCapExceeded {
        burn_bps: u16,
        auction_bps: u16,
        cap_bps: u16,
    },

    #[error("burn step out of bounds: from_units={from_units} delta={delta:?}")]
    BurnStepOutOfBounds { from_units: u8, delta: Step },

    #[error("auction step out of bounds: from_units={from_units} delta={delta:?}")]
    AuctionStepOutOfBounds { from_units: u8, delta: Step },

    #[error("drip step out of bounds: from_units={from_units} delta={delta:?}")]
    DripStepOutOfBounds { from_units: u8, delta: Step },
}

/// CBC-validated split (burn + auction <= 10,000 bps).
/// - Constructs only if the combined bps satisfies the split cap
/// - Once constructed, the invariant is guaranteed
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ValidSplit {
    burn: BurnPct,
    auction: AuctionPct,
}

impl ValidSplit {
    /// Constructs a ValidSplit, enforcing the split cap invariant.
    ///
    /// Preconditions:
    /// - `burn.to_bps() + auction.to_bps() <= 10_000`
    ///
    /// Postconditions:
    /// - The invariant is satisfied for the lifetime of this value
    pub fn new(burn: BurnPct, auction: AuctionPct) -> std::result::Result<Self, DomainError> {
        let burn_bps = burn.to_bps().get();
        let auction_bps = auction.to_bps().get();
        if (burn_bps as u32).saturating_add(auction_bps as u32) <= (BPS_U16 as u32) {
            Ok(Self { burn, auction })
        } else {
            Err(DomainError::SplitCapExceeded {
                burn_bps,
                auction_bps,
                cap_bps: BPS_U16,
            })
        }
    }

    pub fn burn(&self) -> BurnPct {
        self.burn
    }

    pub fn auction(&self) -> AuctionPct {
        self.auction
    }
}

/// A node in the CEO menu graph (setpoint bundle).
/// - CBC: all invariants enforced at construction
/// - Immutable once created
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MenuNode {
    split: ValidSplit,
    drip: DripStep,
}

impl MenuNode {
    /// Constructs a MenuNode from a valid split and drip step.
    pub fn new(split: ValidSplit, drip: DripStep) -> Self {
        Self { split, drip }
    }

    pub fn split(&self) -> ValidSplit {
        self.split
    }

    pub fn drip(&self) -> DripStep {
        self.drip
    }

    pub fn burn_bps(&self) -> Bps {
        self.split.burn.to_bps()
    }

    pub fn auction_bps(&self) -> Bps {
        self.split.auction.to_bps()
    }

    pub fn drip_bps(&self) -> Bps {
        self.drip.to_bps()
    }

    /// Stable key for hashing/indexing (coordinate-derived).
    /// Encoding: (burn_units << 16) | (auction_units << 8) | drip_units
    pub fn key(&self) -> u32 {
        let b = self.split.burn.units() as u32;
        let a = self.split.auction.units() as u32;
        let d = self.drip.units() as u32;
        (b << 16) | (a << 8) | d
    }

    /// Apply a delta (3D step), returning `Err(_)` if any step fails or split cap is violated.
    pub fn apply_delta(&self, delta: &Delta) -> std::result::Result<MenuNode, DomainError> {
        let burn =
            self.split
                .burn
                .apply_step(delta.db)
                .ok_or(DomainError::BurnStepOutOfBounds {
                    from_units: self.split.burn.units(),
                    delta: delta.db,
                })?;

        let auction =
            self.split
                .auction
                .apply_step(delta.da)
                .ok_or(DomainError::AuctionStepOutOfBounds {
                    from_units: self.split.auction.units(),
                    delta: delta.da,
                })?;

        let drip = self
            .drip
            .apply_step(delta.dd)
            .ok_or(DomainError::DripStepOutOfBounds {
                from_units: self.drip.units(),
                delta: delta.dd,
            })?;

        let split = ValidSplit::new(burn, auction)?;
        Ok(MenuNode { split, drip })
    }
}

/// A delta in lattice space: (Δburn, Δauction, Δdrip) ∈ {-1, 0, 1}³
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Delta {
    pub db: Step,
    pub da: Step,
    pub dd: Step,
}

impl Delta {
    pub const NOOP: Delta = Delta {
        db: Step::Zero,
        da: Step::Zero,
        dd: Step::Zero,
    };
}

/// ActionId: One of 27 possible actions = deltas in {-1,0,1}³.
/// Encoding: (db+1)*9 + (da+1)*3 + (dd+1)
/// NoOp (0,0,0) = index 13
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ActionId(u8);

impl ActionId {
    pub const COUNT: usize = 27;

    /// NoOp action: no change to any setpoint
    pub const NOOP: ActionId = ActionId(13);

    /// Constructs an ActionId from an index in [0, 27).
    pub fn new(index: u8) -> Result<Self> {
        if (index as usize) < Self::COUNT {
            Ok(Self(index))
        } else {
            Err(MprdError::InvalidInput(format!(
                "ActionId {index} out of range [0, 27)"
            )))
        }
    }

    pub fn index(self) -> u8 {
        self.0
    }

    /// Iterate over all valid action IDs in ascending index order.
    pub fn iter() -> impl Iterator<Item = ActionId> {
        (0u8..(Self::COUNT as u8)).map(ActionId)
    }

    /// Decode to Delta.
    pub fn to_delta(self) -> Delta {
        let idx = self.0;
        let db = match idx / 9 {
            0 => Step::Neg,
            1 => Step::Zero,
            2 => Step::Pos,
            _ => Step::Pos, // unreachable given ActionId invariant
        };
        let da = match (idx / 3) % 3 {
            0 => Step::Neg,
            1 => Step::Zero,
            2 => Step::Pos,
            _ => Step::Pos, // unreachable given ActionId invariant
        };
        let dd = match idx % 3 {
            0 => Step::Neg,
            1 => Step::Zero,
            2 => Step::Pos,
            _ => Step::Pos, // unreachable given ActionId invariant
        };
        Delta { db, da, dd }
    }

    /// Encode from Delta.
    pub fn from_delta(delta: &Delta) -> Self {
        let db = match delta.db {
            Step::Neg => 0,
            Step::Zero => 1,
            Step::Pos => 2,
        };
        let da = match delta.da {
            Step::Neg => 0,
            Step::Zero => 1,
            Step::Pos => 2,
        };
        let dd = match delta.dd {
            Step::Neg => 0,
            Step::Zero => 1,
            Step::Pos => 2,
        };
        ActionId(db * 9 + da * 3 + dd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burnpct_bounds_and_mapping() {
        assert!(BurnPct::new(BurnPct::MIN_UNITS).is_ok());
        assert!(BurnPct::new(BurnPct::MAX_UNITS).is_ok());
        assert!(BurnPct::new(BurnPct::MAX_UNITS + 1).is_err());

        let b0 = BurnPct::new(0).unwrap();
        let bmax = BurnPct::new(BurnPct::MAX_UNITS).unwrap();
        assert_eq!(b0.to_bps().get(), BurnPct::MIN_BPS);
        assert_eq!(bmax.to_bps().get(), BurnPct::MAX_BPS);
    }

    #[test]
    fn auctionpct_bounds_and_mapping() {
        assert!(AuctionPct::new(AuctionPct::MIN_UNITS).is_ok());
        assert!(AuctionPct::new(AuctionPct::MAX_UNITS).is_ok());
        assert!(AuctionPct::new(AuctionPct::MIN_UNITS - 1).is_err());
        assert!(AuctionPct::new(AuctionPct::MAX_UNITS + 1).is_err());

        let amin = AuctionPct::new(AuctionPct::MIN_UNITS).unwrap();
        let amax = AuctionPct::new(AuctionPct::MAX_UNITS).unwrap();
        assert_eq!(amin.to_bps().get(), AuctionPct::MIN_BPS);
        assert_eq!(amax.to_bps().get(), AuctionPct::MAX_BPS);
    }

    #[test]
    fn dripstep_bounds_and_mapping() {
        assert!(DripStep::new(DripStep::MIN_UNITS).is_ok());
        assert!(DripStep::new(DripStep::MAX_UNITS).is_ok());
        assert!(DripStep::new(DripStep::MIN_UNITS - 1).is_err());
        assert!(DripStep::new(DripStep::MAX_UNITS + 1).is_err());

        let dmin = DripStep::new(DripStep::MIN_UNITS).unwrap();
        let dmax = DripStep::new(DripStep::MAX_UNITS).unwrap();
        assert_eq!(dmin.to_bps().get(), DripStep::MIN_BPS);
        assert_eq!(dmax.to_bps().get(), DripStep::MAX_BPS);
    }

    #[test]
    fn validsplit_enforces_split_cap() {
        let burn = BurnPct::new(45).unwrap(); // 9500
        let auction_ok = AuctionPct::new(5).unwrap(); // 500
        let auction_bad = AuctionPct::new(6).unwrap(); // 600

        assert!(ValidSplit::new(burn, auction_ok).is_ok());
        assert!(matches!(
            ValidSplit::new(burn, auction_bad),
            Err(DomainError::SplitCapExceeded { .. })
        ));
    }

    #[test]
    fn menu_node_key_is_canonical() {
        let burn = BurnPct::new(10).unwrap();
        let auction = AuctionPct::new(10).unwrap();
        let drip = DripStep::new(10).unwrap();
        let split = ValidSplit::new(burn, auction).unwrap();
        let node = MenuNode::new(split, drip);

        let expected_key =
            (burn.units() as u32) << 16 | (auction.units() as u32) << 8 | (drip.units() as u32);
        assert_eq!(node.key(), expected_key);
    }

    #[test]
    fn apply_delta_fails_closed_on_bounds_and_cap() {
        let burn = BurnPct::new(BurnPct::MIN_UNITS).unwrap();
        let auction = AuctionPct::new(AuctionPct::MIN_UNITS).unwrap();
        let drip = DripStep::new(DripStep::MIN_UNITS).unwrap();
        let split = ValidSplit::new(burn, auction).unwrap();
        let node = MenuNode::new(split, drip);

        // Bounds: cannot step below mins.
        let delta_below = Delta {
            db: Step::Neg,
            da: Step::Neg,
            dd: Step::Neg,
        };
        assert!(matches!(
            node.apply_delta(&delta_below),
            Err(DomainError::BurnStepOutOfBounds { .. })
        ));

        // Split cap: (44, 6) is valid (9400 + 600 = 10_000), but stepping burn up violates.
        let burn_cap = BurnPct::new(44).unwrap();
        let auction_cap = AuctionPct::new(6).unwrap();
        let split_cap = ValidSplit::new(burn_cap, auction_cap).unwrap();
        let node_cap = MenuNode::new(split_cap, drip);
        let delta_violate_cap = Delta {
            db: Step::Pos,
            da: Step::Zero,
            dd: Step::Zero,
        };
        assert!(matches!(
            node_cap.apply_delta(&delta_violate_cap),
            Err(DomainError::SplitCapExceeded { .. })
        ));
    }

    #[test]
    fn action_id_noop_is_center_of_encoding() {
        assert_eq!(ActionId::NOOP.index(), 13);
        assert_eq!(ActionId::from_delta(&Delta::NOOP), ActionId::NOOP);
        assert_eq!(ActionId::NOOP.to_delta(), Delta::NOOP);
    }
}
