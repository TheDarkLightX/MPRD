use std::collections::{BTreeMap, BTreeSet};

use crate::{Hash32, MprdError, Result};

use super::auction::{
    apply_carry_cap, clear_prefix_budget, payout_for, AuctionBid, AuctionOutcome,
};
use super::bounds::RuntimeBoundsV6;
use super::math::{add_u64, floor_bps, rage_quit_penalty_linear, sub_u64};
use super::types::{
    Agrs, AgrsPerBcr, Bcr, Bps, EpochId, OperatorId, ParamsV6, Shares, StakeId, StakeStartOutcome,
    StakeStatus,
};

/// Per-transaction service payment input.
///
/// v6 has two fee lanes:
/// - `base_fee_agrs`: protocol lane (contributes to epoch budgets; offsettable by BCR within caps)
/// - `tip_agrs`: tip lane (MARKET-DETERMINED; flows directly to the servicer; never offsettable)
///
/// Contract: this engine does not de-duplicate transactions; callers must enforce anti-replay
/// (e.g., uniqueness of `nonce`) at the policy/boundary layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceTx {
    /// Operator paying the base fee (and optionally requesting an offset).
    pub payer: OperatorId,
    /// Operator who provided the service and receives the tip + payroll attribution.
    pub servicer: OperatorId,
    /// Protocol base fee (input from fee policy / market outside this kernel).
    pub base_fee_agrs: Agrs,
    /// Tip lane: MARKET-DETERMINED.
    /// Operators set tips; users choose whether to pay them.
    /// Tips bypass protocol budgets and flow directly to the servicer.
    pub tip_agrs: Agrs,
    /// User-chosen BCR offset request (in AGRS-equivalent units), bounded by v6 caps.
    /// Offsets burn BCR and discount only the base fee (never the tip lane).
    pub offset_request_bcr: Bcr,
    /// Metered service work units for epoch payroll attribution (not a price signal).
    pub work_units: u64,
    /// Anti-replay / audit identifier (must be unique per `apply_service_tx` at the boundary).
    pub nonce: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpsPayrollOutcome {
    /// Pool available for payroll payouts (derived from `EpochBudgetsV6::ops_payroll`).
    pub ops_payroll_pool: Agrs,
    /// Total AGRS paid out to operators this epoch.
    pub payout_total: Agrs,
    /// Unpaid remainder routed to the reserve (conservation: `payout_total + carry_to_reserve = pool`).
    pub carry_to_reserve: Agrs,
}

/// Per-epoch budgets computed from the v6 fee split.
///
/// Conservation (deterministic):
/// `ops_budget + reserve_budget + burn_surplus + auction_new + unallocated = f_net`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochBudgetsV6 {
    /// Protocol base fee gross for the epoch (before BCR offsets).
    pub f_base_gross: Agrs,
    /// Tip lane total: MARKET-DETERMINED and excluded from protocol budgets.
    pub f_tip: Agrs,
    /// Total offsets applied this epoch (burned BCR, expressed in AGRS-equivalent units).
    pub offset_total: Agrs,
    /// Net protocol fees after offsets: `f_base_gross - offset_total`.
    pub f_net: Agrs,

    /// Ops budget drawn from `f_net` (policy floor and `f_net`-bounded).
    pub ops_budget: Agrs,
    /// Protocol overhead carved out of ops budget (policy-set bps).
    pub ops_overhead: Agrs,
    /// Ops payroll pool paid out pro-rata by `work_units × opi_bps`.
    pub ops_payroll: Agrs,
    /// Reserve intake (capped by `reserve_target_agrs`).
    pub reserve_budget: Agrs,

    /// Direct burn lane from surplus (policy-set bps).
    pub burn_surplus: Agrs,
    /// New auction budget from surplus (policy-set bps; does not include carry-in).
    pub auction_new: Agrs,
    /// Surplus remainder not assigned to burn/auction (explicitly tracked for auditability).
    pub unallocated: Agrs,
}

#[derive(Clone, Debug)]
struct EpochAgg {
    base_fees_gross: u64,
    tips_gross: u64,
    offset_total: u64,
    work_units_by_operator: BTreeMap<OperatorId, u64>,
    drip_applied: bool,
}

impl Default for EpochAgg {
    fn default() -> Self {
        Self {
            base_fees_gross: 0,
            tips_gross: 0,
            offset_total: 0,
            work_units_by_operator: BTreeMap::new(),
            drip_applied: false,
        }
    }
}

#[derive(Clone, Debug)]
struct ActiveStake {
    amount_agrs: u64,
    lock_epochs: u64,
    start_epoch: u64,
    shares: u64,
    status: StakeStatus,
}

#[derive(Clone, Debug)]
struct OperatorState {
    agrs_balance: u64,
    shares_active: u64,
    bcr_balance: u64,
    bcr_escrow: u64,
    opi_bps: Bps,
    stakes: BTreeMap<StakeId, ActiveStake>,
    locked_agrs: BTreeMap<EpochId, u64>,
}

impl OperatorState {
    fn new() -> OperatorState {
        OperatorState {
            agrs_balance: 0,
            shares_active: 0,
            bcr_balance: 0,
            bcr_escrow: 0,
            opi_bps: Bps::MAX, // default to 100% unless set by policy
            stakes: BTreeMap::new(),
            locked_agrs: BTreeMap::new(),
        }
    }
}

/// MPRD Tokenomics v6 engine (pure, deterministic state machine).
///
/// Separation of concerns:
/// - POLICY-SET inputs: `ParamsV6` (budgets, caps, ratchets, locks).
/// - MARKET-DETERMINED inputs: `ServiceTx::tip_agrs` and auction bids (see `auction` module).
/// - SAFETY BOUNDS: `RuntimeBoundsV6` (caps state size / worst-case runtime; not economic).
#[derive(Clone, Debug)]
pub struct TokenomicsV6 {
    params: ParamsV6,
    bounds: RuntimeBoundsV6,
    epoch: EpochId,

    // Monotone accumulator used for the share-rate ratchet.
    total_shares_issued: u64,

    // Current epoch auction carry (already capped). After settlement this becomes the next epoch carry.
    auction_carry: u64,

    // Per-epoch aggregates (reset on `advance_epoch`).
    epoch_agg: EpochAgg,

    // Cached per-epoch budgets (computed once after epoch close).
    budgets: Option<EpochBudgetsV6>,
    payroll_settled: bool,
    auction_settled: bool,

    // Auction bids for this epoch (revealed; BCR is escrowed on reveal).
    bids: Vec<AuctionBid>,

    // Accounts / totals.
    burned_total: u64,
    reserve_balance: u64,
    unallocated_balance: u64,

    operators: BTreeMap<OperatorId, OperatorState>,
}

impl TokenomicsV6 {
    /// Creates a new engine instance at epoch 0.
    ///
    /// Safety bounds are initialized to `RuntimeBoundsV6::default()` and can be tightened
    /// via `set_bounds`.
    pub fn new(params: ParamsV6) -> TokenomicsV6 {
        TokenomicsV6 {
            params,
            bounds: RuntimeBoundsV6::default(),
            epoch: EpochId(0),
            total_shares_issued: 0,
            auction_carry: 0,
            epoch_agg: EpochAgg::default(),
            budgets: None,
            payroll_settled: false,
            auction_settled: false,
            bids: Vec::new(),
            burned_total: 0,
            reserve_balance: 0,
            unallocated_balance: 0,
            operators: BTreeMap::new(),
        }
    }

    /// Creates a new engine instance with explicit safety bounds.
    ///
    /// `RuntimeBoundsV6` is BOUNDED BY SAFETY LIMITS (state size / runtime), not a policy
    /// parameter and not a market outcome.
    pub fn new_with_bounds(params: ParamsV6, bounds: RuntimeBoundsV6) -> Result<TokenomicsV6> {
        bounds.validate()?;
        Ok(TokenomicsV6 {
            params,
            bounds,
            epoch: EpochId(0),
            total_shares_issued: 0,
            auction_carry: 0,
            epoch_agg: EpochAgg::default(),
            budgets: None,
            payroll_settled: false,
            auction_settled: false,
            bids: Vec::new(),
            burned_total: 0,
            reserve_balance: 0,
            unallocated_balance: 0,
            operators: BTreeMap::new(),
        })
    }

    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    pub fn params(&self) -> &ParamsV6 {
        &self.params
    }

    pub fn bounds(&self) -> RuntimeBoundsV6 {
        self.bounds
    }

    /// Updates safety bounds for state size / runtime.
    ///
    /// Contract: bounds are validated before being installed (fail-closed).
    pub fn set_bounds(&mut self, bounds: RuntimeBoundsV6) -> Result<()> {
        bounds.validate()?;
        self.bounds = bounds;
        Ok(())
    }

    /// Admits a new operator account.
    ///
    /// Safety bound: `bounds.max_operators` caps state growth and worst-case computation.
    pub fn admit_operator(&mut self, operator: OperatorId) -> Result<()> {
        if self.operators.contains_key(&operator) {
            return Err(MprdError::InvalidInput("operator already admitted".into()));
        }
        if self.operators.len() >= self.bounds.max_operators {
            return Err(MprdError::BoundedValueExceeded(
                "max operators exceeded".into(),
            ));
        }
        self.operators.insert(operator, OperatorState::new());
        Ok(())
    }

    /// Credits liquid AGRS to an operator (boundary IO; e.g., deposits/mints).
    ///
    /// Preconditions:
    /// - `operator` is admitted.
    pub fn credit_agrs(&mut self, operator: OperatorId, amt: Agrs) -> Result<()> {
        let op = self
            .operators
            .get_mut(&operator)
            .ok_or_else(|| MprdError::InvalidInput("unknown operator".into()))?;
        op.agrs_balance = add_u64(op.agrs_balance, amt.get())?;
        Ok(())
    }

    /// Sets an operator's OPI weight (bps).
    ///
    /// OPI is POLICY-SET / policy-gated (e.g., derived from slashing/quality rules), not market.
    /// It affects payroll attribution but does not affect the tip lane.
    pub fn set_opi(&mut self, operator: OperatorId, opi_bps: Bps) -> Result<()> {
        let op = self
            .operators
            .get_mut(&operator)
            .ok_or_else(|| MprdError::InvalidInput("unknown operator".into()))?;
        op.opi_bps = opi_bps;
        Ok(())
    }

    pub fn bcr_balance(&self, operator: OperatorId) -> Result<Bcr> {
        let op = self
            .operators
            .get(&operator)
            .ok_or_else(|| MprdError::InvalidInput("unknown operator".into()))?;
        Ok(Bcr::new(op.bcr_balance))
    }

    pub fn agrs_balance(&self, operator: OperatorId) -> Result<Agrs> {
        let op = self
            .operators
            .get(&operator)
            .ok_or_else(|| MprdError::InvalidInput("unknown operator".into()))?;
        Ok(Agrs::new(op.agrs_balance))
    }

    pub fn stake_start(
        &mut self,
        operator: OperatorId,
        stake_amount: Agrs,
        lock_epochs: u16,
        nonce: Hash32,
    ) -> Result<StakeStartOutcome> {
        // Preconditions:
        // - epoch is open (no budget finalization yet)
        // - `stake_amount > 0`, `lock_epochs > 0`
        // - operator has sufficient AGRS and stays within safety bounds
        //
        // Postconditions:
        // - AGRS is escrowed into an active stake and S-Shares are minted deterministically
        //
        // Rationale: share minting uses a monotone ratchet (`share_rate_k`) so later stakes mint
        // fewer shares, preventing cheap dilution of long-lived stake weight.
        self.ensure_epoch_open()?;
        let op = self
            .operators
            .get_mut(&operator)
            .ok_or_else(|| MprdError::InvalidInput("unknown operator".into()))?;
        // Safety bound: caps per-operator stake state size (DoS resistance).
        if op.stakes.len() >= self.bounds.max_stakes_per_operator {
            return Err(MprdError::BoundedValueExceeded(
                "max stakes per operator exceeded".into(),
            ));
        }
        if stake_amount.get() == 0 {
            return Err(MprdError::InvalidInput("stake_amount must be > 0".into()));
        }
        if lock_epochs == 0 {
            return Err(MprdError::InvalidInput("lock_epochs must be > 0".into()));
        }

        if op.agrs_balance < stake_amount.get() {
            return Err(MprdError::InvalidInput("insufficient AGRS to stake".into()));
        }
        let shares_minted = super::math::shares_minted(
            stake_amount.get(),
            lock_epochs as u64,
            self.total_shares_issued,
            self.params.share_rate_k(),
        )?;
        let stake_id = StakeId::derive(operator, self.epoch.0, nonce);
        if op.stakes.contains_key(&stake_id) {
            return Err(MprdError::InvalidInput("stake_id collision".into()));
        }

        // Commit after all fallible computations.
        op.agrs_balance = sub_u64(op.agrs_balance, stake_amount.get())?;
        self.total_shares_issued = add_u64(self.total_shares_issued, shares_minted)?;
        let stake = ActiveStake {
            amount_agrs: stake_amount.get(),
            lock_epochs: lock_epochs as u64,
            start_epoch: self.epoch.0,
            shares: shares_minted,
            status: StakeStatus::Active,
        };
        op.shares_active = add_u64(op.shares_active, shares_minted)?;
        op.stakes.insert(stake_id, stake);

        Ok(StakeStartOutcome {
            stake_id,
            shares_minted: Shares::new(shares_minted),
        })
    }

    pub fn stake_end(&mut self, operator: OperatorId, stake_id: StakeId) -> Result<()> {
        // Postconditions (on success):
        // - stake shares are removed (supply decreases)
        // - a linear rage-quit penalty is routed into the auction carry (capped) with excess burned
        //
        // Rationale: exiting early is not a free option; penalties recycle value to the auction/burn
        // lanes instead of being refundable.
        self.ensure_epoch_open()?;
        let op = self
            .operators
            .get_mut(&operator)
            .ok_or_else(|| MprdError::InvalidInput("unknown operator".into()))?;
        let stake = op
            .stakes
            .get(&stake_id)
            .cloned()
            .ok_or_else(|| MprdError::InvalidInput("unknown stake_id".into()))?;
        if stake.status != StakeStatus::Active {
            return Err(MprdError::InvalidInput("stake not active".into()));
        }

        let elapsed = self.epoch.0.saturating_sub(stake.start_epoch);
        let penalty = rage_quit_penalty_linear(stake.amount_agrs, stake.lock_epochs, elapsed)?;
        let refund = sub_u64(stake.amount_agrs, penalty)?;

        let new_agrs_balance = add_u64(op.agrs_balance, refund)?;
        let new_shares_active = sub_u64(op.shares_active, stake.shares)?;
        let (new_carry, new_burned) = compute_new_carry_and_burn(
            self.auction_carry,
            self.burned_total,
            penalty,
            self.params.carry_cap_agrs().get(),
        )?;

        // Commit.
        op.agrs_balance = new_agrs_balance;
        op.shares_active = new_shares_active;
        self.auction_carry = new_carry;
        self.burned_total = new_burned;
        let _ = op.stakes.remove(&stake_id);
        Ok(())
    }

    pub fn accrue_bcr_drip(&mut self) -> Result<()> {
        // Contract: may be applied at most once per epoch (deterministic BCR supply schedule).
        //
        // Rationale: drip makes BCR accrual predictable and policy-shaped (`drip_rate_bps`),
        // providing a steady source of offsets/auction supply for stakers.
        self.ensure_epoch_open()?;
        if self.epoch_agg.drip_applied {
            return Err(MprdError::InvalidInput(
                "bcr drip already applied this epoch".into(),
            ));
        }
        let drip_bps = self.params.drip_rate_bps();
        let mut updates: Vec<(OperatorId, u64)> = Vec::with_capacity(self.operators.len());
        for (oid, op) in &self.operators {
            let mut drip_total: u64 = 0;
            for st in op.stakes.values() {
                if st.status != StakeStatus::Active {
                    continue;
                }
                drip_total = add_u64(drip_total, floor_bps(st.amount_agrs, drip_bps)?)?;
            }
            updates.push((*oid, add_u64(op.bcr_balance, drip_total)?));
        }
        for (oid, new_balance) in updates {
            let op = self
                .operators
                .get_mut(&oid)
                .ok_or_else(|| MprdError::InvalidInput("unknown operator".into()))?;
            op.bcr_balance = new_balance;
        }
        self.epoch_agg.drip_applied = true;
        Ok(())
    }

    /// Applies a service transaction to epoch accounting.
    ///
    /// Preconditions:
    /// - epoch is open and `payer`/`servicer` are admitted
    /// - offsets are within per-tx and per-epoch caps and are backed by payer BCR
    ///
    /// Postconditions:
    /// - `base_fee_agrs` and offsets affect protocol budgets; `tip_agrs` is paid immediately
    /// - payer's BCR decreases by `offset_request_bcr` (BCR is burned on use)
    pub fn apply_service_tx(&mut self, tx: ServiceTx) -> Result<()> {
        self.ensure_epoch_open()?;
        if !self.operators.contains_key(&tx.payer) {
            return Err(MprdError::InvalidInput("unknown payer".into()));
        }
        if !self.operators.contains_key(&tx.servicer) {
            return Err(MprdError::InvalidInput("unknown servicer".into()));
        }

        let new_base_gross = add_u64(self.epoch_agg.base_fees_gross, tx.base_fee_agrs.get())?;

        // Per-epoch offset cap is a function of base fee gross (including this tx).
        let epoch_cap = floor_bps(new_base_gross, self.params.max_offset_per_epoch_bps())?;

        // Per-tx offset cap is a function of this tx's base fee.
        let tx_cap = floor_bps(tx.base_fee_agrs.get(), self.params.max_offset_per_tx_bps())?;
        if tx.offset_request_bcr.get() > tx_cap {
            return Err(MprdError::InvalidInput(
                "offset_request exceeds per-tx cap".into(),
            ));
        }

        let new_offset_total = add_u64(self.epoch_agg.offset_total, tx.offset_request_bcr.get())?;
        if new_offset_total > epoch_cap {
            return Err(MprdError::InvalidInput(
                "offset_request exceeds epoch cap".into(),
            ));
        }

        let payer_prev_bcr = self
            .operators
            .get(&tx.payer)
            .ok_or_else(|| MprdError::InvalidInput("unknown payer".into()))?
            .bcr_balance;
        if payer_prev_bcr < tx.offset_request_bcr.get() {
            return Err(MprdError::InvalidInput(
                "insufficient BCR for offset".into(),
            ));
        }
        let payer_new_bcr = sub_u64(payer_prev_bcr, tx.offset_request_bcr.get())?;

        let servicer_prev_agrs = self
            .operators
            .get(&tx.servicer)
            .ok_or_else(|| MprdError::InvalidInput("unknown servicer".into()))?
            .agrs_balance;
        let servicer_new_agrs = add_u64(servicer_prev_agrs, tx.tip_agrs.get())?;

        let new_tips_gross = add_u64(self.epoch_agg.tips_gross, tx.tip_agrs.get())?;

        // Metered work units for epoch payroll.
        let prev_wu = self
            .epoch_agg
            .work_units_by_operator
            .get(&tx.servicer)
            .copied()
            .unwrap_or(0);
        let new_wu = add_u64(prev_wu, tx.work_units)?;

        // Commit.
        self.epoch_agg.base_fees_gross = new_base_gross;
        self.epoch_agg.offset_total = new_offset_total;
        self.epoch_agg.tips_gross = new_tips_gross;
        self.epoch_agg
            .work_units_by_operator
            .insert(tx.servicer, new_wu);

        let payer = self
            .operators
            .get_mut(&tx.payer)
            .ok_or_else(|| MprdError::InvalidInput("unknown payer".into()))?;
        payer.bcr_balance = payer_new_bcr;

        let servicer = self
            .operators
            .get_mut(&tx.servicer)
            .ok_or_else(|| MprdError::InvalidInput("unknown servicer".into()))?;
        servicer.agrs_balance = servicer_new_agrs;

        Ok(())
    }

    /// Reveals an auction bid and escrows the offered BCR.
    ///
    /// Market input: `min_price` is operator-set and feeds the clearing price via the auction.
    ///
    /// Safety bound: `bounds.max_bids_per_epoch` caps worst-case sorting/settlement costs.
    pub fn auction_reveal(
        &mut self,
        operator: OperatorId,
        qty_bcr: Bcr,
        min_price: AgrsPerBcr,
        nonce: Hash32,
    ) -> Result<()> {
        self.ensure_epoch_open()?;
        if self.bids.len() >= self.bounds.max_bids_per_epoch {
            return Err(MprdError::BoundedValueExceeded("max bids exceeded".into()));
        }
        let bid = AuctionBid::new(operator, qty_bcr, min_price, nonce)?;
        let op = self
            .operators
            .get_mut(&operator)
            .ok_or_else(|| MprdError::InvalidInput("unknown operator".into()))?;
        if op.bcr_balance < qty_bcr.get() {
            return Err(MprdError::InvalidInput("insufficient BCR to escrow".into()));
        }
        let new_balance = sub_u64(op.bcr_balance, qty_bcr.get())?;
        let new_escrow = add_u64(op.bcr_escrow, qty_bcr.get())?;
        op.bcr_balance = new_balance;
        op.bcr_escrow = new_escrow;
        self.bids.push(bid);
        Ok(())
    }

    /// Finalizes the epoch budgets and closes the epoch to further actions.
    ///
    /// Postconditions (on first call):
    /// - budgets are cached; `ensure_epoch_open()` will start rejecting new actions
    /// - `burned_total`, `reserve_balance`, and `unallocated_balance` advance deterministically
    pub fn finalize_epoch(&mut self) -> Result<EpochBudgetsV6> {
        if let Some(b) = self.budgets.clone() {
            return Ok(b);
        }
        let f_base_gross = self.epoch_agg.base_fees_gross;
        let offset_total = self.epoch_agg.offset_total;
        if offset_total > f_base_gross {
            return Err(MprdError::InvalidInput(
                "offset_total cannot exceed base fees gross".into(),
            ));
        }
        let f_net = sub_u64(f_base_gross, offset_total)?;

        let ops_floor_pct = floor_bps(f_net, self.params.ops_pay_bps())?;
        let ops_floor_epoch = ops_floor_pct.max(self.params.ops_floor_fixed_agrs().get());
        let ops_budget = f_net.min(ops_floor_epoch);
        let ops_overhead = floor_bps(ops_budget, self.params.overhead_bps())?;
        let ops_payroll = sub_u64(ops_budget, ops_overhead)?;

        let reserve_budget =
            (sub_u64(f_net, ops_budget)?).min(self.params.reserve_target_agrs().get());
        let surplus = sub_u64(sub_u64(f_net, ops_budget)?, reserve_budget)?;

        let burn_surplus = floor_bps(surplus, self.params.burn_surplus_bps())?;
        let auction_new = floor_bps(surplus, self.params.auction_surplus_bps())?;
        let unallocated = sub_u64(sub_u64(surplus, burn_surplus)?, auction_new)?;

        // Apply deterministic accounting rails atomically.
        let new_burned_total = add_u64(self.burned_total, burn_surplus)?;
        let new_reserve_balance = add_u64(self.reserve_balance, reserve_budget)?;
        let new_unallocated_balance = add_u64(self.unallocated_balance, unallocated)?;

        let budgets = EpochBudgetsV6 {
            f_base_gross: Agrs::new(f_base_gross),
            f_tip: Agrs::new(self.epoch_agg.tips_gross),
            offset_total: Agrs::new(offset_total),
            f_net: Agrs::new(f_net),
            ops_budget: Agrs::new(ops_budget),
            ops_overhead: Agrs::new(ops_overhead),
            ops_payroll: Agrs::new(ops_payroll),
            reserve_budget: Agrs::new(reserve_budget),
            burn_surplus: Agrs::new(burn_surplus),
            auction_new: Agrs::new(auction_new),
            unallocated: Agrs::new(unallocated),
        };
        self.burned_total = new_burned_total;
        self.reserve_balance = new_reserve_balance;
        self.unallocated_balance = new_unallocated_balance;
        self.budgets = Some(budgets.clone());
        Ok(budgets)
    }

    /// Settles epoch payroll payouts from the finalized budgets.
    ///
    /// Rationale: payroll provides a policy-shaped operator cashflow rail (work metering × OPI),
    /// while tips remain purely market-determined per transaction.
    pub fn settle_ops_payroll(&mut self) -> Result<OpsPayrollOutcome> {
        let budgets = self.finalize_epoch()?;
        if self.payroll_settled {
            return Err(MprdError::InvalidInput(
                "ops payroll already settled".into(),
            ));
        }

        let pool = budgets.ops_payroll.get();
        if pool == 0 {
            self.payroll_settled = true;
            return Ok(OpsPayrollOutcome {
                ops_payroll_pool: budgets.ops_payroll,
                payout_total: Agrs::ZERO,
                carry_to_reserve: Agrs::ZERO,
            });
        }

        // Compute contrib_k = floor(work_units_k * opi_k / 10_000).
        let mut contribs: BTreeMap<OperatorId, u64> = BTreeMap::new();
        let mut total_contrib: u64 = 0;
        for (oid, wu) in &self.epoch_agg.work_units_by_operator {
            let opi = self
                .operators
                .get(oid)
                .ok_or_else(|| MprdError::InvalidInput("unknown operator in work map".into()))?
                .opi_bps;
            let c = floor_bps(*wu, opi)?;
            if c == 0 {
                continue;
            }
            contribs.insert(*oid, c);
            total_contrib = add_u64(total_contrib, c)?;
        }

        let mut payouts: Vec<(OperatorId, u64)> = Vec::new();
        let mut payout_sum: u64 = 0;
        if total_contrib > 0 {
            for (oid, c) in contribs {
                let payout_u128 = (pool as u128).checked_mul(c as u128).ok_or_else(|| {
                    MprdError::BoundedValueExceeded("payroll mul overflow".into())
                })? / (total_contrib as u128);
                let payout = u64::try_from(payout_u128).map_err(|_| {
                    MprdError::BoundedValueExceeded("payroll payout does not fit u64".into())
                })?;
                payout_sum = add_u64(payout_sum, payout)?;
                payouts.push((oid, payout));
            }
        }

        if payout_sum > pool {
            return Err(MprdError::InvalidInput(
                "payroll payouts exceed pool".into(),
            ));
        }
        let carry = sub_u64(pool, payout_sum)?;

        // Validate all balance updates before mutating state.
        let mut new_balances: Vec<(OperatorId, u64)> = Vec::with_capacity(payouts.len());
        for (oid, payout) in &payouts {
            let op = self
                .operators
                .get(oid)
                .ok_or_else(|| MprdError::InvalidInput("unknown operator in payout list".into()))?;
            new_balances.push((*oid, add_u64(op.agrs_balance, *payout)?));
        }
        let new_reserve_balance = add_u64(self.reserve_balance, carry)?;

        // Commit.
        for (oid, new_balance) in new_balances {
            let op = self
                .operators
                .get_mut(&oid)
                .ok_or_else(|| MprdError::InvalidInput("unknown operator in payout list".into()))?;
            op.agrs_balance = new_balance;
        }
        self.reserve_balance = new_reserve_balance;

        self.payroll_settled = true;
        Ok(OpsPayrollOutcome {
            ops_payroll_pool: budgets.ops_payroll,
            payout_total: Agrs::new(payout_sum),
            carry_to_reserve: Agrs::new(carry),
        })
    }

    /// Settles the BCR reverse auction for this epoch.
    ///
    /// Market-determined output: `AuctionOutcome::clearing_price`.
    /// Policy-set controls: auction budget share, carry cap, and `payout_lock_epochs`.
    ///
    /// Postconditions (on success):
    /// - winning BCR is burned; losing BCR is refunded from escrow
    /// - payouts are locked until `epoch + payout_lock_epochs`
    /// - leftover auction budget is carried forward (capped) with excess burned
    pub fn settle_auction(&mut self) -> Result<AuctionOutcome> {
        let budgets = self.finalize_epoch()?;
        if self.auction_settled {
            return Err(MprdError::InvalidInput("auction already settled".into()));
        }

        let auction_available = add_u64(budgets.auction_new.get(), self.auction_carry)?;
        let clearing = clear_prefix_budget(Agrs::new(auction_available), &self.bids)?;

        // Determine winners by bid hash (stable) for escrow release/burn.
        let mut winner_hashes: BTreeSet<Hash32> = BTreeSet::new();
        for w in &clearing.winners {
            winner_hashes.insert(w.bid_hash);
        }

        // Compute escrow clear + refund amounts per operator (no mutation).
        let mut escrow_clear: BTreeMap<OperatorId, u64> = BTreeMap::new();
        let mut refund: BTreeMap<OperatorId, u64> = BTreeMap::new();
        for bid in &self.bids {
            let prev = escrow_clear.get(&bid.operator).copied().unwrap_or(0);
            escrow_clear.insert(bid.operator, add_u64(prev, bid.qty_bcr.get())?);

            if !winner_hashes.contains(&bid.bid_hash) {
                let rprev = refund.get(&bid.operator).copied().unwrap_or(0);
                refund.insert(bid.operator, add_u64(rprev, bid.qty_bcr.get())?);
            }
        }

        // Validate escrow totals are consistent with operator state.
        for (oid, need) in &escrow_clear {
            let op = self
                .operators
                .get(oid)
                .ok_or_else(|| MprdError::InvalidInput("unknown bid.operator".into()))?;
            if op.bcr_escrow != *need {
                return Err(MprdError::InvalidInput(
                    "escrow mismatch (expected sum of bids)".into(),
                ));
            }
        }

        // Compute BCR burned = Σ (escrow_total - refund_total).
        let mut bcr_burned: u64 = 0;
        for (oid, total) in &escrow_clear {
            let r = refund.get(oid).copied().unwrap_or(0);
            bcr_burned = add_u64(bcr_burned, sub_u64(*total, r)?)?;
        }

        // Aggregate locked payouts per operator to preserve locked-map bounds.
        let unlock_epoch = EpochId(
            self.epoch
                .0
                .saturating_add(self.params.payout_lock_epochs() as u64),
        );
        let mut locked_add: BTreeMap<OperatorId, u64> = BTreeMap::new();
        for w in &clearing.winners {
            let payout = payout_for(w.qty_bcr, clearing.clearing_price)?;
            let prev = locked_add.get(&w.operator).copied().unwrap_or(0);
            locked_add.insert(w.operator, add_u64(prev, payout.get())?);
        }

        for (oid, _amt) in &locked_add {
            let op = self
                .operators
                .get(oid)
                .ok_or_else(|| MprdError::InvalidInput("unknown winner.operator".into()))?;
            let needs_new_key = !op.locked_agrs.contains_key(&unlock_epoch);
            // Safety bound: caps the number of distinct unlock epochs tracked per operator.
            if needs_new_key && op.locked_agrs.len() >= self.bounds.max_locked_entries_per_operator
            {
                return Err(MprdError::BoundedValueExceeded(
                    "max locked entries exceeded".into(),
                ));
            }
        }

        // Carry-forward (capped) + burn excess.
        let leftover = sub_u64(auction_available, clearing.payout_total.get())?;
        let (carry_out, burn_excess) =
            apply_carry_cap(Agrs::new(leftover), self.params.carry_cap_agrs())?;
        let new_burned_total = add_u64(self.burned_total, burn_excess.get())?;

        // Validate balance mutations before commit.
        let mut new_bcr_balances: Vec<(OperatorId, u64, u64)> = Vec::new(); // (oid, new_bcr_balance, clear_escrow_to)
        for (oid, total) in &escrow_clear {
            let op = self
                .operators
                .get(oid)
                .ok_or_else(|| MprdError::InvalidInput("unknown bid.operator".into()))?;
            let r = refund.get(oid).copied().unwrap_or(0);
            new_bcr_balances.push((
                *oid,
                add_u64(op.bcr_balance, r)?,
                sub_u64(op.bcr_escrow, *total)?,
            ));
        }
        let mut new_locked: Vec<(OperatorId, u64)> = Vec::new(); // (oid, new_locked_amt_at_unlock)
        for (oid, amt) in &locked_add {
            let op = self
                .operators
                .get(oid)
                .ok_or_else(|| MprdError::InvalidInput("unknown winner.operator".into()))?;
            let prev = op.locked_agrs.get(&unlock_epoch).copied().unwrap_or(0);
            new_locked.push((*oid, add_u64(prev, *amt)?));
        }

        // Commit: clear escrow, refund losers, burn winners implicitly, and lock payouts.
        for (oid, new_bcr_balance, new_escrow) in new_bcr_balances {
            let op = self
                .operators
                .get_mut(&oid)
                .ok_or_else(|| MprdError::InvalidInput("unknown bid.operator".into()))?;
            op.bcr_balance = new_bcr_balance;
            op.bcr_escrow = new_escrow;
        }
        for (oid, new_locked_amt) in new_locked {
            let op = self
                .operators
                .get_mut(&oid)
                .ok_or_else(|| MprdError::InvalidInput("unknown winner.operator".into()))?;
            op.locked_agrs.insert(unlock_epoch, new_locked_amt);
        }
        self.auction_carry = carry_out.get();
        self.burned_total = new_burned_total;
        self.auction_settled = true;
        self.bids.clear();

        Ok(AuctionOutcome {
            clearing_price: clearing.clearing_price,
            qty_bcr_burned: Bcr::new(bcr_burned),
            payout_total: clearing.payout_total,
            carry_out,
            burn_excess,
            winners_len: clearing.winners.len(),
        })
    }

    /// Advances to `next_epoch` after the current epoch is fully settled.
    ///
    /// Preconditions:
    /// - `next_epoch` is monotone
    /// - budgets finalized and both payroll + auction settled (fail-closed otherwise)
    ///
    /// Postconditions:
    /// - unlocks any due auction payouts at or before `next_epoch`
    /// - resets epoch-scoped aggregates/bids and opens the new epoch
    pub fn advance_epoch(&mut self, next_epoch: EpochId) -> Result<()> {
        if next_epoch.0 <= self.epoch.0 {
            return Err(MprdError::InvalidInput("epoch must be monotone".into()));
        }
        if self.budgets.is_none() || !self.payroll_settled || !self.auction_settled {
            return Err(MprdError::InvalidInput(
                "cannot advance: epoch not fully settled".into(),
            ));
        }

        // Unlock due payouts at `next_epoch` (validate first, then commit).
        let mut unlock_plan: Vec<(OperatorId, u64, Vec<EpochId>)> = Vec::new();
        for (oid, op) in &self.operators {
            let mut unlocked_total: u64 = 0;
            let mut to_remove: Vec<EpochId> = Vec::new();
            for (k, v) in &op.locked_agrs {
                if k.0 <= next_epoch.0 {
                    unlocked_total = add_u64(unlocked_total, *v)?;
                    to_remove.push(*k);
                } else {
                    break;
                }
            }
            unlock_plan.push((*oid, add_u64(op.agrs_balance, unlocked_total)?, to_remove));
        }
        for (oid, new_balance, to_remove) in unlock_plan {
            let op = self
                .operators
                .get_mut(&oid)
                .ok_or_else(|| MprdError::InvalidInput("unknown operator".into()))?;
            for k in to_remove {
                op.locked_agrs.remove(&k);
            }
            op.agrs_balance = new_balance;
        }

        // Reset epoch-scoped state.
        self.epoch = next_epoch;
        self.epoch_agg = EpochAgg::default();
        self.budgets = None;
        self.payroll_settled = false;
        self.auction_settled = false;
        self.bids.clear();
        Ok(())
    }

    fn ensure_epoch_open(&self) -> Result<()> {
        if self.budgets.is_some() {
            return Err(MprdError::InvalidInput(
                "epoch is finalized; no further actions allowed".into(),
            ));
        }
        Ok(())
    }
}

fn compute_new_carry_and_burn(
    current_carry: u64,
    current_burned_total: u64,
    add_amt: u64,
    carry_cap: u64,
) -> Result<(u64, u64)> {
    if add_amt == 0 {
        return Ok((current_carry, current_burned_total));
    }
    let carry_added = add_u64(current_carry, add_amt)?;
    if carry_added <= carry_cap {
        return Ok((carry_added, current_burned_total));
    }
    let excess = sub_u64(carry_added, carry_cap)?;
    Ok((carry_cap, add_u64(current_burned_total, excess)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenomics_v6::types::Bps;

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

    fn id(b: u8) -> OperatorId {
        OperatorId(Hash32([b; 32]))
    }

    #[test]
    fn fee_split_offsets_apply_to_base_fee_only_and_payroll_pays_ops() {
        let mut eng = TokenomicsV6::new(params());
        let a = id(1);
        let b = id(2);
        eng.admit_operator(a).unwrap();
        eng.admit_operator(b).unwrap();

        // Fund payer A so they can stake (and earn BCR drip).
        eng.credit_agrs(a, Agrs::new(1_000_000)).unwrap();
        eng.stake_start(a, Agrs::new(100_000), 365, Hash32([9; 32]))
            .unwrap();
        eng.accrue_bcr_drip().unwrap();

        // A offsets base fee; B receives tip immediately.
        let tx = ServiceTx {
            payer: a,
            servicer: b,
            base_fee_agrs: Agrs::new(10_000),
            tip_agrs: Agrs::new(100),
            offset_request_bcr: Bcr::new(100),
            work_units: 10_000,
            nonce: Hash32([7; 32]),
        };
        eng.apply_service_tx(tx).unwrap();

        // Tip paid directly to servicer.
        assert_eq!(eng.agrs_balance(b).unwrap().get(), 100);
        // Offset consumed payer BCR (1:1).
        assert_eq!(eng.bcr_balance(a).unwrap().get(), 0);

        let budgets = eng.finalize_epoch().unwrap();
        assert_eq!(budgets.f_base_gross.get(), 10_000);
        assert_eq!(budgets.offset_total.get(), 100);
        assert_eq!(budgets.f_net.get(), 9_900);

        // Budget conservation rail.
        let sum = budgets.ops_budget.get()
            + budgets.reserve_budget.get()
            + budgets.burn_surplus.get()
            + budgets.auction_new.get()
            + budgets.unallocated.get();
        assert_eq!(sum, budgets.f_net.get());

        // Payroll pays based on work_units × OPI (default OPI=10k).
        let payroll = eng.settle_ops_payroll().unwrap();
        assert_eq!(payroll.ops_payroll_pool.get(), budgets.ops_payroll.get());
        assert_eq!(
            eng.agrs_balance(b).unwrap().get(),
            100 + payroll.payout_total.get()
        );

        // No bids → no auction payouts.
        let auc = eng.settle_auction().unwrap();
        assert_eq!(auc.payout_total.get(), 0);

        eng.advance_epoch(EpochId(1)).unwrap();

        // Epoch is open again (can accept new actions).
        let tx2 = ServiceTx {
            payer: a,
            servicer: b,
            base_fee_agrs: Agrs::new(1),
            tip_agrs: Agrs::new(0),
            offset_request_bcr: Bcr::new(0),
            work_units: 0,
            nonce: Hash32([8; 32]),
        };
        eng.apply_service_tx(tx2).unwrap();
    }
}
