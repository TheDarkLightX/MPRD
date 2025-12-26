//! Kani verification harnesses for CBC types.
//!
//! Run with: cargo kani --harness <name>

#[cfg(kani)]
mod kani_verification {
    use crate::tokenomics_v6::types::*;

    /// Verify BurnPct stays within bounds
    #[kani::proof]
    fn burn_pct_bounds() {
        let units: u8 = kani::any();
        kani::assume(units <= BurnPct::MAX_UNITS);

        let burn = BurnPct::new(units).unwrap();
        let bps = burn.to_bps().get();

        kani::assert(bps >= BurnPct::MIN_BPS, "BurnPct below min");
        kani::assert(bps <= BurnPct::MAX_BPS, "BurnPct above max");
    }

    /// Verify AuctionPct stays within bounds
    #[kani::proof]
    fn auction_pct_bounds() {
        let units: u8 = kani::any();
        kani::assume(units >= AuctionPct::MIN_UNITS && units <= AuctionPct::MAX_UNITS);

        let auction = AuctionPct::new(units).unwrap();
        let bps = auction.to_bps().get();

        kani::assert(bps >= AuctionPct::MIN_BPS, "AuctionPct below min");
        kani::assert(bps <= AuctionPct::MAX_BPS, "AuctionPct above max");
    }

    /// Verify DripStep stays within bounds
    #[kani::proof]
    fn drip_step_bounds() {
        let units: u8 = kani::any();
        kani::assume(units >= DripStep::MIN_UNITS && units <= DripStep::MAX_UNITS);

        let drip = DripStep::new(units).unwrap();
        let bps = drip.to_bps().get();

        kani::assert(bps >= DripStep::MIN_BPS, "DripStep below min");
        kani::assert(bps <= DripStep::MAX_BPS, "DripStep above max");
    }

    /// Verify ValidSplit enforces the split cap invariant
    #[kani::proof]
    fn valid_split_cap_invariant() {
        let burn_units: u8 = kani::any();
        let auction_units: u8 = kani::any();

        kani::assume(burn_units <= BurnPct::MAX_UNITS);
        kani::assume(
            auction_units >= AuctionPct::MIN_UNITS && auction_units <= AuctionPct::MAX_UNITS,
        );

        let burn = BurnPct::new(burn_units).unwrap();
        let auction = AuctionPct::new(auction_units).unwrap();

        if let Ok(split) = ValidSplit::new(burn, auction) {
            let burn_bps = split.burn().to_bps().get() as u32;
            let auction_bps = split.auction().to_bps().get() as u32;
            kani::assert(
                burn_bps + auction_bps <= 10_000,
                "ValidSplit violated split cap",
            );
        }
    }

    /// Verify ActionId roundtrip
    #[kani::proof]
    fn action_id_roundtrip() {
        let idx: u8 = kani::any();
        kani::assume(idx < 27);

        let action = ActionId::new(idx).unwrap();
        let delta = action.to_delta();
        let roundtrip = ActionId::from_delta(&delta);

        kani::assert(action == roundtrip, "ActionId roundtrip failed");
    }

    /// Verify NoOp is index 13 and encodes to (0,0,0)
    #[kani::proof]
    fn noop_encoding() {
        let noop = ActionId::NOOP;
        kani::assert(noop.index() == 13, "NoOp not at index 13");

        let delta = noop.to_delta();
        kani::assert(delta.db == Step::Zero, "NoOp db not Zero");
        kani::assert(delta.da == Step::Zero, "NoOp da not Zero");
        kani::assert(delta.dd == Step::Zero, "NoOp dd not Zero");
    }
}
