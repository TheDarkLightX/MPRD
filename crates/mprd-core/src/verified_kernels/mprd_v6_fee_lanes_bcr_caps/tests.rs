//! Generated tests for mprd_v6_fee_lanes_bcr_caps.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn init_satisfies_invariants() {
        let s = State::init();
        assert!(check_invariants(&s).is_ok());
    }

    #[test]
    fn test_apply_tx_from_init() {
        let s = State::init();
        let cmd = Command::ApplyTx {
            base_fee: 0,
            tip: 0,
            offset_req: 0,
        };
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    // TODO: Add CE regression tests here
    // TODO: Add MBT equivalence harness
}
