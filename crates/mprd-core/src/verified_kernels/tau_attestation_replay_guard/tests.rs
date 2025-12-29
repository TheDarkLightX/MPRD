//! Generated tests for tau_attestation_replay_guard.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn init_satisfies_invariants() {
        let s = State::init();
        assert!(check_invariants(&s).is_ok());
    }

    #[test]
    fn test_accept_from_init() {
        let s = State::init();
        let cmd = Command::Accept;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_chain_breaks_from_init() {
        let s = State::init();
        let cmd = Command::ChainBreaks;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_receive_stale_from_init() {
        let s = State::init();
        let cmd = Command::ReceiveStale;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_reject_from_init() {
        let s = State::init();
        let cmd = Command::Reject;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    // TODO: Add CE regression tests here
    // TODO: Add MBT equivalence harness
}
