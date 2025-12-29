//! Generated tests for nonce_manager_lifecycle.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn init_satisfies_invariants() {
        let s = State::init();
        assert!(check_invariants(&s).is_ok());
    }

    #[test]
    fn test_advance_window_from_init() {
        let s = State::init();
        let cmd = Command::AdvanceWindow;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_consume_nonce_from_init() {
        let s = State::init();
        let cmd = Command::ConsumeNonce { nonce_time: 0 };
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_set_window_size_from_init() {
        let s = State::init();
        let cmd = Command::SetWindowSize { new_size: 1 };
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_tick_time_from_init() {
        let s = State::init();
        let cmd = Command::TickTime { new_time: 0 };
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    // TODO: Add CE regression tests here
    // TODO: Add MBT equivalence harness
}
