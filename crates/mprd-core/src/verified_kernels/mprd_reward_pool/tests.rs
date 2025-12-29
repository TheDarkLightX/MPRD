//! Generated tests for mprd_reward_pool.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn init_satisfies_invariants() {
        let s = State::init();
        assert!(check_invariants(&s).is_ok());
    }

    #[test]
    fn test_add_to_pool_from_init() {
        let s = State::init();
        let cmd = Command::AddToPool { amt: 1 };
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_finalize_from_init() {
        let s = State::init();
        let cmd = Command::Finalize;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_pay_recipient_from_init() {
        let s = State::init();
        let cmd = Command::PayRecipient { amt: 1 };
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_start_distribution_from_init() {
        let s = State::init();
        let cmd = Command::StartDistribution;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    // TODO: Add CE regression tests here
    // TODO: Add MBT equivalence harness
}
