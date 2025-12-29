//! Generated tests for selector_fail_closed_required_limits.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn init_satisfies_invariants() {
        let s = State::init();
        assert!(check_invariants(&s).is_ok());
    }

    #[test]
    fn test_limits_invalid_from_init() {
        let s = State::init();
        let cmd = Command::LimitsInvalid;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_limits_missing_from_init() {
        let s = State::init();
        let cmd = Command::LimitsMissing;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_none_allowed_from_init() {
        let s = State::init();
        let cmd = Command::NoneAllowed;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_receive_allowed_from_init() {
        let s = State::init();
        let cmd = Command::ReceiveAllowed;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_select_from_init() {
        let s = State::init();
        let cmd = Command::Select;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    // TODO: Add CE regression tests here
    // TODO: Add MBT equivalence harness
}
