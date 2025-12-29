//! Generated tests for selector_canonical_tiebreak.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn init_satisfies_invariants() {
        let s = State::init();
        assert!(check_invariants(&s).is_ok());
    }

    #[test]
    fn test_select_by_score_from_init() {
        let s = State::init();
        let cmd = Command::SelectByScore;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_select_canonical_from_init() {
        let s = State::init();
        let cmd = Command::SelectCanonical;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_setup_a_wins_score_from_init() {
        let s = State::init();
        let cmd = Command::SetupAWinsScore;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_setup_b_wins_score_from_init() {
        let s = State::init();
        let cmd = Command::SetupBWinsScore;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_setup_tie_a_canonical_from_init() {
        let s = State::init();
        let cmd = Command::SetupTieACanonical;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    #[test]
    fn test_setup_tie_b_canonical_from_init() {
        let s = State::init();
        let cmd = Command::SetupTieBCanonical;
        // This may fail if precondition not satisfied from init
        let _ = step(&s, cmd);
    }

    // TODO: Add CE regression tests here
    // TODO: Add MBT equivalence harness
}
