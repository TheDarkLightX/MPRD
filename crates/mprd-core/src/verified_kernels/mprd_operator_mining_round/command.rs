//! Commands for mprd_operator_mining_round.


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    CloseRound { hash: u64 },
    CompletePayments,
    FileDispute,
    Finalize,
    PayMiner,
    RunProofCheck,
    RunSpecCheck,
    Submit,
}
