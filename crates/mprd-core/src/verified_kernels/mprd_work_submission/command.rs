//! Commands for mprd_work_submission.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    FileDispute,
    Reject,
    Reward,
    RunProofCheck,
    RunSpecCheck,
    SubmitWork { hash: u64 },
}
