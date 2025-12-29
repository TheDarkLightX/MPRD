//! mprd_v6_stake_penalty_shares kernel module.
//! Generated from IR hash: 270a76fb9b62fd6c

pub mod types;
pub mod state;
pub mod command;
pub mod invariants;
pub mod step;

#[cfg(test)]
mod tests;

pub use types::*;
pub use state::State;
pub use command::Command;
pub use step::{step, Effects};
pub use invariants::check_invariants;
