//! mprd_v6_stake_penalty_shares kernel module.
//! Generated from IR hash: 270a76fb9b62fd6c

pub mod command;
pub mod invariants;
pub mod state;
pub mod step;
pub mod types;

#[cfg(test)]
mod tests;

pub use command::Command;
pub use invariants::check_invariants;
pub use state::State;
pub use step::{step, Effects};
pub use types::*;
