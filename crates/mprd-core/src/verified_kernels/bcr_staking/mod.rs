//! bcr_staking kernel module.
//! Generated from IR hash: 3a689bfcd8d45a74

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
