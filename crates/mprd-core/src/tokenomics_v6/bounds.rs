use crate::{MprdError, Result};

/// Runtime bounds for the in-memory v6 engine.
///
/// These are **safety bounds**, not economic parameters:
/// - they prevent unbounded memory/CPU usage (DoS resistance)
/// - they make evaluation + settlement predictable
///
/// Production deployments may set these based on seat count / capacity planning,
/// but they MUST remain bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeBoundsV6 {
    pub max_operators: usize,
    pub max_stakes_per_operator: usize,
    pub max_bids_per_epoch: usize,
    pub max_locked_entries_per_operator: usize,
}

impl RuntimeBoundsV6 {
    pub const HARD_MAX_OPERATORS: usize = 5_000_000;
    pub const HARD_MAX_STAKES_PER_OPERATOR: usize = 1024;
    pub const HARD_MAX_BIDS_PER_EPOCH: usize = 1_000_000;
    pub const HARD_MAX_LOCKED_ENTRIES_PER_OPERATOR: usize = 100_000;

    /// Default: sized to the expected 100k–500k operator range (configurable).
    pub const DEFAULT_MAX_OPERATORS: usize = 500_000;
    /// Default: typical per-operator stake fanout (configurable).
    pub const DEFAULT_MAX_STAKES_PER_OPERATOR: usize = 64;
    /// Default: bounded auction complexity per epoch (configurable).
    pub const DEFAULT_MAX_BIDS_PER_EPOCH: usize = 4096;
    /// Default: bounded payout-lock fanout per operator (configurable).
    pub const DEFAULT_MAX_LOCKED_ENTRIES_PER_OPERATOR: usize = 1024;

    pub fn new(
        max_operators: usize,
        max_stakes_per_operator: usize,
        max_bids_per_epoch: usize,
        max_locked_entries_per_operator: usize,
    ) -> Result<Self> {
        let b = RuntimeBoundsV6 {
            max_operators,
            max_stakes_per_operator,
            max_bids_per_epoch,
            max_locked_entries_per_operator,
        };
        b.validate()?;
        Ok(b)
    }

    pub fn validate(self) -> Result<()> {
        if self.max_operators == 0 || self.max_operators > Self::HARD_MAX_OPERATORS {
            return Err(MprdError::InvalidInput(format!(
                "max_operators out of bounds: {}",
                self.max_operators
            )));
        }
        if self.max_stakes_per_operator == 0
            || self.max_stakes_per_operator > Self::HARD_MAX_STAKES_PER_OPERATOR
        {
            return Err(MprdError::InvalidInput(format!(
                "max_stakes_per_operator out of bounds: {}",
                self.max_stakes_per_operator
            )));
        }
        if self.max_bids_per_epoch == 0 || self.max_bids_per_epoch > Self::HARD_MAX_BIDS_PER_EPOCH {
            return Err(MprdError::InvalidInput(format!(
                "max_bids_per_epoch out of bounds: {}",
                self.max_bids_per_epoch
            )));
        }
        if self.max_locked_entries_per_operator == 0
            || self.max_locked_entries_per_operator > Self::HARD_MAX_LOCKED_ENTRIES_PER_OPERATOR
        {
            return Err(MprdError::InvalidInput(format!(
                "max_locked_entries_per_operator out of bounds: {}",
                self.max_locked_entries_per_operator
            )));
        }
        Ok(())
    }
}

impl Default for RuntimeBoundsV6 {
    fn default() -> Self {
        Self {
            max_operators: Self::DEFAULT_MAX_OPERATORS,
            max_stakes_per_operator: Self::DEFAULT_MAX_STAKES_PER_OPERATOR,
            max_bids_per_epoch: Self::DEFAULT_MAX_BIDS_PER_EPOCH,
            max_locked_entries_per_operator: Self::DEFAULT_MAX_LOCKED_ENTRIES_PER_OPERATOR,
        }
    }
}
