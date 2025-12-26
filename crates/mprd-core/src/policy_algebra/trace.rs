use crate::{Hash32, MprdError, Result};

use super::ast::PolicyOutcomeKind;

/// Stable reason codes for policy traces.
///
/// These codes are intended to be machine-consumable (no string matching).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TraceReasonCode {
    Allow = 1,
    DenySignalFalse = 2,
    DenyMissingSignal = 3,
    DenyVetoSignalTrue = 4,
    DenyVetoMissingSignal = 5,
    NeutralVetoNotTriggered = 6,
    DenyThresholdNotMet = 7,
    DenyAnyNoAllow = 8,
    DenyUnknown = 9,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEntry {
    pub node_hash: Hash32,
    pub outcome: PolicyOutcomeKind,
    pub reason: TraceReasonCode,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyTrace {
    entries: Vec<TraceEntry>,
}

impl PolicyTrace {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn entries(&self) -> &[TraceEntry] {
        &self.entries
    }

    pub fn push_bounded(&mut self, entry: TraceEntry, max_trace_nodes: usize) -> Result<()> {
        if self.entries.len() >= max_trace_nodes {
            return Err(MprdError::BoundedValueExceeded(format!(
                "PolicyTrace exceeded max_trace_nodes={max_trace_nodes}"
            )));
        }
        self.entries.push(entry);
        Ok(())
    }
}
