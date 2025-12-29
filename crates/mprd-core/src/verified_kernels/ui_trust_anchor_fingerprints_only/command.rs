//! Commands for ui_trust_anchor_fingerprints_only.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    AttemptRawDisplay,
    ClearKey,
    DisplayFingerprint,
    HideDisplay,
    LoadKey,
}
