//! Commands for ui_mode_adaptive_gates.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    ConfigureAnchors,
    GoLocal,
    GoPrivate,
    GoTrustless,
}
