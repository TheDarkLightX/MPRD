use serde::{Deserialize, Serialize};

/// A single verification step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationStep {
    pub name: String,
    pub passed: bool,
    pub details: Option<String>,
}
