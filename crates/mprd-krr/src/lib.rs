//! # mprd-krr: Knowledge Representation and Reasoning Layer 2
//!
//! A KRR system that works on top of TML (black box) providing:
//! - Justification DAG extraction via delta debugging
//! - Trust propagation via semiring algebra
//! - OWL 2 RL → TML compilation
//! - Explanation generation (Why/Why-Not)

pub mod types;
pub mod dag;
pub mod ddmin;
pub mod trust;
pub mod tml;
pub mod explain;
pub mod error;
pub mod composition;

// Re-exports
pub use types::{FactId, TrustScore, RuleFingerprint, JustificationHash};
pub use dag::{Justification, JustificationDag};
pub use trust::{TrustSemiring, MinSemiring, ProductSemiring};
pub use tml::{TmlRunner, TmlCli};
pub use error::KrrError;
