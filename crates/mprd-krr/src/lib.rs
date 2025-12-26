//! # mprd-krr: Knowledge Representation and Reasoning Layer 2
//!
//! A KRR system that works on top of TML (black box) providing:
//! - Justification DAG extraction via delta debugging
//! - Trust propagation via semiring algebra
//! - OWL 2 RL → TML compilation
//! - Explanation generation (Why/Why-Not)

pub mod composition;
pub mod dag;
pub mod ddmin;
pub mod error;
pub mod explain;
pub mod tml;
pub mod trust;
pub mod types;

// Re-exports
pub use dag::{Justification, JustificationDag};
pub use error::KrrError;
pub use tml::{TmlCli, TmlRunner};
pub use trust::{MinSemiring, ProductSemiring, TrustSemiring};
pub use types::{FactId, JustificationHash, RuleFingerprint, TrustScore};
