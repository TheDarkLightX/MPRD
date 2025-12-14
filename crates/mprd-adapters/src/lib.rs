//! MPRD Adapters
//!
//! Production adapters for executing actions, storing policies, and
//! integrating with external systems.
//!
//! # Executors
//!
//! - `HttpExecutor`: Execute via HTTP endpoint
//! - `WebhookExecutor`: Fire-and-forget webhook
//! - `FileExecutor`: Audit trail to file
//! - `CompositeExecutor`: Chain multiple executors
//!
//! # Storage
//!
//! - `IpfsStorage`: Store and retrieve policies from IPFS
//! - `LocalStorage`: File-based policy storage

pub mod egress;
pub mod executors;
pub mod storage;

pub use executors::{
    CompositeExecutor, FileExecutor, HttpExecutor, HttpExecutorConfig, NoOpExecutor,
    WebhookExecutor,
};

pub use storage::{IpfsConfig, IpfsPolicyStorage, LocalPolicyStorage};
