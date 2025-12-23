//! Registry-bound attestors (fail-fast production wiring).
//!
//! These attestors enforce verifier-trusted registry state constraints at the proving boundary:
//! - `policy_epoch/registry_root` pinning
//! - policy authorization (policy_hash + exec kind/version)
//! - guest image routing via the signed manifest
//!
//! This prevents "prove something that will never verify" and closes the production checklist
//! gap where policy authorization was only enforced at verification time.

use crate::policy_fetch::{PolicyArtifactStore, RegistryBoundMpbPolicyProvider};
use crate::registry_state::PolicyAuthorizationProvider;
use crate::risc0_host::{
    MpbPolicyProvider, Risc0MpbAttestor, Risc0TauCompiledAttestor, TauCompiledPolicyProvider,
};
use mprd_core::{
    Decision, DecisionToken, MprdError, PolicyRef, ProofBundle, Result, StateSnapshot,
};
use std::sync::Arc;

/// Registry-bound Risc0 MPB attestor (mpb-v1).
pub struct RegistryBoundRisc0MpbAttestor {
    guest_elf: &'static [u8],
    policy_ref: PolicyRef,
    mpb_fuel_limit: u32,
    authorization: Arc<dyn PolicyAuthorizationProvider>,
    policy_provider: Arc<dyn MpbPolicyProvider>,
}

impl RegistryBoundRisc0MpbAttestor {
    pub fn new(
        guest_elf: &'static [u8],
        policy_ref: PolicyRef,
        mpb_fuel_limit: u32,
        authorization: Arc<dyn PolicyAuthorizationProvider>,
        store: Arc<dyn PolicyArtifactStore>,
    ) -> Self {
        let provider = RegistryBoundMpbPolicyProvider::new(
            policy_ref.clone(),
            Arc::clone(&authorization),
            store,
        );
        Self {
            guest_elf,
            policy_ref,
            mpb_fuel_limit,
            authorization,
            policy_provider: Arc::new(provider),
        }
    }
}

impl mprd_core::ZkAttestor for RegistryBoundRisc0MpbAttestor {
    fn attest(
        &self,
        token: &DecisionToken,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[mprd_core::CandidateAction],
    ) -> Result<ProofBundle> {
        // Fail-fast: prove only under the intended registry authorization context.
        if token.policy_ref != self.policy_ref {
            return Err(MprdError::InvalidInput(
                "token policy_ref does not match verifier-trusted policy_ref".into(),
            ));
        }

        // Resolve and route image_id via the signed manifest.
        let resolution = self
            .authorization
            .resolve(&token.policy_hash, &token.policy_ref)?;

        let image_id: [u8; 32] = resolution.image_id;

        // Prove with the registry-routed image id and registry-bound policy provider.
        let inner = Risc0MpbAttestor::new(
            self.guest_elf,
            image_id,
            self.mpb_fuel_limit,
            Arc::clone(&self.policy_provider),
        );
        inner.attest(token, decision, state, candidates)
    }
}

/// Registry-bound Risc0 Tau-compiled (TCV) attestor (tau_compiled_v1).
pub struct RegistryBoundRisc0TauCompiledAttestor {
    guest_elf: &'static [u8],
    policy_ref: PolicyRef,
    authorization: Arc<dyn PolicyAuthorizationProvider>,
    policy_provider: Arc<dyn TauCompiledPolicyProvider>,
}

impl RegistryBoundRisc0TauCompiledAttestor {
    pub fn new(
        guest_elf: &'static [u8],
        policy_ref: PolicyRef,
        authorization: Arc<dyn PolicyAuthorizationProvider>,
        policy_provider: Arc<dyn TauCompiledPolicyProvider>,
    ) -> Self {
        Self {
            guest_elf,
            policy_ref,
            authorization,
            policy_provider,
        }
    }
}

impl mprd_core::ZkAttestor for RegistryBoundRisc0TauCompiledAttestor {
    fn attest(
        &self,
        token: &DecisionToken,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[mprd_core::CandidateAction],
    ) -> Result<ProofBundle> {
        // Fail-fast: prove only under the intended registry authorization context.
        if token.policy_ref != self.policy_ref {
            return Err(MprdError::InvalidInput(
                "token policy_ref does not match verifier-trusted policy_ref".into(),
            ));
        }

        // Resolve and route image_id via the signed manifest.
        let resolution = self
            .authorization
            .resolve(&token.policy_hash, &token.policy_ref)?;

        let image_id: [u8; 32] = resolution.image_id;

        let inner = Risc0TauCompiledAttestor::new(
            self.guest_elf,
            image_id,
            Arc::clone(&self.policy_provider),
        );
        inner.attest(token, decision, state, candidates)
    }
}
