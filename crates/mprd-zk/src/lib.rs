pub mod abi;

use mprd_core::{
    CandidateAction, Decision, DecisionToken, MprdError, ProofBundle, Result, StateSnapshot,
    VerificationStatus, ZkAttestor, ZkLocalVerifier,
};

/// Configuration for the Risc0-based ZK pipeline.
///
/// This is a placeholder; additional fields (e.g. image ID, method ID) will be
/// added when Risc0 is fully wired in.
#[derive(Clone)]
pub struct Risc0Config {
    pub method_elf: &'static [u8],
}

pub struct Risc0ZkAttestor {
    config: Risc0Config,
}

impl Risc0ZkAttestor {
    pub fn new(config: Risc0Config) -> Self {
        Self { config }
    }
}

impl ZkAttestor for Risc0ZkAttestor {
    /// Current behavior:
    /// - Always returns `MprdError::ZkError("ZK attestation not implemented")`.
    ///
    /// This is deliberate to avoid silent insecure operation before the
    /// Risc0 pipeline is fully implemented.
    fn attest(
        &self,
        _decision: &Decision,
        _state: &StateSnapshot,
        _candidates: &[CandidateAction],
    ) -> Result<ProofBundle> {
        Err(MprdError::ZkError(
            "ZK attestation not implemented; wire Risc0 before use".into(),
        ))
    }
}

/// Local verifier backed by Risc0 receipts.
pub struct Risc0ZkLocalVerifier {
    config: Risc0Config,
}

impl Risc0ZkLocalVerifier {
    pub fn new(config: Risc0Config) -> Self {
        Self { config }
    }
}

impl ZkLocalVerifier for Risc0ZkLocalVerifier {
    /// Current behavior:
    /// - Always returns `VerificationStatus::Failure` with a descriptive
    ///   message.
    ///
    /// This prevents accidental acceptance of unverified actions while the
    /// ZK pipeline is still under construction.
    fn verify(&self, _token: &DecisionToken, _proof: &ProofBundle) -> VerificationStatus {
        VerificationStatus::Failure(
            "ZK local verification not implemented; wire Risc0 before use".into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mprd_core::{Hash32, PolicyHash, StateHash};
    use std::collections::HashMap;

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn dummy_config() -> Risc0Config {
        Risc0Config { method_elf: &[] }
    }

    #[test]
    fn attestor_returns_explicit_error() {
        let attestor = Risc0ZkAttestor::new(dummy_config());

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(1),
        };

        let decision = Decision {
            chosen_index: 0,
            chosen_action: CandidateAction {
                action_type: "A".into(),
                params: HashMap::new(),
                score: mprd_core::Score(0),
                candidate_hash: dummy_hash(2),
            },
            policy_hash: dummy_hash(3),
            decision_commitment: dummy_hash(4),
        };

        let result = attestor.attest(&decision, &state, &[]);
        assert!(matches!(result, Err(MprdError::ZkError(_))));
    }

    #[test]
    fn verifier_always_fails_in_stub_mode() {
        let verifier = Risc0ZkLocalVerifier::new(dummy_config());

        let token = DecisionToken {
            policy_hash: dummy_hash(5),
            state_hash: dummy_hash(6),
            chosen_action_hash: dummy_hash(7),
            nonce_or_tx_hash: dummy_hash(8),
            timestamp_ms: 0,
            signature: vec![],
        };

        let proof = ProofBundle {
            policy_hash: dummy_hash(9),
            state_hash: dummy_hash(10),
            candidate_set_hash: dummy_hash(11),
            chosen_action_hash: dummy_hash(12),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        let status = verifier.verify(&token, &proof);
        assert!(matches!(status, VerificationStatus::Failure(_)));
    }
}

