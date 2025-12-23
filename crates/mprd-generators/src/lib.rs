use mprd_core::{Hash32, PolicyRef, StateRef};
use mprd_risc0_shared::{
    action_encoding_id_v1, compute_decision_commitment_v3, limits_bytes_mpb_v1, limits_hash_mpb_v1,
    policy_exec_kind_mpb_id_v1, policy_exec_version_id_v1, state_encoding_id_v1, GuestJournalV3,
    JOURNAL_VERSION,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug)]
pub struct GenSeed(pub [u8; 32]);

impl GenSeed {
    pub fn from_u64(x: u64) -> Self {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&x.to_le_bytes());
        Self(b)
    }
}

#[derive(Clone, Debug)]
pub struct DeterministicGen {
    seed: [u8; 32],
    counter: u64,
}

impl DeterministicGen {
    pub fn new(seed: GenSeed) -> Self {
        Self {
            seed: seed.0,
            counter: 0,
        }
    }

    pub fn next_u64(&mut self, domain: &[u8]) -> u64 {
        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(&self.next_bytes(domain, 8)[..8]);
        u64::from_le_bytes(tmp)
    }

    pub fn next_u32(&mut self, domain: &[u8]) -> u32 {
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&self.next_bytes(domain, 4)[..4]);
        u32::from_le_bytes(tmp)
    }

    pub fn next_hash32(&mut self, domain: &[u8]) -> Hash32 {
        Hash32(self.next_id32(domain))
    }

    pub fn next_id32(&mut self, domain: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.next_bytes(domain, 32)[..32]);
        out
    }

    pub fn next_bytes(&mut self, domain: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let block = self.next_block(domain);
            let take = (len - out.len()).min(block.len());
            out.extend_from_slice(&block[..take]);
        }
        out
    }

    fn next_block(&mut self, domain: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"MPRD_DETERMINISTIC_GEN_V1");
        hasher.update(domain);
        hasher.update(self.seed);
        hasher.update(self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        hasher.finalize().into()
    }
}

#[derive(Clone, Debug)]
pub struct DecodedMpbV1Fixture {
    pub token: mprd_core::DecisionToken,
    pub proof: mprd_core::ProofBundle,
    pub journal: GuestJournalV3,
}

/// Deterministically generate a self-consistent `(DecisionToken, ProofBundle, GuestJournalV3)`
/// fixture for `policy_exec_kind = mpb-v1`, suitable for metamorphic testing of decoded-journal
/// verification.
pub fn decoded_mpb_v1_fixture(seed: GenSeed) -> DecodedMpbV1Fixture {
    let mut g = DeterministicGen::new(seed);

    let policy_epoch = (g.next_u64(b"policy_epoch") % 1_000_000).max(1);
    let state_epoch = (g.next_u64(b"state_epoch") % 1_000_000).max(1);

    let token = mprd_core::DecisionToken {
        policy_hash: g.next_hash32(b"policy_hash"),
        policy_ref: PolicyRef {
            policy_epoch,
            registry_root: g.next_hash32(b"registry_root"),
        },
        state_hash: g.next_hash32(b"state_hash"),
        state_ref: StateRef {
            state_source_id: g.next_hash32(b"state_source_id"),
            state_epoch,
            state_attestation_hash: g.next_hash32(b"state_attestation_hash"),
        },
        chosen_action_hash: g.next_hash32(b"chosen_action_hash"),
        nonce_or_tx_hash: g.next_hash32(b"nonce_or_tx_hash"),
        timestamp_ms: 0,
        signature: Vec::new(),
    };

    let proof = mprd_core::ProofBundle {
        policy_hash: token.policy_hash.clone(),
        state_hash: token.state_hash.clone(),
        candidate_set_hash: g.next_hash32(b"candidate_set_hash"),
        chosen_action_hash: token.chosen_action_hash.clone(),
        limits_hash: Hash32(limits_hash_mpb_v1()),
        limits_bytes: limits_bytes_mpb_v1().to_vec(),
        chosen_action_preimage: Vec::new(),
        risc0_receipt: Vec::new(),
        attestation_metadata: Default::default(),
    };

    let chosen_index = g.next_u32(b"chosen_index");

    let mut journal = GuestJournalV3 {
        journal_version: JOURNAL_VERSION,

        policy_hash: token.policy_hash.0,
        policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
        policy_exec_version_id: policy_exec_version_id_v1(),
        state_encoding_id: state_encoding_id_v1(),
        action_encoding_id: action_encoding_id_v1(),

        policy_epoch: token.policy_ref.policy_epoch,
        registry_root: token.policy_ref.registry_root.0,

        state_source_id: token.state_ref.state_source_id.0,
        state_epoch: token.state_ref.state_epoch,
        state_attestation_hash: token.state_ref.state_attestation_hash.0,

        state_hash: token.state_hash.0,
        candidate_set_hash: proof.candidate_set_hash.0,
        chosen_action_hash: token.chosen_action_hash.0,
        limits_hash: limits_hash_mpb_v1(),
        nonce_or_tx_hash: token.nonce_or_tx_hash.0,

        chosen_index,
        allowed: true,

        decision_commitment: [0u8; 32],
    };
    journal.decision_commitment = compute_decision_commitment_v3(&journal);

    DecodedMpbV1Fixture {
        token,
        proof,
        journal,
    }
}
