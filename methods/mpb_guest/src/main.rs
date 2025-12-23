#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::str;
use mprd_mpb::MpbVm;
use mprd_risc0_shared::{
    action_encoding_id_v1, compute_decision_commitment_v3, limits_hash_mpb_v1,
    hash_candidate_preimage_v1, hash_candidate_set_preimage_v1, hash_state_preimage_v1,
    mpb_register_mapping_id_v1, policy_exec_kind_mpb_id_v1, policy_exec_version_id_v1,
    state_encoding_id_v1, GuestJournalV3, MpbGuestInputV3, MpbVarBindingV1, JOURNAL_VERSION,
    MAX_CANDIDATE_PREIMAGE_BYTES_V1, MAX_CANDIDATES_V1, MAX_POLICY_BYTECODE_BYTES_V1,
    MAX_POLICY_VARIABLES_V1, MAX_STATE_PREIMAGE_BYTES_V1, MPB_FUEL_LIMIT_V1,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

const MAX_CANDIDATES: usize = MAX_CANDIDATES_V1;
const MAX_VAR_BINDINGS: usize = MAX_POLICY_VARIABLES_V1;

fn validate_var_bindings(vars: &[MpbVarBindingV1]) -> bool {
    if vars.len() > MAX_VAR_BINDINGS {
        return false;
    }
    let mut prev: Option<&[u8]> = None;
    for v in vars {
        if v.reg as usize >= MpbVm::MAX_REGISTERS {
            return false;
        }
        if str::from_utf8(&v.name).is_err() {
            return false;
        }
        if let Some(p) = prev {
            if v.name.as_slice() <= p {
                return false;
            }
        }
        prev = Some(v.name.as_slice());
    }
    true
}

fn compute_policy_hash(bytecode: &[u8], vars: &[MpbVarBindingV1]) -> [u8; 32] {
    let mut tmp: Vec<(&[u8], u8)> = Vec::with_capacity(vars.len());
    for v in vars {
        tmp.push((v.name.as_slice(), v.reg));
    }
    mprd_mpb::policy_hash_v1(bytecode, &tmp)
}

fn main() {
    let input: MpbGuestInputV3 = env::read();

    // Fail-closed ABI sanity checks (the guest should not accept "hinted" IDs).
    if input.policy_exec_kind_id != policy_exec_kind_mpb_id_v1()
        || input.policy_exec_version_id != policy_exec_version_id_v1()
        || input.mpb_register_mapping_id != mpb_register_mapping_id_v1()
        || input.state_encoding_id != state_encoding_id_v1()
        || input.action_encoding_id != action_encoding_id_v1()
    {
        panic!("unsupported ABI ids");
    }

    if input.candidates_preimages.is_empty() || input.candidates_preimages.len() > MAX_CANDIDATES {
        panic!("invalid candidate count");
    }

    if input.state_preimage.len() > MAX_STATE_PREIMAGE_BYTES_V1 {
        panic!("state_preimage too large");
    }

    if input.policy_bytecode.len() > MAX_POLICY_BYTECODE_BYTES_V1 {
        panic!("policy_bytecode too large");
    }

    if input.mpb_fuel_limit != MPB_FUEL_LIMIT_V1 {
        panic!("unsupported mpb_fuel_limit");
    }

    if !validate_var_bindings(&input.policy_variables) {
        panic!("invalid policy_variables");
    }

    // Commitments derived from canonical preimage bytes.
    let policy_hash = compute_policy_hash(&input.policy_bytecode, &input.policy_variables);
    let state_hash = hash_state_preimage_v1(&input.state_preimage);

    // Evaluate policy per candidate, compute candidate hashes and select deterministically.
    let mut candidate_hashes: Vec<[u8; 32]> = Vec::with_capacity(input.candidates_preimages.len());
    let mut best: Option<(usize, i64)> = None;
    let bindings: Vec<(&[u8], u8)> = input
        .policy_variables
        .iter()
        .map(|b| (b.name.as_slice(), b.reg))
        .collect();

    for (idx, cand_preimage) in input.candidates_preimages.iter().enumerate() {
        if cand_preimage.len() > MAX_CANDIDATE_PREIMAGE_BYTES_V1 {
            panic!("candidate_preimage too large");
        }
        let candidate_hash = hash_candidate_preimage_v1(cand_preimage);
        candidate_hashes.push(candidate_hash);

        let score = mprd_mpb::candidate_score_from_preimage_v1(cand_preimage)
            .unwrap_or_else(|_| panic!("malformed candidate encoding"));

        let regs = mprd_mpb::registers_from_preimages_v1(
            &input.state_preimage,
            cand_preimage,
            &bindings,
        )
        .unwrap_or_else(|_| panic!("malformed state/candidate encoding"));

        let mut vm = MpbVm::with_fuel(&regs, MPB_FUEL_LIMIT_V1);
        let allowed = vm.execute(&input.policy_bytecode).map(|v| v != 0).unwrap_or(false);

        if allowed {
            match best {
                None => best = Some((idx, score)),
                Some((_best_idx, best_score)) => {
                    if score > best_score {
                        best = Some((idx, score));
                    }
                }
            }
        }
    }

    // Fail-closed: if no candidates are allowed (including out-of-fuel / invalid bytecode),
    // commit a denial journal rather than panicking. Verifiers MUST reject `allowed=false`.
    let (chosen_index, allowed) = match best {
        Some((idx, _score)) => (idx, true),
        None => (0usize, false),
    };
    let chosen_index_u32: u32 = chosen_index.try_into().unwrap();
    let chosen_action_hash = candidate_hashes[chosen_index];

    // Candidate set hash preimage: u32 count + hashes in order (matches mprd-core layout).
    let mut set_preimage = Vec::with_capacity(4 + candidate_hashes.len() * 32);
    set_preimage.extend_from_slice(&(candidate_hashes.len() as u32).to_le_bytes());
    for h in &candidate_hashes {
        set_preimage.extend_from_slice(h);
    }
    let candidate_set_hash = hash_candidate_set_preimage_v1(&set_preimage);

    // mpb-v1 fuel semantics are pinned and committed via limits_hash.
    let limits_hash = limits_hash_mpb_v1();

    let mut journal = GuestJournalV3 {
        journal_version: JOURNAL_VERSION,
        policy_hash,
        policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
        policy_exec_version_id: policy_exec_version_id_v1(),
        state_encoding_id: state_encoding_id_v1(),
        action_encoding_id: action_encoding_id_v1(),
        policy_epoch: input.policy_epoch,
        registry_root: input.registry_root,
        state_source_id: input.state_source_id,
        state_epoch: input.state_epoch,
        state_attestation_hash: input.state_attestation_hash,
        state_hash,
        candidate_set_hash,
        chosen_action_hash,
        limits_hash,
        nonce_or_tx_hash: input.nonce_or_tx_hash,
        chosen_index: chosen_index_u32,
        allowed,
        decision_commitment: [0u8; 32],
    };

    journal.decision_commitment = compute_decision_commitment_v3(&journal);
    env::commit(&journal);
}
