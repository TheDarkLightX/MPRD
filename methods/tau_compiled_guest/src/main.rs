#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use mprd_risc0_shared::{
    action_encoding_id_v1, compute_decision_commitment_v3, hash_candidate_preimage_v1,
    hash_candidate_set_preimage_v1, hash_state_preimage_v1, limits_hash,
    policy_exec_kind_tau_compiled_id_v1, policy_exec_version_id_v1, state_encoding_id_v1,
    tau_compiled_policy_hash_v1, tcv_key_hash_v1, decode_compiled_tau_policy_v1,
    tcv_eval_circuit_bitset_v1_validated,
    CompiledTauPolicyV1, TcvArithOpV1, TcvGateTypeV1, TcvOperandSourceV1, TcvValueKindV1,
    GuestJournalV3, JOURNAL_VERSION, TauCompiledGuestInputV3,
    MAX_CANDIDATE_PREIMAGE_BYTES_V1, MAX_CANDIDATES_V1, MAX_STATE_PREIMAGE_BYTES_V1,
    MAX_TCV_COMPILED_POLICY_BYTES_V1,
    MAX_TCV_PREDICATES_V1,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

type KeyHash = [u8; 32];

fn read_u32_le(bytes: &[u8], offset: &mut usize) -> Option<u32> {
    if *offset + 4 > bytes.len() {
        return None;
    }
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&bytes[*offset..*offset + 4]);
    *offset += 4;
    Some(u32::from_le_bytes(tmp))
}

fn read_i64_le(bytes: &[u8], offset: &mut usize) -> Option<i64> {
    if *offset + 8 > bytes.len() {
        return None;
    }
    let mut tmp = [0u8; 8];
    tmp.copy_from_slice(&bytes[*offset..*offset + 8]);
    *offset += 8;
    Some(i64::from_le_bytes(tmp))
}

fn read_u64_le(bytes: &[u8], offset: &mut usize) -> Option<u64> {
    if *offset + 8 > bytes.len() {
        return None;
    }
    let mut tmp = [0u8; 8];
    tmp.copy_from_slice(&bytes[*offset..*offset + 8]);
    *offset += 8;
    Some(u64::from_le_bytes(tmp))
}

fn read_len_prefixed_bytes<'a>(bytes: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let len = read_u32_le(bytes, offset)? as usize;
    if len == 0 || *offset + len > bytes.len() {
        return None;
    }
    let out = &bytes[*offset..*offset + len];
    *offset += len;
    Some(out)
}

fn skip_len_prefixed_bytes(bytes: &[u8], offset: &mut usize) -> Option<()> {
    let len = read_u32_le(bytes, offset)? as usize;
    if *offset + len > bytes.len() {
        return None;
    }
    *offset += len;
    Some(())
}

fn skip_value(bytes: &[u8], offset: &mut usize, tag: u8) -> Option<()> {
    match tag {
        0x00 => {
            if *offset >= bytes.len() {
                return None;
            }
            *offset += 1;
            Some(())
        }
        0x01 => {
            read_i64_le(bytes, offset)?;
            Some(())
        }
        0x02 => {
            read_u64_le(bytes, offset)?;
            Some(())
        }
        0x03 | 0x04 => skip_len_prefixed_bytes(bytes, offset),
        _ => None,
    }
}

fn parse_required_u64_from_kv_preimage(
    fields_only: &[u8],
    required_key_hashes: &[KeyHash],
) -> Option<Vec<Option<u64>>> {
    let mut values: Vec<Option<u64>> = vec![None; required_key_hashes.len()];
    let mut o = 0usize;
    while o < fields_only.len() {
        let key = read_len_prefixed_bytes(fields_only, &mut o)?;
        let computed = tcv_key_hash_v1(key);
        if o >= fields_only.len() {
            return None;
        }
        let tag = fields_only[o];
        o += 1;

        if let Ok(idx) = required_key_hashes.binary_search(&computed) {
            if values[idx].is_some() {
                return None;
            }
            let v = match tag {
                0x02 => read_u64_le(fields_only, &mut o)?,
                0x00 => {
                    if o >= fields_only.len() {
                        return None;
                    }
                    let b = fields_only[o] != 0;
                    o += 1;
                    if b { 1 } else { 0 }
                }
                _ => return None,
            };
            values[idx] = Some(v);
        } else {
            skip_value(fields_only, &mut o, tag)?;
        }
    }
    Some(values)
}

fn lookup_required_u64(
    required_key_hashes: &[KeyHash],
    values: &[Option<u64>],
    target: KeyHash,
) -> Option<u64> {
    let idx = required_key_hashes.binary_search(&target).ok()?;
    values.get(idx)?.as_ref().copied()
}

fn parse_candidate_preimage(
    candidate_preimage: &[u8],
    required_param_key_hashes: &[KeyHash],
) -> Option<(i64, Vec<Option<u64>>)> {
    let mut o = 0usize;
    // action_type
    read_len_prefixed_bytes(candidate_preimage, &mut o)?;
    // score
    let score = read_i64_le(candidate_preimage, &mut o)?;
    let values = parse_required_u64_from_kv_preimage(&candidate_preimage[o..], required_param_key_hashes)?;
    Some((score, values))
}

fn eval_predicates(
    policy: &CompiledTauPolicyV1,
    state_required: &[KeyHash],
    state_values: &[Option<u64>],
    candidate_required: &[KeyHash],
    candidate_values: &[Option<u64>],
) -> Option<Vec<bool>> {
    let mut out: Vec<bool> = Vec::with_capacity(policy.predicates.len());
    for p in &policy.predicates {
        let left = eval_operand_u64(&p.left, state_required, state_values, candidate_required, candidate_values)?;
        let right = eval_operand_u64(&p.right, state_required, state_values, candidate_required, candidate_values)?;
        let res = match p.op {
            TcvArithOpV1::LessThan => left < right,
            TcvArithOpV1::LessThanEq => left <= right,
            TcvArithOpV1::GreaterThan => left > right,
            TcvArithOpV1::GreaterThanEq => left >= right,
            TcvArithOpV1::Equals => left == right,
            TcvArithOpV1::NotEquals => left != right,
        };
        out.push(res);
    }
    Some(out)
}

fn eval_operand_u64(
    path: &mprd_risc0_shared::TcvOperandPathV1,
    state_required: &[KeyHash],
    state_values: &[Option<u64>],
    candidate_required: &[KeyHash],
    candidate_values: &[Option<u64>],
) -> Option<u64> {
    // v1 forbids i64 operands.
    if path.value_kind == TcvValueKindV1::I64 {
        return None;
    }

    match path.source {
        TcvOperandSourceV1::Constant => Some(u64::from_le_bytes(path.constant_value)),
        TcvOperandSourceV1::State => lookup_required_u64(state_required, state_values, path.key_hash),
        TcvOperandSourceV1::Candidate => lookup_required_u64(candidate_required, candidate_values, path.key_hash),
    }
}

fn eval_circuit(
    policy: &CompiledTauPolicyV1,
    predicate_results: &[bool],
    state_required: &[KeyHash],
    state_values: &[Option<u64>],
) -> Option<bool> {
    let mut max_wire: u32 = policy.output_wire;
    for g in &policy.gates {
        max_wire = max_wire.max(g.out_wire);
        match g.gate_type {
            TcvGateTypeV1::And | TcvGateTypeV1::Or => {
                max_wire = max_wire.max(g.in1).max(g.in2);
            }
            TcvGateTypeV1::Not => {
                max_wire = max_wire.max(g.in1);
            }
            _ => {}
        }
    }
    if (max_wire as usize) >= mprd_risc0_shared::MAX_TCV_WIRES_V1 {
        return None;
    }
    let mut wires: Vec<bool> = vec![false; (max_wire + 1) as usize];
    let mut written: Vec<bool> = vec![false; wires.len()];

    for g in &policy.gates {
        let out = g.out_wire as usize;
        if out >= wires.len() || written[out] {
            return None;
        }
        match g.gate_type {
            TcvGateTypeV1::PredicateInput => {
                let pred_idx = g.in1 as usize;
                if pred_idx >= predicate_results.len() {
                    return None;
                }
                wires[out] = predicate_results[pred_idx];
            }
            TcvGateTypeV1::Constant => {
                if g.in1 != 0 && g.in1 != 1 {
                    return None;
                }
                wires[out] = g.in1 == 1;
            }
            TcvGateTypeV1::TemporalInput => {
                let field_idx = g.in1 as usize;
                if field_idx >= policy.temporal_fields.len() {
                    return None;
                }
                let tf = &policy.temporal_fields[field_idx];
                let lookback = g.in2 as usize;
                let key_hash = if lookback == 0 {
                    tf.current_key_hash
                } else {
                    let i = lookback - 1;
                    if i >= tf.prev_key_hashes.len() {
                        return None;
                    }
                    tf.prev_key_hashes[i]
                };
                let v = lookup_required_u64(state_required, state_values, key_hash).unwrap_or(0);
                wires[out] = v != 0;
            }
            TcvGateTypeV1::And => {
                let in1 = g.in1 as usize;
                let in2 = g.in2 as usize;
                if in1 >= wires.len() || in2 >= wires.len() || !written[in1] || !written[in2] {
                    return None;
                }
                wires[out] = wires[in1] && wires[in2];
            }
            TcvGateTypeV1::Or => {
                let in1 = g.in1 as usize;
                let in2 = g.in2 as usize;
                if in1 >= wires.len() || in2 >= wires.len() || !written[in1] || !written[in2] {
                    return None;
                }
                wires[out] = wires[in1] || wires[in2];
            }
            TcvGateTypeV1::Not => {
                let in1 = g.in1 as usize;
                if in1 >= wires.len() || !written[in1] {
                    return None;
                }
                wires[out] = !wires[in1];
            }
        }
        written[out] = true;
    }

    let out = policy.output_wire as usize;
    if out >= wires.len() || !written[out] {
        return None;
    }
    Some(wires[out])
}

fn gather_required_key_hashes(policy: &CompiledTauPolicyV1) -> (Vec<KeyHash>, Vec<KeyHash>) {
    let mut state: Vec<KeyHash> = Vec::new();
    let mut candidate: Vec<KeyHash> = Vec::new();

    for p in &policy.predicates {
        for operand in [&p.left, &p.right] {
            match operand.source {
                TcvOperandSourceV1::State => state.push(operand.key_hash),
                TcvOperandSourceV1::Candidate => candidate.push(operand.key_hash),
                _ => {}
            }
        }
    }

    for tf in &policy.temporal_fields {
        state.push(tf.current_key_hash);
        for h in &tf.prev_key_hashes {
            state.push(*h);
        }
    }

    state.sort();
    state.dedup();
    candidate.sort();
    candidate.dedup();
    (state, candidate)
}

fn eval_predicates_for_candidate(
    policy: &CompiledTauPolicyV1,
    state_required: &[KeyHash],
    state_values: &[Option<u64>],
    candidate_required: &[KeyHash],
    candidate_values: &[Option<u64>],
    tmp: &mut [bool; MAX_TCV_PREDICATES_V1],
) -> Option<usize> {
    if policy.predicates.len() > MAX_TCV_PREDICATES_V1 {
        return None;
    }

    for i in 0..policy.predicates.len() {
        let p = &policy.predicates[i];
        let left = eval_operand_u64(&p.left, state_required, state_values, candidate_required, candidate_values)?;
        let right = eval_operand_u64(&p.right, state_required, state_values, candidate_required, candidate_values)?;
        tmp[i] = match p.op {
            TcvArithOpV1::LessThan => left < right,
            TcvArithOpV1::LessThanEq => left <= right,
            TcvArithOpV1::GreaterThan => left > right,
            TcvArithOpV1::GreaterThanEq => left >= right,
            TcvArithOpV1::Equals => left == right,
            TcvArithOpV1::NotEquals => left != right,
        };
    }
    Some(policy.predicates.len())
}

fn main() {
    let input: TauCompiledGuestInputV3 = env::read();

    if input.policy_exec_kind_id != policy_exec_kind_tau_compiled_id_v1()
        || input.policy_exec_version_id != policy_exec_version_id_v1()
        || input.state_encoding_id != state_encoding_id_v1()
        || input.action_encoding_id != action_encoding_id_v1()
    {
        panic!("unsupported ABI ids");
    }

    if input.compiled_policy_bytes.len() > MAX_TCV_COMPILED_POLICY_BYTES_V1 {
        panic!("compiled_policy_bytes too large");
    }
    if input.state_preimage.len() > MAX_STATE_PREIMAGE_BYTES_V1 {
        panic!("state_preimage too large");
    }
    if input.candidates_preimages.is_empty() || input.candidates_preimages.len() > MAX_CANDIDATES_V1 {
        panic!("invalid candidate count");
    }
    if input
        .candidates_preimages
        .iter()
        .any(|b| b.len() > MAX_CANDIDATE_PREIMAGE_BYTES_V1)
    {
        panic!("candidate_preimage too large");
    }
    // v1: no additional execution limits defined (must be empty and committed as empty).
    if !input.limits_bytes.is_empty() {
        panic!("unsupported non-empty limits_bytes");
    }

    // Bind policy_hash to the compiled artifact bytes.
    let policy_hash = tau_compiled_policy_hash_v1(&input.compiled_policy_bytes);
    let state_hash = hash_state_preimage_v1(&input.state_preimage);

    let mut candidate_hashes: Vec<[u8; 32]> = Vec::with_capacity(input.candidates_preimages.len());
    let mut scores: Vec<i64> = Vec::with_capacity(input.candidates_preimages.len());

    let policy = decode_compiled_tau_policy_v1(&input.compiled_policy_bytes)
        .unwrap_or_else(|_| panic!("invalid compiled_policy_bytes"));
    let (state_required, candidate_required) = gather_required_key_hashes(&policy);
    let state_values = parse_required_u64_from_kv_preimage(&input.state_preimage, &state_required)
        .unwrap_or_else(|| panic!("invalid state_preimage"));

    let n = input.candidates_preimages.len();
    let mask: u64 = if n >= 64 {
        u64::MAX
    } else {
        (1u64 << (n as u32)) - 1
    };

    let mut predicate_bits: Vec<u64> = vec![0u64; policy.predicates.len()];
    let mut candidates_valid_mask: u64 = 0;
    let mut tmp_preds = [false; MAX_TCV_PREDICATES_V1];

    for (idx, cand_preimage) in input.candidates_preimages.iter().enumerate() {
        candidate_hashes.push(hash_candidate_preimage_v1(cand_preimage));
        let candidate = parse_candidate_preimage(cand_preimage, &candidate_required);
        let (score, candidate_values) = match candidate {
            Some((s, v)) => (s, v),
            None => (i64::MIN, vec![None; candidate_required.len()]),
        };
        scores.push(score);

        let pred_count = match eval_predicates_for_candidate(
            &policy,
            &state_required,
            &state_values,
            &candidate_required,
            &candidate_values,
            &mut tmp_preds,
        ) {
            Some(c) => c,
            None => continue,
        };

        candidates_valid_mask |= 1u64 << (idx as u32);
        for pred_idx in 0..pred_count {
            if tmp_preds[pred_idx] {
                predicate_bits[pred_idx] |= 1u64 << (idx as u32);
            }
        }
    }

    let allowed_mask = tcv_eval_circuit_bitset_v1_validated(
        &policy,
        &predicate_bits,
        mask,
        |field_idx, lookback| {
            let field_idx = field_idx as usize;
            let lookback = lookback as usize;
            let tf = &policy.temporal_fields[field_idx];
            let key_hash = if lookback == 0 {
                tf.current_key_hash
            } else {
                tf.prev_key_hashes[lookback - 1]
            };
            lookup_required_u64(&state_required, &state_values, key_hash).unwrap_or(0) != 0
        },
    ) & candidates_valid_mask;

    let mut best: Option<(usize, i64)> = None;
    for idx in 0..n {
        if (allowed_mask >> (idx as u32)) & 1 == 0 {
            continue;
        }
        let score = scores[idx];
        match best {
            None => best = Some((idx, score)),
            Some((best_idx, best_score)) => {
                if score > best_score || (score == best_score && idx < best_idx) {
                    best = Some((idx, score));
                }
            }
        }
    }

    let (chosen_index, allowed) = match best {
        Some((idx, _)) => (idx, true),
        None => (0usize, false),
    };
    let chosen_index_u32: u32 = match chosen_index.try_into() {
        Ok(v) => v,
        Err(_) => panic!("chosen_index out of range"),
    };
    let chosen_action_hash = candidate_hashes[chosen_index];

    // Candidate set hash preimage: u32 count + hashes in order (matches mprd-core layout).
    let mut set_preimage = Vec::with_capacity(4 + candidate_hashes.len() * 32);
    set_preimage.extend_from_slice(&(candidate_hashes.len() as u32).to_le_bytes());
    for h in &candidate_hashes {
        set_preimage.extend_from_slice(h);
    }
    let candidate_set_hash = hash_candidate_set_preimage_v1(&set_preimage);

    let limits_hash = limits_hash(&[]);

    let mut journal = GuestJournalV3 {
        journal_version: JOURNAL_VERSION,
        policy_hash,
        policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
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
