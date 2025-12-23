//! Production-grade input validation and canonicalization.
//!
//! This module enforces bounded inputs (DoS resistance) and provides canonicalization helpers
//! used at pipeline boundaries.

use crate::hash::{
    candidate_hash_preimage, hash_candidate_preimage_v1, hash_state_preimage_v1,
    state_hash_preimage,
};
use crate::{CandidateAction, MprdError, Result, StateSnapshot, Value};
use std::collections::HashMap;

// =============================================================================
// Bounds (v1)
// =============================================================================

pub const MAX_STATE_FIELDS_V1: usize = 256;
pub const MAX_POLICY_INPUTS_V1: usize = 64;
pub const MAX_KEY_BYTES_V1: usize = 64;
pub const MAX_STRING_BYTES_V1: usize = 1024;
pub const MAX_VALUE_BYTES_V1: usize = 16 * 1024;
pub const MAX_ACTION_TYPE_BYTES_V1: usize = 64;
pub const MAX_ACTION_PARAMS_V1: usize = 64;

pub const MAX_STATE_PREIMAGE_BYTES_V1: usize = 64 * 1024;
pub const MAX_CANDIDATE_PREIMAGE_BYTES_V1: usize = 16 * 1024;

pub const ACTION_TYPE_NOOP_V1: &str = "noop";
pub const ACTION_TYPE_HTTP_CALL_V1: &str = "http_call";

/// Validate a canonical v1 action schema (fail-closed).
///
/// This function is intentionally pure: it validates syntax/types only and does not perform any
/// network I/O (e.g. DNS resolution). SSRF-hardening checks should run at the executor boundary.
pub fn validate_action_schema_v1(action_type: &str, params: &HashMap<String, Value>) -> Result<()> {
    match action_type {
        ACTION_TYPE_NOOP_V1 => {
            if !params.is_empty() {
                return Err(MprdError::InvalidInput(
                    "noop action must not include params".into(),
                ));
            }
            Ok(())
        }
        ACTION_TYPE_HTTP_CALL_V1 => {
            // Deny unknown keys (fail-closed).
            for k in params.keys() {
                match k.as_str() {
                    "http_method"
                    | "http_url"
                    | "http_body"
                    | "http_content_type"
                    | "http_expected_status" => {}
                    _ => {
                        return Err(MprdError::InvalidInput(format!(
                            "http_call has unknown param key: {k}"
                        )))
                    }
                }
            }

            let method = params.get("http_method").ok_or_else(|| {
                MprdError::InvalidInput("http_call missing required param http_method".into())
            })?;
            let url = params.get("http_url").ok_or_else(|| {
                MprdError::InvalidInput("http_call missing required param http_url".into())
            })?;

            let Value::String(method) = method else {
                return Err(MprdError::InvalidInput(
                    "http_method must be a String".into(),
                ));
            };

            match method.as_str() {
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" => {}
                _ => {
                    return Err(MprdError::InvalidInput(
                        "http_method must be one of GET/POST/PUT/PATCH/DELETE".into(),
                    ))
                }
            }

            let Value::String(url) = url else {
                return Err(MprdError::InvalidInput("http_url must be a String".into()));
            };

            // Syntactic URL validation only (do not resolve DNS here).
            let url = url::Url::parse(url)
                .map_err(|e| MprdError::InvalidInput(format!("invalid http_url: {e}")))?;
            if url.username() != "" || url.password().is_some() {
                return Err(MprdError::InvalidInput(
                    "http_url must not include userinfo".into(),
                ));
            }
            if url.fragment().is_some() {
                return Err(MprdError::InvalidInput(
                    "http_url must not include a fragment".into(),
                ));
            }
            if url.host_str().is_none() {
                return Err(MprdError::InvalidInput(
                    "http_url must include a host".into(),
                ));
            }
            match url.scheme() {
                "https" | "http" => {}
                _ => {
                    return Err(MprdError::InvalidInput(
                        "http_url scheme must be http or https".into(),
                    ))
                }
            }

            if let Some(body) = params.get("http_body") {
                if !matches!(body, Value::Bytes(_)) {
                    return Err(MprdError::InvalidInput("http_body must be Bytes".into()));
                }
            }

            if let Some(ct) = params.get("http_content_type") {
                if !matches!(ct, Value::String(_)) {
                    return Err(MprdError::InvalidInput(
                        "http_content_type must be a String".into(),
                    ));
                }
            }

            if let Some(es) = params.get("http_expected_status") {
                let status_u64: u64 = match es {
                    Value::UInt(u) => *u,
                    Value::Int(i) if *i >= 0 => *i as u64,
                    _ => {
                        return Err(MprdError::InvalidInput(
                            "http_expected_status must be a non-negative integer".into(),
                        ))
                    }
                };
                if !(100..=599).contains(&status_u64) {
                    return Err(MprdError::InvalidInput(
                        "http_expected_status must be in [100, 599]".into(),
                    ));
                }
            }

            Ok(())
        }
        _ => Err(MprdError::InvalidInput(format!(
            "unsupported action_type (v1): {action_type}"
        ))),
    }
}

fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(MprdError::InvalidInput("empty key".into()));
    }
    if key.len() > MAX_KEY_BYTES_V1 {
        return Err(MprdError::BoundedValueExceeded(format!(
            "key too long ({} > {})",
            key.len(),
            MAX_KEY_BYTES_V1
        )));
    }
    Ok(())
}

fn validate_value(value: &Value) -> Result<()> {
    match value {
        Value::Bool(_) | Value::Int(_) | Value::UInt(_) => Ok(()),
        Value::String(s) => {
            if s.len() > MAX_STRING_BYTES_V1 {
                return Err(MprdError::BoundedValueExceeded(format!(
                    "string too large ({} > {})",
                    s.len(),
                    MAX_STRING_BYTES_V1
                )));
            }
            Ok(())
        }
        Value::Bytes(b) => {
            if b.len() > MAX_VALUE_BYTES_V1 {
                return Err(MprdError::BoundedValueExceeded(format!(
                    "bytes too large ({} > {})",
                    b.len(),
                    MAX_VALUE_BYTES_V1
                )));
            }
            Ok(())
        }
    }
}

pub fn validate_state_snapshot_v1(state: &StateSnapshot) -> Result<()> {
    if state.fields.len() > MAX_STATE_FIELDS_V1 {
        return Err(MprdError::BoundedValueExceeded(format!(
            "too many state fields ({} > {})",
            state.fields.len(),
            MAX_STATE_FIELDS_V1
        )));
    }
    if state.policy_inputs.len() > MAX_POLICY_INPUTS_V1 {
        return Err(MprdError::BoundedValueExceeded(format!(
            "too many policy_inputs ({} > {})",
            state.policy_inputs.len(),
            MAX_POLICY_INPUTS_V1
        )));
    }

    for (k, v) in &state.fields {
        validate_key(k)?;
        validate_value(v)?;
    }

    for (k, v) in &state.policy_inputs {
        validate_key(k)?;
        if v.len() > MAX_VALUE_BYTES_V1 {
            return Err(MprdError::BoundedValueExceeded(format!(
                "policy_inputs value too large ({} > {})",
                v.len(),
                MAX_VALUE_BYTES_V1
            )));
        }
    }

    // Enforce preimage size bound.
    let preimage = state_hash_preimage(state);
    if preimage.len() > MAX_STATE_PREIMAGE_BYTES_V1 {
        return Err(MprdError::BoundedValueExceeded(format!(
            "state_preimage too large ({} > {})",
            preimage.len(),
            MAX_STATE_PREIMAGE_BYTES_V1
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash32, Score};
    use proptest::prelude::*;
    use std::collections::HashSet;

    #[test]
    fn validate_action_schema_rejects_http_call_userinfo_and_fragment() {
        let mut params = HashMap::new();
        params.insert("http_method".into(), Value::String("GET".into()));
        params.insert(
            "http_url".into(),
            Value::String("http://user:pass@example.com/".into()),
        );
        assert!(validate_action_schema_v1(ACTION_TYPE_HTTP_CALL_V1, &params).is_err());

        params.insert(
            "http_url".into(),
            Value::String("https://example.com/#frag".into()),
        );
        assert!(validate_action_schema_v1(ACTION_TYPE_HTTP_CALL_V1, &params).is_err());
    }

    #[test]
    fn validate_state_snapshot_rejects_too_many_fields() {
        let mut fields = HashMap::new();
        for i in 0..=MAX_STATE_FIELDS_V1 {
            fields.insert(format!("k{i}"), Value::UInt(1));
        }
        let state = StateSnapshot {
            fields,
            policy_inputs: HashMap::new(),
            state_hash: crate::Hash32([0u8; 32]),
            state_ref: crate::StateRef::unknown(),
        };
        assert!(validate_state_snapshot_v1(&state).is_err());
    }

    proptest! {
        #[test]
        fn decode_candidate_preimage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = decode_candidate_preimage_v1(&bytes);
        }

        #[test]
        fn validate_action_schema_accepts_basic_http_call(host in "[a-z]{1,10}\\.example") {
            let mut params = HashMap::new();
            params.insert("http_method".into(), Value::String("GET".into()));
            params.insert("http_url".into(), Value::String(format!("https://{host}/")));
            prop_assert!(validate_action_schema_v1(ACTION_TYPE_HTTP_CALL_V1, &params).is_ok());
        }

        #[test]
        fn validate_action_schema_rejects_unknown_param_key(key in "[a-z_]{1,16}") {
            prop_assume!(key != "http_method" && key != "http_url" && key != "http_body" && key != "http_content_type" && key != "http_expected_status");
            let mut params = HashMap::new();
            params.insert("http_method".into(), Value::String("GET".into()));
            params.insert("http_url".into(), Value::String("https://example.com/".into()));
            params.insert(key, Value::UInt(1));
            prop_assert!(validate_action_schema_v1(ACTION_TYPE_HTTP_CALL_V1, &params).is_err());
        }

        #[test]
        fn candidate_preimage_roundtrips(
            action_type in "[a-z_]{1,16}",
            score in -1000i64..1000i64,
            params in proptest::collection::vec(("[a-z]{1,8}", any::<u8>()), 0..16)
        ) {
            let mut uniq = HashSet::new();
            let mut map = HashMap::new();
            for (k, v) in params {
                if uniq.insert(k.clone()) {
                    map.insert(k, Value::UInt(v as u64));
                }
            }

            let candidate = CandidateAction {
                action_type: action_type.clone(),
                params: map.clone(),
                score: Score(score),
                candidate_hash: Hash32([0u8; 32]),
            };

            let preimage = candidate_hash_preimage(&candidate);
            let decoded = decode_candidate_preimage_v1(&preimage).expect("decode");
            prop_assert_eq!(decoded.0, action_type);
            prop_assert_eq!(decoded.2, score);
            prop_assert_eq!(decoded.1, map);
        }
    }
}

pub fn canonicalize_state_snapshot_v1(state: StateSnapshot) -> Result<StateSnapshot> {
    validate_state_snapshot_v1(&state)?;
    let preimage = state_hash_preimage(&state);
    let state_hash = hash_state_preimage_v1(&preimage);
    Ok(StateSnapshot {
        state_hash,
        ..state
    })
}

pub fn validate_candidate_action_v1(candidate: &CandidateAction) -> Result<()> {
    if candidate.action_type.is_empty() {
        return Err(MprdError::InvalidInput("action_type is empty".into()));
    }
    if candidate.action_type.len() > MAX_ACTION_TYPE_BYTES_V1 {
        return Err(MprdError::BoundedValueExceeded(format!(
            "action_type too long ({} > {})",
            candidate.action_type.len(),
            MAX_ACTION_TYPE_BYTES_V1
        )));
    }

    if candidate.params.len() > MAX_ACTION_PARAMS_V1 {
        return Err(MprdError::BoundedValueExceeded(format!(
            "too many action params ({} > {})",
            candidate.params.len(),
            MAX_ACTION_PARAMS_V1
        )));
    }

    for (k, v) in &candidate.params {
        validate_key(k)?;
        validate_value(v)?;
    }

    // Enforce candidate preimage size bound (the bytes that become `chosen_action_hash`).
    let preimage = candidate_hash_preimage(candidate);
    if preimage.len() > MAX_CANDIDATE_PREIMAGE_BYTES_V1 {
        return Err(MprdError::BoundedValueExceeded(format!(
            "candidate_preimage too large ({} > {})",
            preimage.len(),
            MAX_CANDIDATE_PREIMAGE_BYTES_V1
        )));
    }

    Ok(())
}

pub fn canonicalize_candidates_v1(
    mut candidates: Vec<CandidateAction>,
) -> Result<Vec<CandidateAction>> {
    for c in &mut candidates {
        validate_candidate_action_v1(c)?;
        let preimage = candidate_hash_preimage(c);
        c.candidate_hash = hash_candidate_preimage_v1(&preimage);
    }
    Ok(candidates)
}

/// Decode a v1 candidate preimage (the bytes hashed as `chosen_action_hash`).
///
/// This is used by executors to derive the action to execute *from the committed transcript*.
pub fn decode_candidate_preimage_v1(bytes: &[u8]) -> Result<(String, HashMap<String, Value>, i64)> {
    let mut i = 0usize;
    let read_u32 = |bytes: &[u8], i: &mut usize| -> Result<u32> {
        if *i + 4 > bytes.len() {
            return Err(MprdError::InvalidInput("truncated u32".into()));
        }
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&bytes[*i..*i + 4]);
        *i += 4;
        Ok(u32::from_le_bytes(tmp))
    };

    let read_i64 = |bytes: &[u8], i: &mut usize| -> Result<i64> {
        if *i + 8 > bytes.len() {
            return Err(MprdError::InvalidInput("truncated i64".into()));
        }
        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(&bytes[*i..*i + 8]);
        *i += 8;
        Ok(i64::from_le_bytes(tmp))
    };

    let action_len = read_u32(bytes, &mut i)? as usize;
    if action_len > MAX_ACTION_TYPE_BYTES_V1 || i + action_len > bytes.len() {
        return Err(MprdError::InvalidInput("invalid action_type length".into()));
    }
    let action_type = std::str::from_utf8(&bytes[i..i + action_len])
        .map_err(|_| MprdError::InvalidInput("action_type not utf8".into()))?
        .to_string();
    i += action_len;

    let score = read_i64(bytes, &mut i)?;

    let mut params: HashMap<String, Value> = HashMap::new();
    let mut prev_key: Option<String> = None;
    while i < bytes.len() {
        let key_len = read_u32(bytes, &mut i)? as usize;
        if key_len == 0 || key_len > MAX_KEY_BYTES_V1 || i + key_len > bytes.len() {
            return Err(MprdError::InvalidInput("invalid param key length".into()));
        }
        let key = std::str::from_utf8(&bytes[i..i + key_len])
            .map_err(|_| MprdError::InvalidInput("param key not utf8".into()))?
            .to_string();
        i += key_len;

        if let Some(prev) = &prev_key {
            if key <= *prev {
                return Err(MprdError::InvalidInput(
                    "param keys not strictly increasing".into(),
                ));
            }
        }
        prev_key = Some(key.clone());

        if params.len() >= MAX_ACTION_PARAMS_V1 {
            return Err(MprdError::BoundedValueExceeded("too many params".into()));
        }

        if i >= bytes.len() {
            return Err(MprdError::InvalidInput("truncated value tag".into()));
        }
        let tag = bytes[i];
        i += 1;
        let v = match tag {
            0x00 => {
                if i >= bytes.len() {
                    return Err(MprdError::InvalidInput("truncated bool".into()));
                }
                let b = bytes[i] != 0;
                i += 1;
                Value::Bool(b)
            }
            0x01 => Value::Int(read_i64(bytes, &mut i)?),
            0x02 => {
                if i + 8 > bytes.len() {
                    return Err(MprdError::InvalidInput("truncated u64".into()));
                }
                let mut tmp = [0u8; 8];
                tmp.copy_from_slice(&bytes[i..i + 8]);
                i += 8;
                Value::UInt(u64::from_le_bytes(tmp))
            }
            0x03 => {
                let len = read_u32(bytes, &mut i)? as usize;
                if len > MAX_STRING_BYTES_V1 || i + len > bytes.len() {
                    return Err(MprdError::InvalidInput("invalid string length".into()));
                }
                let s = std::str::from_utf8(&bytes[i..i + len])
                    .map_err(|_| MprdError::InvalidInput("string not utf8".into()))?
                    .to_string();
                i += len;
                Value::String(s)
            }
            0x04 => {
                let len = read_u32(bytes, &mut i)? as usize;
                if len > MAX_VALUE_BYTES_V1 || i + len > bytes.len() {
                    return Err(MprdError::InvalidInput("invalid bytes length".into()));
                }
                let out = bytes[i..i + len].to_vec();
                i += len;
                Value::Bytes(out)
            }
            _ => return Err(MprdError::InvalidInput("unknown value tag".into())),
        };

        params.insert(key, v);
    }

    Ok((action_type, params, score))
}
