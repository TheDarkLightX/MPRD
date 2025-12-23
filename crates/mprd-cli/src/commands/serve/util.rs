use sha2::Digest;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

use mprd_core::{Hash32, Value};

#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum BuildStateFieldsError {
    #[error("All provided state fields were invalid: {rejected_keys:?}")]
    AllFieldsInvalid { rejected_keys: Vec<String> },
}

pub(super) fn now_ms() -> i64 {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_millis(0))
        .as_millis();
    i64::try_from(ms).unwrap_or(0)
}

pub(super) fn env_opt(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub(super) fn fingerprint_hex(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    hex::encode(&digest[..8])
}

pub(super) fn prune_seen(
    seen: &mut HashMap<String, i64>,
    retention_ms: Option<i64>,
    max_entries: Option<usize>,
) {
    if seen.is_empty() {
        return;
    }

    if let Some(retention_ms) = retention_ms {
        let cutoff = now_ms().saturating_sub(retention_ms);
        seen.retain(|_, ts| *ts >= cutoff);
    }

    if let Some(max_entries) = max_entries {
        if seen.len() <= max_entries {
            return;
        }
        let mut entries: Vec<(&String, &i64)> = seen.iter().collect();
        entries.sort_by_key(|(_, ts)| std::cmp::Reverse(**ts));
        let remove_ids: Vec<String> = entries
            .into_iter()
            .enumerate()
            .filter_map(|(idx, (id, _))| {
                if idx >= max_entries {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for id in remove_ids {
            seen.remove(&id);
        }
    }
}

fn json_number_to_value(n: &serde_json::Number) -> Option<Value> {
    let Some(i) = n.as_i64() else {
        return n.as_u64().map(Value::UInt);
    };

    if i < 0 {
        return Some(Value::Int(i));
    }

    n.as_u64().map(Value::UInt)
}

pub(super) fn json_to_value(v: serde_json::Value) -> Option<Value> {
    match v {
        serde_json::Value::Bool(b) => Some(Value::Bool(b)),
        serde_json::Value::Number(n) => json_number_to_value(&n),
        serde_json::Value::String(s) => Some(Value::String(s)),
        _ => None,
    }
}

pub(super) fn build_state_fields(
    input: Option<HashMap<String, serde_json::Value>>,
) -> std::result::Result<HashMap<String, Value>, BuildStateFieldsError> {
    let Some(input) = input else {
        return Ok(HashMap::from([("balance".into(), Value::UInt(1_000))]));
    };

    let mut rejected_keys = Vec::new();
    let mut fields: HashMap<String, Value> = HashMap::new();

    for (key, value) in input {
        match json_to_value(value) {
            Some(v) => {
                fields.insert(key, v);
            }
            None => {
                rejected_keys.push(key);
            }
        }
    }

    if !rejected_keys.is_empty() && fields.is_empty() {
        rejected_keys.sort();
        return Err(BuildStateFieldsError::AllFieldsInvalid { rejected_keys });
    }

    if fields.is_empty() {
        return Ok(HashMap::from([("balance".into(), Value::UInt(1_000))]));
    }

    Ok(fields)
}

pub(super) fn page_bounds(total: usize, page: u32, page_size: u32) -> (usize, usize) {
    if total == 0 || page_size == 0 {
        return (0, 0);
    }

    let page = page.max(1);
    let page_size = page_size.min(200);

    let start = (page - 1)
        .checked_mul(page_size)
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(total);
    let end = start.saturating_add(page_size as usize).min(total);
    (start.min(total), end.min(total))
}

fn is_ascii_hex(s: &str) -> bool {
    s.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
}

pub(super) fn is_decision_id(s: &str) -> bool {
    s.len() == 64 && is_ascii_hex(s)
}

pub(super) fn is_placeholder_hex64(s: &str) -> bool {
    s.chars().all(|c| c == '0') && s.len() == 64
}

pub(super) fn is_safe_path_id(s: &str, max_len: usize) -> bool {
    if s.is_empty() || s.len() > max_len {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ':' | '.'))
}

pub(super) fn parse_hash32(hex_str: &str) -> std::result::Result<Hash32, String> {
    let bytes = hex::decode(hex_str).map_err(|_| "Invalid hex".to_string())?;
    if bytes.len() != 32 {
        return Err("Expected 32-byte hex".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Hash32(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mprd_core::Value;
    use proptest::prelude::*;

    #[test]
    fn json_to_value_supports_bool_int_uint_and_string() {
        assert_eq!(
            json_to_value(serde_json::json!(true)),
            Some(Value::Bool(true))
        );
        assert_eq!(json_to_value(serde_json::json!(-1)), Some(Value::Int(-1)));
        assert_eq!(json_to_value(serde_json::json!(1)), Some(Value::UInt(1)));
        assert_eq!(
            json_to_value(serde_json::json!("x")),
            Some(Value::String("x".to_string()))
        );
        assert_eq!(json_to_value(serde_json::json!([1, 2, 3])), None);
    }

    #[test]
    fn build_state_fields_defaults_when_missing() {
        let fields = build_state_fields(None).expect("should default");
        assert_eq!(fields.get("balance"), Some(&Value::UInt(1_000)));
    }

    #[test]
    fn build_state_fields_fails_closed_when_all_fields_invalid() {
        let mut input = HashMap::new();
        input.insert("nested".to_string(), serde_json::json!({"x": 1}));
        let err = build_state_fields(Some(input)).expect_err("should fail closed");
        assert_eq!(
            err,
            BuildStateFieldsError::AllFieldsInvalid {
                rejected_keys: vec!["nested".to_string()]
            }
        );
    }

    #[test]
    fn build_state_fields_accepts_partial_valid_input() {
        let mut input = HashMap::new();
        input.insert("balance".to_string(), serde_json::json!(7));
        input.insert("nested".to_string(), serde_json::json!({"x": 1}));
        let fields = build_state_fields(Some(input)).expect("should succeed");
        assert_eq!(fields.get("balance"), Some(&Value::UInt(7)));
    }

    #[test]
    fn page_bounds_handles_overflow_and_empty() {
        assert_eq!(page_bounds(0, 1, 50), (0, 0));
        assert_eq!(page_bounds(10, 1, 5), (0, 5));
        assert_eq!(page_bounds(10, 2, 5), (5, 10));
        assert_eq!(page_bounds(10, 3, 5), (10, 10));
        assert_eq!(page_bounds(10, u32::MAX, 200), (10, 10));
    }

    #[test]
    fn decision_id_validation_requires_hex_and_length() {
        assert!(is_decision_id(&"a".repeat(64)));
        assert!(!is_decision_id("abc"));
        assert!(!is_decision_id(&"a".repeat(63)));
        assert!(!is_decision_id(&"g".repeat(64)));
    }

    #[test]
    fn safe_path_id_allows_expected_charset() {
        assert!(is_safe_path_id("verification_failure:abcd", 128));
        assert!(is_safe_path_id("inc_deadbeef", 128));
        assert!(!is_safe_path_id("bad/id", 128));
        assert!(!is_safe_path_id("", 128));
    }

    proptest! {
        #[test]
        fn page_bounds_is_in_range(
            total in 0usize..10_000,
            page in 1u32..5_000,
            page_size in 1u32..200,
        ) {
            let (start, end) = page_bounds(total, page, page_size);
            prop_assert!(start <= end);
            prop_assert!(end <= total);
            if start < total {
                prop_assert!(end > start);
                prop_assert!((end - start) <= page_size as usize);
            } else {
                prop_assert_eq!(start, total);
                prop_assert_eq!(end, total);
            }
        }

        #[test]
        fn parse_hash32_roundtrips(bytes in any::<[u8; 32]>()) {
            let hex_str = hex::encode(bytes);
            let parsed = parse_hash32(&hex_str).expect("valid hex");
            prop_assert_eq!(parsed.0, bytes);
        }

        #[test]
        fn safe_path_id_rejects_slashes(
            left in "[a-zA-Z0-9_:\\-\\.]{1,32}",
            right in "[a-zA-Z0-9_:\\-\\.]{1,32}",
        ) {
            let candidate = format!("{left}/{right}");
            prop_assert!(!is_safe_path_id(&candidate, 128));
        }
    }
}
