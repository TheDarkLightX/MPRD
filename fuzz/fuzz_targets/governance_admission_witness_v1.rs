#![no_main]

use libfuzzer_sys::fuzz_target;
use mprd_core::{
    GovernanceAdmissionWitnessV1, GovernanceUpdateKindV1, Hash32, StateRef, StateSnapshot,
};
use std::collections::HashMap;

fn byte(data: &[u8], idx: usize) -> u8 {
    data.get(idx).copied().unwrap_or(0)
}

fn bit(data: &[u8], idx: usize) -> bool {
    (byte(data, idx) & 1) == 1
}

fn encode_bool(style: u8, value: bool) -> Vec<u8> {
    match style % 7 {
        0 => vec![u8::from(value)],
        1 => {
            if value {
                b"1".to_vec()
            } else {
                b"0".to_vec()
            }
        }
        2 => {
            if value {
                b"true".to_vec()
            } else {
                b"false".to_vec()
            }
        }
        3 => {
            if value {
                b"True".to_vec()
            } else {
                b"False".to_vec()
            }
        }
        4 => {
            if value {
                b"TRUE".to_vec()
            } else {
                b"FALSE".to_vec()
            }
        }
        5 => {
            if value {
                b"T".to_vec()
            } else {
                b"F".to_vec()
            }
        }
        _ => {
            if value {
                vec![1]
            } else {
                vec![0]
            }
        }
    }
}

fn core_update_kind(update_kind: u8) -> Option<GovernanceUpdateKindV1> {
    match mprd_zk::UpdateKind::from_u8(update_kind) {
        Some(mprd_zk::UpdateKind::PolicyTweak) => Some(GovernanceUpdateKindV1::PolicyTweak),
        Some(mprd_zk::UpdateKind::SafetyRuleChange) => {
            Some(GovernanceUpdateKindV1::SafetyRuleChange)
        }
        Some(mprd_zk::UpdateKind::AgentCapabilityExpand) => {
            Some(GovernanceUpdateKindV1::AgentCapabilityExpand)
        }
        None => None,
    }
}

fn one_hot_lane(update_kind: u8) -> (bool, bool, bool) {
    match mprd_zk::UpdateKind::from_u8(update_kind) {
        Some(mprd_zk::UpdateKind::PolicyTweak) => (true, false, false),
        Some(mprd_zk::UpdateKind::SafetyRuleChange) => (false, true, false),
        Some(mprd_zk::UpdateKind::AgentCapabilityExpand) => (false, false, true),
        None => (false, false, false),
    }
}

fn state_for(
    update_kind: u8,
    profile_app_ok: bool,
    profile_safety_ok: bool,
    link_ok: bool,
    styles: &[u8],
) -> StateSnapshot {
    let (is_policy_tweak, is_safety_change, is_cap_expand) = one_hot_lane(update_kind);
    let style = |idx: usize| byte(styles, idx);

    StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::from([
            (
                mprd_core::GOVERNANCE_INPUT_IS_POLICY_TWEAK_V1.into(),
                encode_bool(style(0), is_policy_tweak),
            ),
            (
                mprd_core::GOVERNANCE_INPUT_IS_SAFETY_CHANGE_V1.into(),
                encode_bool(style(1), is_safety_change),
            ),
            (
                mprd_core::GOVERNANCE_INPUT_IS_CAP_EXPAND_V1.into(),
                encode_bool(style(2), is_cap_expand),
            ),
            (
                mprd_core::GOVERNANCE_INPUT_PROFILE_APP_OK_V1.into(),
                encode_bool(style(3), profile_app_ok),
            ),
            (
                mprd_core::GOVERNANCE_INPUT_PROFILE_SAFETY_OK_V1.into(),
                encode_bool(style(4), profile_safety_ok),
            ),
            (
                mprd_core::GOVERNANCE_INPUT_LINK_OK_V1.into(),
                encode_bool(style(5), link_ok),
            ),
        ]),
        state_hash: Hash32([0x71; 32]),
        state_ref: StateRef::unknown(),
    }
}

fn assert_same_result(
    left: &mprd_core::Result<GovernanceAdmissionWitnessV1>,
    right: &mprd_core::Result<GovernanceAdmissionWitnessV1>,
) {
    match (left, right) {
        (Ok(lhs), Ok(rhs)) => assert_eq!(lhs, rhs),
        (Err(lhs), Err(rhs)) => assert_eq!(lhs.to_string(), rhs.to_string()),
        _ => panic!("governance admission result mismatch: left={left:?}, right={right:?}"),
    }
}

fuzz_target!(|data: &[u8]| {
    let update_kind = byte(data, 0);
    let profile_app_ok = bit(data, 1);
    let profile_safety_ok = bit(data, 2);
    let link_ok = bit(data, 3);
    let styles = data.get(4..).unwrap_or(&[]);

    let gate_input = mprd_zk::GovernanceGateInput {
        update_kind,
        profile_app_ok,
        profile_safety_ok,
        link_ok,
    };
    let gate_res = mprd_zk::governance_admission_witness_from_gate_input_v1(&gate_input);

    if let Some(core_kind) = core_update_kind(update_kind) {
        let field_res = mprd_core::governance_admission_witness_from_fields_v1(
            core_kind,
            profile_app_ok,
            profile_safety_ok,
            link_ok,
        );
        assert_same_result(&gate_res, &field_res);

        let state_res = mprd_core::governance_admission_witness_v1(&state_for(
            update_kind,
            profile_app_ok,
            profile_safety_ok,
            link_ok,
            styles,
        ));
        match (&field_res, &state_res) {
            (Ok(expected), Ok(Some(actual))) => assert_eq!(expected, actual),
            (Err(lhs), Err(rhs)) => assert_eq!(lhs.to_string(), rhs.to_string()),
            _ => panic!(
                "governance state projection mismatch: fields={field_res:?}, state={state_res:?}"
            ),
        }
    } else {
        assert!(gate_res.is_err());
        let state_res = mprd_core::governance_admission_witness_v1(&state_for(
            update_kind,
            profile_app_ok,
            profile_safety_ok,
            link_ok,
            styles,
        ));
        assert!(state_res.is_err());
    }
});
