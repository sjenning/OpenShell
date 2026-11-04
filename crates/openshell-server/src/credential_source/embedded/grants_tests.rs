// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::collections::HashMap;

fn legacy() -> LegacyState {
    LegacyState {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: "legacy-id".into(),
            workspace: "workspace".into(),
            resource_version: 7,
            annotations: HashMap::from([(COMPLETED.into(), "completed-mint".into())]),
            ..Default::default()
        }),
        provider_id: "provider".into(),
        credential_key: "TOKEN".into(),
        strategy: Strategy::Oauth2RefreshToken as i32,
        status: "refreshed".into(),
        authorization_epoch: "exact-old-epoch".into(),
        last_refresh_at_ms: 1234,
        expires_at_ms: 9000,
        next_refresh_at_ms: 8000,
        ..Default::default()
    }
}
#[test]
fn preserves_completed_history_schedule_and_authorization_epoch() {
    let state = legacy();
    let observed = status(&state).unwrap();
    assert_eq!(
        provider_refresh::effective_authorization_epoch(&state).unwrap(),
        "exact-old-epoch"
    );
    assert_eq!(observed.version, 7);
    assert_eq!(observed.phase, GrantPhase::Refreshed);
    assert_eq!(
        observed.completed_attempt.as_deref(),
        Some("completed-mint")
    );
    assert_eq!(observed.last_refresh_time_ms, Some(1234));
    assert_eq!(observed.next_refresh_at_ms, 8000);
    assert_eq!(observed.expiration_time_ms, Some(9000));
    assert!(!observed.uncertain);
}
#[test]
fn inflight_unknown_attempts_park_but_classified_retry_failures_keep_their_schedule() {
    let mut state = legacy();
    state
        .metadata
        .as_mut()
        .unwrap()
        .annotations
        .insert(ATTEMPT.into(), "new-attempt".into());
    state.status = "refresh_committing".into();
    let inflight = status(&state).unwrap();
    assert!(inflight.uncertain);
    assert_eq!(inflight.attempt_id.as_deref(), Some("new-attempt"));
    state.status = "failed".into();
    state.failure_code = "refresh_failed".into();
    state.recovery_action = Action::Retry as i32;
    let known_failure = status(&state).unwrap();
    assert!(!known_failure.uncertain);
    assert_eq!(known_failure.phase, GrantPhase::Failed);
    assert_eq!(known_failure.recovery_action, Some(RecoveryAction::Retry));
    assert_eq!(known_failure.next_refresh_at_ms, state.next_refresh_at_ms);
    state.failure_code = "mint_outcome_unknown".into();
    assert!(status(&state).unwrap().uncertain);
}
#[test]
fn rounds_profile_durations_without_changing_semantic_output_bindings() {
    let mut state = legacy();
    state.refresh_before = Some(prost_types::Duration {
        seconds: 0,
        nanos: 1,
    });
    state.max_lifetime = Some(prost_types::Duration {
        seconds: 60,
        nanos: 1,
    });
    let registry = openshell_credential_issuer::builtins::registry();
    let descriptor = registry
        .describe()
        .find(|descriptor| descriptor.name == "oauth2_refresh_token")
        .unwrap();
    let (plan, schedule) = plan(&state, descriptor, Strategy::Oauth2RefreshToken).unwrap();
    assert_eq!(schedule.refresh_before_ms, 1);
    assert_eq!(schedule.max_lifetime_seconds, 61);
    assert_eq!(
        plan.outputs,
        BTreeMap::from([("access_token".into(), "TOKEN".into())])
    );
    state
        .additional_output_keys
        .insert("unexpected".into(), "OTHER".into());
    assert!(super::plan(&state, descriptor, Strategy::Oauth2RefreshToken).is_err());
}
#[test]
fn arbitrary_legacy_error_prose_and_subtypes_do_not_enter_imported_history() {
    let mut state = legacy();
    state.status = "failed".into();
    state.failure_code = "oauth_invalid_grant".into();
    state.provider_error_subtype = "arbitrary-sensitive-upstream-body".into();
    state.last_error = "private-secret-diagnostic".into();
    assert!(status(&state).unwrap().provider_error_subtype.is_empty());
    state.provider_error_subtype = "invalid_rapt".into();
    assert_eq!(
        status(&state).unwrap().provider_error_subtype,
        "invalid_rapt"
    );
}

#[test]
fn persisted_failure_statuses_with_retained_attempts_preserve_classification_and_schedule() {
    for (persisted_status, action, phase, next_refresh) in [
        ("error", Action::Retry, GrantPhase::Failed, 61_000),
        (
            "configuration_required",
            Action::FixConfiguration,
            GrantPhase::Failed,
            3_601_000,
        ),
        (
            "reauthorization_required",
            Action::Reauthorize,
            GrantPhase::Parked,
            i64::MAX,
        ),
        (
            "investigation_required",
            Action::Investigate,
            GrantPhase::Failed,
            61_000,
        ),
        (
            "investigation_required",
            Action::Investigate,
            GrantPhase::Parked,
            i64::MAX,
        ),
    ] {
        let mut state = legacy();
        state.status = persisted_status.into();
        state.recovery_action = action as i32;
        state.failure_code = "refresh_failed".into();
        state.next_refresh_at_ms = next_refresh;
        state.last_error_at_ms = 2345;
        state
            .metadata
            .as_mut()
            .unwrap()
            .annotations
            .insert(ATTEMPT.into(), "failed-attempt".into());
        let observed = status(&state).unwrap();
        assert!(
            !observed.uncertain,
            "{persisted_status} is a classified outcome, not an unknown exchange"
        );
        assert_eq!(observed.phase, phase);
        assert_eq!(observed.failure_code, "refresh_failed");
        assert_eq!(observed.next_refresh_at_ms, next_refresh);
        assert_eq!(observed.last_error_time_ms, Some(2345));
        assert_eq!(observed.attempt_id.as_deref(), Some("failed-attempt"));
        assert_eq!(
            observed.completed_attempt.as_deref(),
            Some("completed-mint")
        );
        let expected_action = match action {
            Action::Retry => RecoveryAction::Retry,
            Action::FixConfiguration => RecoveryAction::FixConfiguration,
            Action::Reauthorize => RecoveryAction::Reauthorize,
            Action::Investigate => RecoveryAction::Investigate,
            Action::Unspecified => unreachable!(),
        };
        assert_eq!(observed.recovery_action, Some(expected_action));
        // Older rows with an absent recovery field still carry an explicit
        // classified status; do not erase that recovery boundary.
        state.recovery_action = Action::Unspecified as i32;
        assert_eq!(
            status(&state).unwrap().recovery_action,
            Some(expected_action)
        );
        state.failure_code = "mint_outcome_unknown".into();
        assert!(status(&state).unwrap().uncertain);
    }
}

#[test]
fn protected_client_id_is_projected_to_encrypted_descriptor_configuration() {
    let mut state = legacy();
    state.secret_material_keys = vec![
        "client_id".into(),
        "refresh_token".into(),
        "scopes".into(),
        "refresh_before_seconds".into(),
        "max_lifetime_seconds".into(),
    ];
    // This is the merged result of inline and resolved protected legacy
    // material; the storage classification must not change minter categories.
    let material = HashMap::from([
        ("client_id".into(), "protected-client-id".into()),
        ("refresh_token".into(), "protected-refresh-token".into()),
        ("scopes".into(), "first,second third".into()),
        ("refresh_before_seconds".into(), "300".into()),
        ("max_lifetime_seconds".into(), "0".into()),
    ]);
    let registry = openshell_credential_issuer::builtins::registry();
    let descriptor = registry
        .describe()
        .find(|descriptor| descriptor.name == "oauth2_refresh_token")
        .unwrap();
    let projected = project_material(&state, descriptor, material.clone(), 3600).unwrap();
    assert_eq!(projected.0["client_id"], "protected-client-id");
    assert_eq!(projected.0["scope"], "first second third");
    assert_eq!(projected.1["refresh_token"], "protected-refresh-token");
    assert!(!projected.1.contains_key("client_id"));
    assert!(!projected.0.contains_key("refresh_token"));
    assert!(!projected.0.contains_key("refresh_before_seconds"));
    assert!(!projected.1.contains_key("refresh_before_seconds"));
    assert_eq!(projected.0["max_lifetime_seconds"], "3600");
    state.secret_material_keys.clear();
    assert_eq!(
        project_material(&state, descriptor, material, 3600).unwrap(),
        projected
    );
    let unknown = HashMap::from([("undeclared_secret".into(), "private-value".into())]);
    state.secret_material_keys.push("undeclared_secret".into());
    assert!(project_material(&state, descriptor, unknown, 3600).is_err());
}

#[test]
fn legacy_schedule_retains_full_protobuf_range_beyond_native_and_u32_limits() {
    let registry = openshell_credential_issuer::builtins::registry();
    let descriptor = registry
        .describe()
        .find(|value| value.name == "oauth2_refresh_token")
        .unwrap();
    let mut state = legacy();
    for seconds in [
        86_400,
        i64::from(u32::MAX) + 1,
        openshell_core::time::MAX_DURATION_SECONDS,
    ] {
        state.max_lifetime = Some(prost_types::Duration { seconds, nanos: 1 });
        state.refresh_before = Some(prost_types::Duration {
            seconds: 46_800,
            nanos: 1,
        });
        let (_, schedule) = plan(&state, descriptor, Strategy::Oauth2RefreshToken).unwrap();
        assert_eq!(
            schedule.max_lifetime_seconds,
            u64::try_from(seconds).unwrap() + 1
        );
        assert_eq!(schedule.refresh_before_ms, 46_800_001);
        let (_, projected) = plan(&state, descriptor, Strategy::Oauth2RefreshToken).unwrap();
        let (config, _) = project_material(
            &state,
            descriptor,
            HashMap::new(),
            projected.max_lifetime_seconds,
        )
        .unwrap();
        assert_eq!(config["max_lifetime_seconds"], (seconds + 1).to_string());
    }
    state.max_lifetime = Some(prost_types::Duration {
        seconds: 0,
        nanos: 0,
    });
    assert!(plan(&state, descriptor, Strategy::Oauth2RefreshToken).is_err());
}
