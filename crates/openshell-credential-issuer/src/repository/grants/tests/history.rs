// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn legacy_format_one_metadata_has_absent_history_and_no_error_subtype() {
    let mut value = serde_json::to_value(state()).unwrap();
    let object = value.as_object_mut().unwrap();
    for field in [
        "last_refresh_time_ms",
        "last_error_time_ms",
        "provider_error_subtype",
    ] {
        object.remove(field);
    }
    let restored: GrantState = serde_json::from_value(value).unwrap();
    restored.validate().unwrap();
    assert!(restored.last_refresh_time_ms.is_none());
    assert!(restored.last_error_time_ms.is_none());
    assert!(restored.provider_error_subtype.is_empty());
}

#[tokio::test]
async fn sanitized_failure_history_reopens_and_history_changes_advance_status_version() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("issuer.db").display()
    );
    let repository = Repository::open(&url).await.unwrap();
    let scope = test_scope("history");
    let mut state = state();
    save(&repository, &scope, None, &state).await.unwrap();
    state.phase = GrantPhase::Failed;
    state.recovery_action = Some(RecoveryAction::Reauthorize);
    state.failure_code = "oauth_invalid_grant".into();
    state.provider_error_subtype = "invalid_rapt".into();
    state.last_error_time_ms = Some(10_000);
    state.next_refresh_at_ms = i64::MAX;
    state.version = 2;
    save(&repository, &scope, Some(1), &state).await.unwrap();
    state.last_error_time_ms = Some(20_000);
    assert!(
        repository
            .grants(&scope)
            .prepare(Some(2), &state)
            .await
            .is_err()
    );
    state.version = 3;
    save(&repository, &scope, Some(2), &state).await.unwrap();
    let reopened = Repository::open(&url).await.unwrap();
    let loaded = reopened
        .grants(&scope)
        .load("grant")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.state.last_error_time_ms, Some(20_000));
    assert_eq!(loaded.state.provider_error_subtype, "invalid_rapt");
    assert_eq!(loaded.state.version, 3);
    assert!(!format!("{:?}", loaded.state).contains("invalid_rapt"));
}

#[test]
fn durable_history_rejects_invalid_timestamps_and_unknown_or_uncorrelated_subtypes() {
    for time in [0, -1] {
        let mut invalid = state();
        invalid.last_error_time_ms = Some(time);
        assert_eq!(
            invalid.validate().unwrap_err().code(),
            tonic::Code::DataLoss
        );
        invalid.last_error_time_ms = None;
        invalid.last_refresh_time_ms = Some(time);
        assert!(invalid.validate().is_err());
    }
    for (code, subtype) in [
        ("oauth_invalid_grant", "private-body"),
        ("", "invalid_rapt"),
    ] {
        let mut invalid = state();
        invalid.failure_code = code.into();
        invalid.provider_error_subtype = subtype.into();
        let error = invalid.validate().unwrap_err();
        assert!(!format!("{error:?}").contains(subtype));
    }
}
