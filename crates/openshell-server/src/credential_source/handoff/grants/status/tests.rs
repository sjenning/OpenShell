// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use openshell_core::proto::ObjectMeta;

fn fixture() -> (PublishedGrant, Provider) {
    let grant = PublishedGrant {
        journal: "journal".into(),
        source: "issuer".into(),
        workspace: "default".into(),
        provider_id: "provider-id".into(),
        credential_key: "TOKEN".into(),
        credential_keys: vec!["TOKEN".into()],
        strategy_name: "custom:test".into(),
        grant: "grant-id".into(),
    };
    let provider = Provider {
        metadata: Some(ObjectMeta {
            id: "provider-id".into(),
            name: "provider".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    (grant, provider)
}
fn failed() -> refresh::GrantStatus {
    refresh::GrantStatus {
        grant: "grant-id".into(),
        state: "parked".into(),
        version: 3,
        failure_code: "oauth_invalid_grant".into(),
        provider_error_subtype: "invalid_rapt".into(),
        recovery_action: minter::RecoveryAction::Reauthorize as i32,
        last_refresh_time: Some(openshell_core::time::timestamp_from_millis(1000).unwrap()),
        last_error_time: Some(openshell_core::time::timestamp_from_millis(2000).unwrap()),
        ..Default::default()
    }
}
#[test]
fn remote_history_projects_to_the_public_status_without_raw_error_prose() {
    let (grant, provider) = fixture();
    let status = failed();
    let projected = grant.project_status(&provider, status.clone()).unwrap();
    assert_eq!(projected.last_refresh_time, status.last_refresh_time);
    assert_eq!(projected.last_error_time, status.last_error_time);
    assert_eq!(projected.provider_error_subtype, "invalid_rapt");
    assert!(projected.last_error.contains("reauthorize"));
    let mut unknown = failed();
    unknown.provider_error_subtype = "private-upstream-body".into();
    unknown.failure_code = "private_diagnostic_or_hash".into();
    let projected = grant.project_status(&provider, unknown).unwrap();
    assert!(projected.provider_error_subtype.is_empty());
    assert!(!projected.last_error.contains("private"));
}
#[test]
fn success_retains_historical_error_time_but_clears_current_error_and_subtype() {
    let (grant, provider) = fixture();
    let mut status = failed();
    status.state = "refreshed".into();
    status.failure_code.clear();
    status.recovery_action = minter::RecoveryAction::Unspecified as i32;
    // Defensive projection drops even a stale but formerly recognized subtype.
    let projected = grant.project_status(&provider, status).unwrap();
    assert!(projected.last_error_time.is_some());
    assert!(projected.last_error.is_empty());
    assert!(projected.provider_error_subtype.is_empty());
    let legacy = grant
        .project_status(
            &provider,
            refresh::GrantStatus {
                grant: "grant-id".into(),
                state: "pending".into(),
                version: 1,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(legacy.status, "configured");
    assert!(legacy.last_refresh_time.is_none());
    assert!(legacy.last_error_time.is_none());
}
#[test]
fn malformed_remote_history_timestamps_fail_closed() {
    let (grant, provider) = fixture();
    let mut status = failed();
    status.last_error_time.as_mut().unwrap().nanos = -1;
    assert!(grant.project_status(&provider, status).is_err());
}
