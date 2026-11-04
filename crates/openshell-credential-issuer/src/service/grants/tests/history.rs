// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn refresh_history_survives_failure_manual_recovery_and_new_service() {
    let fixture = Fixture::new().await;
    let grant = create(&fixture).await;
    let before = fixture
        .runtime()
        .load(&test_scope(A), &grant.grant)
        .await
        .unwrap();
    let status = grant_status(&before.state).unwrap();
    assert!(status.last_refresh_time.is_none());
    assert!(status.last_error_time.is_none());
    let success = fixture
        .runtime()
        .ensure(test_scope(A), grant.grant.clone(), 0)
        .await
        .unwrap();
    let refreshed = success.last_refresh_time.unwrap();
    assert!(success.last_error_time.is_none());
    fixture
        .minter
        .recognized_subtype
        .store(true, Ordering::SeqCst);
    let error = fixture
        .runtime()
        .rotate(
            test_scope(A),
            grant.grant.clone(),
            idempotency("fail-with-subtype").unwrap(),
        )
        .await
        .unwrap_err();
    assert!(!format!("{error:?}").contains("private-upstream-body"));
    let failed = fixture
        .runtime()
        .load(&test_scope(A), &grant.grant)
        .await
        .unwrap();
    let status = grant_status(&failed.state).unwrap();
    assert_eq!(status.last_refresh_time, Some(refreshed));
    let last_error = status.last_error_time.unwrap();
    assert_eq!(status.failure_code, "oauth_invalid_grant");
    assert_eq!(status.provider_error_subtype, "invalid_rapt");
    assert_eq!(status.state, "parked");
    assert!(!format!("{status:?}").contains("private"));
    fixture
        .minter
        .recognized_subtype
        .store(false, Ordering::SeqCst);
    let restarted = CredentialRefreshService::new(
        &fixture.store,
        fixture.runtime().minters.clone(),
        fixture.runtime().spool.clone(),
    )
    .unwrap();
    let recovered = restarted
        .runtime
        .rotate(
            test_scope(A),
            grant.grant.clone(),
            idempotency("recover-with-subtype").unwrap(),
        )
        .await
        .unwrap()
        .status
        .unwrap();
    assert_eq!(recovered.state, "refreshed");
    assert_eq!(recovered.last_error_time, Some(last_error));
    assert!(recovered.failure_code.is_empty());
    assert!(recovered.provider_error_subtype.is_empty());
    assert!(
        openshell_core::time::timestamp_to_millis(recovered.last_refresh_time.as_ref().unwrap())
            .unwrap()
            >= openshell_core::time::timestamp_to_millis(&refreshed).unwrap()
    );
    let persisted = fixture
        .runtime()
        .load(&test_scope(A), &grant.grant)
        .await
        .unwrap();
    let persisted = grant_status(&persisted.state).unwrap();
    assert_eq!(persisted.last_refresh_time, recovered.last_refresh_time);
    assert_eq!(persisted.last_error_time, Some(last_error));
}
