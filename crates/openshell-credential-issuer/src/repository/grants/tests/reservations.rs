// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
fn reserved() -> GrantState {
    let mut state = state();
    state.phase = GrantPhase::Reserved;
    state.material.clear();
    state.definition.config_backing.clear();
    state.next_refresh_at_ms = i64::MAX;
    state
}
#[test]
fn reservations_reject_material_configuration_attempts_and_due_schedules() {
    let original = reserved();
    original.validate().unwrap();
    let mut invalid = original.clone();
    invalid.definition.config_backing = vec![1];
    assert!(invalid.validate().is_err());
    let mut invalid = original.clone();
    invalid.material.insert("refresh_token".into(), vec![1]);
    assert!(invalid.validate().is_err());
    let mut invalid = original;
    invalid.next_refresh_at_ms = 0;
    assert!(invalid.validate().is_err());
    let mut pending = state();
    pending.definition.config_backing.clear();
    assert!(pending.validate().is_err());
}
#[tokio::test]
async fn initialization_can_set_configuration_once_without_changing_reserved_identity() {
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let scope = test_scope("gateway");
    let reserved = reserved();
    save(&repository, &scope, None, &reserved).await.unwrap();
    let mut initialized = state();
    initialized.version = 2;
    let mut wrong = initialized.clone();
    wrong
        .definition
        .outputs
        .get_mut("access_token")
        .unwrap()
        .reference = "injected".into();
    assert_eq!(
        save(&repository, &scope, Some(1), &wrong)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    let mut wrong = initialized.clone();
    wrong.definition.identity.authorization_epoch = "different".into();
    assert_eq!(
        save(&repository, &scope, Some(1), &wrong)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    save(&repository, &scope, Some(1), &initialized)
        .await
        .unwrap();
    initialized.definition.config_backing = vec![9];
    assert_eq!(
        save(&repository, &scope, Some(2), &initialized)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    let mut reverted = reserved;
    reverted.version = 3;
    assert!(save(&repository, &scope, Some(2), &reverted).await.is_err());
    let loaded = repository
        .grants(&scope)
        .load("grant")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.state.phase, GrantPhase::Pending);
    assert_eq!(loaded.state.version, 2);
    assert_eq!(loaded.state.definition.config_backing, vec![1]);
}
