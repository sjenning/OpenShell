// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::proto::ObjectMeta;
use std::collections::HashMap;

fn state() -> StoredProviderCredentialRefreshState {
    StoredProviderCredentialRefreshState {
        metadata: Some(ObjectMeta {
            id: "grant-id".to_string(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        provider_id: "provider-id".to_string(),
        credential_key: "ACCESS_TOKEN".to_string(),
        status: "configured".to_string(),
        material: HashMap::from([(
            "client_secret".to_string(),
            "never-project-secret".to_string(),
        )]),
        last_error: "never-project-upstream-error".to_string(),
        ..Default::default()
    }
}

#[test]
fn legacy_epoch_projection_uses_the_immutable_id_without_projecting_material() {
    let stored = state();
    let projected = grant_checkpoint(&stored).unwrap();
    assert_eq!(projected.identity.authorization_epoch, stored.object_id());
    assert_eq!(projected.identity.owner.workspace, "default");
    assert_eq!(projected.identity.owner.provider_id, stored.provider_id);
    assert_eq!(
        projected.identity.owner.credential_key,
        stored.credential_key
    );
    assert!(!format!("{projected:?}").contains("never-project"));
    assert_eq!(
        projected.admit(&projected).unwrap(),
        GrantAdmission::Prepare
    );
}

#[test]
fn names_and_storage_revisions_are_not_grant_identity_but_reauthorization_is() {
    let observed = state();
    let before = grant_checkpoint(&observed).unwrap();
    let mut live = observed;
    live.provider_name = "renamed-provider".to_string();
    live.metadata.as_mut().unwrap().name = "renamed-storage-row".to_string();
    live.metadata.as_mut().unwrap().resource_version = 10;
    assert_eq!(
        grant_checkpoint(&live).unwrap().admit(&before).unwrap(),
        GrantAdmission::Prepare
    );
    live.authorization_epoch = "new-authorization".to_string();
    assert_eq!(
        grant_checkpoint(&live)
            .unwrap()
            .admit(&before)
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
}

#[test]
fn projection_preserves_receipts_tombstones_and_unknown_recovery_backoff() {
    let mut stored = state();
    let before = grant_checkpoint(&stored).unwrap();
    stored.status = "refreshed".to_string();
    stored.metadata.as_mut().unwrap().annotations.insert(
        super::super::COMPLETED_MINT_ANNOTATION.to_string(),
        "completed".to_string(),
    );
    assert_eq!(
        grant_checkpoint(&stored).unwrap().admit(&before).unwrap(),
        GrantAdmission::Current
    );
    stored.recovery_action = i32::MAX;
    stored.next_refresh_at_ms = 101;
    assert_eq!(
        grant_checkpoint(&stored)
            .unwrap()
            .ensure_mintable(RefreshTrigger::Automatic, 100)
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    stored.metadata.as_mut().unwrap().deletion_time = Some(prost_types::Timestamp::default());
    assert_eq!(
        grant_checkpoint(&stored)
            .unwrap()
            .admit(&before)
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
}
