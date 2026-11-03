// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
mod publication;
mod reservations;
use crate::{ReferenceState, ReferenceStateStore, auth::test_scope, minter::MaterialDescriptor};

fn state() -> GrantState {
    GrantState {
        format_version: 1,
        definition: GrantDefinition {
            identity: GrantIdentity {
                id: "grant".into(),
                authorization_epoch: "epoch".into(),
                owner: SecretOwner {
                    workspace: "default".into(),
                    provider_id: "provider".into(),
                    credential_key: "TOKEN".into(),
                },
            },
            descriptor: StrategyDescriptor {
                name: "custom:test".into(),
                config: vec![],
                secret_material: vec![MaterialDescriptor {
                    name: "refresh_token".into(),
                    required: true,
                }],
                outputs: vec!["access_token".into()],
                rotated_secret_material: vec!["refresh_token".into()],
            },
            config_backing: vec![1],
            outputs: BTreeMap::from([(
                "access_token".into(),
                OutputBinding {
                    credential_key: "TOKEN".into(),
                    reference: "reference".into(),
                },
            )]),
            refresh_before_ms: 300_000,
            max_lifetime_seconds: 3600,
        },
        material: BTreeMap::from([("refresh_token".into(), vec![2])]),
        version: 1,
        phase: GrantPhase::Pending,
        expiration_time_ms: None,
        next_refresh_at_ms: 0,
        recovery_action: None,
        failure_code: String::new(),
        attempt: None,
        completed_attempt: None,
        retired: vec![],
    }
}
async fn save(
    repository: &Arc<Repository>,
    scope: &GatewayScope,
    expected: Option<u64>,
    state: &GrantState,
) -> Result<(), Status> {
    let (mutation, event) = repository.grants(scope).prepare(expected, state).await?;
    repository
        .for_gateway(scope)
        .commit(&[mutation], &event.into_iter().collect::<Vec<_>>())
        .await?;
    Ok(())
}
#[tokio::test]
async fn creation_joins_reserved_outputs_and_events_and_is_scoped_by_creator() {
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let scope = test_scope("gateway");
    let state = state();
    let (grant, event) = repository
        .grants(&scope)
        .prepare(None, &state)
        .await
        .unwrap();
    let (reference, change) = repository
        .references(&scope)
        .prepare(
            "reference",
            None,
            &ReferenceState::reserved(state.definition.identity.owner.clone()),
        )
        .await
        .unwrap();
    repository
        .for_gateway(&scope)
        .commit(&[grant, reference], &[event.unwrap(), change.unwrap()])
        .await
        .unwrap();
    assert_eq!(
        repository
            .for_gateway(&scope)
            .current_sequence()
            .await
            .unwrap(),
        2
    );
    assert!(
        repository
            .grants(&test_scope("other-gateway"))
            .load("grant")
            .await
            .unwrap()
            .is_none()
    );
    let loaded = repository
        .grants(&scope)
        .load("grant")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.revision, 1);
    assert_eq!(loaded.state.phase, GrantPhase::Pending);
    assert!(
        repository
            .references(&scope)
            .load("reference")
            .await
            .unwrap()
            .unwrap()
            .state
            .pending_value
    );
    let mut conflict = state.clone();
    conflict.phase = GrantPhase::Failed;
    conflict.version = 2;
    assert_eq!(
        save(&repository, &scope, Some(99), &conflict)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    for index in 0..5 {
        let mut changed = state.clone();
        match index {
            0 => changed.definition.identity.authorization_epoch = "other".into(),
            1 => changed.definition.identity.owner.provider_id = "other".into(),
            2 => {
                changed
                    .definition
                    .outputs
                    .get_mut("access_token")
                    .unwrap()
                    .reference = "other".into();
            }
            3 => changed.definition.descriptor.name = "custom:other".into(),
            _ => changed.definition.config_backing = vec![3],
        }
        assert_eq!(
            save(&repository, &scope, Some(1), &changed)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Aborted
        );
    }
}
#[tokio::test]
async fn cleanup_revisions_are_silent_and_deletion_never_resurrects() {
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let scope = test_scope("gateway");
    let mut state = state();
    save(&repository, &scope, None, &state).await.unwrap();
    state.retired.push(RetiredBacking {
        owner: state.definition.identity.owner.clone(),
        purpose: "grant-material-v1".into(),
        backing: vec![9],
    });
    save(&repository, &scope, Some(1), &state).await.unwrap();
    assert_eq!(
        repository
            .for_gateway(&scope)
            .current_sequence()
            .await
            .unwrap(),
        1
    );
    state.retired.clear();
    save(&repository, &scope, Some(2), &state).await.unwrap();
    state.phase = GrantPhase::Deleting;
    state.version = 2;
    save(&repository, &scope, Some(3), &state).await.unwrap();
    state.phase = GrantPhase::Pending;
    state.version = 3;
    assert!(save(&repository, &scope, Some(4), &state).await.is_err());
    state.phase = GrantPhase::Deleted;
    save(&repository, &scope, Some(4), &state).await.unwrap();
    assert!(state.checkpoint().schedule.deleting);
    let event = repository
        .for_gateway(&scope)
        .events_after(2, 10)
        .await
        .unwrap();
    assert_eq!(event.len(), 1);
    assert!(event[0].change.deleted);
}
#[tokio::test]
async fn attempt_identity_and_staged_ownership_survive_metadata_updates() {
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let scope = test_scope("gateway");
    let mut state = state();
    save(&repository, &scope, None, &state).await.unwrap();
    state.phase = GrantPhase::Refreshing;
    state.version = 2;
    state.attempt = Some(GrantAttempt {
        id: "attempt".into(),
        encrypted_result: None,
        expected_output_versions: BTreeMap::from([("access_token".into(), 1)]),
        output_candidates: BTreeMap::new(),
        material_candidates: BTreeMap::new(),
        rotation_receipt: None,
    });
    save(&repository, &scope, Some(1), &state).await.unwrap();
    let mut changed = state.clone();
    changed.attempt.as_mut().unwrap().id = "replacement".into();
    assert_eq!(
        save(&repository, &scope, Some(2), &changed)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    state.phase = GrantPhase::Publishing;
    state.version = 3;
    state.attempt.as_mut().unwrap().encrypted_result = Some(vec![1]);
    state
        .attempt
        .as_mut()
        .unwrap()
        .output_candidates
        .insert("access_token".into(), vec![4]);
    save(&repository, &scope, Some(2), &state).await.unwrap();
    let mut deleting = state.clone();
    deleting.phase = GrantPhase::Deleting;
    deleting.version = 4;
    deleting.attempt = None;
    assert!(save(&repository, &scope, Some(3), &deleting).await.is_err());
    deleting.retired.push(RetiredBacking {
        owner: state.definition.identity.owner.clone(),
        purpose: "provider-value-v1".into(),
        backing: vec![4],
    });
    save(&repository, &scope, Some(3), &deleting).await.unwrap();
}

#[tokio::test]
async fn enumeration_advances_past_workspace_filtered_records() {
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let scope = test_scope("gateway");
    for (id, workspace) in [("a", "default"), ("b", "other")] {
        let mut record = state();
        record.definition.identity.id = id.into();
        record.definition.identity.owner.workspace = workspace.into();
        // Seed metadata predating a workspace-policy narrowing. No value access.
        repository
            .for_gateway(&scope)
            .commit(
                &[Mutation::Put {
                    kind: KIND.into(),
                    key: id.into(),
                    expected: None,
                    payload: serde_json::to_vec(&record).unwrap(),
                }],
                &[],
            )
            .await
            .unwrap();
    }
    let grants = repository.grants(&scope);
    let first = grants.list(None, 1).await.unwrap();
    assert_eq!(first.grants.len(), 1);
    assert_eq!(first.after.as_deref(), Some("a"));
    let filtered = grants.list(first.after.as_deref(), 1).await.unwrap();
    assert!(filtered.grants.is_empty());
    assert_eq!(filtered.after.as_deref(), Some("b"));
    assert!(
        grants
            .list(filtered.after.as_deref(), 1)
            .await
            .unwrap()
            .after
            .is_none()
    );
}

#[test]
fn malformed_attempts_and_parked_outcomes_fail_closed() {
    let mut state = state();
    state.phase = GrantPhase::Refreshing;
    assert!(state.validate().is_err());
    state.attempt = Some(GrantAttempt {
        id: "attempt".into(),
        encrypted_result: None,
        expected_output_versions: BTreeMap::from([("access_token".into(), 1)]),
        output_candidates: BTreeMap::new(),
        material_candidates: BTreeMap::new(),
        rotation_receipt: None,
    });
    state.validate().unwrap();
    state.phase = GrantPhase::Publishing;
    assert!(state.validate().is_err());
    state.phase = GrantPhase::Parked;
    state.recovery_action = Some(RecoveryAction::Investigate);
    state.next_refresh_at_ms = i64::MAX;
    state.validate().unwrap();
    assert!(
        state
            .checkpoint()
            .ensure_mintable(crate::engine::RefreshTrigger::ExplicitRotation, 100)
            .is_err()
    );
    assert!(!state.allows(GrantPhase::Refreshing));
    assert!(!format!("{state:?}").contains("config_backing"));
}
