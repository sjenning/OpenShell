// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{ReferenceReplacement, SecretOwner, auth::test_scope};
use tonic::Code;

fn owner(key: &str) -> SecretOwner {
    SecretOwner {
        workspace: "default".to_string(),
        provider_id: "provider-id".to_string(),
        credential_key: key.to_string(),
    }
}
fn grant_put(expected: Option<u64>, receipt: &str) -> Mutation {
    Mutation::Put {
        kind: "grant-v1".to_string(),
        key: "grant".to_string(),
        expected,
        payload: receipt.as_bytes().to_vec(),
    }
}

#[tokio::test]
async fn native_reference_rotation_keeps_versions_separate_from_cleanup_and_publishes_revocation() {
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let refs = repository.references(&test_scope("a"));
    let registry = refs.registry();
    registry
        .adopt("ref", &owner("TOKEN"), b"old-handle".to_vec())
        .await
        .unwrap();
    registry
        .replace(
            "ref",
            &owner("TOKEN"),
            1,
            b"new-handle".to_vec(),
            Some(999_999),
        )
        .await
        .unwrap();
    let rotated = refs.load("ref").await.unwrap().unwrap();
    assert_eq!(rotated.state.version, 2);
    assert_eq!(rotated.revision, 2);
    registry
        .acknowledge_deletion("ref", &owner("TOKEN"), b"old-handle")
        .await
        .unwrap();
    let cleaned = refs.load("ref").await.unwrap().unwrap();
    assert_eq!(cleaned.state.version, 2);
    assert_eq!(cleaned.revision, 3);
    assert!(cleaned.state.pending_deletions.is_empty());
    assert_eq!(refs.storage().events_after(0, 10).await.unwrap().len(), 2);
    registry.revoke("ref", &owner("TOKEN")).await.unwrap();
    let revoked = refs.load("ref").await.unwrap().unwrap();
    assert_eq!(revoked.state.version, 3);
    assert!(revoked.state.revoked);
    let events = refs.storage().events_after(0, 10).await.unwrap();
    assert_eq!(events.len(), 3);
    assert!(events[2].change.deleted);
    assert_eq!(events[2].change.version, 3);
}

#[tokio::test]
async fn outputs_and_completion_receipt_commit_together_and_checks_fence_all_of_them() {
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let refs = repository.references(&test_scope("a"));
    let registry = refs.registry();
    for key in ["a", "b"] {
        registry
            .adopt(key, &owner(key), format!("old-{key}").into_bytes())
            .await
            .unwrap();
    }
    refs.storage()
        .commit(&[grant_put(None, "in-progress")], &[])
        .await
        .unwrap();
    let replacements = ["a", "b"].map(|key| ReferenceReplacement {
        reference: key.to_string(),
        owner: owner(key),
        expected_version: 1,
        backing: format!("new-{key}").into_bytes(),
        expiration_time_ms: None,
    });
    let writes = registry.prepare_replacements(&replacements).await.unwrap();
    let (mut mutations, changes) = refs.prepare_many(&writes).await.unwrap();
    mutations.push(grant_put(Some(1), "completed-attempt"));
    mutations.push(Mutation::Check {
        kind: "owner-fence-v1".to_string(),
        key: "missing-owner".to_string(),
        expected: 1,
    });
    assert_eq!(
        refs.storage()
            .commit(&mutations, &changes)
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    assert_eq!(
        refs.storage()
            .load("grant-v1", "grant")
            .await
            .unwrap()
            .unwrap()
            .payload,
        b"in-progress"
    );
    for key in ["a", "b"] {
        assert_eq!(refs.load(key).await.unwrap().unwrap().state.version, 1);
    }
    assert_eq!(refs.storage().events_after(0, 10).await.unwrap().len(), 2);
    mutations.pop();
    refs.storage().commit(&mutations, &changes).await.unwrap();
    assert_eq!(
        refs.storage()
            .load("grant-v1", "grant")
            .await
            .unwrap()
            .unwrap()
            .payload,
        b"completed-attempt"
    );
    for key in ["a", "b"] {
        assert_eq!(refs.load(key).await.unwrap().unwrap().state.version, 2);
    }
    assert_eq!(refs.storage().events_after(0, 10).await.unwrap().len(), 4);
}

#[tokio::test]
async fn namespace_workspace_and_immutable_owner_checks_precede_metadata_access() {
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let a = repository.references(&test_scope("a"));
    let b = repository.references(&test_scope("b"));
    a.registry()
        .adopt("ref", &owner("TOKEN"), b"handle".to_vec())
        .await
        .unwrap();
    assert!(b.load("ref").await.unwrap().is_none());
    let mut state = a.load("ref").await.unwrap().unwrap().state;
    state.owner.workspace = "other".to_string();
    assert_eq!(
        a.compare_and_swap("ref", Some(1), &state)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    state.owner = owner("different-key");
    assert_eq!(
        a.compare_and_swap("ref", Some(1), &state)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(a.load("ref").await.unwrap().unwrap().revision, 1);
}

#[tokio::test]
async fn malformed_transitions_cannot_drop_retired_handles_or_resurrect_tombstones() {
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let refs = repository.references(&test_scope("a"));
    let registry = refs.registry();
    registry
        .adopt("ref", &owner("TOKEN"), b"old".to_vec())
        .await
        .unwrap();
    let mut bad = refs.load("ref").await.unwrap().unwrap().state;
    bad.backing = b"new".to_vec();
    assert!(refs.compare_and_swap("ref", Some(1), &bad).await.is_err());
    bad.version = 2;
    assert!(refs.compare_and_swap("ref", Some(1), &bad).await.is_err());
    registry.revoke("ref", &owner("TOKEN")).await.unwrap();
    let record = refs.load("ref").await.unwrap().unwrap();
    let mut resurrect = record.state;
    resurrect.version += 1;
    resurrect.revoked = false;
    assert!(
        refs.compare_and_swap("ref", Some(record.revision), &resurrect)
            .await
            .is_err()
    );
    assert!(refs.load("ref").await.unwrap().unwrap().state.revoked);
}
