// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::{collections::HashMap, sync::Mutex};

mod batches;

#[derive(Debug, Default)]
struct MemoryStore(Mutex<HashMap<String, StoredReference>>);

#[async_trait]
impl ReferenceStateStore for MemoryStore {
    async fn load(&self, reference: &str) -> Result<Option<StoredReference>, Status> {
        Ok(self.0.lock().unwrap().get(reference).cloned())
    }
    async fn compare_and_swap(
        &self,
        reference: &str,
        expected: Option<u64>,
        state: &ReferenceState,
    ) -> Result<(), Status> {
        let mut entries = self.0.lock().unwrap();
        let existing = entries.get(reference).map(|record| record.revision);
        if existing != expected {
            return Err(Status::aborted("conflict"));
        }
        entries.insert(
            reference.to_string(),
            StoredReference {
                state: state.clone(),
                revision: existing.unwrap_or(0) + 1,
            },
        );
        Ok(())
    }

    async fn compare_and_swap_many(&self, writes: &[ReferenceWrite]) -> Result<(), Status> {
        let mut entries = self.0.lock().unwrap();
        for write in writes {
            if entries.get(&write.reference).map(|record| record.revision)
                != Some(write.expected_revision)
            {
                return Err(Status::aborted("conflict"));
            }
        }
        for write in writes {
            entries.insert(
                write.reference.clone(),
                StoredReference {
                    state: write.state.clone(),
                    revision: write.expected_revision + 1,
                },
            );
        }
        Ok(())
    }
}

fn owner() -> SecretOwner {
    SecretOwner {
        workspace: "workspace".into(),
        provider_id: "provider-id".into(),
        credential_key: "API_KEY".into(),
    }
}

#[tokio::test]
async fn adoption_requires_complete_ownership() {
    let registry = ReferenceRegistry::new(Arc::new(MemoryStore::default()));
    let mut scopes = [owner(), owner(), owner()];
    scopes[0].workspace.clear();
    scopes[1].provider_id.clear();
    scopes[2].credential_key.clear();
    for scope in scopes {
        assert_eq!(
            registry
                .adopt("ref", &scope, vec![1])
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
    }
}

#[tokio::test]
async fn migration_is_idempotent_and_survives_reconstruction() {
    let store = Arc::new(MemoryStore::default());
    let registry = ReferenceRegistry::new(store.clone());
    let first = registry.adopt("legacy", &owner(), vec![1]).await.unwrap();
    assert_eq!(first.version, 1);
    assert_eq!(
        registry.adopt("legacy", &owner(), vec![1]).await.unwrap(),
        first
    );
    registry
        .replace("legacy", &owner(), 1, vec![2], Some(1234))
        .await
        .unwrap();
    let restarted = ReferenceRegistry::new(store);
    let state = restarted.adopt("legacy", &owner(), vec![1]).await.unwrap();
    assert_eq!(state.version, 2);
    assert_eq!(state.backing, vec![2]);
    assert_eq!(state.expiration_time_ms, Some(1234));
    assert_eq!(state.pending_deletions, vec![vec![1]]);
}

#[tokio::test]
async fn concurrent_replacements_have_exactly_one_winner() {
    let store = Arc::new(MemoryStore::default());
    let first = ReferenceRegistry::new(store.clone());
    let second = ReferenceRegistry::new(store);
    first.adopt("ref", &owner(), vec![1]).await.unwrap();
    let owner = owner();
    let (left, right) = tokio::join!(
        first.replace("ref", &owner, 1, vec![2], None),
        second.replace("ref", &owner, 1, vec![3], None),
    );
    assert_ne!(left.is_ok(), right.is_ok());
    assert_eq!(
        left.err().or_else(|| right.err()).unwrap().code(),
        Code::Aborted
    );
    assert_eq!(
        first.observe("ref", &owner).await.unwrap().unwrap().version,
        2
    );
}

#[tokio::test]
async fn scope_cannot_be_changed_by_adoption_rotation_or_deletion() {
    let registry = ReferenceRegistry::new(Arc::new(MemoryStore::default()));
    registry.adopt("ref", &owner(), vec![1]).await.unwrap();
    let mut other_workspace = owner();
    other_workspace.workspace = "other".into();
    let mut other_provider = owner();
    other_provider.provider_id = "other".into();
    let mut other_key = owner();
    other_key.credential_key = "OTHER".into();
    for other in [other_workspace, other_provider, other_key] {
        assert_eq!(
            registry.observe("ref", &other).await.unwrap_err().code(),
            Code::PermissionDenied
        );
        assert_eq!(
            registry
                .adopt("ref", &other, vec![1])
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        assert_eq!(
            registry
                .replace("ref", &other, 1, vec![2], None)
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        assert_eq!(
            registry.revoke("ref", &other).await.unwrap_err().code(),
            Code::PermissionDenied
        );
        assert_eq!(
            registry
                .acknowledge_deletion("ref", &other, &[1])
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
    }
}

#[tokio::test]
async fn cleanup_preserves_versions_and_revocation_prevents_resurrection() {
    let registry = ReferenceRegistry::new(Arc::new(MemoryStore::default()));
    registry.adopt("ref", &owner(), vec![1]).await.unwrap();
    registry
        .replace("ref", &owner(), 1, vec![2], None)
        .await
        .unwrap();
    registry
        .replace("ref", &owner(), 2, vec![3], None)
        .await
        .unwrap();
    registry
        .acknowledge_deletion("ref", &owner(), &[1])
        .await
        .unwrap();
    let live = registry.observe("ref", &owner()).await.unwrap().unwrap();
    assert_eq!(live.version, 3);
    assert_eq!(live.pending_deletions, vec![vec![2]]);
    let deleted = registry.revoke("ref", &owner()).await.unwrap();
    assert_eq!(deleted.pending_deletions, vec![vec![2], vec![3]]);
    assert_eq!(registry.revoke("ref", &owner()).await.unwrap(), deleted);
    for backing in &deleted.pending_deletions {
        registry
            .acknowledge_deletion("ref", &owner(), backing)
            .await
            .unwrap();
    }
    assert_eq!(
        registry
            .adopt("ref", &owner(), vec![1])
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert_eq!(
        registry
            .replace("ref", &owner(), 4, vec![4], None)
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    // Reconfiguration uses a fresh identity, even for the same owner.
    assert_eq!(
        registry
            .adopt("new-epoch", &owner(), vec![4])
            .await
            .unwrap()
            .version,
        1
    );
}

#[tokio::test]
async fn abandoned_candidates_are_owned_without_deleting_the_current_value() {
    let registry = ReferenceRegistry::new(Arc::new(MemoryStore::default()));
    registry.adopt("ref", &owner(), vec![1]).await.unwrap();
    assert_eq!(
        registry
            .abandon_candidate("ref", &owner(), vec![1])
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    let pending = registry
        .abandon_candidate("ref", &owner(), vec![2])
        .await
        .unwrap();
    assert_eq!(pending.pending_deletions, vec![vec![2]]);
    assert_eq!(pending.version, 1);
    assert_eq!(
        registry
            .abandon_candidate("ref", &owner(), vec![2])
            .await
            .unwrap(),
        pending
    );
    assert_eq!(
        registry
            .replace("ref", &owner(), 1, vec![2], None)
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    registry
        .acknowledge_deletion("ref", &owner(), &[2])
        .await
        .unwrap();
    assert_eq!(
        registry
            .observe("ref", &owner())
            .await
            .unwrap()
            .unwrap()
            .backing,
        vec![1]
    );
    registry.revoke("ref", &owner()).await.unwrap();
    assert!(
        registry
            .inspect("ref", &owner())
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(
        registry.observe("ref", &owner()).await.unwrap_err().code(),
        Code::NotFound
    );
}

#[tokio::test]
async fn replacements_require_immutable_fresh_handles_and_do_not_wrap_versions() {
    let store = Arc::new(MemoryStore::default());
    let registry = ReferenceRegistry::new(store.clone());
    registry.adopt("ref", &owner(), vec![1]).await.unwrap();
    assert_eq!(
        registry
            .replace("ref", &owner(), 1, vec![1], None)
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        registry
            .replace("ref", &owner(), 1, vec![], None)
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    store
        .0
        .lock()
        .unwrap()
        .get_mut("ref")
        .unwrap()
        .state
        .version = u64::MAX;
    assert_eq!(
        registry
            .replace("ref", &owner(), u64::MAX, vec![2], None)
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        registry.revoke("ref", &owner()).await.unwrap_err().code(),
        Code::ResourceExhausted
    );
}
