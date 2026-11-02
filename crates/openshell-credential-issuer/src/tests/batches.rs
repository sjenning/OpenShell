// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

async fn fixture() -> (
    Arc<MemoryStore>,
    ReferenceRegistry,
    Vec<ReferenceReplacement>,
) {
    let store = Arc::new(MemoryStore::default());
    let registry = ReferenceRegistry::new(store.clone());
    let mut replacements = Vec::new();
    for index in 1..=3_u8 {
        let reference = format!("ref-{index}");
        let owner = SecretOwner {
            credential_key: format!("OUTPUT_{index}"),
            ..owner()
        };
        registry
            .adopt(&reference, &owner, vec![index])
            .await
            .unwrap();
        replacements.push(ReferenceReplacement {
            reference,
            owner,
            expected_version: 1,
            backing: vec![index + 10],
            expiration_time_ms: Some(42_000),
        });
    }
    (store, registry, replacements)
}

#[tokio::test]
async fn multi_output_replacement_preserves_identity_and_owns_every_retired_handle() {
    let (_, registry, replacements) = fixture().await;
    let states = registry.replace_many(&replacements).await.unwrap();
    for (index, (replacement, state)) in replacements.iter().zip(states).enumerate() {
        assert_eq!(state.version, 2);
        assert_eq!(state.backing, replacement.backing);
        assert_eq!(state.expiration_time_ms, Some(42_000));
        assert_eq!(
            state.pending_deletions,
            vec![vec![u8::try_from(index).unwrap() + 1]]
        );
        assert_eq!(
            registry
                .observe(&replacement.reference, &replacement.owner)
                .await
                .unwrap(),
            Some(state)
        );
    }
}

#[tokio::test]
async fn preparation_has_no_side_effects_and_a_stale_member_rolls_back_every_write() {
    let (store, registry, replacements) = fixture().await;
    let writes = registry.prepare_replacements(&replacements).await.unwrap();
    for replacement in &replacements {
        assert_eq!(
            registry
                .observe(&replacement.reference, &replacement.owner)
                .await
                .unwrap()
                .unwrap()
                .version,
            1
        );
    }
    // A separate winner changes the last member after the whole set was prepared.
    let last = replacements.last().unwrap();
    registry
        .replace(&last.reference, &last.owner, 1, vec![99], None)
        .await
        .unwrap();
    assert_eq!(
        store
            .compare_and_swap_many(&writes)
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    for replacement in &replacements[..2] {
        assert_eq!(
            registry
                .observe(&replacement.reference, &replacement.owner)
                .await
                .unwrap()
                .unwrap()
                .version,
            1
        );
    }
}

#[tokio::test]
async fn invalid_member_never_publishes_earlier_members() {
    for invalid in 0..7 {
        let (_, registry, mut replacements) = fixture().await;
        match invalid {
            0 => replacements[2].expected_version = 99,
            1 => replacements[2].owner.workspace = "another-workspace".to_string(),
            2 => replacements[2].backing.clear(),
            3 => replacements[2].reference = replacements[0].reference.clone(),
            4 => replacements[2].backing = replacements[0].backing.clone(),
            // A candidate must not alias a sibling's live or retired backing.
            5 => replacements[2].backing = vec![1],
            _ => {
                registry
                    .revoke(&replacements[2].reference, &replacements[2].owner)
                    .await
                    .unwrap();
            }
        }
        assert!(registry.replace_many(&replacements).await.is_err());
        for replacement in &replacements[..2] {
            assert_eq!(
                registry
                    .observe(&replacement.reference, &replacement.owner)
                    .await
                    .unwrap()
                    .unwrap()
                    .version,
                1
            );
        }
    }
}

#[tokio::test]
async fn concurrent_output_sets_have_one_winner_and_never_mix_values() {
    let (_, registry, replacements) = fixture().await;
    let mut competitor = replacements.clone();
    for replacement in &mut competitor {
        replacement.backing[0] += 10;
    }
    let (first, second) = tokio::join!(
        registry.replace_many(&replacements),
        registry.replace_many(&competitor)
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let winner = if first.is_ok() {
        replacements
    } else {
        competitor
    };
    for replacement in winner {
        let state = registry
            .observe(&replacement.reference, &replacement.owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.version, 2);
        assert_eq!(state.backing, replacement.backing);
    }
}

#[tokio::test]
async fn retired_sibling_handles_and_version_exhaustion_reject_the_whole_group() {
    let (store, registry, mut replacements) = fixture().await;
    registry
        .replace(
            &replacements[0].reference,
            &replacements[0].owner,
            1,
            vec![50],
            None,
        )
        .await
        .unwrap();
    replacements[0].expected_version = 2;
    replacements[2].backing = vec![1];
    assert_eq!(
        registry
            .replace_many(&replacements)
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    replacements[2].backing = vec![13];
    store
        .0
        .lock()
        .unwrap()
        .get_mut(&replacements[2].reference)
        .unwrap()
        .state
        .version = u64::MAX;
    replacements[2].expected_version = u64::MAX;
    assert_eq!(
        registry
            .replace_many(&replacements)
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        registry
            .observe(&replacements[0].reference, &replacements[0].owner)
            .await
            .unwrap()
            .unwrap()
            .version,
        2
    );
    assert_eq!(
        registry
            .observe(&replacements[1].reference, &replacements[1].owner)
            .await
            .unwrap()
            .unwrap()
            .version,
        1
    );
}

#[derive(Debug)]
struct CleanupConflict {
    store: MemoryStore,
    calls: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl ReferenceStateStore for CleanupConflict {
    async fn load(&self, reference: &str) -> Result<Option<StoredReference>, Status> {
        self.store.load(reference).await
    }
    async fn compare_and_swap(
        &self,
        reference: &str,
        revision: Option<u64>,
        state: &ReferenceState,
    ) -> Result<(), Status> {
        self.store
            .compare_and_swap(reference, revision, state)
            .await
    }
    async fn compare_and_swap_many(&self, writes: &[ReferenceWrite]) -> Result<(), Status> {
        if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            // Simulate cleanup changing only the storage revision after prepare.
            let mut records = self.store.0.lock().unwrap();
            records.get_mut(&writes[2].reference).unwrap().revision += 1;
        }
        self.store.compare_and_swap_many(writes).await
    }
}

#[tokio::test]
async fn cleanup_conflicts_rebuild_all_storage_fences_without_advancing_value_versions_twice() {
    let (_, registry, replacements) = fixture().await;
    let store = Arc::new(CleanupConflict {
        store: MemoryStore::default(),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    for replacement in &replacements {
        let original = registry
            .observe(&replacement.reference, &replacement.owner)
            .await
            .unwrap()
            .unwrap();
        store
            .compare_and_swap(&replacement.reference, None, &original)
            .await
            .unwrap();
    }
    let registry = ReferenceRegistry::new(store.clone());
    let updated = registry.replace_many(&replacements).await.unwrap();
    assert!(
        updated
            .iter()
            .all(|state| state.version == 2 && state.pending_deletions.len() == 1)
    );
    assert_eq!(store.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[derive(Debug, Default)]
struct SingleOnlyStore(MemoryStore);
#[async_trait]
impl ReferenceStateStore for SingleOnlyStore {
    async fn load(&self, reference: &str) -> Result<Option<StoredReference>, Status> {
        self.0.load(reference).await
    }
    async fn compare_and_swap(
        &self,
        reference: &str,
        revision: Option<u64>,
        state: &ReferenceState,
    ) -> Result<(), Status> {
        self.0.compare_and_swap(reference, revision, state).await
    }
}

#[tokio::test]
async fn adapters_without_transactions_fail_closed_instead_of_sequential_fallback() {
    let store = Arc::new(SingleOnlyStore::default());
    let registry = ReferenceRegistry::new(store);
    registry.adopt("a", &owner(), vec![1]).await.unwrap();
    registry.adopt("b", &owner(), vec![2]).await.unwrap();
    let replacements = ["a", "b"]
        .into_iter()
        .enumerate()
        .map(|(index, reference)| ReferenceReplacement {
            reference: reference.to_string(),
            owner: owner(),
            expected_version: 1,
            backing: vec![u8::try_from(index).unwrap() + 11],
            expiration_time_ms: None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        registry
            .replace_many(&replacements)
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        registry
            .observe("a", &owner())
            .await
            .unwrap()
            .unwrap()
            .version,
        1
    );
    assert_eq!(
        registry
            .observe("b", &owner())
            .await
            .unwrap()
            .unwrap()
            .version,
        1
    );
    assert_eq!(
        registry.replace_many(&[]).await.unwrap_err().code(),
        Code::InvalidArgument
    );
}
