// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::persistence::AtomicWrite;
use openshell_credential_issuer::ReferenceReplacement;

async fn fixture() -> (
    Arc<Store>,
    Arc<ReferenceRegistry>,
    Vec<ReferenceReplacement>,
) {
    let store = Arc::new(crate::persistence::test_store().await);
    let registry = new_registry(store.clone());
    let mut replacements = Vec::new();
    for index in 1..=3_u8 {
        let reference = format!("reference-{index}");
        let owner = SecretOwner {
            workspace: "workspace".to_string(),
            provider_id: "provider-id".to_string(),
            credential_key: format!("OUTPUT_{index}"),
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
async fn native_reference_batches_have_one_concurrent_winner() {
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
        assert_eq!(state.pending_deletions.len(), 1);
    }
}

#[tokio::test]
async fn reference_publication_can_share_one_transaction_with_the_grant_receipt() {
    let (store, registry, replacements) = fixture().await;
    store
        .write_atomically(&[
            AtomicWrite::Create {
                object_type: "test-grant".to_string(),
                id: "grant".to_string(),
                name: "grant".to_string(),
                workspace: "workspace".to_string(),
                payload: vec![0],
            },
            AtomicWrite::Create {
                object_type: "test-owner".to_string(),
                id: "provider".to_string(),
                name: "provider".to_string(),
                workspace: "workspace".to_string(),
                payload: vec![7],
            },
        ])
        .await
        .unwrap();
    let prepared = registry.prepare_replacements(&replacements).await.unwrap();
    let reference_writes = prepared
        .iter()
        .map(|write| AtomicWrite::Update {
            object_type: OBJECT_TYPE.to_string(),
            id: write.reference.clone(),
            payload: serde_json::to_vec(&write.state).unwrap(),
            expected_version: write.expected_revision,
        })
        .collect::<Vec<_>>();
    let receipt = |version| AtomicWrite::Update {
        object_type: "test-grant".to_string(),
        id: "grant".to_string(),
        payload: vec![1],
        expected_version: version,
    };
    for (grant_version, owner_version) in [(2, 1), (1, 2)] {
        let mut conflicting_group = reference_writes.clone();
        conflicting_group.push(receipt(grant_version));
        conflicting_group.push(AtomicWrite::Check {
            object_type: "test-owner".to_string(),
            id: "provider".to_string(),
            expected_version: owner_version,
        });
        assert!(store.write_atomically(&conflicting_group).await.is_err());
    }
    for replacement in &replacements {
        let state = registry
            .observe(&replacement.reference, &replacement.owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.version, 1);
        assert!(state.pending_deletions.is_empty());
    }
    assert_eq!(
        store
            .get("test-grant", "grant")
            .await
            .unwrap()
            .unwrap()
            .payload,
        vec![0]
    );
    let mut valid = reference_writes;
    valid.push(receipt(1));
    valid.push(AtomicWrite::Check {
        object_type: "test-owner".to_string(),
        id: "provider".to_string(),
        expected_version: 1,
    });
    store.write_atomically(&valid).await.unwrap();
    let provider = store.get("test-owner", "provider").await.unwrap().unwrap();
    assert_eq!(provider.resource_version, 1);
    assert_eq!(provider.payload, vec![7]);
    for replacement in &replacements {
        let state = registry
            .observe(&replacement.reference, &replacement.owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.version, 2);
        assert_eq!(state.backing, replacement.backing);
    }
    assert_eq!(
        store
            .get("test-grant", "grant")
            .await
            .unwrap()
            .unwrap()
            .payload,
        vec![1]
    );
}
