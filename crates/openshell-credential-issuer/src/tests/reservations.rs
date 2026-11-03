// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn reservations_publish_first_outputs_atomically_without_fake_retired_backings() {
    let store = Arc::new(MemoryStore::default());
    let registry = ReferenceRegistry::new(store.clone());
    for key in ["a", "b"] {
        let state = registry.reserve(key, &owner()).await.unwrap();
        assert!(state.pending_value);
        assert!(state.backing.is_empty());
        assert_eq!(state.version, 1);
        assert_eq!(registry.reserve(key, &owner()).await.unwrap(), state);
    }
    let replacements = ["a", "b"]
        .into_iter()
        .enumerate()
        .map(|(index, key)| ReferenceReplacement {
            reference: key.to_string(),
            owner: owner(),
            expected_version: 1,
            backing: vec![u8::try_from(index + 1).unwrap()],
            expiration_time_ms: Some(123_456),
        })
        .collect::<Vec<_>>();
    let states = registry.replace_many(&replacements).await.unwrap();
    for state in states {
        assert!(!state.pending_value);
        assert_eq!(state.version, 2);
        assert!(state.pending_deletions.is_empty());
        assert!(!state.backing.is_empty());
    }
    assert_eq!(store.load("a").await.unwrap().unwrap().revision, 2);
}

#[tokio::test]
async fn unminted_reservations_can_be_revoked_without_ever_allocating_values() {
    let registry = ReferenceRegistry::new(Arc::new(MemoryStore::default()));
    registry.reserve("ref", &owner()).await.unwrap();
    let state = registry.revoke("ref", &owner()).await.unwrap();
    assert!(state.revoked);
    assert!(state.pending_value);
    assert_eq!(state.version, 2);
    assert!(state.pending_deletions.is_empty());
    assert!(state.backing.is_empty());
    assert_eq!(
        registry.reserve("ref", &owner()).await.unwrap_err().code(),
        Code::NotFound
    );
    assert_eq!(
        registry
            .replace("ref", &owner(), 2, vec![1], None)
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
}

#[test]
fn legacy_metadata_defaults_to_a_materialized_value_and_malformed_reservations_fail_closed() {
    let state: ReferenceState = serde_json::from_value(serde_json::json!({ "owner": owner(), "version": 1, "backing": [1], "expiration_time_ms": null, "revoked": false, "pending_deletions": [] })).unwrap();
    assert!(!state.pending_value);
    authorize(&state, &owner()).unwrap();
    let mut pending = ReferenceState::reserved(owner());
    pending.backing = vec![1];
    assert!(authorize(&pending, &owner()).is_err());
    pending.backing.clear();
    pending.expiration_time_ms = Some(1);
    assert!(authorize(&pending, &owner()).is_err());
}
