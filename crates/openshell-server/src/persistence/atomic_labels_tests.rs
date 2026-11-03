// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::{AtomicWrite, Store, test_store};
use std::collections::HashMap;
fn labels(value: &str) -> HashMap<String, String> {
    HashMap::from([("team".into(), value.into())])
}
async fn indexed_labels(store: &Store, id: &str) -> HashMap<String, String> {
    serde_json::from_str(
        &store
            .get("atomic_labels", id)
            .await
            .unwrap()
            .unwrap()
            .labels
            .unwrap(),
    )
    .unwrap()
}
async fn exercise(store: &Store) {
    store
        .write_atomically(&[AtomicWrite::CreateLabeled {
            object_type: "atomic_labels".into(),
            id: "one".into(),
            name: "one".into(),
            workspace: "default".into(),
            payload: b"original".to_vec(),
            labels: labels("old"),
        }])
        .await
        .unwrap();
    assert_eq!(indexed_labels(store, "one").await, labels("old"));
    store
        .write_atomically(&[AtomicWrite::Update {
            object_type: "atomic_labels".into(),
            id: "one".into(),
            expected_version: 1,
            payload: b"payload-only".to_vec(),
        }])
        .await
        .unwrap();
    assert_eq!(indexed_labels(store, "one").await, labels("old"));
    let update = |version, labels| AtomicWrite::UpdateLabeled {
        object_type: "atomic_labels".into(),
        id: "one".into(),
        expected_version: version,
        payload: b"updated".to_vec(),
        labels,
    };
    store
        .write_atomically(&[update(2, labels("new"))])
        .await
        .unwrap();
    assert_eq!(indexed_labels(store, "one").await, labels("new"));
    let bad = AtomicWrite::Check {
        object_type: "zzz".into(),
        id: "absent".into(),
        expected_version: 1,
    };
    assert!(
        store
            .write_atomically(&[update(3, labels("rollback")), bad.clone()])
            .await
            .is_err()
    );
    assert_eq!(indexed_labels(store, "one").await, labels("new"));
    assert_eq!(
        store
            .get("atomic_labels", "one")
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        3
    );
    assert!(
        store
            .write_atomically(&[
                AtomicWrite::CreateLabeled {
                    object_type: "atomic_labels".into(),
                    id: "two".into(),
                    name: "two".into(),
                    workspace: "default".into(),
                    payload: vec![],
                    labels: labels("rollback")
                },
                bad
            ])
            .await
            .is_err()
    );
    assert!(store.get("atomic_labels", "two").await.unwrap().is_none());
    store
        .write_atomically(&[update(3, HashMap::new())])
        .await
        .unwrap();
    assert!(indexed_labels(store, "one").await.is_empty());
    assert!(
        store
            .write_atomically(&[update(3, labels("stale"))])
            .await
            .is_err()
    );
    assert!(indexed_labels(store, "one").await.is_empty());
}
#[tokio::test]
async fn sqlite_atomic_labels_follow_payload_cas_and_rollback() {
    exercise(&test_store().await).await;
}
#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_atomic_labels_follow_payload_cas_and_rollback() {
    let schema = super::test_postgres::TestSchema::create("atomic_labels").await;
    let store = schema.connect_store().await;
    exercise(&store).await;
    drop(store);
    schema.drop_schema().await;
}
