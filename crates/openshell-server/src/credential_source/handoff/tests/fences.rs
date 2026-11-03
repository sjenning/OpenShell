// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
#[tokio::test]
async fn update_owner_version_and_labels_are_checked_before_external_allocation() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let original = provider();
    store.put_message(&original).await.unwrap();
    assert_eq!(
        StaticHandoff::begin(&store, &source, &original, &["TOKEN".into()], Some(2))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    let mut wrong = original.clone();
    wrong.metadata.as_mut().unwrap().workspace = "other".into();
    assert!(
        StaticHandoff::begin(&store, &source, &wrong, &["TOKEN".into()], Some(1))
            .await
            .is_err()
    );
    let mut labeled = original.clone();
    labeled
        .metadata
        .as_mut()
        .unwrap()
        .labels
        .insert("team".into(), "one".into());
    assert!(
        StaticHandoff::begin(&store, &source, &labeled, &["TOKEN".into()], Some(1))
            .await
            .is_err()
    );
    let mut handoff = StaticHandoff::begin(&store, &source, &original, &["TOKEN".into()], Some(1))
        .await
        .unwrap();
    handoff.reserve(&store, &source).await.unwrap();
    handoff
        .fill(
            &store,
            &source,
            &HashMap::from([("TOKEN".into(), "new-value".into())]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    let mut replacement = original.clone();
    replacement.credential_handles = handoff.handles(&source).unwrap();
    assert!(
        handoff
            .publish(
                &store,
                &source,
                AtomicWrite::Update {
                    object_type: "provider".into(),
                    id: original.object_id().into(),
                    payload: replacement.encode_to_vec(),
                    expected_version: 2
                }
            )
            .await
            .is_err()
    );
    assert!(
        store
            .get_message::<Provider>(original.object_id())
            .await
            .unwrap()
            .unwrap()
            .credential_handles
            .is_empty()
    );
    handoff
        .publish(
            &store,
            &source,
            AtomicWrite::Update {
                object_type: "provider".into(),
                id: original.object_id().into(),
                payload: replacement.encode_to_vec(),
                expected_version: 1,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .get_message::<Provider>(original.object_id())
            .await
            .unwrap()
            .unwrap()
            .credential_handles,
        replacement.credential_handles
    );
}
#[tokio::test]
async fn publication_rejects_values_or_changed_source_and_label_indexes() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let other = RemoteProviderSource::new("other", issuer.watched.clone()).unwrap();
    let mut handoff = prepared(&store, &source).await;
    let mut payload = provider();
    payload.credential_handles = handoff.handles(&source).unwrap();
    payload
        .credentials
        .insert("TOKEN".into(), "must-not-persist".into());
    assert!(
        handoff
            .publish(&store, &source, write(&payload))
            .await
            .is_err()
    );
    payload.credentials.clear();
    assert!(
        handoff
            .publish(&store, &other, write(&payload))
            .await
            .is_err()
    );
    payload
        .metadata
        .as_mut()
        .unwrap()
        .labels
        .insert("team".into(), "one".into());
    assert!(
        handoff
            .publish(&store, &source, write(&payload))
            .await
            .is_err()
    );
    assert!(
        store
            .get_message::<Provider>(payload.object_id())
            .await
            .unwrap()
            .is_none()
    );
    handoff.abort(&store, &source).await.unwrap();
}
