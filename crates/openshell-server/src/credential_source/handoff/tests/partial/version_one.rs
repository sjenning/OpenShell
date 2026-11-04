// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;

async fn legacy(
    store: &Store,
    issuer: &Issuer,
    source: &RemoteProviderSource,
    expiration: Option<i64>,
) -> Provider {
    let mut provider = provider();
    let secret = issuer
        .watched
        .put_secret(wire::PutSecretRequest {
            owner: Some(crate::credential_source::owner(&provider, "TOKEN").unwrap()),
            value: "legacy-private".into(),
            expiration_time: expiration
                .map(|time| openshell_core::time::timestamp_from_millis(time).unwrap()),
            idempotency_key: "version-one-static".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(secret.version, 1);
    provider.credential_handles.insert(
        "TOKEN".into(),
        source.reference_handle(&secret.reference, None).unwrap(),
    );
    store
        .write_atomically(&[
            write(&provider),
            StaticHandoff::migration_write(source, &provider, &["TOKEN".into()], None).unwrap(),
        ])
        .await
        .unwrap();
    source.register_provider(&provider).unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    provider
}

#[tokio::test]
async fn version_one_static_expiration_edits_preserve_the_conservative_issuer_bound_without_values()
{
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let bound = current_time_ms() + 60_000;
    let mut provider = legacy(&store, &issuer, &source, Some(bound)).await;
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    let reads = issuer.resolves.load(Ordering::SeqCst);
    for (version, expiration) in [
        (1, Some(bound - 1_000)),
        (2, Some(bound + 1_000)),
        (3, None),
    ] {
        let owned = StaticHandoff::published_for_provider(&store, &source, &provider)
            .await
            .unwrap();
        provider.credential_expiration_times = expiration
            .map(|time| {
                HashMap::from([(
                    "TOKEN".into(),
                    openshell_core::time::timestamp_from_millis(time).unwrap(),
                )])
            })
            .unwrap_or_default();
        StaticHandoff::update_preserving(&store, &source, &provider, version, &owned)
            .await
            .unwrap();
        let mut projected = provider.clone();
        source.project_expiration_times(&mut projected).unwrap();
        assert_eq!(
            projected.credential_expiration_times["TOKEN"],
            openshell_core::time::timestamp_from_millis(expiration.unwrap_or(bound).min(bound))
                .unwrap()
        );
    }
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), reads);
}

#[tokio::test]
async fn version_one_expiration_edit_is_refenced_at_publication_even_with_a_stale_watch() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let original = legacy(&store, &issuer, &source, None).await;
    let owned = StaticHandoff::published_for_provider(&store, &source, &original)
        .await
        .unwrap();
    let mut candidate = original.clone();
    candidate.credential_expiration_times.insert(
        "TOKEN".into(),
        openshell_core::time::timestamp_from_millis(1).unwrap(),
    );
    StaticHandoff::check_retained_expirations(&source, &original, &candidate, std::iter::empty())
        .await
        .unwrap();
    let binding = source
        .decode(&original.credential_handles["TOKEN"])
        .unwrap();
    // Bypass the watched mutation wrapper and do not wait for watch catch-up.
    // Publication must authenticate expected_version=1 at the issuer itself.
    issuer
        .raw
        .put_secret(wire::PutSecretRequest {
            owner: Some(crate::credential_source::owner(&original, "TOKEN").unwrap()),
            reference: binding.reference,
            expected_version: Some(1),
            value: "issuer-owned-version-two".into(),
            idempotency_key: "advance-before-publication".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    let reads = issuer.resolves.load(Ordering::SeqCst);
    assert!(
        StaticHandoff::update_preserving(&store, &source, &candidate, 1, &owned)
            .await
            .is_err()
    );
    assert_eq!(
        store
            .get_message::<Provider>(original.object_id())
            .await
            .unwrap()
            .unwrap()
            .credential_expiration_times,
        original.credential_expiration_times
    );
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), reads);
}

#[tokio::test]
async fn replacing_a_sibling_keeps_version_one_expiration_edits_and_the_publication_fence() {
    for advance in [false, true] {
        let store = test_store().await;
        let issuer = Issuer::start().await;
        let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
        let original = legacy(&store, &issuer, &source, None).await;
        let owned = StaticHandoff::published_for_provider(&store, &source, &original)
            .await
            .unwrap();
        let mut candidate = original.clone();
        candidate.credential_expiration_times.insert(
            "TOKEN".into(),
            openshell_core::time::timestamp_from_millis(current_time_ms() + 60_000).unwrap(),
        );
        let mut handoff =
            StaticHandoff::begin(&store, &source, &candidate, &["SIBLING".into()], Some(1))
                .await
                .unwrap();
        handoff.reserve(&store, &source).await.unwrap();
        handoff
            .fill(
                &store,
                &source,
                &HashMap::from([("SIBLING".into(), "new-sibling".into())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        candidate
            .credential_handles
            .extend(handoff.handles(&source).unwrap());
        if advance {
            let binding = source
                .decode(&original.credential_handles["TOKEN"])
                .unwrap();
            issuer
                .raw
                .put_secret(wire::PutSecretRequest {
                    owner: Some(crate::credential_source::owner(&original, "TOKEN").unwrap()),
                    reference: binding.reference,
                    expected_version: Some(1),
                    value: "version-two".into(),
                    idempotency_key: "advance-sibling-publication".into(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        issuer.fail_resolves.store(true, Ordering::SeqCst);
        let reads = issuer.resolves.load(Ordering::SeqCst);
        let result = handoff
            .publish_replacing(
                &store,
                &source,
                AtomicWrite::Update {
                    object_type: "provider".into(),
                    id: candidate.object_id().into(),
                    expected_version: 1,
                    payload: candidate.encode_to_vec(),
                },
                &owned,
            )
            .await;
        let stored = store
            .get_message::<Provider>(original.object_id())
            .await
            .unwrap()
            .unwrap();
        if advance {
            assert!(result.is_err());
            assert_eq!(stored.credential_handles, original.credential_handles);
            assert_eq!(
                stored.credential_expiration_times,
                original.credential_expiration_times
            );
        } else {
            result.unwrap();
            assert_eq!(stored.credential_handles, candidate.credential_handles);
            assert_eq!(
                stored.credential_expiration_times,
                candidate.credential_expiration_times
            );
        }
        assert_eq!(issuer.resolves.load(Ordering::SeqCst), reads);
    }
}

#[tokio::test]
async fn explicit_expiration_spec_noops_keep_their_version_fence_through_both_publication_paths() {
    for expiration in [None, Some(1)] {
        for sibling in [false, true] {
            let store = test_store().await;
            let issuer = Issuer::start().await;
            let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
            let mut original = legacy(&store, &issuer, &source, None).await;
            original.credential_expiration_times = expiration
                .map(|time| {
                    HashMap::from([(
                        "TOKEN".into(),
                        openshell_core::time::timestamp_from_millis(time).unwrap(),
                    )])
                })
                .unwrap_or_default();
            // Unconditional fixture upserts do not advance the native CAS
            // version. Use a real fenced update so a later ABORTED cannot be
            // mistaken for rejecting expected_version=2 before issuer checks.
            original.metadata.as_mut().unwrap().resource_version = 2;
            store
                .write_atomically(&[AtomicWrite::Update {
                    object_type: "provider".into(),
                    id: original.object_id().into(),
                    payload: original.encode_to_vec(),
                    expected_version: 1,
                }])
                .await
                .unwrap();
            assert_eq!(
                store
                    .get("provider", original.object_id())
                    .await
                    .unwrap()
                    .unwrap()
                    .resource_version,
                2
            );
            let mut update = Provider {
                credential_expiration_times: original.credential_expiration_times.clone(),
                ..Default::default()
            };
            let clear = if expiration.is_none() {
                vec!["TOKEN".into()]
            } else {
                Vec::new()
            };
            let intent = ExpirationIntent::capture(&source, &original, &update, &clear)
                .await
                .unwrap();
            let owned = StaticHandoff::published_for_provider(&store, &source, &original)
                .await
                .unwrap();
            let mut candidate = original.clone();
            let mut staged = if sibling {
                update
                    .credentials
                    .insert("SIBLING".into(), "sibling".into());
                let mut handoff =
                    StaticHandoff::begin(&store, &source, &candidate, &["SIBLING".into()], Some(2))
                        .await
                        .unwrap();
                handoff.reserve(&store, &source).await.unwrap();
                handoff
                    .fill(&store, &source, &update.credentials, &HashMap::new())
                    .await
                    .unwrap();
                candidate
                    .credential_handles
                    .extend(handoff.handles(&source).unwrap());
                Some(handoff)
            } else {
                None
            };
            let binding = source
                .decode(&original.credential_handles["TOKEN"])
                .unwrap();
            issuer.hold_secret_watch.store(true, Ordering::SeqCst);
            issuer
                .raw
                .put_secret(wire::PutSecretRequest {
                    owner: Some(crate::credential_source::owner(&original, "TOKEN").unwrap()),
                    reference: binding.reference,
                    expected_version: Some(1),
                    value: "version-two".into(),
                    expiration_time: Some(
                        openshell_core::time::timestamp_from_millis(current_time_ms() + 60_000)
                            .unwrap(),
                    ),
                    idempotency_key: "noop-publication-advance".into(),
                })
                .await
                .unwrap();
            issuer.fail_resolves.store(true, Ordering::SeqCst);
            let result = if let Some(handoff) = staged.as_mut() {
                handoff
                    .publish_replacing_with_expiration_intent(
                        &store,
                        &source,
                        AtomicWrite::Update {
                            object_type: "provider".into(),
                            id: original.object_id().into(),
                            payload: candidate.encode_to_vec(),
                            expected_version: 2,
                        },
                        &owned,
                        Some(&intent),
                    )
                    .await
            } else {
                StaticHandoff::update_preserving_with_expiration_intent(
                    &store,
                    &source,
                    &candidate,
                    2,
                    &owned,
                    Some(&intent),
                )
                .await
            };
            let error = result.unwrap_err();
            assert_eq!(error.code(), tonic::Code::Aborted);
            let stored = store
                .get_message::<Provider>(original.object_id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.metadata.as_ref().unwrap().resource_version, 2);
            assert_eq!(stored.credential_handles, original.credential_handles);
            assert_eq!(
                stored.credential_expiration_times,
                original.credential_expiration_times
            );
            assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
        }
    }
}
