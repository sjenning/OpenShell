// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
mod postgres;

use super::*;
async fn published(store: &Store, source: &RemoteProviderSource) -> (StaticHandoff, Provider) {
    let mut journal = prepared(store, source).await;
    let mut provider = provider();
    provider.credential_handles = journal.handles(source).unwrap();
    journal
        .publish(store, source, write(&provider))
        .await
        .unwrap();
    (journal, provider)
}
async fn replacement(
    store: &Store,
    source: &RemoteProviderSource,
    provider: &Provider,
) -> (StaticHandoff, AtomicWrite) {
    let mut journal = StaticHandoff::begin(store, source, provider, &["TOKEN".into()], Some(1))
        .await
        .unwrap();
    journal.reserve(store, source).await.unwrap();
    journal
        .fill(
            store,
            source,
            &HashMap::from([("TOKEN".into(), "replacement-value".into())]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    let mut updated = provider.clone();
    updated.credential_handles = journal.handles(source).unwrap();
    let write = AtomicWrite::Update {
        object_type: "provider".into(),
        id: provider.object_id().into(),
        payload: updated.encode_to_vec(),
        expected_version: 1,
    };
    (journal, write)
}
async fn inspect(
    issuer: &Issuer,
    journal: &StaticHandoff,
) -> Result<wire::ResolveSecretsResponse, Status> {
    issuer
        .raw
        .resolve_secrets(wire::ResolveSecretsRequest {
            purpose: wire::ResolvePurpose::MetadataInspection as i32,
            secrets: vec![wire::ResolveSecretRequest {
                request_id: "check".into(),
                owner: Some(journal.owner("TOKEN")),
                reference: journal.state.slots["TOKEN"].reference.clone().unwrap(),
                expected_version: None,
            }],
        })
        .await
}
#[tokio::test]
async fn replacement_claims_old_epoch_before_cleanup_and_never_revokes_new_values() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let (mut old, provider) = published(&store, &source).await;
    let (mut new, write) = replacement(&store, &source, &provider).await;
    new.publish_replacing(&store, &source, write, &[old.clone()])
        .await
        .unwrap();
    assert!(new.is_published());
    assert_eq!(new.provider_id(), provider.object_id());
    assert!(inspect(&issuer, &old).await.is_ok());
    assert!(old.abort(&store, &source).await.is_err());
    let mut cleanup = StaticHandoff::load(&store, old.id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cleanup.state.phase, Phase::Aborting);
    cleanup.abort(&store, &source).await.unwrap();
    assert!(inspect(&issuer, &old).await.is_err());
    assert!(inspect(&issuer, &new).await.is_ok());
    assert_eq!(
        store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap()
            .credential_handles,
        new.state
            .slots
            .iter()
            .map(|(key, slot)| (
                key.clone(),
                source
                    .reference_handle(slot.reference.as_deref().unwrap(), None)
                    .unwrap()
            ))
            .collect()
    );
}
#[tokio::test]
async fn missing_or_stale_retirement_ownership_rolls_back_the_entire_replacement() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let (old, provider) = published(&store, &source).await;
    let (mut new, write) = replacement(&store, &source, &provider).await;
    assert!(new.publish(&store, &source, write.clone()).await.is_err());
    let mut stale = old.clone();
    stale.revision += 1;
    assert_eq!(
        new.publish_replacing(&store, &source, write, &[stale])
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    assert_eq!(
        StaticHandoff::load(&store, new.id())
            .await
            .unwrap()
            .unwrap()
            .state
            .phase,
        Phase::Ready
    );
    assert!(
        StaticHandoff::load(&store, old.id())
            .await
            .unwrap()
            .unwrap()
            .is_published()
    );
    assert_eq!(
        store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap()
            .credential_handles,
        provider.credential_handles
    );
    assert!(inspect(&issuer, &old).await.is_ok());
    new.abort(&store, &source).await.unwrap();
}
#[tokio::test]
async fn provider_deletion_claims_all_bindings_atomically_and_survives_lost_acknowledgement() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let (old, provider) = published(&store, &source).await;
    assert!(
        StaticHandoff::delete_provider(&store, &source, provider.object_id(), 1, &[])
            .await
            .is_err()
    );
    assert!(
        StaticHandoff::delete_provider(
            &store,
            &source,
            provider.object_id(),
            2,
            std::slice::from_ref(&old)
        )
        .await
        .is_err()
    );
    assert!(
        StaticHandoff::load(&store, old.id())
            .await
            .unwrap()
            .unwrap()
            .is_published()
    );
    StaticHandoff::delete_provider(
        &store,
        &source,
        provider.object_id(),
        1,
        std::slice::from_ref(&old),
    )
    .await
    .unwrap();
    assert!(
        store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(inspect(&issuer, &old).await.is_ok());
    // Recover from durable metadata, not an inferred missing-parent outcome.
    let mut cleanup = StaticHandoff::load(&store, old.id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cleanup.state.phase, Phase::Aborting);
    cleanup.abort(&store, &source).await.unwrap();
    assert!(inspect(&issuer, &old).await.is_err());
    assert!(
        StaticHandoff::load(&store, old.id())
            .await
            .unwrap()
            .is_none()
    );
}
