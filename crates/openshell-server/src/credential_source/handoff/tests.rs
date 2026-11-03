// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
mod fences;
mod partial;
mod recovery;
mod retirement;

use super::*;
use crate::{
    credential_source::{ProviderCredentialSource as _, tests::issuer::Issuer},
    persistence::{current_time_ms, test_store},
};
use openshell_core::proto::ObjectMeta;
use std::time::Duration;
fn provider() -> Provider {
    Provider {
        metadata: Some(ObjectMeta {
            id: "provider-id".into(),
            name: "provider".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        r#type: "custom".into(),
        ..Default::default()
    }
}
fn write(provider: &Provider) -> AtomicWrite {
    AtomicWrite::Create {
        object_type: "provider".into(),
        id: provider.object_id().into(),
        name: provider.object_name().into(),
        workspace: provider.object_workspace().into(),
        payload: provider.encode_to_vec(),
    }
}
async fn prepared(store: &Store, source: &RemoteProviderSource) -> StaticHandoff {
    let mut handoff = StaticHandoff::begin(store, source, &provider(), &["TOKEN".into()], None)
        .await
        .unwrap();
    handoff.reserve(store, source).await.unwrap();
    handoff
        .fill(
            store,
            source,
            &HashMap::from([("TOKEN".into(), "never-in-the-gateway-journal".into())]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    handoff
}
#[tokio::test]
async fn complete_handoff_publishes_provider_and_receipt_atomically_without_persisting_values() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let mut handoff = prepared(&store, &source).await;
    let record = store.get(KIND, handoff.id()).await.unwrap().unwrap();
    assert!(
        !String::from_utf8(record.payload)
            .unwrap()
            .contains("never-in-the-gateway-journal")
    );
    let mut provider = provider();
    provider.credential_handles = handoff.handles(&source).unwrap();
    handoff
        .publish(&store, &source, write(&provider))
        .await
        .unwrap();
    let current = StaticHandoff::load(&store, handoff.id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.state.phase, Phase::Published);
    assert!(handoff.abort(&store, &source).await.is_err());
    let stored = store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(stored.credentials.is_empty());
    source.register_provider(&stored).unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        source
            .resolve_provider_handles(&stored, current_time_ms())
            .await
            .unwrap()
            .values["TOKEN"],
        "never-in-the-gateway-journal"
    );
}
#[tokio::test]
async fn cleanup_claim_fences_a_late_publisher_before_any_remote_revocation() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let mut handoff = prepared(&store, &source).await;
    let mut late = handoff.clone();
    let mut provider = provider();
    provider.credential_handles = late.handles(&source).unwrap();
    handoff.state.phase = Phase::Aborting;
    handoff.save(&store).await.unwrap();
    assert_eq!(
        late.publish(&store, &source, write(&provider))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    assert!(
        store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .is_none()
    );
    handoff.abort(&store, &source).await.unwrap();
    assert!(
        StaticHandoff::load(&store, handoff.id())
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
async fn unknown_reservation_result_is_discovered_and_revoked_after_journal_reload() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let handoff = StaticHandoff::begin(&store, &source, &provider(), &["TOKEN".into()], None)
        .await
        .unwrap();
    let result = issuer
        .raw
        .reserve_secret(wire::ReserveSecretRequest {
            owner: Some(handoff.owner("TOKEN")),
            idempotency_key: handoff.operation("TOKEN", "reserve").unwrap(),
        })
        .await
        .unwrap();
    let mut recovered = StaticHandoff::load(&store, handoff.id())
        .await
        .unwrap()
        .unwrap();
    assert!(recovered.state.slots["TOKEN"].reference.is_none());
    recovered.abort(&store, &source).await.unwrap();
    assert!(
        issuer
            .raw
            .resolve_secrets(wire::ResolveSecretsRequest {
                purpose: wire::ResolvePurpose::MetadataInspection as i32,
                secrets: vec![wire::ResolveSecretRequest {
                    request_id: "revoked".into(),
                    reference: result.reference,
                    owner: Some(handoff.owner("TOKEN")),
                    expected_version: None
                }]
            })
            .await
            .is_err()
    );
}
#[tokio::test]
async fn failed_fill_is_one_shot_and_cleanup_cannot_be_followed_by_late_fill() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let mut handoff = StaticHandoff::begin(&store, &source, &provider(), &["TOKEN".into()], None)
        .await
        .unwrap();
    handoff.reserve(&store, &source).await.unwrap();
    let mut stale = handoff.clone();
    let values = HashMap::from([("TOKEN".into(), "do-not-persist".repeat(90_000))]);
    assert!(
        handoff
            .fill(&store, &source, &values, &HashMap::new())
            .await
            .is_err()
    );
    assert_eq!(
        StaticHandoff::load(&store, handoff.id())
            .await
            .unwrap()
            .unwrap()
            .state
            .phase,
        Phase::Filling
    );
    assert!(
        handoff
            .fill(
                &store,
                &source,
                &HashMap::from([("TOKEN".into(), "changed".into())]),
                &HashMap::new()
            )
            .await
            .is_err()
    );
    assert!(
        !String::from_utf8(
            store
                .get(KIND, handoff.id())
                .await
                .unwrap()
                .unwrap()
                .payload
        )
        .unwrap()
        .contains("do-not-persist")
    );
    handoff.abort(&store, &source).await.unwrap();
    assert!(
        stale
            .fill(
                &store,
                &source,
                &HashMap::from([("TOKEN".into(), "late".into())]),
                &HashMap::new()
            )
            .await
            .is_err()
    );
    assert!(
        store
            .get_message::<Provider>("provider-id")
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
async fn name_conflict_rolls_back_publication_and_preserves_owned_cleanup() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let mut handoff = prepared(&store, &source).await;
    let mut other = provider();
    other.metadata.as_mut().unwrap().id = "other-id".into();
    store.put_message(&other).await.unwrap();
    let mut provider = provider();
    provider.credential_handles = handoff.handles(&source).unwrap();
    assert!(
        handoff
            .publish(&store, &source, write(&provider))
            .await
            .is_err()
    );
    assert_eq!(
        StaticHandoff::load(&store, handoff.id())
            .await
            .unwrap()
            .unwrap()
            .state
            .phase,
        Phase::Ready
    );
    assert!(
        store
            .get_message::<Provider>("provider-id")
            .await
            .unwrap()
            .is_none()
    );
    handoff.abort(&store, &source).await.unwrap();
}
