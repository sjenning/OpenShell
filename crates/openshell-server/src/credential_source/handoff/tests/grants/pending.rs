// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
mod postgres;
async fn prepared(store: &Store, source: &RemoteProviderSource) -> StaticHandoff {
    let mut handoff = begin(store, source).await;
    handoff.reserve(store, source).await.unwrap();
    handoff
        .prepare_grant(
            store,
            source,
            &HashMap::from([("audience".into(), "private-audience".into())]),
            &HashMap::from([("seed".into(), "private-refresh-material".into())]),
        )
        .await
        .unwrap();
    handoff
}
#[tokio::test]
async fn pending_grant_publication_does_not_request_a_mint_and_first_values_keep_bindings() {
    let store = test_store().await;
    let (issuer, source, minter) = issuer().await;
    let mut handoff = prepared(&store, &source).await;
    let id = handoff.grant_id().unwrap().to_owned();
    let mut provider = provider();
    provider.credential_handles = handoff.handles(&source).unwrap();
    handoff
        .publish(&store, &source, write(&provider))
        .await
        .unwrap();
    let before = store
        .get("provider", provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        source
            .refresh_statuses(&store, &provider, "TOKEN")
            .await
            .unwrap()[0]
            .status,
        "configured"
    );
    assert!(
        source
            .export_grants(&provider, &["TOKEN".into(), "OTHER_TOKEN".into()])
            .await
            .unwrap()
            .contains(&id)
    );
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        source
            .resolve_provider_handles(&provider, current_time_ms())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
    issuer
        .watched
        .ensure_fresh(refresh::EnsureFreshRequest {
            grant: id,
            min_remaining: None,
        })
        .await
        .unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    let values = source
        .resolve_provider_handles(&provider, current_time_ms())
        .await
        .unwrap();
    assert_eq!(values.values["TOKEN"], "first-1");
    assert!(values.versions.values().all(|version| *version == 2));
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
    let after = store
        .get("provider", provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.payload, before.payload);
    assert_eq!(after.resource_version, before.resource_version);
}
#[tokio::test]
async fn first_value_required_handoffs_cannot_publish_pending_outputs() {
    let store = test_store().await;
    let (_issuer, source, minter) = issuer().await;
    let mut handoff = prepared(&store, &source).await;
    let mut metadata = serde_json::to_value(&handoff.state).unwrap();
    metadata["grant"]
        .as_object_mut()
        .unwrap()
        .remove("pending_publication");
    handoff.state = serde_json::from_value(metadata).unwrap();
    let mut provider = provider();
    provider.credential_handles = handoff.handles(&source).unwrap();
    assert_eq!(
        handoff
            .publish(&store, &source, write(&provider))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert!(
        store
            .get("provider", provider.object_id())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn lost_initialization_response_is_cleaned_from_metadata_without_replaying_inputs() {
    let store = test_store().await;
    let (issuer, source, minter) = issuer().await;
    let mut handoff = begin(&store, &source).await;
    handoff.reserve(&store, &source).await.unwrap();
    let id = handoff.grant_id().unwrap().to_owned();
    handoff.state.phase = Phase::Filling;
    handoff.save(&store).await.unwrap();
    issuer
        .raw
        .initialize_grant(refresh::InitializeGrantRequest {
            grant: id.clone(),
            config: HashMap::from([("audience".into(), "private-audience".into())]),
            secret_material: HashMap::from([("seed".into(), "private-refresh-material".into())]),
            idempotency_key: handoff.operation("TOKEN", "initialize-grant").unwrap(),
        })
        .await
        .unwrap();
    let metadata = String::from_utf8(
        store
            .get(KIND, handoff.id())
            .await
            .unwrap()
            .unwrap()
            .payload,
    )
    .unwrap();
    assert!(!metadata.contains("private-audience"));
    assert!(!metadata.contains("private-refresh-material"));
    let result = StaticHandoff::recover_page(&store, &source, None, 32, i64::MAX)
        .await
        .unwrap();
    assert_eq!(result.cleaned, 1);
    assert!(store.get(KIND, handoff.id()).await.unwrap().is_none());
    assert_eq!(
        issuer
            .raw
            .get_grant(refresh::GetGrantRequest { grant: id })
            .await
            .unwrap()
            .status
            .unwrap()
            .state,
        "deleting"
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
}
