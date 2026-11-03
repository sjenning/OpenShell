// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use openshell_core::GetResourceVersion as _;

async fn current(store: &Store) -> Provider {
    store
        .get_message::<Provider>("provider-id")
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn detach_claim_fences_mutations_and_recovery_transfers_the_complete_static_bundle() {
    let store = test_store().await;
    let (issuer, source, minter) = issuer().await;
    let (mut handoff, _) = published(&store, &source).await;
    let provider = current(&store).await;
    let old = handoff.clone();
    let proof = handoff.published_grant(&provider).unwrap();
    handoff
        .begin_detach(&store, &source, &provider)
        .await
        .unwrap();
    assert!(proof.restore(&store).await.is_err());
    let owned = StaticHandoff::published_for_provider(&store, &source, &provider)
        .await
        .unwrap();
    assert!(
        StaticHandoff::delete_provider(
            &store,
            &source,
            provider.object_id(),
            provider.get_resource_version(),
            &owned
        )
        .await
        .is_err()
    );
    assert!(
        StaticHandoff::update_preserving(
            &store,
            &source,
            &provider,
            provider.get_resource_version(),
            &owned
        )
        .await
        .is_err()
    );
    let result = StaticHandoff::recover_page(&store, &source, None, 128, i64::MIN)
        .await
        .unwrap();
    assert_eq!(result.detached, 1);
    assert_eq!(result.failures, 0);
    let provider = current(&store).await;
    let journal = StaticHandoff::load(&store, handoff.id())
        .await
        .unwrap()
        .unwrap();
    assert!(journal.grant_id().is_none());
    assert!(!journal.is_detaching());
    for key in ["TOKEN", "OTHER_TOKEN"] {
        let binding = source.decode(&provider.credential_handles[key]).unwrap();
        assert!(binding.grant.is_none());
        assert_eq!(Some(binding.reference), old.state.slots[key].reference);
    }
    assert!(
        source
            .refresh_statuses(&store, &provider, "")
            .await
            .unwrap()
            .is_empty()
    );
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
    assert_eq!(values.values["OTHER_TOKEN"], "second-1");
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
    // A stale pre-claim owner cannot revoke either the grant or its static outputs.
    assert!(old.clone().abort(&store, &source).await.is_err());
    // Static bundles can now remove one key without revoking siblings, despite
    // those references having no ReserveSecret receipt in this journal.
    let mut candidate = provider.clone();
    candidate.credential_handles.remove("TOKEN");
    StaticHandoff::update_preserving(
        &store,
        &source,
        &candidate,
        provider.get_resource_version(),
        &[journal],
    )
    .await
    .unwrap();
    let result = StaticHandoff::recover_page(&store, &source, None, 128, i64::MIN)
        .await
        .unwrap();
    assert_eq!(result.failures, 0);
    let provider = current(&store).await;
    let owned = StaticHandoff::published_for_provider(&store, &source, &provider)
        .await
        .unwrap();
    StaticHandoff::delete_provider(
        &store,
        &source,
        provider.object_id(),
        provider.get_resource_version(),
        &owned,
    )
    .await
    .unwrap();
    let result = StaticHandoff::recover_page(&store, &source, None, 128, i64::MIN)
        .await
        .unwrap();
    assert_eq!(result.failures, 0);
    assert!(
        StaticHandoff::load(&store, handoff.id())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn detach_recovery_replays_a_lost_issuer_response_without_revocation_or_reminting() {
    let store = test_store().await;
    let (issuer, source, minter) = issuer().await;
    let (mut handoff, _) = published(&store, &source).await;
    let provider = current(&store).await;
    handoff
        .begin_detach(&store, &source, &provider)
        .await
        .unwrap();
    issuer
        .raw
        .detach_grant(refresh::DetachGrantRequest {
            grant: handoff.grant_id().unwrap().into(),
            idempotency_key: handoff.operation("TOKEN", "detach-grant").unwrap(),
        })
        .await
        .unwrap();
    let result = StaticHandoff::recover_page(&store, &source, None, 128, i64::MIN)
        .await
        .unwrap();
    assert_eq!(result.detached, 1);
    assert_eq!(result.failures, 0);
    // A competing caller can establish that this exact conversion committed.
    handoff.finish_detach(&store, &source).await.unwrap();
    let result = StaticHandoff::recover_page(&store, &source, None, 128, i64::MIN)
        .await
        .unwrap();
    assert_eq!(result.detached, 0);
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
    let provider = current(&store).await;
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        source
            .resolve_provider_handles(&provider, current_time_ms())
            .await
            .unwrap()
            .values["TOKEN"],
        "first-1"
    );
}

#[tokio::test]
async fn pending_values_cannot_be_detached_and_keep_their_refresh_configuration() {
    let store = test_store().await;
    let (_issuer, source, minter) = issuer().await;
    let mut handoff = pending::prepared(&store, &source).await;
    let mut provider = provider();
    provider.credential_handles = handoff.handles(&source).unwrap();
    handoff
        .publish(&store, &source, write(&provider))
        .await
        .unwrap();
    let provider = current(&store).await;
    assert_eq!(
        handoff
            .begin_detach(&store, &source, &provider)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let journal = StaticHandoff::load(&store, handoff.id())
        .await
        .unwrap()
        .unwrap();
    assert!(!journal.is_detaching());
    assert!(journal.grant_id().is_some());
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL"]
async fn postgres_detach_claim_and_static_publication_are_fenced_across_connections() {
    let schema = crate::persistence::test_postgres::TestSchema::create("issuer_detach").await;
    let first = schema.connect_store().await;
    let second = schema.connect_store().await;
    let (issuer, source, minter) = issuer().await;
    let (mut handoff, _) = published(&first, &source).await;
    let provider = current(&first).await;
    let stale = handoff.clone();
    handoff
        .begin_detach(&first, &source, &provider)
        .await
        .unwrap();
    assert!(
        StaticHandoff::delete_provider(
            &second,
            &source,
            provider.object_id(),
            provider.get_resource_version(),
            &[stale]
        )
        .await
        .is_err()
    );
    let result = StaticHandoff::recover_page(&second, &source, None, 128, i64::MIN)
        .await
        .unwrap();
    assert_eq!(result.detached, 1);
    assert_eq!(result.failures, 0);
    handoff.finish_detach(&first, &source).await.unwrap();
    let provider = current(&first).await;
    assert!(
        source
            .refresh_statuses(&second, &provider, "")
            .await
            .unwrap()
            .is_empty()
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
            .unwrap()
            .values["TOKEN"],
        "first-1"
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
    drop(first);
    drop(second);
    schema.drop_schema().await;
}

#[tokio::test]
async fn competing_detach_finalizers_accept_only_the_exact_committed_static_bundle() {
    let store = test_store().await;
    let (_issuer, source, _minter) = issuer().await;
    let (mut first, _) = published(&store, &source).await;
    let provider = current(&store).await;
    first
        .begin_detach(&store, &source, &provider)
        .await
        .unwrap();
    let mut second = first.clone();
    let mut stale = first.clone();
    let (a, b) = tokio::join!(
        first.finish_detach(&store, &source),
        second.finish_detach(&store, &source)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(
        current(&store).await.get_resource_version(),
        provider.get_resource_version() + 1
    );
    let provider = current(&store).await;
    let mut replacement = provider.clone();
    replacement.credential_handles.remove("TOKEN");
    StaticHandoff::update_preserving(
        &store,
        &source,
        &replacement,
        provider.get_resource_version(),
        &[first],
    )
    .await
    .unwrap();
    assert!(
        stale.finish_detach(&store, &source).await.is_err(),
        "a changed bundle cannot satisfy a previous transfer proof"
    );
}
