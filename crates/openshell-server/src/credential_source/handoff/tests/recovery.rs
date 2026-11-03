// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
mod postgres;

use super::*;
#[tokio::test]
async fn filtered_pages_advance_even_when_source_or_provider_does_not_match() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let other = RemoteProviderSource::new("other", issuer.watched.clone()).unwrap();
    let foreign = StaticHandoff::begin(&store, &other, &provider(), &["TOKEN".into()], None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let wanted = StaticHandoff::begin(&store, &source, &provider(), &["TOKEN".into()], None)
        .await
        .unwrap();
    let first = StaticHandoff::list_page(&store, &source, "default", "provider-id", None, 1)
        .await
        .unwrap();
    assert!(first.handoffs.is_empty());
    assert!(first.next_cursor.is_some());
    let second = StaticHandoff::list_page(
        &store,
        &source,
        "default",
        "provider-id",
        first.next_cursor.as_ref(),
        1,
    )
    .await
    .unwrap();
    assert_eq!(second.handoffs[0].id(), wanted.id());
    assert!(second.next_cursor.is_none());
    assert!(
        StaticHandoff::load(&store, foreign.id())
            .await
            .unwrap()
            .is_some()
    );
}
#[tokio::test]
async fn idle_recovery_keeps_fresh_foreign_and_published_ownership_even_if_parent_is_missing() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let other = RemoteProviderSource::new("other", issuer.watched.clone()).unwrap();
    let old = StaticHandoff::begin(&store, &source, &provider(), &["TOKEN".into()], None)
        .await
        .unwrap();
    let foreign = StaticHandoff::begin(&store, &other, &provider(), &["TOKEN".into()], None)
        .await
        .unwrap();
    let cutoff = current_time_ms();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let fresh = StaticHandoff::begin(&store, &source, &provider(), &["TOKEN".into()], None)
        .await
        .unwrap();
    let mut live = prepared(&store, &source).await;
    let mut provider = provider();
    provider.credential_handles = live.handles(&source).unwrap();
    live.publish(&store, &source, write(&provider))
        .await
        .unwrap();
    assert_eq!(
        StaticHandoff::published_for_provider(&store, &source, &provider)
            .await
            .unwrap()
            .len(),
        1
    );
    store
        .delete("provider", provider.object_id())
        .await
        .unwrap();
    let result = StaticHandoff::recover_page(&store, &source, None, 128, cutoff)
        .await
        .unwrap();
    assert_eq!(result.cleaned, 1);
    assert_eq!(result.failures, 0);
    assert!(
        StaticHandoff::load(&store, old.id())
            .await
            .unwrap()
            .is_none()
    );
    for retained in [&foreign, &fresh, &live] {
        assert!(
            StaticHandoff::load(&store, retained.id())
                .await
                .unwrap()
                .is_some()
        );
    }
}
#[tokio::test]
async fn failed_cleanup_retains_ownership_and_does_not_block_an_unrelated_journal() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let mut denied = provider();
    denied.metadata.as_mut().unwrap().workspace = "forbidden".into();
    let denied = StaticHandoff::begin(&store, &source, &denied, &["TOKEN".into()], None)
        .await
        .unwrap();
    let healthy = StaticHandoff::begin(&store, &source, &provider(), &["TOKEN".into()], None)
        .await
        .unwrap();
    let result = StaticHandoff::recover_page(&store, &source, None, 128, i64::MAX)
        .await
        .unwrap();
    assert_eq!(result.cleaned, 1);
    assert_eq!(result.failures, 1);
    assert!(
        StaticHandoff::load(&store, healthy.id())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        StaticHandoff::load(&store, denied.id())
            .await
            .unwrap()
            .unwrap()
            .state
            .phase,
        Phase::Aborting
    );
    assert!(
        StaticHandoff::spawn_reconciler(std::sync::Arc::new(store), source, Duration::from_secs(1))
            .is_err()
    );
}
