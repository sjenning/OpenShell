// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_pending_publication_and_cleanup_claims_preserve_zero_mint_admission() {
    let schema = crate::persistence::test_postgres::TestSchema::create("issuer_pending").await;
    let store = schema.connect_store().await;
    let other = schema.connect_store().await;
    let (_issuer, source, minter) = issuer().await;
    let mut handoff = prepared(&store, &source).await;
    let mut provider = provider();
    provider.credential_handles = handoff.handles(&source).unwrap();
    handoff
        .publish(&other, &source, write(&provider))
        .await
        .unwrap();
    let current = StaticHandoff::load(&store, handoff.id())
        .await
        .unwrap()
        .unwrap();
    assert!(current.is_published());
    assert_eq!(
        source
            .refresh_statuses(&other, &provider, "TOKEN")
            .await
            .unwrap()[0]
            .status,
        "configured"
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
    StaticHandoff::delete_provider(
        &store,
        &source,
        provider.object_id(),
        1,
        std::slice::from_ref(&current),
    )
    .await
    .unwrap();
    let mut claimed = StaticHandoff::load(&other, current.id())
        .await
        .unwrap()
        .unwrap();
    claimed.abort(&other, &source).await.unwrap();
    assert!(
        store
            .get("provider", provider.object_id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.get(KIND, current.id()).await.unwrap().is_none());
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
    drop(other);
    drop(store);
    schema.drop_schema().await;
}
