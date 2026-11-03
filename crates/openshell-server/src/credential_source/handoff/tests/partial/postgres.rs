// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_partial_retirement_keeps_active_siblings_across_replicas() {
    let schema = crate::persistence::test_postgres::TestSchema::create("issuer_partial").await;
    let first = schema.connect_store().await;
    let second = schema.connect_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let (old, mut provider) = two_keys(&first, &source).await;
    provider.credential_handles.remove("FIRST");
    StaticHandoff::update_preserving(&second, &source, &provider, 1, std::slice::from_ref(&old))
        .await
        .unwrap();
    let result = StaticHandoff::recover_page(&first, &source, None, 128, i64::MIN)
        .await
        .unwrap();
    assert_eq!(result.cleaned, 1);
    assert!(metadata(&issuer, &old, "FIRST").await.is_err());
    assert!(metadata(&issuer, &old, "SECOND").await.is_ok());
    let remaining = StaticHandoff::load(&second, old.id())
        .await
        .unwrap()
        .unwrap();
    assert!(remaining.is_published());
    assert_eq!(remaining.state.slots.len(), 1);
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
    drop(second);
    drop(first);
    schema.drop_schema().await;
}
