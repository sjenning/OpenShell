// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_grant_publication_and_retirement_claims_are_atomic_across_connections() {
    let schema = crate::persistence::test_postgres::TestSchema::create("issuer_grant").await;
    let store = schema.connect_store().await;
    let other = schema.connect_store().await;
    let (issuer, source, minter) = issuer().await;
    let (old, mut provider) = published(&store, &source).await;
    let old_id = old.grant_id().unwrap().to_owned();
    let mut replacement = StaticHandoff::begin_grant(&other, &source, &provider, plan(), Some(1))
        .await
        .unwrap();
    replacement.reserve(&other, &source).await.unwrap();
    fill(&mut replacement, &other, &source).await.unwrap();
    provider.credential_handles = replacement.handles(&source).unwrap();
    let write = AtomicWrite::Update {
        object_type: "provider".into(),
        id: provider.object_id().into(),
        payload: provider.encode_to_vec(),
        expected_version: 1,
    };
    let mut stale = old.clone();
    stale.revision += 1;
    assert_eq!(
        replacement
            .publish_replacing(&other, &source, write.clone(), &[stale])
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    assert!(
        StaticHandoff::load(&store, old.id())
            .await
            .unwrap()
            .unwrap()
            .is_published()
    );
    assert_eq!(
        StaticHandoff::load(&store, replacement.id())
            .await
            .unwrap()
            .unwrap()
            .state
            .phase,
        Phase::Ready
    );
    assert_eq!(
        store
            .get("provider", provider.object_id())
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        1
    );
    replacement
        .publish_replacing(&other, &source, write, std::slice::from_ref(&old))
        .await
        .unwrap();
    let mut retired = StaticHandoff::load(&store, old.id())
        .await
        .unwrap()
        .unwrap();
    retired.abort(&store, &source).await.unwrap();
    assert_eq!(
        issuer
            .raw
            .get_grant(refresh::GetGrantRequest { grant: old_id })
            .await
            .unwrap()
            .status
            .unwrap()
            .state,
        "deleting"
    );
    StaticHandoff::delete_provider(
        &store,
        &source,
        provider.object_id(),
        2,
        std::slice::from_ref(&replacement),
    )
    .await
    .unwrap();
    assert!(
        other
            .get("provider", provider.object_id())
            .await
            .unwrap()
            .is_none()
    );
    let mut retired = StaticHandoff::load(&other, replacement.id())
        .await
        .unwrap()
        .unwrap();
    retired.abort(&other, &source).await.unwrap();
    assert_eq!(minter.calls.load(Ordering::SeqCst), 2);
    drop(other);
    drop(store);
    schema.drop_schema().await;
}
