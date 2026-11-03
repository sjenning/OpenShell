// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_replacement_and_deletion_keep_retirement_claims_atomic() {
    let schema = crate::persistence::test_postgres::TestSchema::create("issuer_retire").await;
    let store = schema.connect_store().await;
    let other = schema.connect_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let (old, provider) = published(&store, &source).await;
    let (mut new, write) = replacement(&other, &source, &provider).await;
    let mut stale = old.clone();
    stale.revision += 1;
    assert_eq!(
        new.publish_replacing(&other, &source, write.clone(), &[stale])
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
        StaticHandoff::load(&store, new.id())
            .await
            .unwrap()
            .unwrap()
            .state
            .phase,
        Phase::Ready
    );
    new.publish_replacing(&other, &source, write, std::slice::from_ref(&old))
        .await
        .unwrap();
    let mut retired = StaticHandoff::load(&store, old.id())
        .await
        .unwrap()
        .unwrap();
    retired.abort(&store, &source).await.unwrap();
    assert!(inspect(&issuer, &old).await.is_err());
    assert!(inspect(&issuer, &new).await.is_ok());
    StaticHandoff::delete_provider(
        &store,
        &source,
        provider.object_id(),
        2,
        std::slice::from_ref(&new),
    )
    .await
    .unwrap();
    assert!(
        other
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .is_none()
    );
    let mut retired = StaticHandoff::load(&other, new.id())
        .await
        .unwrap()
        .unwrap();
    retired.abort(&other, &source).await.unwrap();
    assert!(inspect(&issuer, &new).await.is_err());
    drop(other);
    drop(store);
    schema.drop_schema().await;
}
