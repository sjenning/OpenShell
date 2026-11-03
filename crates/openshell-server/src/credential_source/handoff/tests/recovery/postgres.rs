// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_recovery_discovers_and_cleans_another_replica_journal() {
    let schema = crate::persistence::test_postgres::TestSchema::create("issuer_recover").await;
    let first = schema.connect_store().await;
    let second = schema.connect_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let mut journal = StaticHandoff::begin(&first, &source, &provider(), &["TOKEN".into()], None)
        .await
        .unwrap();
    journal.reserve(&first, &source).await.unwrap();
    let page = StaticHandoff::list_page(&second, &source, "default", "provider-id", None, 1)
        .await
        .unwrap();
    assert_eq!(page.handoffs[0].id(), journal.id());
    let result = StaticHandoff::recover_page(&second, &source, None, 1, i64::MAX)
        .await
        .unwrap();
    assert_eq!(result.cleaned, 1);
    assert_eq!(result.failures, 0);
    assert!(
        StaticHandoff::load(&first, journal.id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        journal
            .fill(
                &first,
                &source,
                &HashMap::from([("TOKEN".into(), "late".into())]),
                &HashMap::new()
            )
            .await
            .is_err()
    );
    drop(second);
    drop(first);
    schema.drop_schema().await;
}
