// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use tokio_stream::StreamExt as _;
#[tokio::test]
async fn service_drain_closes_both_watches_but_publishes_disconnected_mint_before_returning() {
    let fixture = Fixture::new().await;
    let created = create(&fixture).await;
    let mut secrets = crate::service::watch::start(fixture.store.runtime.clone(), test_scope(A), 0)
        .await
        .unwrap();
    let mut grants = fixture
        .runtime()
        .watch_grants(test_scope(A), 0)
        .await
        .unwrap();
    fixture.minter.block.store(true, Ordering::SeqCst);
    let runtime = fixture.runtime();
    let grant = created.grant.clone();
    let caller = tokio::spawn(async move { runtime.ensure(test_scope(A), grant, 0).await });
    fixture.minter.started.notified().await;
    caller.abort();
    fixture.store.stop_admission();
    let store = fixture.store.clone();
    let drain = tokio::spawn(async move { store.drain().await });
    tokio::task::yield_now().await;
    assert!(!drain.is_finished());
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(frame) = secrets.next().await {
            frame.unwrap();
        }
        while let Some(frame) = grants.next().await {
            frame.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(
        crate::service::watch::start(fixture.store.runtime.clone(), test_scope(A), 0)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    assert_eq!(
        fixture
            .runtime()
            .watch_grants(test_scope(A), 0)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    assert_eq!(
        fixture
            .runtime()
            .ensure(test_scope(A), created.grant.clone(), 0)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    fixture.minter.release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), drain)
        .await
        .unwrap()
        .unwrap();
    let resolved = values(&fixture, &created).await;
    assert_eq!(resolved.secrets.len(), 2);
    assert!(resolved.secrets.iter().all(|secret| secret.version == 2));
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
    fixture.store.drain().await;
}
