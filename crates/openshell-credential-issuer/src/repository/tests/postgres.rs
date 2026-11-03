// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use tokio::time::timeout;

async fn replicas() -> (ScopedRepository, ScopedRepository) {
    let url = std::env::var("OPENSHELL_TEST_ISSUER_POSTGRES_URL")
        .expect("set a disposable OPENSHELL_TEST_ISSUER_POSTGRES_URL");
    let scope = test_scope(&format!("pg-{}", uuid::Uuid::new_v4()));
    let (a, b) = tokio::join!(Repository::open(&url), Repository::open(&url));
    (
        a.unwrap().for_gateway(&scope),
        b.unwrap().for_gateway(&scope),
    )
}

#[tokio::test]
#[ignore = "requires a disposable OPENSHELL_TEST_ISSUER_POSTGRES_URL"]
async fn postgres_replicas_fence_multi_output_publication_and_preserve_events() {
    let (a, b) = replicas().await;
    a.commit(
        &[put("a", None, "old-a"), put("b", None, "old-b")],
        &[change("a", 1), change("b", 1)],
    )
    .await
    .unwrap();
    let a_mutations = [
        put("a", Some(1), "replica-a"),
        put("b", Some(1), "replica-a"),
    ];
    let b_mutations = [
        put("b", Some(1), "replica-b"),
        put("a", Some(1), "replica-b"),
    ];
    let changes = [change("a", 2), change("b", 2)];
    let (ra, rb) = tokio::join!(
        a.commit(&a_mutations, &changes),
        b.commit(&b_mutations, &changes)
    );
    assert_ne!(ra.is_ok(), rb.is_ok());
    let error = if let Err(error) = ra {
        error
    } else {
        rb.unwrap_err()
    };
    assert_eq!(error.code(), Code::Aborted);
    let first = a.load("reference", "a").await.unwrap().unwrap();
    let second = b.load("reference", "b").await.unwrap().unwrap();
    assert_eq!(first.revision, 2);
    assert_eq!(second.revision, 2);
    assert_eq!(first.payload, second.payload);
    let events = b.events_after(0, 10).await.unwrap();
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    assert_eq!(events[3].change.version, 2);
}

#[tokio::test]
#[ignore = "requires a disposable OPENSHELL_TEST_ISSUER_POSTGRES_URL"]
async fn postgres_leases_exclude_replicas_and_release_on_cancellation_and_drop() {
    let (a, b) = replicas().await;
    let first = a.acquire_refresh_lease("grant").await.unwrap();
    assert!(
        timeout(Duration::from_millis(100), b.acquire_refresh_lease("grant"))
            .await
            .is_err()
    );
    let unrelated = timeout(
        Duration::from_secs(2),
        b.acquire_refresh_lease("other-grant"),
    )
    .await
    .unwrap()
    .unwrap();
    drop(unrelated);
    // Pending lock waiters cannot starve writes: data and lease pools differ.
    timeout(
        Duration::from_secs(2),
        b.commit(&[put("while-leased", None, "ok")], &[]),
    )
    .await
    .unwrap()
    .unwrap();
    drop(first);
    let next = timeout(Duration::from_secs(3), b.acquire_refresh_lease("grant"))
        .await
        .unwrap()
        .unwrap();
    drop(next);
    timeout(Duration::from_secs(3), a.acquire_refresh_lease("grant"))
        .await
        .unwrap()
        .unwrap();
}
