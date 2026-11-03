// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
#[tokio::test]
async fn drain_rejects_new_work_but_retains_disconnected_admitted_exchanges() {
    let coordinator = coordinator(1, 1);
    let (started, ready) = oneshot::channel();
    let (release, resume) = oneshot::channel();
    let copy = coordinator.clone();
    let caller = tokio::spawn(async move {
        copy.run("grant", async move {
            started.send(()).unwrap();
            resume.await.unwrap();
            Ok(())
        })
        .await
    });
    ready.await.unwrap();
    caller.abort();
    coordinator.stop_admission();
    let a = coordinator.clone();
    let first = tokio::spawn(async move { a.drain().await });
    let b = coordinator.clone();
    let second = tokio::spawn(async move { b.drain().await });
    tokio::task::yield_now().await;
    assert!(!first.is_finished());
    assert!(!second.is_finished());
    assert_eq!(
        coordinator
            .run::<(), _>(
                "new",
                std::future::poll_fn(|_| panic!("rejected work was polled"))
            )
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        first.await.unwrap();
        second.await.unwrap();
    })
    .await
    .unwrap();
    coordinator.drain().await;
}
#[tokio::test]
async fn canceled_drain_does_not_cancel_an_exchange_and_can_be_awaited_again() {
    let coordinator = coordinator(1, 1);
    let (started, ready) = oneshot::channel();
    let (release, resume) = oneshot::channel();
    let copy = coordinator.clone();
    let caller = tokio::spawn(async move {
        copy.run("grant", async move {
            started.send(()).unwrap();
            resume.await.unwrap();
            Ok(())
        })
        .await
    });
    ready.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), coordinator.drain())
            .await
            .is_err()
    );
    assert!(!caller.is_finished());
    release.send(()).unwrap();
    caller.await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(1), coordinator.drain())
        .await
        .unwrap();
}
#[tokio::test]
async fn drain_waits_for_queued_work_and_panic_releases_its_admission() {
    let coordinator = coordinator(1, 2);
    let (started, ready) = oneshot::channel();
    let (release, resume) = oneshot::channel();
    let copy = coordinator.clone();
    let caller = tokio::spawn(async move {
        copy.run::<(), _>("first", async move {
            started.send(()).unwrap();
            resume.await.unwrap();
            panic!("test worker panic");
        })
        .await
    });
    ready.await.unwrap();
    let copy = coordinator.clone();
    let queued = tokio::spawn(async move { copy.run("second", async { Ok(42) }).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while coordinator.admissions.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    coordinator.stop_admission();
    let copy = coordinator.clone();
    let drain = tokio::spawn(async move { copy.drain().await });
    tokio::task::yield_now().await;
    assert!(!drain.is_finished());
    release.send(()).unwrap();
    assert_eq!(caller.await.unwrap().unwrap_err().code(), Code::Internal);
    assert_eq!(queued.await.unwrap().unwrap(), 42);
    tokio::time::timeout(Duration::from_secs(1), drain)
        .await
        .unwrap()
        .unwrap();
}
