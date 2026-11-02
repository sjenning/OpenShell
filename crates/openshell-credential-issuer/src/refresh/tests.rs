// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use tokio::sync::oneshot;
use tonic::Code;

fn coordinator(executors: usize, admissions: usize) -> RefreshCoordinator {
    RefreshCoordinator::new(RefreshLimits {
        executors,
        admissions,
        wait_timeout: Duration::from_secs(2),
    })
    .unwrap()
}

#[test]
fn invalid_limits_are_rejected() {
    for limits in [
        RefreshLimits {
            executors: 0,
            ..RefreshLimits::default()
        },
        RefreshLimits {
            executors: 2,
            admissions: 1,
            ..RefreshLimits::default()
        },
        RefreshLimits {
            admissions: Semaphore::MAX_PERMITS + 1,
            ..RefreshLimits::default()
        },
        RefreshLimits {
            wait_timeout: Duration::ZERO,
            ..RefreshLimits::default()
        },
    ] {
        assert_eq!(
            RefreshCoordinator::new(limits).unwrap_err().code(),
            Code::InvalidArgument
        );
    }
}

#[test]
fn grant_locks_are_shared_and_unused_entries_are_collected() {
    let coordinator = coordinator(1, 2);
    let first = coordinator.lock_for("grant-a").unwrap();
    let same = coordinator.lock_for("grant-a").unwrap();
    assert!(Arc::ptr_eq(&first, &same));
    assert!(!Arc::ptr_eq(
        &first,
        &coordinator.lock_for("grant-b").unwrap()
    ));
    drop(first);
    drop(same);
    let _other = coordinator.lock_for("grant-c").unwrap();
    assert_eq!(coordinator.locks.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn caller_cancellation_does_not_cancel_refresh_or_release_its_lock() {
    let coordinator = coordinator(1, 2);
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let (finished_tx, finished_rx) = oneshot::channel();
    let runner = coordinator.clone();
    let caller = tokio::spawn(async move {
        runner
            .run("grant", async move {
                started_tx.send(()).unwrap();
                release_rx.await.unwrap();
                finished_tx.send(()).unwrap();
                Ok(())
            })
            .await
    });
    started_rx.await.unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    let lock = coordinator.lock_for("grant").unwrap();
    assert!(lock.try_lock().is_err());
    assert_eq!(coordinator.admissions.available_permits(), 1);
    release_tx.send(()).unwrap();
    finished_rx.await.unwrap();
    assert_eq!(
        coordinator.run("grant", async { Ok(42) }).await.unwrap(),
        42
    );
    assert_eq!(coordinator.admissions.available_permits(), 2);
}

#[tokio::test]
async fn bounded_admission_counts_both_active_and_queued_operations() {
    let coordinator = coordinator(1, 2);
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let runner = coordinator.clone();
    let first = tokio::spawn(async move {
        runner
            .run("first", async move {
                started_tx.send(()).unwrap();
                release_rx.await.unwrap();
                Ok(())
            })
            .await
    });
    started_rx.await.unwrap();
    let runner = coordinator.clone();
    let second = tokio::spawn(async move { runner.run("second", async { Ok(()) }).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while coordinator.admissions.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(coordinator.executors.available_permits(), 0);
    let error = coordinator
        .run::<(), _>("third", async { panic!("rejected work must not run") })
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
    release_tx.send(()).unwrap();
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();
    assert_eq!(coordinator.admissions.available_permits(), 2);
}

#[tokio::test]
async fn same_grant_waiters_do_not_consume_executors() {
    let coordinator = coordinator(2, 3);
    let lock = coordinator.lock_for("grant").unwrap();
    let held = lock.lock_owned().await;
    let runner = coordinator.clone();
    let waiter = tokio::spawn(async move { runner.run("grant", async { Ok(()) }).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while coordinator.admissions.available_permits() == 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(coordinator.executors.available_permits(), 2);
    coordinator
        .run("independent", async { Ok(()) })
        .await
        .unwrap();
    drop(held);
    waiter.await.unwrap().unwrap();
}

#[tokio::test]
async fn queue_timeout_never_polls_operation_and_releases_admission() {
    let coordinator = RefreshCoordinator::new(RefreshLimits {
        executors: 1,
        admissions: 1,
        wait_timeout: Duration::from_millis(5),
    })
    .unwrap();
    let lock = coordinator.lock_for("grant").unwrap();
    let _held = lock.lock_owned().await;
    let error = coordinator
        .run::<(), _>("grant", async { panic!("timed-out work must not run") })
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(coordinator.admissions.available_permits(), 1);
}

#[tokio::test]
async fn executor_timeout_does_not_cancel_an_in_flight_mint() {
    let coordinator = RefreshCoordinator::new(RefreshLimits {
        executors: 1,
        admissions: 2,
        wait_timeout: Duration::from_millis(5),
    })
    .unwrap();
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let runner = coordinator.clone();
    let first = tokio::spawn(async move {
        runner
            .run("active", async move {
                started_tx.send(()).unwrap();
                release_rx.await.unwrap();
                Ok(())
            })
            .await
    });
    started_rx.await.unwrap();
    let error = coordinator
        .run::<(), _>("queued", async {
            panic!("executor timeout must not poll queued work")
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
    assert!(!first.is_finished());
    release_tx.send(()).unwrap();
    first.await.unwrap().unwrap();
    assert_eq!(coordinator.admissions.available_permits(), 2);
}

#[tokio::test]
async fn operation_errors_and_panics_release_coordination() {
    let coordinator = coordinator(1, 1);
    let error = coordinator
        .run("grant", async { Err::<(), _>(Status::aborted("fenced")) })
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Aborted);
    let error = coordinator
        .run::<(), _>("grant", async { panic!("simulated worker panic") })
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Internal);
    coordinator.run("grant", async { Ok(()) }).await.unwrap();
}
