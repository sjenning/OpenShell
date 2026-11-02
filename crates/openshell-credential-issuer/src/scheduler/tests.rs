// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn schedule(deadline: i64) -> GrantSchedule {
    GrantSchedule {
        next_refresh_at_ms: deadline,
        recovery_action: None,
        rotation_requested: false,
        deleting: false,
        pending_cleanup: false,
    }
}

#[test]
fn candidate_deadlines_include_absent_and_exact_deadlines() {
    for deadline in [-1, 0, 99, 100] {
        assert!(schedule(deadline).due(100));
        assert_eq!(
            schedule(deadline).trigger(100),
            Some(RefreshTrigger::Automatic)
        );
    }
    assert!(!schedule(101).has_work(100));
    assert_eq!(schedule(101).trigger(100), None);
}

#[test]
fn explicit_rotation_bypasses_the_snapshot_deadline_not_durable_authorization_checks() {
    let mut state = schedule(i64::MAX);
    state.rotation_requested = true;
    assert!(state.has_work(100));
    assert_eq!(state.trigger(100), Some(RefreshTrigger::ExplicitRotation));
}

#[test]
fn maintenance_is_not_delayed_by_a_parked_mint() {
    let mut state = schedule(i64::MAX);
    state.pending_cleanup = true;
    assert!(state.has_work(100));
    assert_eq!(state.trigger(100), None);
    state.deleting = true;
    state.rotation_requested = true;
    assert!(state.has_work(100));
    assert_eq!(state.trigger(100), None);
}

#[test]
fn reauthorization_remains_blocked_even_with_an_expired_backoff() {
    for deadline in [0, 99, 101, i64::MAX] {
        let mut state = schedule(deadline);
        state.recovery_action = Some(RecoveryAction::Reauthorize);
        assert_eq!(
            state.ensure_automatic_ready(100).unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
    }
}

#[test]
fn all_other_recovery_actions_honor_live_retry_deadlines() {
    for action in [
        RecoveryAction::Retry,
        RecoveryAction::FixConfiguration,
        RecoveryAction::Investigate,
    ] {
        let mut state = schedule(101);
        state.recovery_action = Some(action);
        assert_eq!(
            state.ensure_automatic_ready(100).unwrap_err().code(),
            tonic::Code::Unavailable
        );
        state.ensure_automatic_ready(101).unwrap();
    }
    // Existing healthy values may be refreshed on demand before their deadline.
    schedule(i64::MAX).ensure_automatic_ready(100).unwrap();
}

#[test]
fn profile_lead_time_preserves_fractional_milliseconds_and_defaults() {
    assert_eq!(next_refresh_at_ms(1_000_000, None), 700_000);
    assert_eq!(
        next_refresh_at_ms(1_000_000, Some(Duration::ZERO)),
        1_000_000
    );
    assert_eq!(
        next_refresh_at_ms(10_000, Some(Duration::from_millis(500))),
        9_500
    );
    assert_eq!(
        next_refresh_at_ms(10_000, Some(Duration::from_nanos(1))),
        9_999
    );
    assert_eq!(next_refresh_at_ms(0, None), 0);
    assert_eq!(next_refresh_at_ms(-1, None), 0);
}

#[test]
fn deadlines_saturate_instead_of_wrapping() {
    assert_eq!(next_refresh_at_ms(1, Some(Duration::MAX)), 1 - i64::MAX);
    assert_eq!(retry_at_ms(100, RetrySchedule::Short), 60_100);
    assert_eq!(retry_at_ms(100, RetrySchedule::Configuration), 3_600_100);
    for retry in [
        RetrySchedule::Short,
        RetrySchedule::Configuration,
        RetrySchedule::Parked,
    ] {
        assert_eq!(retry_at_ms(i64::MAX - 1, retry), i64::MAX);
    }
}

struct Sweep {
    count: AtomicUsize,
    slow_first: bool,
}

#[async_trait]
impl RefreshSweep for Sweep {
    async fn sweep(&self) -> Result<(), Status> {
        let count = self.count.fetch_add(1, Ordering::SeqCst);
        if count == 0 {
            if self.slow_first {
                tokio::time::sleep(Duration::from_mins(1)).await;
            }
            return Err(Status::unavailable("transient sweep failure"));
        }
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn driver_sweeps_immediately_retries_errors_and_can_be_stopped() {
    let sweep = Arc::new(Sweep {
        count: AtomicUsize::new(0),
        slow_first: false,
    });
    let task = spawn(sweep.clone(), Duration::from_secs(10)).unwrap();
    tokio::task::yield_now().await;
    assert_eq!(sweep.count.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(10)).await;
    tokio::task::yield_now().await;
    assert_eq!(sweep.count.load(Ordering::SeqCst), 2);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(sweep.count.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn slow_sweeps_do_not_overlap_or_burst_to_catch_up() {
    let sweep = Arc::new(Sweep {
        count: AtomicUsize::new(0),
        slow_first: true,
    });
    let task = spawn(sweep.clone(), Duration::from_secs(10)).unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(59)).await;
    tokio::task::yield_now().await;
    assert_eq!(sweep.count.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(sweep.count.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_secs(9)).await;
    tokio::task::yield_now().await;
    assert_eq!(sweep.count.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(sweep.count.load(Ordering::SeqCst), 3);
    task.abort();
}

#[tokio::test]
async fn zero_interval_is_rejected_without_starting_a_worker() {
    let sweep = Arc::new(Sweep {
        count: AtomicUsize::new(0),
        slow_first: false,
    });
    let result = spawn(sweep.clone(), Duration::ZERO);
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    assert_eq!(sweep.count.load(Ordering::SeqCst), 0);
}
