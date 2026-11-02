// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Issuer scheduling policy and periodic sweep driver. Durable adapters still
//! reload and fence live state under the refresh lease before an upstream call.

use crate::engine::RefreshTrigger;
use crate::minter::{RecoveryAction, RetrySchedule};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tonic::Status;

/// Non-secret scheduling projection of a durable grant, not an authorization
/// decision. In particular, candidate selection never substitutes for `prepare`.
#[derive(Debug, Clone, Copy)]
pub struct GrantSchedule {
    pub next_refresh_at_ms: i64,
    pub recovery_action: Option<RecoveryAction>,
    pub rotation_requested: bool,
    pub deleting: bool,
    pub pending_cleanup: bool,
}

impl GrantSchedule {
    #[must_use]
    pub const fn due(self, now_ms: i64) -> bool {
        self.next_refresh_at_ms <= 0 || self.next_refresh_at_ms <= now_ms
    }

    #[must_use]
    pub const fn has_work(self, now_ms: i64) -> bool {
        self.deleting || self.pending_cleanup || self.due(now_ms) || self.rotation_requested
    }

    #[must_use]
    pub const fn trigger(self, now_ms: i64) -> Option<RefreshTrigger> {
        if self.deleting {
            None
        } else if self.rotation_requested {
            Some(RefreshTrigger::ExplicitRotation)
        } else if self.due(now_ms) {
            Some(RefreshTrigger::Automatic)
        } else {
            None
        }
    }

    /// Call on the freshly reloaded grant under the distributed lease. Manual
    /// rotations are separate requests; automatic callers must honor backoff.
    pub fn ensure_automatic_ready(self, now_ms: i64) -> Result<(), Status> {
        if self.recovery_action == Some(RecoveryAction::Reauthorize) {
            return Err(Status::failed_precondition(
                "credential refresh requires recovery",
            ));
        }
        if self.recovery_action.is_some() && self.next_refresh_at_ms > now_ms {
            return Err(Status::unavailable(
                "credential refresh is in retry backoff",
            ));
        }
        Ok(())
    }
}

/// Round only at the millisecond persistence boundary; a positive fractional
/// millisecond lead time must not collapse into the absent/default sentinel.
#[must_use]
pub fn next_refresh_at_ms(expires_at_ms: i64, refresh_before: Option<Duration>) -> i64 {
    if expires_at_ms <= 0 {
        return 0;
    }
    let before = refresh_before.unwrap_or(Duration::from_mins(5));
    let ms = before
        .as_millis()
        .saturating_add(u128::from(!before.subsec_nanos().is_multiple_of(1_000_000)));
    expires_at_ms.saturating_sub(i64::try_from(ms).unwrap_or(i64::MAX))
}

#[must_use]
pub const fn retry_at_ms(now_ms: i64, schedule: RetrySchedule) -> i64 {
    match schedule {
        RetrySchedule::Short => now_ms.saturating_add(60_000),
        RetrySchedule::Configuration => now_ms.saturating_add(3_600_000),
        RetrySchedule::Parked => i64::MAX,
    }
}

/// Enumerate durable grants, perform maintenance, and refresh candidates through
/// the shared engine. The adapter owns persistence and post-commit invalidation.
#[async_trait]
pub trait RefreshSweep: Send + Sync + 'static {
    async fn sweep(&self) -> Result<(), Status>;
}

/// Immediate first sweep, no overlapping sweeps, delayed missed ticks, and
/// continued polling after an error. Aborting the driver does not cancel mints
/// already detached by `RefreshEngine`.
pub fn spawn(
    sweep: Arc<dyn RefreshSweep>,
    interval: Duration,
) -> Result<tokio::task::JoinHandle<()>, Status> {
    if interval.is_zero() {
        return Err(Status::invalid_argument(
            "refresh interval must be positive",
        ));
    }
    Ok(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(error) = sweep.sweep().await {
                tracing::warn!(error = %error, "credential refresh worker tick failed");
            }
        }
    }))
}

#[cfg(test)]
mod tests;
