// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, cancellation-safe local refresh coordination. Durable fencing and
//! recovery belong to the operation and must be checked after acquiring its
//! distributed lease, before contacting a minter.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tonic::Status;

#[derive(Debug, Clone, Copy)]
pub struct RefreshLimits {
    pub executors: usize,
    /// Includes queued and executing operations.
    pub admissions: usize,
    pub wait_timeout: Duration,
}

impl Default for RefreshLimits {
    fn default() -> Self {
        Self {
            executors: 4,
            admissions: 32,
            wait_timeout: Duration::from_secs(40),
        }
    }
}

/// Clones share locks and limits. Use one coordinator for both refresh and
/// maintenance mutations of the same grants; keys must identify immutable
/// grant ownership, not mutable provider display names.
#[derive(Debug, Clone)]
pub struct RefreshCoordinator {
    locks: Arc<Mutex<HashMap<String, Weak<AsyncMutex<()>>>>>,
    executors: Arc<Semaphore>,
    admissions: Arc<Semaphore>,
    admission_capacity: usize,
    finished: Arc<Notify>,
    wait_timeout: Duration,
}
struct Admission {
    permit: Option<OwnedSemaphorePermit>,
    finished: Arc<Notify>,
}
impl Drop for Admission {
    fn drop(&mut self) {
        // Publish permit release before waking every concurrent drain waiter.
        drop(self.permit.take());
        self.finished.notify_waiters();
    }
}

impl RefreshCoordinator {
    pub fn new(limits: RefreshLimits) -> Result<Self, Status> {
        if limits.executors == 0
            || limits.admissions < limits.executors
            || limits.admissions > Semaphore::MAX_PERMITS
            || limits.wait_timeout.is_zero()
        {
            return Err(Status::invalid_argument(
                "invalid credential refresh limits",
            ));
        }
        Ok(Self {
            locks: Arc::default(),
            executors: Arc::new(Semaphore::new(limits.executors)),
            admissions: Arc::new(Semaphore::new(limits.admissions)),
            admission_capacity: limits.admissions,
            finished: Arc::default(),
            wait_timeout: limits.wait_timeout,
        })
    }

    /// Permanently reject new work without interrupting queued or executing
    /// operations. Stop background schedulers before draining a service.
    pub fn stop_admission(&self) {
        self.admissions.close();
    }

    /// Await every admitted detached task, including disconnected callers.
    /// Canceling this wait never cancels their work. The process host chooses
    /// its shutdown deadline; a timeout does not prove an upstream failure.
    pub async fn drain(&self) {
        self.stop_admission();
        loop {
            let notified = self.finished.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.admissions.available_permits() == self.admission_capacity {
                return;
            }
            notified.await;
        }
    }

    /// Maintenance uses the same local exclusion without occupying an executor.
    /// Weak entries prevent retaining every grant ever refreshed.
    pub fn lock_for(&self, key: &str) -> Result<Arc<AsyncMutex<()>>, Status> {
        let mut locks = self
            .locks
            .lock()
            .map_err(|_| Status::internal("refresh coordination unavailable"))?;
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = locks
            .get(key)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| Arc::new(AsyncMutex::new(())));
        locks.insert(key.to_owned(), Arc::downgrade(&lock));
        Ok(lock)
    }

    /// Detach before polling the operation: a caller disconnect must not cancel
    /// an exchange after an upstream rotates irreplaceable refresh material.
    /// Only queue waits time out; never cancel an in-flight mint on this timer.
    pub async fn run<T, F>(&self, key: &str, operation: F) -> Result<T, Status>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, Status>> + Send + 'static,
    {
        let admission =
            self.admissions
                .clone()
                .try_acquire_owned()
                .map_err(|error| match error {
                    TryAcquireError::Closed => {
                        Status::unavailable("credential refresh is shutting down")
                    }
                    TryAcquireError::NoPermits => {
                        Status::resource_exhausted("credential refresh queue is full")
                    }
                })?;
        let admission = Admission {
            permit: Some(admission),
            finished: self.finished.clone(),
        };
        let lock = self.lock_for(key)?;
        let executors = self.executors.clone();
        let timeout = self.wait_timeout;
        tokio::spawn(async move {
            let _admission = admission;
            let _local = tokio::time::timeout(timeout, lock.lock_owned())
                .await
                .map_err(|_| Status::unavailable("credential refresh is busy"))?;
            let _executor = tokio::time::timeout(timeout, executors.acquire_owned())
                .await
                .map_err(|_| Status::resource_exhausted("credential refresh workers are busy"))?
                .map_err(|_| Status::unavailable("credential refresh workers stopped"))?;
            operation.await
        })
        .await
        .map_err(|_| Status::internal("credential refresh worker failed"))?
    }
}

impl Default for RefreshCoordinator {
    fn default() -> Self {
        Self::new(RefreshLimits::default()).expect("default refresh limits are valid")
    }
}

#[cfg(test)]
mod tests;
