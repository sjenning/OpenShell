// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Refresh orchestration independent of gateway persistence and provider records.

use std::sync::Arc;

use async_trait::async_trait;
use tonic::Status;

use crate::minter::{
    MintFailure, MintRequest, MintResponse, MinterRegistry, RecoveryAction, RetrySchedule,
};
use crate::refresh::RefreshCoordinator;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTrigger {
    Automatic,
    ExplicitRotation,
}

pub enum Preparation<S, A> {
    /// A completed mint already satisfies the caller's observed generation.
    Current(S),
    Ready(A),
}

/// Durable adapter contract. Every mutation must fence immutable grant identity,
/// authorization epoch, and storage revision, including after lease loss.
#[async_trait]
pub trait RefreshStateStore: Send + Sync + 'static {
    type Snapshot: Send + Sync + 'static;
    type Attempt: Send + Sync + 'static;
    type Lease: Send;

    fn coordination_key(&self, observed: &Self::Snapshot) -> String;
    async fn acquire_lease(&self, observed: &Self::Snapshot) -> Result<Self::Lease, Status>;

    /// Reload under the lease; recheck deletion, authorization, coalescing and
    /// live retry eligibility. Before returning Ready, durably record uncertainty
    /// and the engine-supplied attempt ID. Return that exact ID from `mint_request`
    /// and use it as the completion receipt. Never reuse a grant with an unresolved exchange.
    async fn prepare(
        &self,
        observed: Self::Snapshot,
        trigger: RefreshTrigger,
        attempt_id: &str,
    ) -> Result<Preparation<Self::Snapshot, Self::Attempt>, Status>;

    /// Resolve only this attempt's material, after its uncertainty marker commits.
    async fn mint_request(&self, attempt: &Self::Attempt) -> Result<MintRequest, MintFailure>;

    /// Stage rotated material before outputs, fence publication, and return only
    /// after its completed-mint receipt commits. This method owns recovery for
    /// partial publication; the engine must not flatten it into a mint failure.
    async fn commit(
        &self,
        attempt: Self::Attempt,
        response: MintResponse,
    ) -> Result<Self::Snapshot, Status>;

    async fn record_failure(
        &self,
        attempt: &Self::Attempt,
        failure: MintFailure,
    ) -> Result<(), Status>;
}

/// Post-commit invalidation, never delivery of values.
///
/// Implementations should be nonblocking and tolerate duplicate notifications.
/// Durable replay is a separate persistence concern, not supplied by this callback.
#[async_trait]
pub trait RefreshSink<S>: Send + Sync + 'static {
    async fn committed(&self, snapshot: &S);
}

pub struct RefreshEngine<S: RefreshStateStore> {
    store: Arc<S>,
    minters: Arc<MinterRegistry>,
    sink: Arc<dyn RefreshSink<S::Snapshot>>,
    coordinator: RefreshCoordinator,
}

impl<S: RefreshStateStore> RefreshEngine<S> {
    #[must_use]
    pub fn new(
        store: Arc<S>,
        minters: Arc<MinterRegistry>,
        sink: Arc<dyn RefreshSink<S::Snapshot>>,
        coordinator: RefreshCoordinator,
    ) -> Self {
        Self {
            store,
            minters,
            sink,
            coordinator,
        }
    }

    pub async fn refresh(
        &self,
        observed: S::Snapshot,
        trigger: RefreshTrigger,
    ) -> Result<S::Snapshot, Status> {
        let key = self.store.coordination_key(&observed);
        let store = self.store.clone();
        let minters = self.minters.clone();
        let sink = self.sink.clone();
        self.coordinator
            .run(
                &key,
                Box::pin(async move {
                    let _lease = store.acquire_lease(&observed).await?;
                    let attempt_id = uuid::Uuid::new_v4().to_string();
                    let attempt = match store.prepare(observed, trigger, &attempt_id).await? {
                        Preparation::Current(snapshot) => return Ok(snapshot),
                        Preparation::Ready(attempt) => attempt,
                    };
                    let result = match store.mint_request(&attempt).await {
                        Ok(request) if request.attempt_id == attempt_id => {
                            minters.mint(request).await
                        }
                        Ok(_) => Err(MintFailure {
                            status: Status::failed_precondition(
                                "credential refresh attempt does not match its durable preparation",
                            ),
                            recovery_action: RecoveryAction::Investigate,
                            failure_code: "refresh_attempt_mismatch",
                            provider_error_subtype: None,
                            retry_schedule: RetrySchedule::Parked,
                        }),
                        Err(failure) => Err(failure),
                    };
                    let response = match result {
                        Ok(response) => response,
                        Err(failure) => {
                            let status = failure.status.clone();
                            store.record_failure(&attempt, failure).await?;
                            return Err(status);
                        }
                    };
                    let snapshot = store.commit(attempt, response).await?;
                    sink.committed(&snapshot).await;
                    Ok(snapshot)
                }),
            )
            .await
    }
}

#[cfg(test)]
mod tests;
