// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Bounded metadata discovery and cancellation-safe ownership recovery.
use super::{KIND, Phase, RemoteProviderSource, StaticHandoff, Store, invalid, storage};
use crate::persistence::{ObjectCursor, ObjectListQuery};
use openshell_core::{ObjectId as _, ObjectWorkspace as _, proto::Provider};
use std::{sync::Arc, time::Duration};
use tonic::{Code, Status};
/// A filtered page retains the raw scan cursor even when no matching rows remain.
#[derive(Debug)]
pub struct HandoffPage {
    pub handoffs: Vec<StaticHandoff>,
    pub next_cursor: Option<ObjectCursor>,
}
#[derive(Debug, Default)]
pub struct RecoveryPage {
    pub scanned: usize,
    pub cleaned: usize,
    pub conflicts: usize,
    pub failures: usize,
    pub next_cursor: Option<ObjectCursor>,
}
/// Dropping the worker cancels scanning, not issuer-admitted work. Every
/// uncertain cleanup remains owned by its persisted Aborting journal.
#[derive(Debug)]
pub struct HandoffReconciler(tokio::task::JoinHandle<()>);
impl Drop for HandoffReconciler {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl StaticHandoff {
    /// Trusted gateway discovery, not a public authorization endpoint. Returned
    /// records are still checked against immutable source/workspace/provider IDs.
    pub async fn list_page(
        store: &Store,
        source: &RemoteProviderSource,
        workspace: &str,
        provider_id: &str,
        after: Option<&ObjectCursor>,
        limit: u32,
    ) -> Result<HandoffPage, Status> {
        if !(1..=128).contains(&limit) {
            return Err(invalid());
        }
        let page = store
            .list_object_page(KIND, ObjectListQuery::Workspace(workspace), after, limit)
            .await
            .map_err(storage)?;
        let mut handoffs = Vec::new();
        for row in page.records {
            let handoff = Self::from_record(row)?;
            if handoff.state.source == source.name.as_ref()
                && handoff.state.provider_id == provider_id
            {
                handoffs.push(handoff);
            }
        }
        Ok(HandoffPage {
            handoffs,
            next_cursor: page.next_cursor,
        })
    }
    /// Collect only live ownership for one current provider. Retiring records
    /// remain discoverable by the recovery scanner, not mutation publication.
    pub async fn published_for_provider(
        store: &Store,
        source: &RemoteProviderSource,
        provider: &Provider,
    ) -> Result<Vec<Self>, Status> {
        let mut cursor = None;
        let mut owned = Vec::new();
        loop {
            let page = Self::list_page(
                store,
                source,
                provider.object_workspace(),
                provider.object_id(),
                cursor.as_ref(),
                128,
            )
            .await?;
            owned.extend(page.handoffs.into_iter().filter(Self::is_published));
            if owned.len() > 64 {
                return Err(Status::resource_exhausted(
                    "too many issuer ownership journals",
                ));
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(owned)
    }
    /// Recover one raw keyset page. Failed rows retain ownership and do not block
    /// unrelated rows. Never reclaim Published rows, even if their parent is gone.
    /// `idle_before_ms` is a trusted cutoff, not supplied by a public request.
    pub async fn recover_page(
        store: &Store,
        source: &RemoteProviderSource,
        after: Option<&ObjectCursor>,
        limit: u32,
        idle_before_ms: i64,
    ) -> Result<RecoveryPage, Status> {
        if !(1..=128).contains(&limit) {
            return Err(invalid());
        }
        let page = store
            .list_object_page(KIND, ObjectListQuery::AllWorkspaces, after, limit)
            .await
            .map_err(storage)?;
        let mut result = RecoveryPage {
            scanned: page.records.len(),
            next_cursor: page.next_cursor,
            ..Default::default()
        };
        for row in page.records {
            let updated = row.updated_at_ms;
            let Ok(mut handoff) = Self::from_record(row) else {
                result.failures += 1;
                continue;
            };
            if handoff.state.source != source.name.as_ref()
                || handoff.state.phase == Phase::Published
                || (handoff.state.phase != Phase::Aborting && updated > idle_before_ms)
            {
                continue;
            }
            match handoff.abort(store, source).await {
                Ok(()) => result.cleaned += 1,
                Err(error) if error.code() == Code::Aborted => result.conflicts += 1,
                Err(_) => result.failures += 1,
            }
        }
        Ok(result)
    }
    /// Start bounded scans with a conservative idle cutoff. Journal revision
    /// claims, rather than elapsed time, fence a still-running late publisher.
    pub fn spawn_reconciler(
        store: Arc<Store>,
        source: RemoteProviderSource,
        idle_timeout: Duration,
    ) -> Result<HandoffReconciler, Status> {
        if idle_timeout < Duration::from_mins(1) || idle_timeout > Duration::from_hours(1) {
            return Err(invalid());
        }
        let idle_ms = i64::try_from(idle_timeout.as_millis()).map_err(|_| invalid())?;
        Ok(HandoffReconciler(tokio::spawn(async move {
            let mut cursor = None;
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let cutoff = crate::persistence::current_time_ms().saturating_sub(idle_ms);
                if let Ok(page) =
                    Self::recover_page(&store, &source, cursor.as_ref(), 32, cutoff).await
                {
                    if page.failures > 0 {
                        tracing::warn!(
                            failures = page.failures,
                            "issuer handoff cleanup remains pending"
                        );
                    }
                    cursor = page.next_cursor;
                } else {
                    tracing::warn!("issuer handoff recovery scan failed");
                    cursor = None;
                }
            }
        })))
    }
}
