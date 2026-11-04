// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Bounded, durable cancellation of unpublished internal credential operations.
use super::super::owner;
use super::{Intent, KIND, Phase, reservation_key};
use crate::{
    credential_source::{RemoteProviderSource, invalid, wire},
    persistence::{ObjectCursor, ObjectListQuery},
};
use std::{collections::HashMap, time::Duration};
use tonic::{Code, Status};

#[derive(Debug, Default)]
pub struct RecoveryPage {
    pub scanned: usize,
    pub cleaned: usize,
    pub conflicts: usize,
    pub failures: usize,
    /// Old, unfenced journals are deliberately not collected by timeout alone.
    pub legacy_retained: usize,
    pub next_cursor: Option<ObjectCursor>,
}
/// Keep this guard alongside the gateway's other issuer worker guards.
#[derive(Debug)]
pub struct InternalReconciler(tokio::task::JoinHandle<()>);
impl Drop for InternalReconciler {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl RemoteProviderSource {
    /// Start ONLY after SSH and supervisor publication both include
    /// `internal_publication_writes` in their native final transaction.
    /// Age selects candidates; the durable Closing CAS, not age or assumed
    /// process death, is what revokes their publication authority.
    pub(crate) fn spawn_internal_reconciler(
        &self,
        idle_timeout: Duration,
    ) -> Result<InternalReconciler, Status> {
        if idle_timeout < Duration::from_mins(1)
            || idle_timeout > Duration::from_hours(1)
            || self.gateway.is_none()
        {
            return Err(invalid());
        }
        let source = self.clone();
        let idle_ms = i64::try_from(idle_timeout.as_millis()).map_err(|_| invalid())?;
        Ok(InternalReconciler(tokio::spawn(async move {
            let mut cursor = None;
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let cutoff = crate::persistence::current_time_ms().saturating_sub(idle_ms);
                match source
                    .recover_internal_page(cursor.as_ref(), 32, cutoff)
                    .await
                {
                    Ok(page) => {
                        if page.failures > 0 {
                            tracing::warn!(
                                failures = page.failures,
                                "internal issuer recovery remains pending"
                            );
                        }
                        if page.legacy_retained > 0 {
                            tracing::warn!(
                                count = page.legacy_retained,
                                "unfenced legacy internal issuer intents require explicit recovery"
                            );
                        }
                        cursor = page.next_cursor;
                    }
                    Err(error) => {
                        tracing::warn!(code = ?error.code(), "internal issuer recovery scan failed");
                        cursor = None;
                    }
                }
            }
        })))
    }
    pub(crate) async fn recover_internal_page(
        &self,
        after: Option<&ObjectCursor>,
        limit: u32,
        cutoff_ms: i64,
    ) -> Result<RecoveryPage, Status> {
        if !(1..=128).contains(&limit) {
            return Err(invalid());
        }
        let store = self.gateway.clone().ok_or_else(invalid)?;
        let page = store
            .list_object_page(KIND, ObjectListQuery::AllWorkspaces, after, limit)
            .await
            .map_err(|_| Status::unavailable("internal issuer recovery inventory unavailable"))?;
        let mut report = RecoveryPage {
            next_cursor: page.next_cursor,
            ..Default::default()
        };
        for row in page.records {
            report.scanned += 1;
            let updated = row.updated_at_ms;
            let Ok(mut intent) = Intent::from_record(store.clone(), row) else {
                report.failures += 1;
                continue;
            };
            if intent.state.source != self.name.as_ref()
                || matches!(intent.state.phase, Phase::Published | Phase::Closed)
            {
                continue;
            }
            // The previous unshipped protocol did not fence final publication.
            // Never infer death for such a record from a clock or owner scan.
            if intent.state.format != 2 {
                report.legacy_retained += 1;
                continue;
            }
            if intent.state.phase == Phase::Staging && updated > cutoff_ms {
                continue;
            }
            match intent.reclaim(self).await {
                Ok(()) => report.cleaned += 1,
                Err(error) if error.code() == Code::Aborted => report.conflicts += 1,
                Err(_) => report.failures += 1,
            }
        }
        Ok(report)
    }
}
impl Intent {
    async fn reclaim(&mut self, source: &RemoteProviderSource) -> Result<(), Status> {
        if self.state.phase == Phase::Staging {
            self.state.phase = Phase::Closing;
            // A native publication Update at the old version can no longer
            // succeed after this point, even if its writer is still running.
            self.persist().await?;
        }
        if self.state.phase != Phase::Closing {
            return Err(invalid());
        }
        let keys = self.state.references.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            let identity = self.state.identity();
            let id = reservation_key(identity, &self.state.operation, &key)?;
            // Also recover a reservation whose acknowledgement was lost before
            // bind. Reusing its secret-free receipt never allocates a new value.
            let reserved = source
                .client
                .reserve_secret(wire::ReserveSecretRequest {
                    owner: Some(owner(identity, &key)?),
                    idempotency_key: format!("internal-reserve:{id}"),
                })
                .await?;
            let slot = self.state.references.get_mut(&key).ok_or_else(invalid)?;
            if slot.as_ref().is_some_and(|old| old != &reserved.reference) {
                return Err(Status::data_loss(
                    "internal reservation identity changed during recovery",
                ));
            }
            if slot.is_none() {
                *slot = Some(reserved.reference.clone());
                self.persist().await?;
            }
            let handle = source.reference_handle(&reserved.reference, None)?;
            source
                .delete_internal(self.state.identity(), &HashMap::from([(key, handle)]))
                .await?;
        }
        // Keep a value-free terminal receipt to prevent operation-key reuse /
        // revision ABA. It owns no references and performs no future cleanup.
        self.state.phase = Phase::Closed;
        for reference in self.state.references.values_mut() {
            *reference = None;
        }
        self.persist().await
    }
}
