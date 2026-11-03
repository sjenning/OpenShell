// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::kernel::{Purpose, Snapshot};
use super::operations::output_owner;
use super::{GrantRuntime, now_ms};
use crate::{
    ReferenceStateStore, auth::GatewayScope, engine::RefreshTrigger, minter::RecoveryAction,
    repository::grants::GrantPhase,
};
use std::{sync::Arc, time::Duration};
use tonic::Status;

impl GrantRuntime {
    pub(super) fn spawn_worker(
        self: Arc<Self>,
        interval: Duration,
    ) -> Result<tokio::task::JoinHandle<()>, Status> {
        if interval.is_zero() {
            return Err(Status::invalid_argument(
                "issuer refresh interval must be positive",
            ));
        }
        let runtime = Arc::downgrade(&self);
        Ok(tokio::spawn(async move {
            let mut ticks = tokio::time::interval(interval);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticks.tick().await;
                let Some(runtime) = runtime.upgrade() else {
                    return;
                };
                if let Err(error) = runtime.tick().await {
                    tracing::warn!(code=?error.code(),"issuer grant sweep failed");
                }
            }
        }))
    }
    pub(super) async fn tick(self: &Arc<Self>) -> Result<(), Status> {
        self.store.maintenance().await?;
        for scope in self.store.policy.configured_scopes()? {
            let grants = self.store.repository.grants(&scope);
            let mut cursor = None;
            loop {
                let page = grants.list(cursor.as_deref(), 64).await?;
                for grant in page.grants {
                    let id = grant.state.definition.identity.id.clone();
                    if let Err(error) = self.housekeep(&scope, &id).await {
                        tracing::warn!(grant=%id,code=?error.code(),"issuer grant maintenance deferred");
                        continue;
                    }
                    let loaded = self.load(&scope, &id).await?;
                    let purpose = if loaded.state.phase == GrantPhase::Publishing {
                        Some(Purpose::Recovery)
                    } else if matches!(
                        loaded.state.phase,
                        GrantPhase::Pending | GrantPhase::Failed | GrantPhase::Refreshed
                    ) && loaded.state.checkpoint().schedule.due(now_ms()?)
                        && loaded
                            .state
                            .checkpoint()
                            .ensure_mintable(RefreshTrigger::Automatic, now_ms()?)
                            .is_ok()
                    {
                        Some(Purpose::Scheduled)
                    } else {
                        None
                    };
                    if let Some(purpose) = purpose
                        && let Err(error) = self
                            .execute(
                                Snapshot {
                                    scope: scope.clone(),
                                    loaded,
                                    purpose,
                                    result: None,
                                },
                                RefreshTrigger::Automatic,
                            )
                            .await
                    {
                        tracing::warn!(grant=%id,code=?error.code(),"issuer grant refresh deferred");
                    }
                }
                let Some(after) = page.after else { break };
                cursor = Some(after);
            }
        }
        Ok(())
    }
    async fn housekeep(&self, scope: &GatewayScope, id: &str) -> Result<(), Status> {
        let lock = self
            .store
            .coordinator
            .lock_for(&Self::coordination_key(scope, id))?;
        let Ok(_local) = lock.try_lock_owned() else {
            return Ok(());
        };
        let store = self.store.repository.for_gateway(scope);
        let Some(_lease) = store.try_refresh_lease(&format!("grant:{id}")).await? else {
            return Ok(());
        };
        let mut current = self.load(scope, id).await?;
        if current.state.phase == GrantPhase::Refreshing {
            let mut state = current.state;
            state.phase = GrantPhase::Parked;
            state.recovery_action = Some(RecoveryAction::Investigate);
            state.failure_code = "mint_outcome_unknown".into();
            state.next_refresh_at_ms = i64::MAX;
            state.version = state
                .version
                .checked_add(1)
                .ok_or_else(|| Status::resource_exhausted("issuer grant version exhausted"))?;
            current = self
                .save(scope, current.revision, &state, Vec::new())
                .await?;
        }
        while let Some(retired) = current.state.retired.first().cloned() {
            self.store
                .storage
                .delete(scope, &retired.owner, &retired.purpose, &retired.backing)
                .await?;
            let mut state = current.state;
            state.retired.remove(0);
            current = self
                .save(scope, current.revision, &state, Vec::new())
                .await?;
        }
        if current.state.phase == GrantPhase::Deleting {
            let refs = self.store.repository.references(scope);
            for (name, binding) in &current.state.definition.outputs {
                let record = refs
                    .load(&binding.reference)
                    .await?
                    .ok_or_else(|| Status::data_loss("deleted grant output metadata is missing"))?;
                scope.authorize_bound_owner(
                    scope.identity(),
                    &record.state.owner,
                    &output_owner(&current.state, name)?,
                )?;
                if !record.state.revoked || !record.state.pending_deletions.is_empty() {
                    return Ok(());
                }
            }
            let mut state = current.state;
            state.phase = GrantPhase::Deleted;
            state.version = state
                .version
                .checked_add(1)
                .ok_or_else(|| Status::resource_exhausted("issuer grant version exhausted"))?;
            state.next_refresh_at_ms = i64::MAX;
            state.recovery_action = None;
            state.failure_code.clear();
            self.save(scope, current.revision, &state, Vec::new())
                .await?;
        }
        Ok(())
    }
}
