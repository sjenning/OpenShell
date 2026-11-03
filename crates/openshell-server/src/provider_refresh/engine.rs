// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway persistence and publication adapters for the shared refresh engine.

use std::sync::Arc;

use async_trait::async_trait;
use openshell_credential_issuer::SecretOwner;
use openshell_credential_issuer::engine::{
    Preparation, RefreshEngine, RefreshSink, RefreshStateStore, RefreshTrigger,
};
use openshell_credential_issuer::grant::{GrantAdmission, GrantCheckpoint, GrantIdentity};
use openshell_credential_issuer::minter::{MintFailure, MintRequest, MintResponse};

use super::{
    ATTEMPT_ANNOTATION, Provider, ProviderCredentialRefreshRecoveryAction, REFRESH_COORDINATOR,
    RefreshFailure, Status, Store, StoredProviderCredentialRefreshState,
    cleanup_pending_secret_deletions, commit_minted_refresh, completed_mint, current_time_ms,
    effective_authorization_epoch, get_refresh_state, minters, persist_refresh_failure_state,
    persist_refresh_state_if_current, refresh_material_scope, refresh_schedule, refresh_state_name,
    refresh_strategy_name, resolve_refresh_material, seconds_until_ms,
    validate_secret_material_references,
};
use openshell_core::{ObjectId, ObjectWorkspace};
use tracing::{info, warn};

pub(super) struct GatewayRefreshStore {
    store: Store,
    credentials: crate::credentials::CredentialRuntime,
    compute: Option<crate::compute::ComputeRuntime>,
}

pub(super) struct PreparedRefresh {
    pub state: StoredProviderCredentialRefreshState,
    pub provider: Provider,
    pub expected_version: u64,
    pub attempt_id: String,
    pub output_versions: Option<std::collections::HashMap<String, u64>>,
}

/// Project only non-secret durable state. The issuer never sees provider
/// profiles, credential handles, or material while deciding admission.
fn grant_checkpoint(
    state: &StoredProviderCredentialRefreshState,
) -> Result<GrantCheckpoint, Status> {
    Ok(GrantCheckpoint {
        identity: GrantIdentity {
            id: state.object_id().to_string(),
            authorization_epoch: effective_authorization_epoch(state)?.to_string(),
            owner: SecretOwner {
                workspace: state.object_workspace().to_string(),
                provider_id: state.provider_id.clone(),
                credential_key: state.credential_key.clone(),
            },
        },
        status: state.status.clone(),
        failure_code: state.failure_code.clone(),
        completed_attempt: completed_mint(state).map(ToString::to_string),
        schedule: refresh_schedule(state),
    })
}

struct GatewayRefreshSink(crate::credentials::CredentialRuntime);

#[async_trait]
impl RefreshSink<StoredProviderCredentialRefreshState> for GatewayRefreshSink {
    async fn committed(&self, snapshot: &StoredProviderCredentialRefreshState) {
        self.0
            .notify_reference_change(refresh_material_scope(snapshot));
    }
}

pub(super) fn new_engine(
    store: &Store,
    credentials: &crate::credentials::CredentialRuntime,
    compute: Option<&crate::compute::ComputeRuntime>,
) -> RefreshEngine<GatewayRefreshStore> {
    RefreshEngine::new(
        Arc::new(GatewayRefreshStore {
            store: store.clone(),
            credentials: credentials.clone(),
            compute: compute.cloned(),
        }),
        minters::MINTERS.clone(),
        Arc::new(GatewayRefreshSink(credentials.clone())),
        REFRESH_COORDINATOR.clone(),
    )
}

#[async_trait]
impl RefreshStateStore for GatewayRefreshStore {
    type Snapshot = StoredProviderCredentialRefreshState;
    type Attempt = PreparedRefresh;
    type Lease = crate::persistence::RefreshMutationGuard;

    fn coordination_key(&self, observed: &Self::Snapshot) -> String {
        refresh_state_name(&observed.provider_id, &observed.credential_key)
    }

    async fn acquire_lease(&self, observed: &Self::Snapshot) -> Result<Self::Lease, Status> {
        self.store
            .acquire_refresh_guard(&observed.provider_id, &observed.credential_key)
            .await
            .map_err(|_| Status::unavailable("credential refresh coordination unavailable"))
    }

    async fn prepare(
        &self,
        observed: Self::Snapshot,
        trigger: RefreshTrigger,
        attempt_id: &str,
    ) -> Result<Preparation<Self::Snapshot, Self::Attempt>, Status> {
        let mut state = get_refresh_state(
            &self.store,
            observed.object_workspace(),
            &observed.provider_id,
            &observed.credential_key,
        )
        .await?
        .ok_or_else(|| Status::aborted("provider refresh was deleted"))?;
        let live = grant_checkpoint(&state)?;
        if live.admit(&grant_checkpoint(&observed)?)? == GrantAdmission::Current {
            return Ok(Preparation::Current(state));
        }
        let provider = self
            .store
            .get_message_by_name::<Provider>(observed.object_workspace(), &observed.provider_name)
            .await
            .map_err(|_| Status::internal("fetch provider failed"))?
            .ok_or_else(|| Status::not_found("provider not found"))?;
        if provider.object_id() != observed.provider_id {
            return Err(Status::aborted("provider was replaced"));
        }
        live.ensure_mintable(trigger, current_time_ms())?;
        validate_secret_material_references(&state)?;
        let keys = std::iter::once(state.credential_key.clone())
            .chain(state.additional_output_keys.values().cloned())
            .collect::<Vec<_>>();
        let output_versions = if completed_mint(&state).is_some() {
            self.credentials
                .capture_refresh_reference_versions(&provider, &keys)
                .await?
        } else {
            None
        };
        let mut expected_version = state
            .metadata
            .as_ref()
            .map_or(0, |meta| meta.resource_version);
        match cleanup_pending_secret_deletions(
            &self.store,
            Some(&self.credentials),
            &mut state,
            expected_version,
        )
        .await
        {
            Ok(version) => expected_version = version,
            Err(error) => {
                warn!(provider = %state.provider_name, credential_key = %state.credential_key,
                %error, "provider refresh material cleanup failed; continuing with live refresh");
            }
        }
        info!(provider = %state.provider_name, credential_key = %state.credential_key,
            strategy = %refresh_strategy_name(state.strategy), status = %state.status,
            expires_at_ms = state.expires_at_ms, next_refresh_at_ms = state.next_refresh_at_ms,
            "provider credential refresh started");
        state.status = "refresh_in_progress".to_string();
        state.next_refresh_at_ms = i64::MAX;
        state.recovery_action = ProviderCredentialRefreshRecoveryAction::Investigate as i32;
        state
            .metadata
            .as_mut()
            .ok_or_else(|| Status::failed_precondition("refresh state metadata missing"))?
            .annotations
            .insert(ATTEMPT_ANNOTATION.to_string(), attempt_id.to_string());
        let expected_version =
            persist_refresh_state_if_current(&self.store, &state, expected_version)
                .await?
                .ok_or_else(|| Status::aborted("provider refresh changed before minting"))?;
        Ok(Preparation::Ready(PreparedRefresh {
            state,
            provider,
            expected_version,
            attempt_id: attempt_id.to_string(),
            output_versions,
        }))
    }

    async fn mint_request(&self, attempt: &Self::Attempt) -> Result<MintRequest, MintFailure> {
        let transient = resolve_refresh_material(Some(&self.credentials), &attempt.state)
            .await
            .map_err(RefreshFailure::from)?;
        minters::mint_request(&transient).map_err(MintFailure::from)
    }

    async fn commit(
        &self,
        attempt: Self::Attempt,
        response: MintResponse,
    ) -> Result<Self::Snapshot, Status> {
        let minted = match minters::map_response(&attempt.state, response) {
            Ok(minted) => minted,
            Err(failure) => {
                let status = failure.status.clone();
                self.record_failure(&attempt, failure.into()).await?;
                return Err(status);
            }
        };
        commit_minted_refresh(
            &self.store,
            &self.credentials,
            self.compute.as_ref(),
            attempt,
            minted,
        )
        .await
    }

    async fn record_failure(
        &self,
        attempt: &Self::Attempt,
        failure: MintFailure,
    ) -> Result<(), Status> {
        let failure = RefreshFailure::from(failure);
        let mut state = attempt.state.clone();
        persist_refresh_failure_state(&self.store, &mut state, attempt.expected_version, &failure)
            .await?;
        warn!(provider = %state.provider_name, credential_key = %state.credential_key,
            strategy = %refresh_strategy_name(state.strategy), status = %state.status,
            next_refresh_at_ms = state.next_refresh_at_ms,
            seconds_until_refresh = seconds_until_ms(current_time_ms(), state.next_refresh_at_ms),
            recovery_action = ?failure.recovery_action, failure_code = failure.failure_code,
            error = %failure.status, "provider credential refresh errored");
        Ok(())
    }
}

#[cfg(test)]
mod tests;
