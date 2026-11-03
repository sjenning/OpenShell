// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Project issuer metadata, never embedded refresh state or secret values.
use super::{Provider, RemoteProviderSource, StaticHandoff, Store, invalid};
use openshell_core::{
    ObjectId as _, ObjectName as _, ObjectWorkspace as _,
    proto::{
        ProviderCredentialRefreshRecoveryAction, ProviderCredentialRefreshStatus,
        ProviderCredentialRefreshStrategy,
        credentials::{minter::v1 as minter, refresh::v1 as refresh},
    },
};
use std::collections::HashSet;
use tonic::Status;
fn ownership() -> Status {
    Status::failed_precondition("issuer grant retirement ownership is missing")
}
fn recovery(value: i32) -> Result<i32, Status> {
    Ok(
        match minter::RecoveryAction::try_from(value).map_err(|_| invalid())? {
            minter::RecoveryAction::Unspecified => {
                ProviderCredentialRefreshRecoveryAction::Unspecified
            }
            minter::RecoveryAction::Retry => ProviderCredentialRefreshRecoveryAction::Retry,
            minter::RecoveryAction::FixConfiguration => {
                ProviderCredentialRefreshRecoveryAction::FixConfiguration
            }
            minter::RecoveryAction::Reauthorize => {
                ProviderCredentialRefreshRecoveryAction::Reauthorize
            }
            minter::RecoveryAction::Investigate => {
                ProviderCredentialRefreshRecoveryAction::Investigate
            }
        } as i32,
    )
}
impl StaticHandoff {
    pub async fn refresh_statuses(
        store: &Store,
        source: &RemoteProviderSource,
        provider: &Provider,
        credential_key: &str,
    ) -> Result<Vec<ProviderCredentialRefreshStatus>, Status> {
        source.register_provider(provider)?;
        let owned = Self::published_for_provider(store, source, provider).await?;
        // Validate complete local ownership before any remote request. Missing
        // journals or partial bundles never authorize embedded-state fallback.
        for (key, handle) in &provider.credential_handles {
            let binding = source.decode(handle)?;
            if let Some(grant) = binding.grant.as_deref()
                && !owned.iter().any(|handoff| {
                    handoff.grant_id() == Some(grant)
                        && handoff.state.slots.get(key).is_some_and(|slot| {
                            !slot.retiring && slot.reference.as_ref() == Some(&binding.reference)
                        })
                })
            {
                return Err(ownership());
            }
        }
        let mut primary_keys = HashSet::new();
        let mut selected = Vec::new();
        for handoff in &owned {
            let Some(grant) = &handoff.state.grant else {
                continue;
            };
            if !primary_keys.insert(&grant.plan.credential_key) {
                return Err(ownership());
            }
            for (key, slot) in &handoff.state.slots {
                let binding =
                    source.decode(provider.credential_handles.get(key).ok_or_else(ownership)?)?;
                if binding.grant.as_deref() != handoff.grant_id()
                    || Some(&binding.reference) != slot.reference.as_ref()
                {
                    return Err(ownership());
                }
            }
            if credential_key.is_empty() || credential_key == grant.plan.credential_key {
                selected.push(handoff);
            }
        }
        let mut result = Vec::new();
        for handoff in selected {
            let grant = handoff.state.grant.as_ref().ok_or_else(invalid)?;
            let status = source
                .client
                .get_grant(refresh::GetGrantRequest {
                    grant: handoff.grant_id().ok_or_else(invalid)?.into(),
                })
                .await?
                .status
                .ok_or_else(invalid)?;
            let strategy = if grant.plan.strategy.starts_with("custom:") {
                ProviderCredentialRefreshStrategy::Unspecified
            } else {
                openshell_providers::resolve_refresh_strategy(0, &grant.plan.strategy)
                    .map_err(|_| invalid())?
            };
            result.push(ProviderCredentialRefreshStatus {
                provider: provider.object_name().into(),
                provider_id: provider.object_id().into(),
                credential_key: grant.plan.credential_key.clone(),
                strategy: strategy as i32,
                strategy_name: grant.plan.strategy.clone(),
                status: if status.state == "pending" || status.state == "reserved" {
                    "configured".into()
                } else {
                    status.state
                },
                expiration_time: status.expiration_time,
                next_refresh_time: status.next_refresh_time,
                recovery_action: recovery(status.recovery_action)?,
                failure_code: status.failure_code,
                ..Default::default()
            });
        }
        let current = store
            .get_message::<Provider>(provider.object_id())
            .await
            .map_err(super::storage)?
            .ok_or_else(|| Status::aborted("provider changed during refresh status read"))?;
        if current.object_workspace() != provider.object_workspace()
            || current.object_name() != provider.object_name()
            || current.credential_handles != provider.credential_handles
        {
            return Err(Status::aborted(
                "provider changed during refresh status read",
            ));
        }
        result.sort_by(|a, b| a.credential_key.cmp(&b.credential_key));
        Ok(result)
    }
}
