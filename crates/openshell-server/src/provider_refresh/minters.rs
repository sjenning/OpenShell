// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway mapping between durable grants and issuer-owned stateless minters.

use super::{
    MintedCredential, ProviderCredentialRefreshRecoveryAction, ProviderCredentialRefreshStrategy,
    RefreshFailure, RefreshRetrySchedule, Status, StoredProviderCredentialRefreshState,
    max_lifetime_seconds, refresh_scopes, refresh_strategy_name, strategy_secret_material_keys,
};
use openshell_credential_issuer::minter::{
    MintFailure, MintRequest, MintResponse, MinterRegistry, RecoveryAction, RetrySchedule,
};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

pub(super) const ATTEMPT_ANNOTATION: &str = "openshell.nvidia.com/refresh-attempt";

pub(super) static MINTERS: LazyLock<Arc<MinterRegistry>> = LazyLock::new(|| {
    #[cfg(not(test))]
    let registry = openshell_credential_issuer::builtins::registry();
    #[cfg(test)]
    let registry = openshell_credential_issuer::builtins::registry_with_loopback_sts_for_tests();
    Arc::new(registry)
});

#[cfg(test)]
async fn mint_with_registry(
    registry: &MinterRegistry,
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, RefreshFailure> {
    let response = registry.mint(mint_request(state)?).await?;
    map_response(state, response)
}

pub(super) fn mint_request(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintRequest, RefreshFailure> {
    let strategy = ProviderCredentialRefreshStrategy::try_from(state.strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
    let mut config = state.material.clone();
    let mut secret_material = HashMap::new();
    for key in state
        .secret_material_keys
        .iter()
        .map(String::as_str)
        .chain(strategy_secret_material_keys(strategy).iter().copied())
    {
        if let Some(value) = config.remove(key) {
            secret_material.insert(key.to_string(), value);
        }
    }
    config.insert("token_url".to_string(), state.token_url.clone());
    config.insert("scope".to_string(), refresh_scopes(state).join(" "));
    config.insert(
        "max_lifetime_seconds".to_string(),
        max_lifetime_seconds(state).to_string(),
    );
    let attempt_id = state
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.annotations.get(ATTEMPT_ANNOTATION))
        .cloned()
        .ok_or_else(|| Status::failed_precondition("refresh attempt was not recorded"))?;
    Ok(MintRequest {
        strategy: refresh_strategy_name(state.strategy).to_string(),
        config,
        secret_material,
        attempt_id,
    })
}

pub(super) fn map_response(
    state: &StoredProviderCredentialRefreshState,
    mut minted: MintResponse,
) -> Result<MintedCredential, RefreshFailure> {
    let strategy = ProviderCredentialRefreshStrategy::try_from(state.strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
    // Only the gateway maps semantic output IDs onto pinned profile env keys.
    let primary = if strategy == ProviderCredentialRefreshStrategy::AwsStsAssumeRole {
        "access_key_id"
    } else {
        "access_token"
    };
    let access_token = minted
        .outputs
        .remove(primary)
        .ok_or_else(|| Status::internal("minter primary output missing"))?;
    let mut additional_credentials = HashMap::new();
    for (id, value) in minted.outputs {
        let key = state.additional_output_keys.get(&id).ok_or_else(|| {
            Status::failed_precondition(
                "refresh state missing resolved output key; reconfigure the refresh",
            )
        })?;
        additional_credentials.insert(key.clone(), value);
    }
    Ok(MintedCredential {
        access_token,
        expires_at_ms: minted.expiration_time_ms,
        refresh_token: minted.rotated_secret_material.remove("refresh_token"),
        additional_credentials,
    })
}

#[cfg(test)]
mod tests;

impl From<RefreshFailure> for MintFailure {
    fn from(failure: RefreshFailure) -> Self {
        Self {
            status: failure.status,
            recovery_action: match failure.recovery_action {
                ProviderCredentialRefreshRecoveryAction::Retry
                | ProviderCredentialRefreshRecoveryAction::Unspecified => RecoveryAction::Retry,
                ProviderCredentialRefreshRecoveryAction::Reauthorize => RecoveryAction::Reauthorize,
                ProviderCredentialRefreshRecoveryAction::FixConfiguration => {
                    RecoveryAction::FixConfiguration
                }
                ProviderCredentialRefreshRecoveryAction::Investigate => RecoveryAction::Investigate,
            },
            failure_code: failure.failure_code,
            provider_error_subtype: failure.provider_error_subtype,
            retry_schedule: match failure.retry_schedule {
                RefreshRetrySchedule::Short => RetrySchedule::Short,
                RefreshRetrySchedule::Configuration => RetrySchedule::Configuration,
                RefreshRetrySchedule::Parked => RetrySchedule::Parked,
            },
        }
    }
}

impl From<MintFailure> for RefreshFailure {
    fn from(failure: MintFailure) -> Self {
        Self {
            status: failure.status,
            recovery_action: match failure.recovery_action {
                RecoveryAction::Retry => ProviderCredentialRefreshRecoveryAction::Retry,
                RecoveryAction::Reauthorize => ProviderCredentialRefreshRecoveryAction::Reauthorize,
                RecoveryAction::FixConfiguration => {
                    ProviderCredentialRefreshRecoveryAction::FixConfiguration
                }
                RecoveryAction::Investigate => ProviderCredentialRefreshRecoveryAction::Investigate,
            },
            failure_code: failure.failure_code,
            provider_error_subtype: failure.provider_error_subtype,
            retry_schedule: match failure.retry_schedule {
                RetrySchedule::Short => RefreshRetrySchedule::Short,
                RetrySchedule::Configuration => RefreshRetrySchedule::Configuration,
                RetrySchedule::Parked => RefreshRetrySchedule::Parked,
            },
        }
    }
}
