// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Transitional adapters for the existing built-ins. The shared registry sees
//! only stateless requests and semantic outputs, never stored provider records.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use openshell_credential_issuer::minter::{
    MaterialDescriptor, MintFailure, MintRequest, MintResponse, MinterRegistry, RecoveryAction,
    RetrySchedule, StrategyDescriptor, TokenMinter,
};

use super::{
    MintedCredential, ProviderCredentialRefreshRecoveryAction, ProviderCredentialRefreshStrategy,
    RefreshFailure, RefreshRetrySchedule, Status, StoredProviderCredentialRefreshState,
    max_lifetime_seconds, mint_aws_sts_assume_role, mint_google_service_account_jwt,
    mint_oauth2_client_credentials, mint_oauth2_refresh_token, refresh_scopes,
    refresh_strategy_name, strategy_secret_material_keys,
};

pub(super) const ATTEMPT_ANNOTATION: &str = "openshell.nvidia.com/refresh-attempt";

type MintFuture<'a> =
    Pin<Box<dyn Future<Output = Result<MintedCredential, RefreshFailure>> + Send + 'a>>;
type MintFn = for<'a> fn(&'a StoredProviderCredentialRefreshState) -> MintFuture<'a>;

#[derive(Debug)]
struct BuiltinMinter {
    name: &'static str,
    primary_output: &'static str,
    additional_outputs: &'static [&'static str],
    config: &'static [&'static str],
    secret_material: &'static [&'static str],
    rotates_refresh_token: bool,
    mint: MintFn,
}

#[async_trait]
impl TokenMinter for BuiltinMinter {
    fn describe(&self) -> StrategyDescriptor {
        StrategyDescriptor {
            name: self.name.to_string(),
            config: self
                .config
                .iter()
                .copied()
                .chain(["token_url", "scope", "max_lifetime_seconds"])
                .map(|name| MaterialDescriptor {
                    name: name.to_string(),
                    required: false,
                })
                .collect(),
            secret_material: self
                .secret_material
                .iter()
                .map(|name| MaterialDescriptor {
                    name: (*name).to_string(),
                    required: false,
                })
                .collect(),
            outputs: std::iter::once(self.primary_output)
                .chain(self.additional_outputs.iter().copied())
                .map(str::to_string)
                .collect(),
            rotated_secret_material: if self.rotates_refresh_token {
                vec!["refresh_token".to_string()]
            } else {
                Vec::new()
            },
        }
    }

    async fn mint(&self, mut request: MintRequest) -> Result<MintResponse, MintFailure> {
        // The built-in implementation consumes an ephemeral compatibility DTO.
        // It has no metadata, handles, provider identity, or scheduling state.
        let token_url = request.config.remove("token_url").unwrap_or_default();
        let scopes = request.config.remove("scope").unwrap_or_default();
        let max_lifetime = request
            .config
            .remove("max_lifetime_seconds")
            .ok_or_else(|| RefreshFailure::from(Status::invalid_argument("missing mint lifetime")))?
            .parse::<i64>()
            .map_err(|_| RefreshFailure::from(Status::invalid_argument("invalid mint lifetime")))?;
        if max_lifetime <= 0 {
            return Err(
                RefreshFailure::from(Status::invalid_argument("invalid mint lifetime")).into(),
            );
        }
        let mut material = request.config;
        material.extend(request.secret_material);
        let state = StoredProviderCredentialRefreshState {
            token_url,
            scopes: scopes.split_whitespace().map(str::to_string).collect(),
            max_lifetime: Some(prost_types::Duration {
                seconds: max_lifetime,
                nanos: 0,
            }),
            material,
            additional_output_keys: self
                .additional_outputs
                .iter()
                .map(|id| ((*id).to_string(), (*id).to_string()))
                .collect(),
            ..Default::default()
        };
        let minted = (self.mint)(&state).await?;
        let mut outputs = minted.additional_credentials;
        outputs.insert(self.primary_output.to_string(), minted.access_token);
        Ok(MintResponse {
            outputs,
            expiration_time_ms: minted.expires_at_ms,
            rotated_secret_material: minted
                .refresh_token
                .map(|value| HashMap::from([("refresh_token".to_string(), value)]))
                .unwrap_or_default(),
        })
    }
}

pub(super) static MINTERS: LazyLock<Arc<MinterRegistry>> = LazyLock::new(|| {
    let mut registry = MinterRegistry::default();
    for builtin in [
        BuiltinMinter {
            name: "oauth2_refresh_token",
            primary_output: "access_token",
            additional_outputs: &[],
            config: &["client_id", "tenant_id"],
            secret_material: &["refresh_token", "client_secret"],
            rotates_refresh_token: true,
            mint: |state| Box::pin(mint_oauth2_refresh_token(state)),
        },
        BuiltinMinter {
            name: "oauth2_client_credentials",
            primary_output: "access_token",
            additional_outputs: &[],
            config: &["client_id", "tenant_id"],
            secret_material: &["client_secret", "refresh_token"],
            rotates_refresh_token: true,
            mint: |state| Box::pin(mint_oauth2_client_credentials(state)),
        },
        BuiltinMinter {
            name: "google_service_account_jwt",
            primary_output: "access_token",
            additional_outputs: &[],
            config: &["client_email", "subject", "sub"],
            secret_material: &["private_key", "refresh_token"],
            rotates_refresh_token: true,
            mint: |state| Box::pin(mint_google_service_account_jwt(state)),
        },
        BuiltinMinter {
            name: "aws_sts_assume_role",
            primary_output: "access_key_id",
            additional_outputs: &["secret_access_key", "session_token"],
            config: &[
                "role_arn",
                "session_name",
                "external_id",
                "aws_region",
                "aws_access_key_id",
                "sts_endpoint_url",
            ],
            secret_material: &["aws_secret_access_key", "aws_session_token"],
            rotates_refresh_token: false,
            mint: |state| Box::pin(mint_aws_sts_assume_role(state)),
        },
    ] {
        registry
            .register_builtin(Arc::new(builtin))
            .expect("built-in minter descriptors are valid and unique");
    }
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
    // Translate the legacy profile ABI only here. Minters return semantic IDs,
    // never environment keys or credential reference identities.
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
