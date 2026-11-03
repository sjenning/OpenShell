// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Configure registered single-output minters without inventing a primary-output
//! convention. Custom profile declarations and multi-output bindings need a
//! separate profile-catalog integration; neither is inferred from output order.
use crate::{
    ServerState, compute::MutationScope, credential_source::handoff::GrantPlan,
    grpc::mutation_replay::ordinary::Facts,
};
use openshell_core::proto::{
    ConfigureProviderRefreshRequest, ConfigureProviderRefreshResponse, Provider,
    ProviderCredentialRefreshStrategy,
};
use std::{collections::BTreeMap, sync::Arc};
use tonic::{Response, Status};

fn invalid() -> Status {
    Status::invalid_argument("invalid custom issuer grant configuration")
}

pub(in crate::grpc::provider) async fn configure_custom(
    state: &Arc<ServerState>,
    workspace: &str,
    mut request: ConfigureProviderRefreshRequest,
    facts: &Facts,
) -> Result<Response<ConfigureProviderRefreshResponse>, Status> {
    // An unknown enum or a conflicting built-in selector never becomes a
    // custom request merely because the name has the custom prefix.
    if request.strategy != ProviderCredentialRefreshStrategy::Unspecified as i32
        || request.expiration_time.is_some()
    {
        return Err(invalid());
    }
    let source = state.remote_provider_mutations()?.ok_or_else(|| {
        Status::failed_precondition("custom refresh requires a selected credential issuer")
    })?;
    let descriptor = source
        .issuer()
        .list_strategies()
        .await?
        .strategies
        .into_iter()
        .find(|descriptor| descriptor.name == request.strategy_name)
        .ok_or_else(|| Status::failed_precondition("issuer grant strategy is unavailable"))?;
    if descriptor.outputs.len() != 1 {
        return Err(Status::failed_precondition(
            "custom refresh configuration requires a single-output minter",
        ));
    }
    // The authenticated issuer descriptor, not caller annotations, determines
    // which fields are secret material. Explicit contrary annotations fail.
    for key in &request.secret_material_keys {
        if !request.material.contains_key(key)
            || !descriptor
                .secret_material
                .iter()
                .any(|field| field.name == *key)
        {
            return Err(invalid());
        }
    }
    let seconds = |key: &str, default: i64| -> Result<i64, Status> {
        let value = crate::provider_refresh::parse_material_i64(&request.material, key)?
            .filter(|value| *value != 0)
            .unwrap_or(default);
        if !(0..=43_200).contains(&value) {
            return Err(invalid());
        }
        Ok(value)
    };
    // Reserve scheduling controls for the gateway just as the built-in path
    // does. Refuse ambiguous descriptors rather than swallowing minter inputs.
    for field in descriptor.config.iter().chain(&descriptor.secret_material) {
        if matches!(
            field.name.as_str(),
            "refresh_before_seconds" | "max_lifetime_seconds"
        ) {
            return Err(Status::failed_precondition(
                "custom minter fields conflict with refresh scheduling controls",
            ));
        }
    }
    let lead = seconds("refresh_before_seconds", 300)?;
    let lifetime = seconds("max_lifetime_seconds", 3600)?;
    request.material.remove("refresh_before_seconds");
    request.material.remove("max_lifetime_seconds");
    let mut material = std::collections::HashMap::new();
    for field in &descriptor.secret_material {
        if let Some(value) = request.material.remove(&field.name) {
            material.insert(field.name.clone(), value);
        }
    }
    if request
        .material
        .keys()
        .any(|key| !descriptor.config.iter().any(|field| field.name == *key))
        || descriptor.config.iter().any(|field| {
            field.required
                && request
                    .material
                    .get(&field.name)
                    .is_none_or(|value| value.trim().is_empty())
        })
        || descriptor.secret_material.iter().any(|field| {
            field.required
                && material
                    .get(&field.name)
                    .is_none_or(|value| value.trim().is_empty())
        })
    {
        return Err(invalid());
    }
    let _guard = state
        .compute
        .mutation_guard(MutationScope::Workspace(workspace))
        .await
        .map_err(|error| {
            crate::grpc::persistence_error_to_status(error, "acquire provider mutation lock")
        })?;
    let provider = state
        .store
        .get_message_by_name::<Provider>(workspace, request.provider.trim())
        .await
        .map_err(|_| Status::internal("fetch provider failed"))?
        .ok_or_else(|| Status::not_found("provider not found"))?;
    source.register_provider(&provider)?;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, workspace)
        .await?;
    let key = request.credential_key.trim();
    if super::super::provider_refresh_defaults(&catalog, &provider, key).is_some() {
        return Err(Status::failed_precondition(
            "custom refresh cannot override a profile refresh declaration",
        ));
    }
    super::super::validate_provider_credential_key_available_for_attached_sandboxes_with_source(
        &state.store,
        &catalog,
        workspace,
        &provider,
        key,
        Some(source),
    )
    .await?;
    super::configuration::publish_grant(
        state,
        source,
        &provider,
        GrantPlan {
            credential_key: key.into(),
            strategy: request.strategy_name,
            outputs: BTreeMap::from([(descriptor.outputs[0].clone(), key.into())]),
            refresh_before_ms: u64::try_from(lead).map_err(|_| invalid())? * 1000,
            max_lifetime_seconds: u32::try_from(lifetime).map_err(|_| invalid())?,
        },
        &request.material,
        &material,
        facts,
    )
    .await
}
