// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Registered custom strategies use profile semantic output bindings and the
//! same fixed-bundle handoff, publication, retirement, and replay fences as
//! built-ins. No output identity is inferred from descriptor ordering.
use crate::{
    ServerState, compute::MutationScope, credential_source::handoff::GrantPlan,
    grpc::mutation_replay::ordinary::Facts,
};
use openshell_core::proto::{
    ConfigureProviderRefreshRequest, ConfigureProviderRefreshResponse, Provider,
    ProviderCredentialRefreshStrategy,
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tonic::{Response, Status};

fn invalid() -> Status {
    Status::invalid_argument("invalid custom issuer grant configuration")
}

fn schedule(
    material: &std::collections::HashMap<String, String>,
    key: &str,
    profile: Option<prost_types::Duration>,
    default: Duration,
) -> Result<Duration, Status> {
    let requested = crate::provider_refresh::parse_material_i64(material, key)?;
    let value = match requested {
        Some(0) => default,
        Some(seconds) => Duration::from_secs(u64::try_from(seconds).map_err(|_| invalid())?),
        None => profile
            .as_ref()
            .map(openshell_core::time::duration_to_std)
            .transpose()
            .map_err(|_| invalid())?
            .unwrap_or(default),
    };
    if value > Duration::from_hours(12) {
        return Err(invalid());
    }
    Ok(value)
}

pub(in crate::grpc::provider) async fn configure_custom(
    state: &Arc<ServerState>,
    workspace: &str,
    mut request: ConfigureProviderRefreshRequest,
    facts: &Facts,
) -> Result<Response<ConfigureProviderRefreshResponse>, Status> {
    if request.strategy != ProviderCredentialRefreshStrategy::Unspecified as i32
        || !openshell_providers::custom_strategy_name_is_valid(&request.strategy_name)
        || request.expiration_time.is_some()
    {
        return Err(invalid());
    }
    let source = state.remote_provider_mutations()?.ok_or_else(|| {
        Status::failed_precondition("custom refresh requires a selected credential issuer")
    })?;
    let strategies = source.issuer().list_strategies().await?.strategies;
    let mut matching = strategies
        .iter()
        .filter(|descriptor| descriptor.name == request.strategy_name);
    let descriptor = matching
        .next()
        .ok_or_else(|| Status::failed_precondition("issuer grant strategy is unavailable"))?;
    if matching.next().is_some() {
        return Err(Status::failed_precondition(
            "issuer grant strategy is ambiguous",
        ));
    }
    // The authenticated issuer descriptor, not caller or profile annotations,
    // determines secret material. Explicit contrary annotations fail.
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
    let profile = super::super::get_provider_type_profile_for_scope(
        &catalog,
        &provider.r#type,
        &provider.profile_workspace,
    );
    let defaults = super::super::provider_refresh_defaults(&catalog, &provider, key);
    let outputs = if let Some(refresh) = &defaults {
        if refresh.strategy != ProviderCredentialRefreshStrategy::Unspecified
            || refresh.strategy_name != request.strategy_name
        {
            return Err(Status::failed_precondition(
                "custom refresh does not match the profile refresh declaration",
            ));
        }
        let profile = profile.as_ref().ok_or_else(invalid)?;
        let diagnostics = openshell_providers::validate_profile_set_with_strategies(
            &[(String::new(), profile.clone())],
            &strategies,
        );
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == "error")
        {
            return Err(Status::failed_precondition(
                "profile refresh is incompatible with the selected issuer",
            ));
        }
        openshell_providers::refresh_output_bindings(profile, key, descriptor)
            .map_err(Status::failed_precondition)?
    } else {
        let [output] = descriptor.outputs.as_slice() else {
            return Err(Status::failed_precondition(
                "multi-output custom refresh requires an unambiguous profile output mapping",
            ));
        };
        BTreeMap::from([(output.clone(), key.into())])
    };
    let lead = schedule(
        &request.material,
        "refresh_before_seconds",
        defaults.as_ref().and_then(|refresh| {
            refresh
                .refresh_before_wkt
                .to_proto(refresh.refresh_before_seconds)
        }),
        Duration::from_mins(5),
    )?;
    let lifetime = schedule(
        &request.material,
        "max_lifetime_seconds",
        defaults.as_ref().and_then(|refresh| {
            refresh
                .max_lifetime_wkt
                .to_proto(refresh.max_lifetime_seconds)
        }),
        Duration::from_hours(1),
    )?;
    request.material.remove("refresh_before_seconds");
    request.material.remove("max_lifetime_seconds");
    if let Some(refresh) = &defaults {
        if !refresh.token_url.is_empty() {
            if request.material.contains_key("token_url") {
                return Err(invalid());
            }
            request
                .material
                .insert("token_url".into(), refresh.token_url.clone());
        }
        if !refresh.scopes.is_empty() && !request.material.contains_key("scope") {
            request
                .material
                .insert("scope".into(), refresh.scopes.join(" "));
        }
        super::super::validate_refresh_material(&request.material, Some(refresh))?;
    }
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
    // Check every key in the fixed bundle before allocating any issuer state.
    // The workspace guard excludes concurrent configure/create/attach races.
    for output_key in outputs.values() {
        super::super::validate_provider_credential_key_available_for_attached_sandboxes_with_source(
            &state.store, &catalog, workspace, &provider, output_key, Some(source),
        ).await?;
    }
    super::configuration::publish_grant(
        state,
        source,
        &provider,
        GrantPlan {
            credential_key: key.into(),
            strategy: request.strategy_name,
            outputs,
            refresh_before_ms: u64::try_from(lead.as_millis()).map_err(|_| invalid())?,
            max_lifetime_seconds: u32::try_from(
                lifetime
                    .as_secs()
                    .checked_add(u64::from(lifetime.subsec_nanos() != 0))
                    .ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?,
        },
        &request.material,
        &material,
        facts,
    )
    .await
}
