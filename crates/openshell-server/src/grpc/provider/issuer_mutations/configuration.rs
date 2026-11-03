// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Configure new issuer epochs without persisting configuration or material in
//! gateway records. Published output references may await their first value.
use crate::{
    ServerState,
    credential_source::{
        RemoteProviderSource,
        handoff::{GrantPlan, StaticHandoff},
    },
    grpc::mutation_replay::ordinary::Facts,
};
use openshell_core::{
    GetResourceVersion as _, ObjectName as _, ObjectWorkspace as _,
    proto::{
        ConfigureProviderRefreshResponse, Provider, ProviderCredentialRefreshStrategy,
        credentials::refresh::v1 as wire,
    },
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tonic::{Response, Status};
pub(in crate::grpc::provider) struct Configuration {
    pub credential_key: String,
    pub strategy: ProviderCredentialRefreshStrategy,
    pub material: HashMap<String, String>,
    pub token_url: String,
    pub scopes: Vec<String>,
    pub refresh_before: Option<prost_types::Duration>,
    pub max_lifetime: Option<prost_types::Duration>,
    pub additional_outputs: HashMap<String, String>,
}
fn invalid() -> Status {
    Status::invalid_argument("invalid issuer grant configuration")
}
fn duration(value: Option<&prost_types::Duration>, default: Duration) -> Result<Duration, Status> {
    value
        .map(openshell_core::time::duration_to_std)
        .transpose()
        .map_err(|_| invalid())
        .map(|value| value.unwrap_or(default))
}
impl Configuration {
    fn plan(&self) -> Result<GrantPlan, Status> {
        let lead = duration(self.refresh_before.as_ref(), Duration::from_mins(5))?;
        let lifetime = duration(self.max_lifetime.as_ref(), Duration::from_hours(1))?;
        let seconds = lifetime
            .as_secs()
            .checked_add(u64::from(lifetime.subsec_nanos() != 0))
            .ok_or_else(invalid)?
            .max(1);
        let mut outputs = self
            .additional_outputs
            .clone()
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>();
        let primary = if self.strategy == ProviderCredentialRefreshStrategy::AwsStsAssumeRole {
            "access_key_id"
        } else {
            "access_token"
        };
        if outputs
            .insert(primary.into(), self.credential_key.clone())
            .is_some()
        {
            return Err(invalid());
        }
        Ok(GrantPlan {
            credential_key: self.credential_key.clone(),
            strategy: crate::provider_refresh::refresh_strategy_name(self.strategy as i32).into(),
            outputs,
            refresh_before_ms: u64::try_from(lead.as_millis()).map_err(|_| invalid())?,
            max_lifetime_seconds: u32::try_from(seconds).map_err(|_| invalid())?,
        })
    }
}
pub(in crate::grpc::provider) async fn configure(
    state: &Arc<ServerState>,
    source: &RemoteProviderSource,
    provider: &Provider,
    mut config: Configuration,
    facts: &Facts,
) -> Result<Response<ConfigureProviderRefreshResponse>, Status> {
    source.register_provider(provider)?;
    let plan = config.plan()?;
    let descriptor = source
        .issuer()
        .list_strategies()
        .await?
        .strategies
        .into_iter()
        .find(|descriptor| descriptor.name == plan.strategy)
        .ok_or_else(|| Status::failed_precondition("issuer grant strategy is unavailable"))?;
    // Classify by the pinned minter contract. Both configuration and material
    // are secret-annotated on the wire and encrypted by issuer-owned storage.
    for key in [
        "refresh_before_seconds",
        "max_lifetime_seconds",
        "scope",
        "scopes",
        "token_uri",
    ] {
        config.material.remove(key);
    }
    config.material.insert("token_url".into(), config.token_url);
    config
        .material
        .insert("scope".into(), config.scopes.join(" "));
    let mut material = HashMap::new();
    for field in &descriptor.secret_material {
        if let Some(value) = config.material.remove(&field.name) {
            material.insert(field.name.clone(), value);
        }
    }
    if config
        .material
        .keys()
        .any(|key| !descriptor.config.iter().any(|field| field.name == *key))
    {
        return Err(invalid());
    }
    publish_grant(
        state,
        source,
        provider,
        plan,
        &config.material,
        &material,
        facts,
    )
    .await
}

/// Shared publication path for built-in and registered custom strategies. Only
/// the value-free plan is journaled; inputs go directly to issuer initialization.
pub(super) async fn publish_grant(
    state: &Arc<ServerState>,
    source: &RemoteProviderSource,
    provider: &Provider,
    plan: GrantPlan,
    config: &HashMap<String, String>,
    material: &HashMap<String, String>,
    facts: &Facts,
) -> Result<Response<ConfigureProviderRefreshResponse>, Status> {
    let owned = StaticHandoff::published_for_provider(&state.store, source, provider).await?;
    let mut candidate = provider.clone();
    for handoff in owned.iter().filter(|handoff| handoff.grant_id().is_some()) {
        let binding = handoff.published_grant(provider)?;
        if binding.credential_key == plan.credential_key {
            for key in binding.credential_keys {
                candidate.credential_handles.remove(&key);
                candidate.credential_expiration_times.remove(&key);
            }
        } else if binding
            .credential_keys
            .iter()
            .any(|key| plan.outputs.values().any(|output| output == key))
        {
            return Err(Status::failed_precondition(
                "credential key is managed by another issuer grant",
            ));
        }
    }
    for key in plan.outputs.values() {
        candidate.credential_expiration_times.remove(key);
    }
    let mut handoff = StaticHandoff::begin_grant(
        &state.store,
        source,
        provider,
        plan,
        Some(provider.get_resource_version()),
    )
    .await?;
    let result = async {
        handoff.reserve(&state.store, source).await?;
        handoff
            .prepare_grant(&state.store, source, config, material)
            .await?;
        let status = source
            .issuer()
            .get_grant(wire::GetGrantRequest {
                grant: handoff.grant_id().ok_or_else(invalid)?.into(),
            })
            .await?
            .status
            .ok_or_else(invalid)?;
        candidate
            .credential_handles
            .extend(handoff.handles(source)?);
        super::publish(
            &state.store,
            source,
            &candidate,
            Some(provider),
            Some(provider.get_resource_version()),
            Some(&mut handoff),
        )
        .await?;
        let binding = handoff.published_grant(&candidate)?;
        let status = binding.project_status(&candidate, status)?;
        facts.issuer_refresh(binding, &status)?;
        Ok::<_, Status>(status)
    }
    .await;
    match result {
        Ok(status) => {
            super::super::publish_provider_change(
                state,
                provider.object_workspace(),
                provider.object_name(),
            );
            Ok(Response::new(ConfigureProviderRefreshResponse {
                status: Some(status),
            }))
        }
        Err(error) => {
            let _ = handoff.abort(&state.store, source).await;
            Err(error)
        }
    }
}
