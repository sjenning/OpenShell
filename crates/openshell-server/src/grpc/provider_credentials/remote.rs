// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Issuer-owned freshness and purpose-scoped operator delivery.
use super::{
    Duration, GetProviderCredentialsRequest, GetProviderCredentialsResponse, MAX_RESPONSE_BYTES,
    Provider, RefreshAudit, ServerState, Status, load, resolve_selected, sanitize,
    sufficiently_valid,
};
use crate::credential_source::RemoteProviderSource;
use openshell_core::{
    ObjectId as _,
    proto::{ProviderCredentialValue, ProviderProfile, credentials::refresh::v1 as wire},
};
use std::collections::BTreeMap;
pub(super) async fn retrieve(
    state: &ServerState,
    source: &RemoteProviderSource,
    request: &GetProviderCredentialsRequest,
    provider: &Provider,
    profile: &ProviderProfile,
    lifetime: Duration,
    audit: &mut RefreshAudit,
) -> Result<GetProviderCredentialsResponse, Status> {
    let workspace = openshell_core::ObjectWorkspace::object_workspace(provider);
    // Validate the complete immutable binding set before any freshness effect.
    let grants = source
        .export_grants(provider, &request.credential_keys)
        .await
        .map_err(sanitize)?;
    let mut statuses = BTreeMap::new();
    for grant in grants {
        let status = source
            .issuer()
            .get_grant(wire::GetGrantRequest {
                grant: grant.clone(),
            })
            .await
            .map_err(sanitize)?
            .status
            .ok_or_else(|| Status::aborted("issuer grant status missing"))?;
        if matches!(status.state.as_str(), "deleting" | "deleted") {
            return Err(Status::failed_precondition(
                "issuer refresh is being deleted",
            ));
        }
        statuses.insert(grant, status);
    }
    let mut versions = BTreeMap::new();
    for (grant, mut status) in statuses {
        let reusable = status.expiration_time.is_some()
            && sufficiently_valid(
                Some(&ProviderCredentialValue {
                    value: String::new(),
                    expiration_time: status.expiration_time,
                }),
                lifetime,
            )?;
        if !reusable {
            audit.attempts += 1;
            status = source
                .issuer()
                .ensure_fresh(wire::EnsureFreshRequest {
                    grant: grant.clone(),
                    min_remaining: Some(
                        openshell_core::time::duration_from_std(lifetime)
                            .map_err(|_| Status::invalid_argument("invalid remaining lifetime"))?,
                    ),
                })
                .await
                .map_err(sanitize)?
                .status
                .ok_or_else(|| Status::aborted("issuer grant status missing"))?;
            audit.completed += 1;
        }
        versions.insert(grant, status.version);
    }
    if !versions.is_empty() {
        source
            .issuer()
            .wait_synchronized(Duration::from_secs(10))
            .await
            .map_err(sanitize)?;
    }
    let current = load(state, workspace, &request.name).await?;
    if current
        .metadata
        .as_ref()
        .map(|meta| (&meta.id, meta.resource_version))
        != provider
            .metadata
            .as_ref()
            .map(|meta| (&meta.id, meta.resource_version))
    {
        return Err(Status::aborted(
            "provider changed during credential freshness",
        ));
    }
    let values = resolve_selected(state, &current, &request.credential_keys).await?;
    for (grant, version) in versions {
        let latest = source
            .issuer()
            .get_grant(wire::GetGrantRequest { grant })
            .await
            .map_err(sanitize)?
            .status
            .ok_or_else(|| Status::aborted("issuer grant status missing"))?;
        if latest.version != version || matches!(latest.state.as_str(), "deleting" | "deleted") {
            return Err(Status::aborted("issuer refresh changed during retrieval"));
        }
    }
    let latest = load(state, workspace, &request.name).await?;
    if latest.object_id() != current.object_id()
        || latest.metadata.as_ref().map(|meta| meta.resource_version)
            != current.metadata.as_ref().map(|meta| meta.resource_version)
    {
        return Err(Status::aborted(
            "provider changed during credential resolution",
        ));
    }
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, workspace)
        .await
        .map_err(sanitize)?;
    if super::super::provider::get_provider_type_profile_for_scope(
        &catalog,
        &current.r#type,
        &current.profile_workspace,
    )
    .map(|profile| profile.to_proto())
    .as_ref()
        != Some(profile)
    {
        return Err(Status::aborted(
            "provider credential declarations changed during retrieval",
        ));
    }
    if values
        .iter()
        .map(|(key, value)| key.len() + value.value.len() + 64)
        .sum::<usize>()
        > MAX_RESPONSE_BYTES
    {
        return Err(Status::resource_exhausted(
            "credential response exceeds 1 MiB",
        ));
    }
    for key in &request.credential_keys {
        if !sufficiently_valid(values.get(key), lifetime)? {
            return Err(Status::failed_precondition(
                "credential cannot meet the requested remaining lifetime",
            ));
        }
    }
    Ok(GetProviderCredentialsResponse {
        credentials: values,
    })
}
