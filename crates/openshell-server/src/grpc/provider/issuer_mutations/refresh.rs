// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Public grant mutations use immutable published ownership and issuer epochs.
use crate::{
    ServerState,
    compute::MutationScope,
    credential_source::{
        ProviderCredentialSource as _, RemoteProviderSource, handoff::StaticHandoff,
    },
    grpc::mutation_replay::ordinary::Facts,
};
use openshell_core::proto::{
    Provider, RotateProviderCredentialResponse, credentials::refresh::v1 as wire,
};
use tonic::{Response, Status};
pub(in crate::grpc::provider) async fn rotate(
    state: &std::sync::Arc<ServerState>,
    source: &RemoteProviderSource,
    workspace: &str,
    provider_name: &str,
    credential_key: &str,
    facts: &Facts,
) -> Result<Response<RotateProviderCredentialResponse>, Status> {
    let _guard = state
        .compute
        .mutation_guard(MutationScope::Workspace(workspace))
        .await
        .map_err(|error| {
            crate::grpc::persistence_error_to_status(error, "acquire provider mutation lock")
        })?;
    let provider = state
        .store
        .get_message_by_name::<Provider>(workspace, provider_name)
        .await
        .map_err(|_| Status::internal("fetch provider failed"))?
        .ok_or_else(|| Status::not_found("provider not found"))?;
    source.register_provider(&provider)?;
    let owned = StaticHandoff::published_for_provider(&state.store, source, &provider).await?;
    let mut selected = None;
    for handoff in owned
        .into_iter()
        .filter(|handoff| handoff.grant_id().is_some())
    {
        if handoff.is_detaching() {
            return Err(Status::failed_precondition(
                "provider refresh deletion is in progress",
            ));
        }
        let binding = handoff.published_grant(&provider)?;
        if binding.credential_key == credential_key && selected.replace(binding).is_some() {
            return Err(Status::failed_precondition(
                "issuer grant retirement ownership is missing",
            ));
        }
    }
    let binding =
        selected.ok_or_else(|| Status::not_found("provider refresh configuration not found"))?;
    // Validate the full bundle against issuer-owned immutable owners before any
    // upstream effect; gateway metadata alone cannot authorize another grant.
    source
        .export_grants(&provider, &binding.credential_keys)
        .await?;
    let status = source
        .issuer()
        .rotate_grant(wire::RotateGrantRequest {
            grant: binding.grant.clone(),
            idempotency_key: uuid::Uuid::new_v4().to_string(),
        })
        .await?
        .status
        .ok_or_else(|| Status::aborted("issuer grant status missing"))?;
    let current = binding
        .restore(&state.store)
        .await
        .map_err(|_| Status::aborted("provider changed during credential rotation"))?;
    let status = binding.project_status(&current, status)?;
    facts.issuer_refresh(binding, &status)?;
    super::super::publish_provider_change(state, workspace, provider_name);
    Ok(Response::new(RotateProviderCredentialResponse {
        status: Some(status),
    }))
}

pub(in crate::grpc::provider) async fn delete_refresh(
    state: &std::sync::Arc<ServerState>,
    source: &RemoteProviderSource,
    workspace: &str,
    provider_name: &str,
    credential_key: &str,
    allow_missing: bool,
) -> Result<Response<openshell_core::proto::DeleteProviderRefreshResponse>, Status> {
    let _guard = state
        .compute
        .mutation_guard(MutationScope::Workspace(workspace))
        .await
        .map_err(|error| {
            crate::grpc::persistence_error_to_status(error, "acquire provider mutation lock")
        })?;
    let provider = state
        .store
        .get_message_by_name::<Provider>(workspace, provider_name)
        .await
        .map_err(|_| Status::internal("fetch provider failed"))?
        .ok_or_else(|| Status::not_found("provider not found"))?;
    source.register_provider(&provider)?;
    let owned = StaticHandoff::published_for_provider(&state.store, source, &provider).await?;
    let mut selected = None;
    for handoff in owned
        .into_iter()
        .filter(|handoff| handoff.grant_id().is_some())
    {
        if handoff.published_grant(&provider)?.credential_key == credential_key
            && selected.replace(handoff).is_some()
        {
            return Err(Status::failed_precondition(
                "issuer grant retirement ownership is missing",
            ));
        }
    }
    let Some(mut handoff) = selected else {
        // Do not mistake a missing journal for an absent refresh configuration.
        if source
            .refresh_authorization_epochs(&provider)?
            .contains_key(credential_key)
        {
            return Err(Status::failed_precondition(
                "issuer grant retirement ownership is missing",
            ));
        }
        return Ok(Response::new(
            openshell_core::proto::DeleteProviderRefreshResponse {
                outcome: crate::grpc::deletion_outcome(
                    false,
                    allow_missing,
                    "provider refresh configuration",
                )?,
            },
        ));
    };
    handoff
        .begin_detach(&state.store, source, &provider)
        .await?;
    handoff.finish_detach(&state.store, source).await?;
    super::super::publish_provider_change(state, workspace, provider_name);
    Ok(Response::new(
        openshell_core::proto::DeleteProviderRefreshResponse {
            outcome: openshell_core::proto::DeletionOutcome::Completed.into(),
        },
    ))
}
