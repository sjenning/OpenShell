// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Atomic publication of established refresh outputs without rewriting provider
//! references or changing their authorization epoch.

use crate::credentials::CredentialRuntime;
use crate::persistence::{AtomicWrite, ObjectType, Store};
use openshell_core::proto::Provider;
use openshell_core::{ObjectId, ObjectWorkspace};
use prost::Message as _;
use std::collections::HashMap;
use tonic::{Code, Status};

use super::{
    MintedCredential, StoredProviderCredentialRefreshState, completed_mint, get_refresh_state,
};

pub(super) async fn publish(
    store: &Store,
    credentials: &CredentialRuntime,
    compute: Option<&crate::compute::ComputeRuntime>,
    provider: &Provider,
    expected_versions: &HashMap<String, u64>,
    receipt: (&StoredProviderCredentialRefreshState, u64),
    minted: &MintedCredential,
) -> Result<u64, Status> {
    let (completion, expected_grant_revision) = receipt;
    let expected_attempt = completed_mint(completion)
        .ok_or_else(|| Status::failed_precondition("refresh completion receipt is missing"))?;
    let expiration = openshell_core::time::timestamp_from_millis(minted.expires_at_ms)
        .map_err(|error| Status::internal(error.to_string()))?;
    let mut values = minted.additional_credentials.clone();
    if values
        .insert(
            completion.credential_key.clone(),
            minted.access_token.clone(),
        )
        .is_some()
    {
        return Err(Status::failed_precondition("refresh outputs overlap"));
    }
    let staged = credentials
        .stage_refresh_reference_replacements(
            provider,
            expected_versions,
            &values,
            minted.expires_at_ms,
        )
        .await?;
    let mutation_guard = if let Some(compute) = compute {
        match compute
            .mutation_guard(crate::compute::MutationScope::Workspace(
                provider.object_workspace(),
            ))
            .await
        {
            Ok(guard) => Some(guard),
            Err(error) => {
                credentials
                    .abandon_refresh_reference_replacements(provider, &staged)
                    .await;
                return Err(crate::grpc::persistence_error_to_status(
                    error,
                    "acquire provider mutation lock",
                ));
            }
        }
    } else {
        None
    };
    let mut prepared = Vec::new();
    let result = async {
        // Validate the same logical provider projection as legacy publication,
        // but retain its stable handles and persist no provider mutation.
        let mut projection = provider.clone();
        for key in values.keys() {
            projection
                .credential_expiration_times
                .insert(key.clone(), expiration);
        }
        crate::grpc::provider::validate_provider_update_against_attached_sandboxes(
            store,
            provider.object_workspace(),
            &projection,
        )
        .await?;
        prepared = credentials
            .prepare_refresh_reference_writes(&staged)
            .await?;
        let mut writes = vec![AtomicWrite::Check {
            object_type: Provider::object_type().to_string(),
            id: provider.object_id().to_string(),
            expected_version: provider
                .metadata
                .as_ref()
                .map_or(0, |meta| meta.resource_version),
        }];
        for write in &prepared {
            writes.push(AtomicWrite::Update {
                object_type: crate::credentials::references::OBJECT_TYPE.to_string(),
                id: write.reference.clone(),
                payload: serde_json::to_vec(&write.state)
                    .map_err(|_| Status::internal("encode credential reference failed"))?,
                expected_version: write.expected_revision,
            });
        }
        writes.push(AtomicWrite::Update {
            object_type: StoredProviderCredentialRefreshState::object_type().to_string(),
            id: completion.object_id().to_string(),
            payload: completion.encode_to_vec(),
            expected_version: expected_grant_revision,
        });
        let results = store.write_atomically(&writes).await.map_err(|error| {
            crate::grpc::persistence_error_to_status(error, "commit refreshed references")
        })?;
        results
            .last()
            .and_then(Option::as_ref)
            .map(|result| result.resource_version)
            .ok_or_else(|| Status::internal("refresh publication returned no receipt"))
    }
    .await;
    // Driver cleanup can involve network I/O; never hold the workspace guard.
    drop(mutation_guard);
    match result {
        Ok(version) => {
            credentials
                .finish_refresh_reference_publication(provider, &prepared)
                .await;
            Ok(version)
        }
        Err(error) => {
            if matches!(
                error.code(),
                Code::Aborted
                    | Code::AlreadyExists
                    | Code::PermissionDenied
                    | Code::NotFound
                    | Code::InvalidArgument
                    | Code::FailedPrecondition
            ) {
                // Validation or an atomic precondition failed: no candidate was
                // published. Retain durable cleanup ownership before deletion.
                credentials
                    .abandon_refresh_reference_replacements(provider, &staged)
                    .await;
            } else if let Ok(Some(receipt)) = get_refresh_state(
                store,
                completion.object_workspace(),
                &completion.provider_id,
                &completion.credential_key,
            )
            .await
            {
                // A lost COMMIT acknowledgement is not proof of rollback.
                // Only this exact completed attempt establishes success.
                if receipt.status == "refreshed"
                    && completed_mint(&receipt) == Some(expected_attempt)
                {
                    credentials
                        .finish_refresh_reference_publication(provider, &prepared)
                        .await;
                    return Ok(receipt
                        .metadata
                        .as_ref()
                        .map_or(0, |meta| meta.resource_version));
                }
            }
            // Unknown outcomes retain candidates; deleting them might destroy
            // the published output. The grant's uncertainty fence remains.
            Err(error)
        }
    }
}
