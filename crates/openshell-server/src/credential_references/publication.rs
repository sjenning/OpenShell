// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Staging and ownership for atomic refresh output publication.

use super::{
    CredentialRuntime, Provider, StoreCredentialRequest, owner, provider_scope, reference_key,
};
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
use openshell_credential_issuer::{ReferenceReplacement, ReferenceWrite};
use prost::Message as _;
use std::collections::HashMap;
use tonic::Status;
use tracing::warn;

impl CredentialRuntime {
    /// Only already-established, handle-backed output sets use stable rotation.
    /// First mint and legacy inline credentials retain their adoption path.
    pub(crate) async fn capture_refresh_reference_versions(
        &self,
        provider: &Provider,
        keys: &[String],
    ) -> Result<Option<HashMap<String, u64>>, Status> {
        if self.references.is_none()
            || !self.stores_provider_credentials()
            || keys.iter().any(|key| {
                !provider.credential_handles.contains_key(key)
                    || provider.credentials.contains_key(key)
            })
        {
            return Ok(None);
        }
        let mut versions = HashMap::new();
        for key in keys {
            let handle = &provider.credential_handles[key];
            let state = self
                .reference_state(provider_scope(provider, key), handle)
                .await?
                .ok_or_else(|| Status::failed_precondition("reference registry unavailable"))?;
            versions.insert(key.clone(), state.version);
        }
        Ok(Some(versions))
    }

    pub(crate) async fn stage_refresh_reference_replacements(
        &self,
        provider: &Provider,
        expected_versions: &HashMap<String, u64>,
        values: &HashMap<String, String>,
        expiration_time_ms: i64,
    ) -> Result<Vec<ReferenceReplacement>, Status> {
        if expected_versions.len() != values.len()
            || values
                .keys()
                .any(|key| !expected_versions.contains_key(key))
        {
            return Err(Status::failed_precondition(
                "refresh output set changed during minting",
            ));
        }
        let mut staged = Vec::new();
        for (key, value) in values {
            let result = async {
                let reference = provider
                    .credential_handles
                    .get(key)
                    .ok_or_else(|| Status::aborted("refresh output reference was removed"))?;
                let driver_name = self.registry.driver_for_handle(key, reference)?;
                let mut candidate = self
                    .connected_driver(&driver_name)?
                    .store_credential(StoreCredentialRequest {
                        provider: provider.object_name().to_string(),
                        credential_key: key.clone(),
                        value: value.clone(),
                        existing_handle: None,
                        workspace: provider.object_workspace().to_string(),
                        provider_id: provider.object_id().to_string(),
                        object_id: uuid::Uuid::new_v4().to_string(),
                    })
                    .await?;
                candidate.driver.clone_from(&driver_name);
                if candidate.handle.trim().is_empty() {
                    return Err(Status::internal(
                        "credential driver returned an empty rotation handle",
                    ));
                }
                Ok(ReferenceReplacement {
                    reference: reference_key(reference)?,
                    owner: owner(provider_scope(provider, key)),
                    expected_version: expected_versions[key],
                    backing: candidate.encode_to_vec(),
                    expiration_time_ms: Some(expiration_time_ms),
                })
            }
            .await;
            match result {
                Ok(replacement) => staged.push(replacement),
                Err(error) => {
                    self.abandon_refresh_reference_replacements(provider, &staged)
                        .await;
                    return Err(error);
                }
            }
        }
        Ok(staged)
    }

    pub(crate) async fn prepare_refresh_reference_writes(
        &self,
        replacements: &[ReferenceReplacement],
    ) -> Result<Vec<ReferenceWrite>, Status> {
        self.references
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("reference registry unavailable"))?
            .prepare_replacements(replacements)
            .await
    }

    pub(crate) async fn abandon_refresh_reference_replacements(
        &self,
        provider: &Provider,
        replacements: &[ReferenceReplacement],
    ) {
        let Some(registry) = &self.references else {
            return;
        };
        for replacement in replacements {
            let scope = provider_scope(provider, &replacement.owner.credential_key);
            let result = async {
                let state = registry
                    .abandon_candidate(
                        &replacement.reference,
                        &replacement.owner,
                        replacement.backing.clone(),
                    )
                    .await?;
                self.cleanup_reference(scope, &replacement.reference, &state)
                    .await
            }
            .await;
            if let Err(error) = result {
                warn!(code = ?error.code(), "deferred abandoned refresh output cleanup");
            }
        }
    }

    pub(crate) async fn finish_refresh_reference_publication(
        &self,
        provider: &Provider,
        writes: &[ReferenceWrite],
    ) {
        if let Some(first) = writes.first() {
            self.notify_reference_change(provider_scope(
                provider,
                &first.state.owner.credential_key,
            ));
        }
        for write in writes {
            let scope = provider_scope(provider, &write.state.owner.credential_key);
            if let Err(error) = self
                .cleanup_reference(scope, &write.reference, &write.state)
                .await
            {
                warn!(code = ?error.code(), "deferred retired refresh output cleanup");
            }
        }
    }
}
