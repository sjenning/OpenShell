// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Internal callers use typed issuer owners and the same bounded watched cache.
use super::{RemoteProviderSource, invalid, wire};
use crate::credentials::InternalSecretOwner;
use openshell_core::proto::CredentialHandle;
use openshell_credential_issuer::SecretOwnerKind;
use std::collections::HashMap;
use tonic::{Code, Status};
mod intent;
mod inventory;
#[cfg(test)]
mod tests;
use inventory::candidate_binding;
const SSH_CANDIDATE: &str = "sandbox_ssh_identity_candidate_v1";
const SSH_KEY: &str = "SSH_HOST_PRIVATE_KEY";
const SUPERVISOR_CANDIDATE: &str = "supervisor_instance_material_candidate";
const SUPERVISOR_KEY: &str = "SHARED_INSTANCE_LAUNCH_MATERIAL";

fn owner(owner: InternalSecretOwner<'_>, key: &str) -> Result<wire::SecretOwner, Status> {
    let kind = match owner.kind {
        SecretOwnerKind::Sandbox => wire::secret_owner::Kind::Sandbox(wire::SandboxSecretOwner {
            sandbox_id: owner.id.into(),
        }),
        SecretOwnerKind::SupervisorInstance => {
            wire::secret_owner::Kind::SupervisorInstance(wire::SupervisorInstanceSecretOwner {
                instance_id: owner.id.into(),
            })
        }
        SecretOwnerKind::Provider => {
            return Err(Status::invalid_argument(
                "internal secrets require a typed owner",
            ));
        }
    };
    Ok(wire::SecretOwner {
        workspace: owner.workspace.into(),
        credential_key: key.into(),
        kind: Some(kind),
        ..Default::default()
    })
}
impl RemoteProviderSource {
    pub(crate) fn register_internal(
        &self,
        identity: InternalSecretOwner<'_>,
        key: &str,
        handle: &CredentialHandle,
    ) -> Result<(), Status> {
        let binding = self.decode(handle)?;
        if binding.grant.is_some() {
            return Err(invalid());
        }
        self.client
            .track_secret(owner(identity, key)?, binding.reference)
    }
    pub(crate) async fn store_internal(
        &self,
        identity: InternalSecretOwner<'_>,
        operation: &str,
        values: &HashMap<String, String>,
    ) -> Result<HashMap<String, CredentialHandle>, Status> {
        if values.is_empty() {
            return Ok(HashMap::new());
        }
        if values.len() > self.max_batch || operation.is_empty() {
            return Err(invalid());
        }
        let mut intent = intent::Intent::begin(self, identity, operation, values).await?;
        let mut result = HashMap::new();
        for (key, value) in values {
            let owner = owner(identity, key)?;
            let id = intent::reservation_key(identity, operation, key)?;
            // Replay the value-free allocation after any lost acknowledgement;
            // its immutable reference precedes the conditional value fill.
            let reserved = self
                .client
                .reserve_secret(wire::ReserveSecretRequest {
                    owner: Some(owner.clone()),
                    idempotency_key: format!("internal-reserve:{id}"),
                })
                .await?;
            intent.bind(key, &reserved.reference).await?;
            let handle = self.reference_handle(&reserved.reference, None)?;
            result.insert(key.clone(), handle);
            // Never roll back an ambiguous remote write. Retain references
            // in the deterministic reservation for recovery/replay.
            self.client
                .put_secret(wire::PutSecretRequest {
                    owner: Some(owner),
                    reference: reserved.reference,
                    value: value.clone(),
                    expected_version: Some(1),
                    idempotency_key: format!("internal-fill:{id}"),
                    ..Default::default()
                })
                .await?;
        }
        Ok(result)
    }
    /// Include these writes in the SAME native transaction that creates the
    /// SSH identity or advances the supervisor reservation to published/admitting.
    /// Never publish with a separate `create_scoped`/`put_if` after this returns.
    pub(crate) async fn internal_publication_writes(
        &self,
        identity: InternalSecretOwner<'_>,
        operation: &str,
        candidate_id: &str,
        handles: &HashMap<String, CredentialHandle>,
    ) -> Result<Vec<crate::persistence::AtomicWrite>, Status> {
        intent::Intent::publication_writes(self, identity, operation, candidate_id, handles).await
    }
    pub(crate) async fn resolve_internal(
        &self,
        identity: InternalSecretOwner<'_>,
        handles: &HashMap<String, CredentialHandle>,
    ) -> Result<HashMap<String, String>, Status> {
        if handles.is_empty() {
            return Ok(HashMap::new());
        }
        if handles.len() > self.max_batch {
            return Err(invalid());
        }
        if !self.client.health()?.synchronized() {
            return Err(Status::unavailable(
                "internal issuer watch is not synchronized",
            ));
        }
        let mut secrets = Vec::new();
        for (key, handle) in handles {
            let binding = self.decode(handle)?;
            if binding.grant.is_some() {
                return Err(invalid());
            }
            let owner = owner(identity, key)?;
            self.client
                .track_secret(owner.clone(), binding.reference.clone())?;
            // Direct authorized metadata fetch on first use; values still use
            // the shared version/purpose cache and in-flight watch fences.
            let version = if let Ok(metadata) = self.client.known_secret(&owner, &binding.reference)
            {
                metadata.version
            } else {
                let metadata = self
                    .client
                    .resolve_secrets(wire::ResolveSecretsRequest {
                        secrets: vec![wire::ResolveSecretRequest {
                            request_id: key.clone(),
                            owner: Some(owner.clone()),
                            reference: binding.reference.clone(),
                            expected_version: None,
                        }],
                        purpose: wire::ResolvePurpose::MetadataInspection as i32,
                    })
                    .await?;
                metadata.secrets.first().ok_or_else(invalid)?.version
            };
            secrets.push(wire::ResolveSecretRequest {
                request_id: key.clone(),
                owner: Some(owner),
                reference: binding.reference,
                expected_version: Some(version),
            });
        }
        let response = self
            .client
            .resolve_secrets(wire::ResolveSecretsRequest {
                secrets,
                purpose: wire::ResolvePurpose::SandboxDelivery as i32,
            })
            .await?;
        Ok(response
            .secrets
            .into_iter()
            .map(|value| (value.request_id, value.value))
            .collect())
    }
    pub(crate) async fn delete_internal(
        &self,
        identity: InternalSecretOwner<'_>,
        handles: &HashMap<String, CredentialHandle>,
    ) -> Result<(), Status> {
        let mut first = None;
        for (key, handle) in handles {
            let binding = self.decode(handle)?;
            if binding.grant.is_some() {
                return Err(invalid());
            }
            let bytes = serde_json::to_vec(&(
                identity.workspace,
                identity.id,
                identity.kind,
                key,
                &binding.reference,
            ))
            .map_err(|_| invalid())?;
            let id = hex::encode(openshell_crypto::sha256(&bytes).map_err(|_| invalid())?);
            if let Err(error) = self
                .client
                .delete_secret(wire::DeleteSecretRequest {
                    owner: Some(owner(identity, key)?),
                    reference: binding.reference,
                    expected_version: None,
                    idempotency_key: format!("internal-delete:{id}"),
                })
                .await
                && error.code() != Code::NotFound
            {
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), Err)
    }
}

/// Register existing typed internal bindings before synchronizing watches.
/// Remote selection never adopts legacy local backends or loads a gateway KEK.
pub(super) async fn register_existing(
    store: &crate::persistence::Store,
    source: &RemoteProviderSource,
) -> Result<(), Status> {
    use crate::persistence::ObjectListQuery;
    use prost::Message as _;
    for kind in [
        "sandbox_ssh_identity_v1",
        "supervisor_instance_assignment",
        "supervisor_instance_material_candidate",
    ] {
        let mut cursor = None;
        loop {
            let page = store
                .list_object_page(kind, ObjectListQuery::AllWorkspaces, cursor.as_ref(), 128)
                .await
                .map_err(|_| Status::unavailable("internal issuer inventory unavailable"))?;
            for row in page.records {
                let value: serde_json::Value =
                    serde_json::from_slice(&row.payload).map_err(|_| invalid())?;
                let ssh = kind == "sandbox_ssh_identity_v1";
                let bytes = value
                    .get(if ssh {
                        "credential_handle"
                    } else {
                        "material_handle"
                    })
                    .and_then(|v| v.as_array())
                    .ok_or_else(invalid)?;
                if bytes.is_empty() {
                    continue;
                }
                let bytes = bytes
                    .iter()
                    .map(|n| {
                        n.as_u64()
                            .and_then(|n| u8::try_from(n).ok())
                            .ok_or_else(invalid)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let handle = CredentialHandle::decode(bytes.as_slice()).map_err(|_| invalid())?;
                let id = if ssh {
                    row.name.as_str()
                } else {
                    value
                        .get("route")
                        .and_then(|v| v.as_str())
                        .ok_or_else(invalid)?
                };
                let workspace = if ssh {
                    row.workspace.as_str()
                } else {
                    value
                        .get("workspace")
                        .and_then(|v| v.as_str())
                        .ok_or_else(invalid)?
                };
                source
                    .register_internal(
                        InternalSecretOwner {
                            kind: if ssh {
                                SecretOwnerKind::Sandbox
                            } else {
                                SecretOwnerKind::SupervisorInstance
                            },
                            name: "",
                            workspace,
                            id,
                        },
                        if ssh {
                            "SSH_HOST_PRIVATE_KEY"
                        } else {
                            "SHARED_INSTANCE_LAUNCH_MATERIAL"
                        },
                        &handle,
                    )
                    .map_err(|_| {
                        Status::failed_precondition(
                            "existing internal secrets require explicit issuer migration",
                        )
                    })?;
            }
            let Some(next) = page.next_cursor else {
                break;
            };
            cursor = Some(next);
        }
    }
    inventory::register_ssh_candidates(store, source).await
}
