// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistence adapter and driver staging for embedded issuer references.

use async_trait::async_trait;
use openshell_credential_issuer::{
    ReferenceRegistry, ReferenceState, ReferenceStateStore, ReferenceWrite, SecretOwner,
    StoredReference,
};
use prost::Message as _;

use super::*;
use crate::persistence::ObjectType as _;

#[cfg(test)]
#[path = "credential_references/tests.rs"]
mod tests;

#[path = "credential_references/publication.rs"]
mod publication;

pub const OBJECT_TYPE: &str = "credential_reference_v1";

#[derive(Debug)]
struct DatabaseReferences(Arc<Store>);

#[async_trait]
impl ReferenceStateStore for DatabaseReferences {
    async fn load(&self, reference: &str) -> Result<Option<StoredReference>, Status> {
        self.0
            .get(OBJECT_TYPE, reference)
            .await
            .map_err(|error| persistence_status(error, "load credential reference"))?
            .map(|record| {
                let state = serde_json::from_slice(&record.payload)
                    .map_err(|_| Status::data_loss("invalid credential reference state"))?;
                Ok(StoredReference {
                    state,
                    revision: record.resource_version,
                })
            })
            .transpose()
    }

    async fn compare_and_swap(
        &self,
        reference: &str,
        expected_revision: Option<u64>,
        state: &ReferenceState,
    ) -> Result<(), Status> {
        let payload = serde_json::to_vec(state)
            .map_err(|_| Status::internal("encode credential reference failed"))?;
        self.0
            .put_if(
                OBJECT_TYPE,
                reference,
                reference,
                &state.owner.workspace,
                &payload,
                None,
                expected_revision.map_or(
                    WriteCondition::MustCreate,
                    WriteCondition::MatchResourceVersion,
                ),
            )
            .await
            .map_err(|error| persistence_status(error, "commit credential reference"))?;
        Ok(())
    }

    async fn compare_and_swap_many(&self, writes: &[ReferenceWrite]) -> Result<(), Status> {
        if writes.is_empty() {
            return Err(Status::invalid_argument(
                "credential replacement batch is empty",
            ));
        }
        let writes = writes
            .iter()
            .map(|write| {
                Ok(crate::persistence::AtomicWrite::Update {
                    object_type: OBJECT_TYPE.to_string(),
                    id: write.reference.clone(),
                    expected_version: write.expected_revision,
                    payload: serde_json::to_vec(&write.state)
                        .map_err(|_| Status::internal("encode credential reference failed"))?,
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;
        self.0
            .write_atomically(&writes)
            .await
            .map_err(|error| persistence_status(error, "commit credential references"))?;
        Ok(())
    }
}

fn persistence_status(error: PersistenceError, operation: &str) -> Status {
    match error {
        PersistenceError::UniqueViolation { .. } => {
            Status::already_exists("credential reference exists")
        }
        PersistenceError::Conflict { .. } => Status::aborted("credential reference changed"),
        _ => Status::unavailable(format!("{operation} failed")),
    }
}

pub fn new_registry(store: Arc<Store>) -> Arc<ReferenceRegistry> {
    Arc::new(ReferenceRegistry::new(Arc::new(DatabaseReferences(store))))
}

fn reference_key(handle: &CredentialHandle) -> Result<String, Status> {
    let driver = handle.driver.trim();
    let identity = format!("{}:{driver}{}", driver.len(), handle.handle);
    let digest = openshell_crypto::sha256(identity.as_bytes())
        .map_err(|_| Status::internal("credential reference identity hashing failed"))?;
    Ok(hex::encode(digest))
}

fn owner(scope: RefreshMaterialScope<'_>) -> SecretOwner {
    SecretOwner {
        workspace: scope.workspace.to_string(),
        provider_id: scope.provider_id.to_string(),
        credential_key: scope.credential_key.to_string(),
    }
}

pub fn provider_scope<'a>(provider: &'a Provider, key: &'a str) -> RefreshMaterialScope<'a> {
    let metadata = provider.metadata.as_ref();
    RefreshMaterialScope {
        provider_name: metadata.map_or("", |metadata| metadata.name.as_str()),
        workspace: metadata.map_or("", |metadata| metadata.workspace.as_str()),
        provider_id: metadata.map_or("", |metadata| metadata.id.as_str()),
        credential_key: key,
    }
}

/// Metadata-only observation for both configuration builders. Missing legacy
/// references start at version one; no secret backend is contacted here.
pub async fn versions(store: &Store, provider: &Provider) -> Result<HashMap<String, u64>, Status> {
    let registry = new_registry(Arc::new(store.clone()));
    let mut versions = HashMap::new();
    for (key, handle) in &provider.credential_handles {
        let state = registry
            .inspect(
                &reference_key(handle)?,
                &owner(provider_scope(provider, key)),
            )
            .await?;
        versions.insert(key.clone(), state.map_or(1, |state| state.version));
    }
    Ok(versions)
}

/// Hydrate public expiration metadata without rewriting the provider spec.
/// Later issuer versions supersede legacy provider-authored expiration fields.
pub async fn project_expiration_times(
    store: &Store,
    provider: &mut Provider,
) -> Result<(), Status> {
    let registry = new_registry(Arc::new(store.clone()));
    for (key, handle) in &provider.credential_handles {
        if let Some(state) = registry
            .inspect(
                &reference_key(handle)?,
                &owner(provider_scope(provider, key)),
            )
            .await?
            && state.version > 1
        {
            match state.expiration_time_ms.filter(|_| !state.revoked) {
                Some(expiration) => {
                    let timestamp = openshell_core::time::timestamp_from_millis(expiration)
                        .map_err(|_| {
                            Status::data_loss("invalid credential reference expiration")
                        })?;
                    provider
                        .credential_expiration_times
                        .insert(key.clone(), timestamp);
                }
                None => {
                    provider.credential_expiration_times.remove(key);
                }
            }
        }
    }
    Ok(())
}

/// Deliver embedded version commits through the existing provider fanout,
/// including peer replicas. Overflow invalidates all connected sessions rather
/// than silently dropping a rotation. The task does not keep the gateway alive.
pub fn spawn_reference_notifications(state: &Arc<crate::ServerState>) {
    let mut changes = state.credentials.reference_changes.subscribe();
    let state = Arc::downgrade(state);
    tokio::spawn(async move {
        loop {
            let event = changes.recv().await;
            let Some(state) = state.upgrade() else {
                break;
            };
            match event {
                Ok((workspace, provider)) => {
                    crate::config_delivery::publish_provider(&state, &workspace, &provider);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    crate::config_delivery::publish_all_connected(&state);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

impl CredentialRuntime {
    pub(crate) fn notify_reference_change(&self, scope: RefreshMaterialScope<'_>) {
        let _ = self
            .reference_changes
            .send((scope.workspace.to_string(), scope.provider_name.to_string()));
    }

    pub(super) async fn reference_state(
        &self,
        scope: RefreshMaterialScope<'_>,
        handle: &CredentialHandle,
    ) -> Result<Option<ReferenceState>, Status> {
        let Some(registry) = &self.references else {
            return Ok(None);
        };
        registry
            .adopt(
                &reference_key(handle)?,
                &owner(scope),
                handle.encode_to_vec(),
            )
            .await
            .map(Some)
    }

    /// Replace a value within an authorization epoch. Public provider mutation
    /// continues to stage NEW references; only issuer-owned rotation uses this.
    pub async fn rotate_provider_reference(
        &self,
        scope: RefreshMaterialScope<'_>,
        reference: &CredentialHandle,
        expected_version: u64,
        value: &str,
        expiration_time_ms: Option<i64>,
    ) -> Result<u64, Status> {
        let registry = self.references.as_ref().ok_or_else(|| {
            Status::failed_precondition("versioned references require a persistent store")
        })?;
        let driver_name = self
            .registry
            .driver_for_handle(scope.credential_key, reference)?;
        let driver = self.connected_driver(&driver_name)?;
        let key = reference_key(reference)?;
        let owner = owner(scope);
        let current = registry
            .adopt(&key, &owner, reference.encode_to_vec())
            .await?;
        if current.version != expected_version {
            return Err(Status::aborted("credential reference version changed"));
        }
        current
            .version
            .checked_add(1)
            .ok_or_else(|| Status::resource_exhausted("credential version exhausted"))?;
        let mut candidate = driver
            .store_credential(StoreCredentialRequest {
                provider: scope.provider_name.to_string(),
                credential_key: scope.credential_key.to_string(),
                value: value.to_string(),
                existing_handle: None,
                workspace: scope.workspace.to_string(),
                provider_id: scope.provider_id.to_string(),
                object_id: uuid::Uuid::new_v4().to_string(),
            })
            .await?;
        candidate.driver.clone_from(&driver_name);
        if candidate.handle.trim().is_empty() {
            return Err(Status::internal(
                "credential driver returned an empty rotation handle",
            ));
        }
        let backing = candidate.encode_to_vec();
        let result = registry
            .replace(
                &key,
                &owner,
                expected_version,
                backing.clone(),
                expiration_time_ms,
            )
            .await;
        let committed = match result {
            Ok(state) => state,
            Err(error) => {
                // A lost acknowledgement is not proof the CAS failed. Never
                // delete a candidate that may already be the published value.
                if let Ok(Some(state)) = registry.observe(&key, &owner).await
                    && state.backing == backing
                    && state.version == expected_version.saturating_add(1)
                {
                    state
                } else {
                    if matches!(
                        error.code(),
                        tonic::Code::Aborted
                            | tonic::Code::AlreadyExists
                            | tonic::Code::PermissionDenied
                            | tonic::Code::NotFound
                            | tonic::Code::InvalidArgument
                    ) {
                        let abandoned = registry
                            .abandon_candidate(&key, &owner, backing.clone())
                            .await?;
                        if let Err(cleanup) = self.cleanup_reference(scope, &key, &abandoned).await
                        {
                            warn!(code = ?cleanup.code(), "deferred abandoned credential candidate cleanup");
                        }
                    }
                    return Err(error);
                }
            }
        };
        self.notify_reference_change(scope);
        // Cleanup failure cannot roll back a committed version. Its handles
        // remain in durable state and are retried by subsequent mutation/delete.
        if let Err(error) = self.cleanup_reference(scope, &key, &committed).await {
            warn!(code = ?error.code(), "deferred retired credential handle cleanup");
        }
        Ok(committed.version)
    }

    pub(super) async fn revoke_reference(
        &self,
        scope: RefreshMaterialScope<'_>,
        handle: &CredentialHandle,
    ) -> Result<(), Status> {
        let registry = self
            .references
            .as_ref()
            .expect("persistent reference registry");
        let key = reference_key(handle)?;
        let owner = owner(scope);
        match registry.adopt(&key, &owner, handle.encode_to_vec()).await {
            Ok(_) => {}
            Err(error) if error.code() == tonic::Code::NotFound => {}
            Err(error) => return Err(error),
        }
        let state = registry.revoke(&key, &owner).await?;
        self.notify_reference_change(scope);
        self.cleanup_reference(scope, &key, &state).await
    }

    async fn cleanup_reference(
        &self,
        scope: RefreshMaterialScope<'_>,
        key: &str,
        state: &ReferenceState,
    ) -> Result<(), Status> {
        let registry = self
            .references
            .as_ref()
            .expect("persistent reference registry");
        for backing in &state.pending_deletions {
            let handle = CredentialHandle::decode(backing.as_slice())
                .map_err(|_| Status::data_loss("invalid reference cleanup handle"))?;
            self.delete_raw_handle(scope, handle).await?;
            registry
                .acknowledge_deletion(key, &owner(scope), backing)
                .await?;
        }
        Ok(())
    }

    async fn delete_raw_handle(
        &self,
        scope: RefreshMaterialScope<'_>,
        handle: CredentialHandle,
    ) -> Result<(), Status> {
        let driver_name = self
            .registry
            .driver_for_handle(scope.credential_key, &handle)?;
        self.connected_driver(&driver_name)?
            .delete_credential(DeleteCredentialRequest {
                provider: scope.provider_name.to_string(),
                credential_key: scope.credential_key.to_string(),
                handle: Some(handle),
                workspace: scope.workspace.to_string(),
                provider_id: scope.provider_id.to_string(),
            })
            .await
    }

    /// Paged, idempotent startup adoption. It changes neither provider records
    /// nor their authorization epochs and does not resolve secret values.
    pub async fn migrate_provider_references(&self, store: &Store) -> Result<(), Status> {
        let mut cursor = None;
        loop {
            let page = store
                .list_object_page(
                    Provider::object_type(),
                    crate::persistence::ObjectListQuery::AllWorkspaces,
                    cursor.as_ref(),
                    1000,
                )
                .await
                .map_err(|error| persistence_status(error, "list provider references"))?;
            for record in page.records {
                let provider = Provider::decode(record.payload.as_slice()).map_err(|_| {
                    Status::data_loss("invalid provider during reference migration")
                })?;
                for (key, handle) in &provider.credential_handles {
                    // A previous deletion may already have fenced a provider
                    // still awaiting its own CAS/cleanup. Do not resurrect it.
                    match self
                        .reference_state(provider_scope(&provider, key), handle)
                        .await
                    {
                        Ok(_) => {}
                        Err(error) if error.code() == tonic::Code::NotFound => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            let Some(next) = page.next_cursor else {
                return Ok(());
            };
            cursor = Some(next);
        }
    }
}
