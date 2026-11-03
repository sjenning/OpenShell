// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider delivery's read boundary. Gateway-internal secrets never use it.
use crate::{
    credentials::{CredentialRuntime, ResolvedProviderCredentials, references},
    persistence::Store,
};
use async_trait::async_trait;
use openshell_core::proto::{
    CredentialHandle, Provider, ProviderCredentialRefreshStatus, credentials::store::v1 as wire,
};
use openshell_credential_issuer::remote_issuer::WatchedIssuer;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tonic::Status;

/// Trusted gateway call-site purpose, never a public request selector. Issuer
/// caches bind this purpose alongside immutable owner and explicit version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialReadPurpose {
    SandboxDelivery,
    OperatorExport,
    Refresh,
}
impl CredentialReadPurpose {
    fn wire(self) -> wire::ResolvePurpose {
        match self {
            Self::SandboxDelivery => wire::ResolvePurpose::SandboxDelivery,
            Self::OperatorExport => wire::ResolvePurpose::OperatorExport,
            Self::Refresh => wire::ResolvePurpose::Refresh,
        }
    }
}
#[async_trait]
pub trait ProviderCredentialSource: std::fmt::Debug + Send + Sync {
    /// Opt in to issuer-owned mutation routing. Read-only injected sources do
    /// not silently gain embedded write authority.
    fn remote_mutations(&self) -> Option<&RemoteProviderSource> {
        None
    }
    /// Read issuer-owned refresh metadata. A selected source must not fall back
    /// to unrelated embedded grants, even when it is otherwise read-only.
    async fn refresh_statuses(
        &self,
        _store: &Store,
        _provider: &Provider,
        _credential_key: &str,
    ) -> Result<Vec<ProviderCredentialRefreshStatus>, Status> {
        Err(Status::failed_precondition(
            "selected credential source does not support refresh metadata",
        ))
    }
    /// Project current expiration without fetching secret values. Reconciled
    /// issuer metadata is authoritative after the initial legacy version.
    async fn project_expiration_metadata(
        &self,
        store: &Store,
        provider: &mut Provider,
    ) -> Result<(), Status>;
    /// Capture metadata without reading values. Remote implementations use only
    /// reconciled watch state, so intermediate-token cache hits never await an
    /// issuer. Unknown metadata fails closed rather than guessing version one.
    async fn reference_versions(
        &self,
        store: &Store,
        provider: &Provider,
    ) -> Result<HashMap<String, u64>, Status>;
    async fn resolve_provider_handles(
        &self,
        provider: &Provider,
        now_ms: i64,
    ) -> Result<ResolvedProviderCredentials, Status> {
        self.resolve_provider_handles_for(provider, now_ms, CredentialReadPurpose::SandboxDelivery)
            .await
    }
    async fn resolve_provider_handles_for(
        &self,
        provider: &Provider,
        now_ms: i64,
        purpose: CredentialReadPurpose,
    ) -> Result<ResolvedProviderCredentials, Status>;
}
#[async_trait]
impl ProviderCredentialSource for CredentialRuntime {
    async fn refresh_statuses(
        &self,
        store: &Store,
        provider: &Provider,
        credential_key: &str,
    ) -> Result<Vec<ProviderCredentialRefreshStatus>, Status> {
        use openshell_core::{ObjectId as _, ObjectWorkspace as _};
        let states = if credential_key.is_empty() {
            crate::provider_refresh::list_refresh_states_for_provider(store, provider.object_id())
                .await?
        } else {
            crate::provider_refresh::get_refresh_state(
                store,
                provider.object_workspace(),
                provider.object_id(),
                credential_key,
            )
            .await?
            .into_iter()
            .collect()
        };
        Ok(states
            .iter()
            .map(crate::provider_refresh::refresh_status_from_state)
            .collect())
    }
    async fn project_expiration_metadata(
        &self,
        store: &Store,
        provider: &mut Provider,
    ) -> Result<(), Status> {
        references::project_expiration_times(store, provider).await
    }
    async fn reference_versions(
        &self,
        store: &Store,
        provider: &Provider,
    ) -> Result<HashMap<String, u64>, Status> {
        references::versions(store, provider).await
    }
    async fn resolve_provider_handles_for(
        &self,
        provider: &Provider,
        now_ms: i64,
        _purpose: CredentialReadPurpose,
    ) -> Result<ResolvedProviderCredentials, Status> {
        Self::resolve_provider_handles(self, provider, now_ms).await
    }
}

pub mod handoff;

#[cfg(test)]
pub(crate) mod tests;

const DRIVER: &str = "credential-issuer";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerReferenceBinding {
    version: u32,
    source: String,
    reference: String,
    grant: Option<String>,
}
/// One explicitly configured issuer registration, not a storage driver. Handles
/// cannot be silently resolved by another registration or an embedded driver.
#[derive(Clone)]
pub struct RemoteProviderSource {
    name: Arc<str>,
    client: WatchedIssuer,
    max_batch: usize,
}
impl std::fmt::Debug for RemoteProviderSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteProviderSource")
            .field("registration", &self.name)
            .finish_non_exhaustive()
    }
}
fn invalid() -> Status {
    Status::failed_precondition("provider requires its configured credential issuer")
}
fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn owner(provider: &Provider, key: &str) -> Result<wire::SecretOwner, Status> {
    let metadata = provider.metadata.as_ref().ok_or_else(invalid)?;
    if !id(&metadata.id) || !id(&metadata.workspace) || !id(key) {
        return Err(invalid());
    }
    Ok(wire::SecretOwner {
        workspace: metadata.workspace.clone(),
        provider_id: metadata.id.clone(),
        credential_key: key.into(),
        provider: metadata.name.clone(),
    })
}
impl RemoteProviderSource {
    pub fn new(name: &str, client: WatchedIssuer) -> Result<Self, Status> {
        if name.is_empty()
            || name.len() > 128
            || !name.bytes().all(|value| {
                value.is_ascii_lowercase() || value.is_ascii_digit() || b"_.-".contains(&value)
            })
        {
            return Err(Status::invalid_argument(
                "invalid credential issuer registration",
            ));
        }
        let max_batch =
            usize::try_from(client.capabilities().max_batch_size).map_err(|_| invalid())?;
        Ok(Self {
            name: Arc::from(name),
            client,
            max_batch,
        })
    }
    pub fn reference_handle(
        &self,
        reference: &str,
        grant: Option<&str>,
    ) -> Result<CredentialHandle, Status> {
        if !id(reference) || grant.is_some_and(|value| !id(value)) {
            return Err(invalid());
        }
        let handle = serde_json::to_string(&IssuerReferenceBinding {
            version: 1,
            source: self.name.to_string(),
            reference: reference.into(),
            grant: grant.map(str::to_owned),
        })
        .map_err(|_| invalid())?;
        Ok(CredentialHandle {
            driver: DRIVER.into(),
            handle,
            metadata: HashMap::new(),
        })
    }
    fn decode(&self, handle: &CredentialHandle) -> Result<IssuerReferenceBinding, Status> {
        if handle.driver != DRIVER || !handle.metadata.is_empty() || handle.handle.len() > 1024 {
            return Err(invalid());
        }
        let reference: IssuerReferenceBinding =
            serde_json::from_str(&handle.handle).map_err(|_| invalid())?;
        if reference.version != 1
            || reference.source != self.name.as_ref()
            || !id(&reference.reference)
            || reference.grant.as_ref().is_some_and(|value| !id(value))
        {
            return Err(invalid());
        }
        Ok(reference)
    }
    /// Register persisted ownership and fixed grant outputs before watch
    /// synchronization. No backend reads and no legacy-handle adoption occur.
    pub fn register_provider(&self, provider: &Provider) -> Result<(), Status> {
        if !provider.credentials.is_empty() || provider.credential_handles.len() > self.max_batch {
            return Err(invalid());
        }
        for (key, handle) in &provider.credential_handles {
            let reference = self.decode(handle)?;
            self.client
                .track_secret(owner(provider, key)?, reference.reference)?;
            if let Some(grant) = reference.grant {
                self.client.track_grant(grant)?;
            }
        }
        Ok(())
    }
    pub(crate) fn issuer(&self) -> &WatchedIssuer {
        &self.client
    }
    pub(crate) async fn export_grants(
        &self,
        provider: &Provider,
        keys: &[String],
    ) -> Result<std::collections::BTreeSet<String>, Status> {
        self.register_provider(provider)?;
        let mut grants = std::collections::BTreeSet::new();
        let mut secrets = Vec::new();
        for key in keys {
            let binding = self.decode(
                provider
                    .credential_handles
                    .get(key)
                    .ok_or_else(|| Status::not_found("selected runtime credential is missing"))?,
            )?;
            secrets.push(wire::ResolveSecretRequest {
                request_id: key.clone(),
                owner: Some(owner(provider, key)?),
                reference: binding.reference,
                expected_version: None,
            });
            if let Some(grant) = binding.grant {
                grants.insert(grant);
            }
        }
        self.client
            .resolve_secrets(wire::ResolveSecretsRequest {
                purpose: wire::ResolvePurpose::MetadataInspection as i32,
                secrets,
            })
            .await?;
        Ok(grants)
    }
    fn metadata(
        &self,
        provider: &Provider,
    ) -> Result<HashMap<String, wire::ResolvedSecret>, Status> {
        self.register_provider(provider)?;
        provider
            .credential_handles
            .iter()
            .map(|(key, handle)| {
                let reference = self.decode(handle)?;
                Ok((
                    key.clone(),
                    self.client
                        .known_secret(&owner(provider, key)?, &reference.reference)?,
                ))
            })
            .collect()
    }
    fn expiration(
        provider: &Provider,
        key: &str,
        value: &wire::ResolvedSecret,
    ) -> Result<Option<i64>, Status> {
        let current = value
            .expiration_time
            .as_ref()
            .map(openshell_core::time::timestamp_to_millis)
            .transpose()
            .map_err(|_| invalid())?;
        if value.version > 1 {
            return Ok(current);
        }
        let legacy = provider
            .credential_expiration_times
            .get(key)
            .map(openshell_core::time::timestamp_to_millis)
            .transpose()
            .map_err(|_| invalid())?;
        Ok(match (legacy, current) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        })
    }
    /// Hydrate metadata without updating the provider spec or reading values.
    pub fn project_expiration_times(&self, provider: &mut Provider) -> Result<(), Status> {
        for (key, value) in self.metadata(provider)? {
            match Self::expiration(provider, &key, &value)? {
                Some(expiration) => {
                    provider.credential_expiration_times.insert(
                        key,
                        openshell_core::time::timestamp_from_millis(expiration)
                            .map_err(|_| invalid())?,
                    );
                }
                None => {
                    provider.credential_expiration_times.remove(&key);
                }
            }
        }
        Ok(())
    }
}
#[async_trait]
impl ProviderCredentialSource for RemoteProviderSource {
    async fn refresh_statuses(
        &self,
        store: &Store,
        provider: &Provider,
        credential_key: &str,
    ) -> Result<Vec<ProviderCredentialRefreshStatus>, Status> {
        handoff::StaticHandoff::refresh_statuses(store, self, provider, credential_key).await
    }
    fn remote_mutations(&self) -> Option<&RemoteProviderSource> {
        Some(self)
    }
    async fn project_expiration_metadata(
        &self,
        _store: &Store,
        provider: &mut Provider,
    ) -> Result<(), Status> {
        self.project_expiration_times(provider)
    }
    async fn reference_versions(
        &self,
        _store: &Store,
        provider: &Provider,
    ) -> Result<HashMap<String, u64>, Status> {
        Ok(self
            .metadata(provider)?
            .into_iter()
            .map(|(key, value)| (key, value.version))
            .collect())
    }
    async fn resolve_provider_handles_for(
        &self,
        provider: &Provider,
        now_ms: i64,
        purpose: CredentialReadPurpose,
    ) -> Result<ResolvedProviderCredentials, Status> {
        let metadata = self.metadata(provider)?;
        let mut result = ResolvedProviderCredentials::default();
        let mut requests = Vec::new();
        for (key, value) in &metadata {
            result.versions.insert(key.clone(), value.version);
            if value.pending_value {
                return Err(Status::failed_precondition(
                    "provider credential is awaiting its first value",
                ));
            }
            let expiration = Self::expiration(provider, key, value)?;
            if expiration.is_some_and(|expiration| expiration <= now_ms) {
                result.expired_keys.insert(key.clone());
                continue;
            }
            if let Some(expiration) = expiration {
                result.expires_at_ms.insert(key.clone(), expiration);
            }
            let reference = self.decode(&provider.credential_handles[key])?;
            requests.push(wire::ResolveSecretRequest {
                request_id: key.clone(),
                owner: Some(owner(provider, key)?),
                reference: reference.reference,
                expected_version: Some(value.version),
            });
        }
        if requests.is_empty() {
            return Ok(result);
        }
        let response = self
            .client
            .resolve_secrets(wire::ResolveSecretsRequest {
                secrets: requests,
                purpose: purpose.wire() as i32,
            })
            .await?;
        for value in response.secrets {
            let key = value.request_id;
            if result.versions.get(&key) != Some(&value.version) {
                return Err(Status::aborted(
                    "issuer value version changed during delivery",
                ));
            }
            if let Some(expiration) = value
                .expiration_time
                .as_ref()
                .map(openshell_core::time::timestamp_to_millis)
                .transpose()
                .map_err(|_| invalid())?
            {
                result
                    .expires_at_ms
                    .entry(key.clone())
                    .and_modify(|old| *old = (*old).min(expiration))
                    .or_insert(expiration);
            }
            if result.expires_at_ms.get(&key).is_some_and(|expiration| {
                *expiration <= crate::persistence::current_time_ms().max(now_ms)
            }) {
                result.expired_keys.insert(key);
            } else {
                result.values.insert(key, value.value);
            }
        }
        // Recheck local observations after the whole batch. No source can
        // return a mixed version snapshot even if a watch advances mid-read.
        let current = self
            .metadata(provider)?
            .into_iter()
            .map(|(key, value)| (key, value.version))
            .collect::<HashMap<_, _>>();
        if current != result.versions {
            return Err(Status::aborted("issuer reference changed during delivery"));
        }
        Ok(result)
    }
}
