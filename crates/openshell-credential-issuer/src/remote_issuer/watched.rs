// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded value cache and watch reconciliation for one authenticated issuer.
use super::{RemoteIssuer, refresh, store, validation};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, watch};
use tonic::Status;
mod cache;
mod controller;
#[cfg(test)]
mod tests;
const REFERENCES: usize = 4096;
const GRANTS: usize = 1024;
const VALUES: usize = 512;
const VALUE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Secrets,
    Grants,
}
#[derive(Clone, Debug)]
pub enum IssuerChange {
    Unknown(ChangeKind),
    Secret {
        reference: String,
        version: u64,
        revoked: bool,
    },
    Grant {
        grant: String,
        version: u64,
        deleted: bool,
    },
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WatchHealth {
    pub secrets: bool,
    pub grants: bool,
    pub generation: u64,
}
impl WatchHealth {
    #[must_use]
    pub const fn synchronized(self) -> bool {
        self.secrets && self.grants
    }
}

struct Secret {
    owner: store::SecretOwner,
    metadata: Option<store::ResolvedSecret>,
    version: u64,
    gone: bool,
}
struct Grant {
    metadata: Option<refresh::GrantStatus>,
    version: u64,
    gone: bool,
}
struct CachedCredential {
    value: store::ResolvedSecret,
    deadline: Instant,
    touched: Instant,
}
#[derive(Default)]
struct State {
    health: WatchHealth,
    secrets: BTreeMap<String, Secret>,
    grants: BTreeMap<String, Grant>,
    values: BTreeMap<(String, i32), CachedCredential>,
    bytes: usize,
}
struct Inner {
    client: RemoteIssuer,
    state: Mutex<State>,
    changes: broadcast::Sender<IssuerChange>,
    health: watch::Sender<WatchHealth>,
}
struct Workers(Vec<tokio::task::AbortHandle>);
impl Drop for Workers {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}
#[derive(Clone)]
pub struct WatchedIssuer {
    inner: Arc<Inner>,
    _workers: Arc<Workers>,
}
impl std::fmt::Debug for WatchedIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchedIssuer").finish_non_exhaustive()
    }
}
fn unavailable() -> Status {
    Status::unavailable("issuer watch metadata is not synchronized")
}
fn same_owner(a: &store::SecretOwner, b: &store::SecretOwner) -> bool {
    a.workspace == b.workspace
        && a.provider_id == b.provider_id
        && a.credential_key == b.credential_key
}
impl Inner {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>, Status> {
        self.state.lock().map_err(|_| unavailable())
    }
    fn send(&self, change: IssuerChange) {
        let _ = self.changes.send(change);
    }
    fn track_secret(&self, mut owner: store::SecretOwner, reference: String) -> Result<(), Status> {
        // Display names are audit-only and must not inflate retained bindings.
        owner.provider = String::new();
        if !validation::id(&reference)
            || !validation::id(&owner.workspace)
            || !validation::id(&owner.provider_id)
            || !validation::id(&owner.credential_key)
        {
            return Err(Status::invalid_argument("invalid issuer reference binding"));
        }
        let mut state = self.lock()?;
        if let Some(old) = state.secrets.get(&reference) {
            return if same_owner(&owner, &old.owner) {
                Ok(())
            } else {
                Err(Status::failed_precondition(
                    "issuer reference owner changed",
                ))
            };
        }
        if state.secrets.len() >= REFERENCES {
            return Err(Status::resource_exhausted(
                "issuer tracked reference limit reached",
            ));
        }
        state.secrets.insert(
            reference,
            Secret {
                owner,
                metadata: None,
                version: 0,
                gone: false,
            },
        );
        Ok(())
    }
    fn track_grant(&self, grant: String) -> Result<(), Status> {
        if !validation::id(&grant) {
            return Err(Status::invalid_argument("invalid issuer grant binding"));
        }
        let mut state = self.lock()?;
        if !state.grants.contains_key(&grant) {
            if state.grants.len() >= GRANTS {
                return Err(Status::resource_exhausted(
                    "issuer tracked grant limit reached",
                ));
            }
            state.grants.insert(
                grant,
                Grant {
                    metadata: None,
                    version: 0,
                    gone: false,
                },
            );
        }
        Ok(())
    }
    fn unknown(&self, kind: ChangeKind) -> Result<(), Status> {
        let mut state = self.lock()?;
        state.health.generation = state.health.generation.wrapping_add(1);
        state.values.clear();
        state.bytes = 0;
        match kind {
            ChangeKind::Secrets => {
                state.health.secrets = false;
                for entry in state.secrets.values_mut() {
                    entry.metadata = None;
                    entry.gone = false;
                }
            }
            ChangeKind::Grants => {
                state.health.grants = false;
                for entry in state.grants.values_mut() {
                    entry.metadata = None;
                    entry.gone = false;
                }
            }
        }
        self.health.send_replace(state.health);
        drop(state);
        self.send(IssuerChange::Unknown(kind));
        Ok(())
    }
    fn ready(&self, kind: ChangeKind) -> Result<(), Status> {
        let mut state = self.lock()?;
        match kind {
            ChangeKind::Secrets => state.health.secrets = true,
            ChangeKind::Grants => state.health.grants = true,
        }
        self.health.send_replace(state.health);
        Ok(())
    }
    fn invalidate_values(&self) -> Result<(), Status> {
        let mut state = self.lock()?;
        state.health.generation = state.health.generation.wrapping_add(1);
        state.values.clear();
        state.bytes = 0;
        for entry in state.secrets.values_mut() {
            entry.metadata = None;
        }
        drop(state);
        self.send(IssuerChange::Unknown(ChangeKind::Secrets));
        Ok(())
    }
}
impl WatchedIssuer {
    /// Requires a Tokio runtime. The last clone aborts only the watch workers;
    /// issuer work already admitted by a mutation remains cancellation-safe.
    #[must_use]
    pub fn new(client: RemoteIssuer) -> Self {
        let (changes, _) = broadcast::channel(128);
        let (health, _) = watch::channel(WatchHealth::default());
        let inner = Arc::new(Inner {
            client,
            state: Mutex::default(),
            changes,
            health,
        });
        let secrets = tokio::spawn(controller::secrets(inner.clone()));
        let grants = tokio::spawn(controller::grants(inner.clone()));
        Self {
            inner,
            _workers: Arc::new(Workers(vec![secrets.abort_handle(), grants.abort_handle()])),
        }
    }
    pub fn changes(&self) -> broadcast::Receiver<IssuerChange> {
        self.inner.changes.subscribe()
    }
    pub fn health(&self) -> Result<WatchHealth, Status> {
        Ok(self.inner.lock()?.health)
    }
    pub async fn wait_synchronized(&self, timeout: Duration) -> Result<(), Status> {
        let mut health = self.inner.health.subscribe();
        tokio::time::timeout(timeout, async move {
            loop {
                let observed = *health.borrow_and_update();
                if observed.synchronized() {
                    let state = self.inner.lock()?;
                    if state.health.synchronized()
                        && state
                            .secrets
                            .values()
                            .all(|entry| entry.gone || entry.metadata.is_some())
                        && state
                            .grants
                            .values()
                            .all(|entry| entry.gone || entry.metadata.is_some())
                    {
                        return Ok(());
                    }
                }
                health.changed().await.map_err(|_| unavailable())?;
            }
        })
        .await
        .map_err(|_| unavailable())?
    }
    /// Register persisted bindings before using local-only metadata getters.
    /// Registration never reads a value; the next checkpoint reconciles it.
    pub fn track_secret(&self, owner: store::SecretOwner, reference: String) -> Result<(), Status> {
        self.inner.track_secret(owner, reference)
    }
    pub fn track_grant(&self, grant: String) -> Result<(), Status> {
        self.inner.track_grant(grant)
    }
    pub fn known_secret(
        &self,
        owner: &store::SecretOwner,
        reference: &str,
    ) -> Result<store::ResolvedSecret, Status> {
        let state = self.inner.lock()?;
        if !state.health.synchronized() {
            return Err(unavailable());
        }
        let entry = state.secrets.get(reference).ok_or_else(unavailable)?;
        if !same_owner(owner, &entry.owner) {
            return Err(Status::permission_denied(
                "issuer reference owner does not match",
            ));
        }
        if entry.gone {
            return Err(Status::not_found("issuer reference unavailable"));
        }
        entry.metadata.clone().ok_or_else(unavailable)
    }
    pub fn known_grant(&self, grant: &str) -> Result<refresh::GrantStatus, Status> {
        let state = self.inner.lock()?;
        if !state.health.synchronized() {
            return Err(unavailable());
        }
        let entry = state.grants.get(grant).ok_or_else(unavailable)?;
        if entry.gone {
            return Err(Status::not_found("issuer grant unavailable"));
        }
        entry.metadata.clone().ok_or_else(unavailable)
    }
    pub async fn resolve_secrets(
        &self,
        request: store::ResolveSecretsRequest,
    ) -> Result<store::ResolveSecretsResponse, Status> {
        if prost::Message::encoded_len(&request) > super::LIMIT {
            return Err(Status::resource_exhausted(
                "remote issuer request exceeds limit",
            ));
        }
        validation::requests(&request, self.inner.client.capabilities().max_batch_size)?;
        let before = self.inner.lock()?.health;
        if let Some(response) = cache::get(&self.inner, &request)? {
            return Ok(response);
        }
        let mut response = self.inner.client.resolve_secrets(request.clone()).await?;
        cache::record(&self.inner, &request, &mut response, before)?;
        Ok(response)
    }
    pub async fn put_secret(
        &self,
        request: store::PutSecretRequest,
    ) -> Result<store::PutSecretResponse, Status> {
        let owner = request.owner.clone();
        let result = self.inner.client.put_secret(request).await;
        self.inner.invalidate_values()?;
        if let (Ok(response), Some(owner)) = (&result, owner) {
            self.track_secret(owner, response.reference.clone())?;
        }
        result
    }
    pub async fn delete_secret(
        &self,
        request: store::DeleteSecretRequest,
    ) -> Result<store::DeleteSecretResponse, Status> {
        let result = self.inner.client.delete_secret(request).await;
        self.inner.invalidate_values()?;
        result
    }
    pub async fn list_strategies(&self) -> Result<refresh::ListStrategiesResponse, Status> {
        self.inner.client.list_strategies().await
    }
    pub async fn create_grant(
        &self,
        request: refresh::CreateGrantRequest,
    ) -> Result<refresh::CreateGrantResponse, Status> {
        let owner = request.owner.clone();
        let outputs = request.outputs.clone();
        let result = self.inner.client.create_grant(request).await?;
        self.track_grant(result.grant.clone())?;
        if let Some(owner) = owner {
            for (id, reference) in &result.output_references {
                self.track_secret(
                    store::SecretOwner {
                        credential_key: outputs[id].clone(),
                        ..owner.clone()
                    },
                    reference.clone(),
                )?;
            }
        }
        Ok(result)
    }
    pub async fn get_grant(
        &self,
        request: refresh::GetGrantRequest,
    ) -> Result<refresh::GetGrantResponse, Status> {
        let response = self.inner.client.get_grant(request).await?;
        cache::grant(
            &self.inner,
            response.status.as_ref().ok_or_else(super::invalid)?,
        )?;
        Ok(response)
    }
    pub async fn delete_grant(
        &self,
        request: refresh::DeleteGrantRequest,
    ) -> Result<refresh::DeleteGrantResponse, Status> {
        let result = self.inner.client.delete_grant(request).await;
        self.inner.invalidate_values()?;
        result
    }
    pub async fn rotate_grant(
        &self,
        request: refresh::RotateGrantRequest,
    ) -> Result<refresh::RotateGrantResponse, Status> {
        let result = self.inner.client.rotate_grant(request).await;
        self.inner.invalidate_values()?;
        if let Ok(response) = &result {
            cache::grant(
                &self.inner,
                response.status.as_ref().ok_or_else(super::invalid)?,
            )?;
        }
        result
    }
    pub async fn ensure_fresh(
        &self,
        request: refresh::EnsureFreshRequest,
    ) -> Result<refresh::EnsureFreshResponse, Status> {
        let before = self
            .known_grant(&request.grant)
            .ok()
            .map(|value| value.version);
        let result = self.inner.client.ensure_fresh(request).await;
        if let Ok(response) = &result {
            let status = response.status.as_ref().ok_or_else(super::invalid)?;
            if before != Some(status.version) {
                self.inner.invalidate_values()?;
            }
            cache::grant(&self.inner, status)?;
        } else {
            self.inner.invalidate_values()?;
        }
        result
    }
}
