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
mod mutations;
#[cfg(test)]
mod tests;
mod tracking;
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
    /// Notification epoch, including completed metadata reconciliation.
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
    terminal: bool,
    binding: Arc<()>,
    reservation: Option<[u8; 32]>,
    admissions: usize,
}
struct Grant {
    metadata: Option<refresh::GrantStatus>,
    version: u64,
    gone: bool,
    terminal: bool,
    binding: Arc<()>,
    reservation: Option<tracking::GrantReservation>,
    admissions: usize,
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
    // Completion notifications must not invalidate in-flight values. Metadata
    // uses independent epochs so the controllers cannot starve each other.
    value_generation: u64,
    secret_generation: u64,
    grant_generation: u64,
    secrets_reconciled: bool,
    grants_reconciled: bool,
    reserved_secrets: usize,
    reserved_grants: usize,
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
    match (
        crate::SecretOwner::from_wire(a),
        crate::SecretOwner::from_wire(b),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
impl State {
    fn values_changed(&mut self) {
        self.value_generation = self.value_generation.wrapping_add(1);
        self.health.generation = self.health.generation.wrapping_add(1);
    }
    fn clear_values(&mut self) {
        self.values_changed();
        self.values.clear();
        self.bytes = 0;
    }
}
impl Inner {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>, Status> {
        self.state.lock().map_err(|_| unavailable())
    }
    fn send(&self, change: IssuerChange) {
        let _ = self.changes.send(change);
    }
    fn unknown(&self, kind: ChangeKind) -> Result<(), Status> {
        let mut state = self.lock()?;
        state.clear_values();
        match kind {
            ChangeKind::Secrets => {
                state.health.secrets = false;
                state.secret_generation = state.secret_generation.wrapping_add(1);
                state.secrets_reconciled = false;
                for entry in state.secrets.values_mut() {
                    entry.metadata = None;
                    entry.gone &= entry.terminal;
                }
            }
            ChangeKind::Grants => {
                state.health.grants = false;
                state.grant_generation = state.grant_generation.wrapping_add(1);
                state.grants_reconciled = false;
                for entry in state.grants.values_mut() {
                    entry.metadata = None;
                    entry.gone &= entry.terminal;
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
        let recovered = match kind {
            ChangeKind::Secrets => {
                state.health.secrets = true;
                let complete = state
                    .secrets
                    .values()
                    .all(|entry| entry.gone || entry.metadata.is_some());
                let recovered = complete && !state.secrets_reconciled;
                state.secrets_reconciled = complete;
                recovered
            }
            ChangeKind::Grants => {
                state.health.grants = true;
                let complete = state
                    .grants
                    .values()
                    .all(|entry| entry.gone || entry.metadata.is_some());
                let recovered = complete && !state.grants_reconciled;
                state.grants_reconciled = complete;
                recovered
            }
        };
        if recovered {
            // Per-batch publications may have exposed this generation while
            // other bindings were still unknown. Make final recovery distinct,
            // without fencing unrelated RPCs or notifying on idle checkpoints.
            state.health.generation = state.health.generation.wrapping_add(1);
        }
        self.health.send_replace(state.health);
        Ok(())
    }
    fn invalidate_values(&self) -> Result<(), Status> {
        let mut state = self.lock()?;
        state.secret_generation = state.secret_generation.wrapping_add(1);
        state.secrets_reconciled = false;
        state.clear_values();
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
    #[must_use]
    pub fn capabilities(&self) -> &store::GetCapabilitiesResponse {
        self.inner.client.capabilities()
    }
    pub fn changes(&self) -> broadcast::Receiver<IssuerChange> {
        self.inner.changes.subscribe()
    }
    /// Observe reconciliation boundaries as well as value-free change events.
    /// A healthy transition requires consumers to rebuild snapshots that failed
    /// while metadata was unknown, even if no value version changed.
    pub fn health_changes(&self) -> watch::Receiver<WatchHealth> {
        self.inner.health.subscribe()
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
        let before = self.inner.observe_secrets(&request)?;
        if let Some(response) = cache::get(&self.inner, &request)? {
            return Ok(response);
        }
        let mut response = self.inner.client.resolve_secrets(request.clone()).await?;
        cache::record(&self.inner, &request, &mut response, &before)?;
        Ok(response)
    }
    pub async fn reserve_secret(
        &self,
        request: store::ReserveSecretRequest,
    ) -> Result<store::ReserveSecretResponse, Status> {
        let owner = tracking::owner(
            request
                .owner
                .clone()
                .ok_or_else(|| Status::invalid_argument("issuer owner is required"))?,
        )?;
        let intent = mutations::secret_intent(&request, &owner)?;
        let admission = self.inner.admit_secret_reservation(intent)?;
        let result = self.inner.client.reserve_secret(request).await;
        self.inner.after_mutation(self.inner.invalidate_values());
        if let Ok(response) = &result {
            self.inner
                .after_mutation(admission.commit_secret_reservation(intent, response, owner));
        }
        result
    }
    pub async fn put_secret(
        &self,
        request: store::PutSecretRequest,
    ) -> Result<store::PutSecretResponse, Status> {
        let owner = tracking::owner(
            request
                .owner
                .clone()
                .ok_or_else(|| Status::invalid_argument("issuer owner is required"))?,
        )?;
        let admission = if request.reference.is_empty() {
            Some(self.inner.admit(1, 0)?)
        } else {
            self.track_secret(owner.clone(), request.reference.clone())?;
            None
        };
        let result = self.inner.client.put_secret(request).await;
        self.inner.after_mutation(self.inner.invalidate_values());
        if let (Ok(response), Some(admission)) = (&result, admission) {
            self.inner.after_mutation(
                admission.commit(vec![(response.reference.clone(), owner)], vec![]),
            );
        }
        result
    }
    pub async fn delete_secret(
        &self,
        request: store::DeleteSecretRequest,
    ) -> Result<store::DeleteSecretResponse, Status> {
        let reference = request.reference.clone();
        let result = self.inner.client.delete_secret(request).await;
        self.inner.after_mutation(self.inner.invalidate_values());
        if let Ok(response) = &result {
            self.inner.after_mutation(
                self.inner
                    .lock()
                    .map(|mut state| state.retire_secret(&reference, response.version)),
            );
        }
        result
    }
    pub async fn list_strategies(&self) -> Result<refresh::ListStrategiesResponse, Status> {
        self.inner.client.list_strategies().await
    }
    pub async fn create_grant(
        &self,
        request: refresh::CreateGrantRequest,
    ) -> Result<refresh::CreateGrantResponse, Status> {
        let owners = mutations::output_owners(request.owner.clone(), &request.outputs)?;
        let admission = self.inner.admit(owners.len(), 1)?;
        let result = self.inner.client.create_grant(request).await;
        self.inner.after_mutation(self.inner.invalidate_values());
        if let Ok(response) = &result {
            self.inner.after_mutation(admission.commit(
                mutations::bindings(&owners, &response.output_references),
                vec![response.grant.clone()],
            ));
        }
        result
    }
    pub async fn reserve_grant(
        &self,
        request: refresh::ReserveGrantRequest,
    ) -> Result<refresh::ReserveGrantResponse, Status> {
        let owners = mutations::output_owners(request.owner.clone(), &request.outputs)?;
        let intent = mutations::grant_intent(&request)?;
        let admission = self.inner.admit_grant_reservation(intent, &owners)?;
        let result = self.inner.client.reserve_grant(request).await;
        self.inner.after_mutation(self.inner.invalidate_values());
        if let Ok(response) = &result {
            self.inner
                .after_mutation(admission.commit_grant_reservation(
                    intent,
                    mutations::bindings(&owners, &response.output_references),
                    response,
                ));
        }
        result
    }
    pub async fn initialize_grant(
        &self,
        request: refresh::InitializeGrantRequest,
    ) -> Result<refresh::InitializeGrantResponse, Status> {
        let before = self.inner.observe_grant(&request.grant)?;
        let result = self.inner.client.initialize_grant(request).await;
        self.inner.after_mutation(
            self.inner.mutation_status(
                before,
                result
                    .as_ref()
                    .ok()
                    .and_then(|response| response.status.as_ref()),
                true,
            ),
        );
        result
    }
    pub async fn get_grant(
        &self,
        request: refresh::GetGrantRequest,
    ) -> Result<refresh::GetGrantResponse, Status> {
        let before = self.inner.observe_grant(&request.grant)?;
        let response = self.inner.client.get_grant(request).await?;
        cache::grant(
            &self.inner,
            response.status.as_ref().ok_or_else(super::invalid)?,
            &before,
        )?;
        Ok(response)
    }
    pub async fn delete_grant(
        &self,
        request: refresh::DeleteGrantRequest,
    ) -> Result<refresh::DeleteGrantResponse, Status> {
        let grant = request.grant.clone();
        let result = self.inner.client.delete_grant(request).await;
        self.inner.after_mutation(self.inner.invalidate_values());
        if result.is_ok() {
            self.inner.after_mutation(
                self.inner
                    .lock()
                    .map(|mut state| state.retire_grant(&grant, 0)),
            );
        }
        result
    }
    pub async fn detach_grant(
        &self,
        request: refresh::DetachGrantRequest,
    ) -> Result<refresh::DetachGrantResponse, Status> {
        // Detach retires only the grant. Published output references remain
        // actively tracked, with unchanged values, versions and expiration.
        let grant = request.grant.clone();
        let result = self.inner.client.detach_grant(request).await;
        if result.is_ok() {
            self.inner.after_mutation(
                self.inner
                    .lock()
                    .map(|mut state| state.retire_grant(&grant, 0)),
            );
        }
        result
    }
    pub async fn rotate_grant(
        &self,
        request: refresh::RotateGrantRequest,
    ) -> Result<refresh::RotateGrantResponse, Status> {
        let before = self.inner.observe_grant(&request.grant)?;
        let result = self.inner.client.rotate_grant(request).await;
        self.inner.after_mutation(
            self.inner.mutation_status(
                before,
                result
                    .as_ref()
                    .ok()
                    .and_then(|response| response.status.as_ref()),
                true,
            ),
        );
        result
    }
    pub async fn ensure_fresh(
        &self,
        request: refresh::EnsureFreshRequest,
    ) -> Result<refresh::EnsureFreshResponse, Status> {
        let version = self
            .known_grant(&request.grant)
            .ok()
            .map(|value| value.version);
        let before = self.inner.observe_grant(&request.grant)?;
        let result = self.inner.client.ensure_fresh(request).await;
        let status = result
            .as_ref()
            .ok()
            .and_then(|response| response.status.as_ref());
        let invalidate = status.is_none_or(|status| version != Some(status.version));
        self.inner
            .after_mutation(self.inner.mutation_status(before, status, invalidate));
        result
    }
}
