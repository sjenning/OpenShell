// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authenticated private `CredentialStore` RPC host. No gateway API or database.

use crate::{
    ReferenceState, ReferenceStateStore, SecretOwner,
    auth::{GatewayPolicy, GatewayScope},
    refresh::RefreshCoordinator,
    repository::Repository,
    storage::CredentialStorage,
};
use openshell_core::proto::credentials::store::v1 as wire;
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};

mod grants;
mod maintenance;
mod migration;
pub use migration::LegacyReference;
mod mutations;
mod reservations;
pub use grants::CredentialRefreshService;
pub use grants::migration::{
    LegacyGrant, LegacyGrantActivation, LegacyGrantActivationPage, LegacyGrantOutput,
    LegacyGrantStatus,
};
mod watch;

const MESSAGE_LIMIT: usize = 1024 * 1024;
const BATCH_LIMIT: usize = 64;
const VALUE_PURPOSE: &str = "provider-value-v1";
const IDEMPOTENCY_KIND: &str = "secret-idempotency-v1";
const CANDIDATE_KIND: &str = "secret-candidate-v1";

#[derive(Clone)]
pub struct CredentialStoreService {
    runtime: Arc<Runtime>,
}
impl std::fmt::Debug for CredentialStoreService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialStoreService(<redacted>)")
    }
}
struct Runtime {
    repository: Arc<Repository>,
    storage: CredentialStorage,
    policy: GatewayPolicy,
    coordinator: RefreshCoordinator,
    reads: Arc<Semaphore>,
    watches: Arc<Semaphore>,
    watch_shutdown: tokio::sync::watch::Sender<bool>,
    cache_ttl: Duration,
}
#[derive(Serialize, Deserialize)]
struct Receipt {
    operation: String,
    owner: SecretOwner,
    reference: String,
    version: u64,
    fingerprint: Vec<u8>,
    created_at_ms: i64,
    #[serde(default = "completed_receipt")]
    completed: bool,
    /// Secret-free encoded RPC result for grant operations. Legacy static
    /// operations retain their reference/version projection above.
    #[serde(default)]
    response: Vec<u8>,
    #[serde(default)]
    result_code: i32,
}
fn completed_receipt() -> bool {
    true
}
impl Receipt {
    fn require_completed(&self) -> Result<(), Status> {
        if !self.completed {
            return Err(Status::failed_precondition(
                "issuer operation has an unresolved outcome",
            ));
        }
        if self.result_code != 0 {
            return Err(Status::new(
                tonic::Code::from_i32(self.result_code),
                "issuer operation failed; inspect grant status",
            ));
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
struct Candidate {
    operation_key: String,
    owner: SecretOwner,
    purpose: String,
    backing: Vec<u8>,
}

fn owner(owner: Option<&wire::SecretOwner>) -> Result<SecretOwner, Status> {
    let owner = owner.ok_or_else(|| Status::invalid_argument("issuer secret owner is required"))?;
    SecretOwner::from_wire(owner)
}
fn now_ms() -> Result<i64, Status> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .ok_or_else(|| Status::unavailable("issuer clock unavailable"))
}
fn hex_digest(bytes: &[u8]) -> Result<String, Status> {
    use std::fmt::Write as _;
    let digest = openshell_crypto::sha256(bytes)
        .map_err(|_| Status::unavailable("issuer intent fingerprint unavailable"))?;
    let mut result = String::with_capacity(64);
    for byte in digest {
        write!(result, "{byte:02x}").expect("writing String cannot fail");
    }
    Ok(result)
}
fn idempotency(key: &str) -> Result<String, Status> {
    if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
        return Err(Status::invalid_argument(
            "issuer idempotency key must be nonempty and at most 128 bytes",
        ));
    }
    hex_digest(format!("openshell.issuer.idempotency-key.v1\0{key}").as_bytes())
}
fn valid_reference(reference: &str) -> Result<(), Status> {
    if reference.is_empty() || reference.len() > 256 || reference.chars().any(char::is_control) {
        return Err(Status::invalid_argument(
            "invalid issuer credential reference",
        ));
    }
    Ok(())
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Status> {
    serde_json::from_slice(bytes)
        .map_err(|_| Status::data_loss("invalid issuer operation metadata"))
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Status> {
    serde_json::to_vec(value)
        .map_err(|_| Status::internal("issuer operation metadata encoding failed"))
}
fn same_value(a: &ReferenceState, b: &ReferenceState) -> bool {
    a.owner == b.owner
        && a.version == b.version
        && a.backing == b.backing
        && a.expiration_time_ms == b.expiration_time_ms
        && a.revoked == b.revoked
        && a.pending_value == b.pending_value
}
fn unexpired(expiration: Option<i64>, now: i64) -> Result<(), Status> {
    if expiration.is_some_and(|expiration| expiration <= now) {
        return Err(Status::failed_precondition("issuer credential is expired"));
    }
    Ok(())
}

impl CredentialStoreService {
    /// Host the same store handlers in process with a fixed local gateway
    /// identity. No operator workspace allowlist or transport listener is used.
    pub fn embedded(
        repository: Arc<Repository>,
        storage: CredentialStorage,
        cache_ttl: Duration,
    ) -> Result<Self, Status> {
        Self::new(repository, storage, GatewayPolicy::embedded()?, cache_ttl)
    }

    /// Fixed trusted scope for Rust-only embedded migration/maintenance. This
    /// does not accept an identity, workspace allowlist, or RPC metadata, and
    /// fails when called on a remotely authenticated service.
    pub fn embedded_scope(&self) -> Result<GatewayScope, Status> {
        self.runtime
            .policy
            .authenticate(&crate::auth::local_request(Request::new(())))
    }

    pub fn new(
        repository: Arc<Repository>,
        storage: CredentialStorage,
        policy: GatewayPolicy,
        cache_ttl: Duration,
    ) -> Result<Self, Status> {
        if cache_ttl > Duration::from_mins(1) {
            return Err(Status::invalid_argument(
                "issuer credential cache TTL exceeds one minute",
            ));
        }
        Ok(Self {
            runtime: Arc::new(Runtime {
                repository,
                storage,
                policy,
                coordinator: RefreshCoordinator::default(),
                reads: Arc::new(Semaphore::new(16)),
                watches: Arc::new(Semaphore::new(128)),
                watch_shutdown: tokio::sync::watch::channel(false).0,
                cache_ttl,
            }),
        })
    }
    pub fn into_service(self) -> wire::credential_store_server::CredentialStoreServer<Self> {
        wire::credential_store_server::CredentialStoreServer::new(self)
            .max_decoding_message_size(MESSAGE_LIMIT)
            .max_encoding_message_size(MESSAGE_LIMIT)
    }
    /// Stop new mutations and terminate value-free store/grant watches. Stop
    /// scheduler handles too; reads already in progress may finish normally.
    pub fn stop_admission(&self) {
        self.runtime.coordinator.stop_admission();
        self.runtime.watch_shutdown.send_replace(true);
    }
    /// Wait for detached admitted mutations, even if their caller disconnected.
    /// Hosts may bound this wait, but must not classify a timeout as safe retry.
    pub async fn drain(&self) {
        self.stop_admission();
        self.runtime.coordinator.drain().await;
    }
    pub fn spawn_maintenance(
        &self,
        interval: Duration,
    ) -> Result<tokio::task::JoinHandle<()>, Status> {
        maintenance::spawn(&self.runtime, interval)
    }
}
impl Runtime {
    async fn resolve(
        &self,
        scope: &GatewayScope,
        request: wire::ResolveSecretsRequest,
    ) -> Result<wire::ResolveSecretsResponse, Status> {
        let purpose = wire::ResolvePurpose::try_from(request.purpose)
            .map_err(|_| Status::invalid_argument("invalid issuer resolution purpose"))?;
        if purpose == wire::ResolvePurpose::Unspecified
            || request.secrets.is_empty()
            || request.secrets.len() > BATCH_LIMIT
        {
            return Err(Status::invalid_argument(
                "issuer resolution requires a purpose and bounded nonempty batch",
            ));
        }
        let _permit = self
            .reads
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("issuer resolution capacity exhausted"))?;
        let refs = self.repository.references(scope);
        let mut ids = std::collections::HashSet::new();
        let mut snapshots = Vec::with_capacity(request.secrets.len());
        // Validate every supplied scope and captured state before reading any
        // value. A bad sibling never causes partial authorization/value export.
        for item in request.secrets {
            if item.request_id.is_empty()
                || item.request_id.len() > 128
                || !ids.insert(item.request_id.clone())
            {
                return Err(Status::invalid_argument(
                    "issuer resolution request IDs must be unique and nonempty",
                ));
            }
            valid_reference(&item.reference)?;
            let supplied = owner(item.owner.as_ref())?;
            scope.authorize_owner(&supplied)?;
            let state = refs
                .load(&item.reference)
                .await?
                .ok_or_else(|| Status::not_found("issuer credential reference not found"))?
                .state;
            scope.authorize_bound_owner(scope.identity(), &state.owner, &supplied)?;
            if state.revoked {
                return Err(Status::not_found("issuer credential reference is revoked"));
            }
            if state.pending_value && purpose != wire::ResolvePurpose::MetadataInspection {
                return Err(Status::failed_precondition(
                    "issuer credential reference is awaiting its first value",
                ));
            }
            if item
                .expected_version
                .is_some_and(|version| version != state.version)
            {
                return Err(Status::aborted("issuer credential version changed"));
            }
            snapshots.push((item, state));
        }
        let mut values = Vec::with_capacity(snapshots.len());
        for (item, state) in &snapshots {
            let (value, expiration) = if purpose == wire::ResolvePurpose::MetadataInspection {
                (String::new(), state.expiration_time_ms)
            } else {
                unexpired(state.expiration_time_ms, now_ms()?)?;
                let resolved = self
                    .storage
                    .resolve(scope, &state.owner, VALUE_PURPOSE, &state.backing)
                    .await?;
                let expiration = match (state.expiration_time_ms, resolved.expiration_time_ms) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                unexpired(expiration, now_ms()?)?;
                (resolved.value, expiration)
            };
            values.push(wire::ResolvedSecret {
                request_id: item.request_id.clone(),
                value,
                version: state.version,
                expiration_time: expiration
                    .map(openshell_core::time::timestamp_from_millis)
                    .transpose()
                    .map_err(|_| Status::data_loss("invalid issuer expiration metadata"))?,
                cache_ttl: None,
                pending_value: state.pending_value,
            });
        }
        for (item, state) in &snapshots {
            let live = refs
                .load(&item.reference)
                .await?
                .ok_or_else(|| Status::aborted("issuer credential changed during resolution"))?;
            if !same_value(state, &live.state) {
                return Err(Status::aborted(
                    "issuer credential changed during resolution",
                ));
            }
            if purpose != wire::ResolvePurpose::MetadataInspection {
                unexpired(state.expiration_time_ms, now_ms()?)?;
            }
        }
        // Compute TTLs at the end, not before slower siblings resolve. Recheck
        // backend expiration too, rather than only stored reference metadata.
        let now = now_ms()?;
        for value in &mut values {
            let expiration = value
                .expiration_time
                .as_ref()
                .map(openshell_core::time::timestamp_to_millis)
                .transpose()
                .map_err(|_| Status::data_loss("invalid issuer expiration metadata"))?;
            let ttl = if purpose == wire::ResolvePurpose::MetadataInspection {
                Duration::ZERO
            } else {
                unexpired(expiration, now)?;
                expiration.map_or(self.cache_ttl, |expiration| {
                    self.cache_ttl.min(Duration::from_millis(
                        u64::try_from(expiration.saturating_sub(now)).unwrap_or(0),
                    ))
                })
            };
            value.cache_ttl = Some(
                openshell_core::time::duration_from_std(ttl)
                    .map_err(|_| Status::data_loss("invalid issuer cache TTL"))?,
            );
        }
        let response = wire::ResolveSecretsResponse { secrets: values };
        if response.encoded_len() > MESSAGE_LIMIT {
            return Err(Status::resource_exhausted(
                "issuer resolution response exceeds limit; split the batch",
            ));
        }
        tracing::info!(gateway=scope.identity(), purpose=?purpose, count=response.secrets.len(), "issuer credential resolution authorized");
        Ok(response)
    }
}

#[tonic::async_trait]
impl wire::credential_store_server::CredentialStore for CredentialStoreService {
    async fn get_capabilities(
        &self,
        request: Request<wire::GetCapabilitiesRequest>,
    ) -> Result<Response<wire::GetCapabilitiesResponse>, Status> {
        crate::observability::observe(crate::observability::Operation::GetCapabilities, async {
            self.runtime.policy.authenticate(&request)?;
            Ok(Response::new(wire::GetCapabilitiesResponse {
                protocol_version: 1,
                supports_watch: true,
                supports_expiration: true,
                max_batch_size: u32::try_from(BATCH_LIMIT).expect("bounded batch size"),
                max_response_bytes: u32::try_from(MESSAGE_LIMIT).expect("bounded message size"),
                supports_metadata_inspection: true,
                supports_pending_reservations: true,
            }))
        })
        .await
    }
    async fn reserve_secret(
        &self,
        request: Request<wire::ReserveSecretRequest>,
    ) -> Result<Response<wire::ReserveSecretResponse>, Status> {
        crate::observability::observe(crate::observability::Operation::ReserveSecret, async {
            let scope = self.runtime.policy.authenticate(&request)?;
            let request = request.into_inner();
            scope.authorize_owner(&owner(request.owner.as_ref())?)?;
            if request.encoded_len() > MESSAGE_LIMIT {
                return Err(Status::resource_exhausted("issuer request exceeds limit"));
            }
            let key = idempotency(&request.idempotency_key)?;
            let coordination = format!("{}:secret-operation:{key}", scope.namespace());
            let runtime = self.runtime.clone();
            let response = self
                .runtime
                .coordinator
                .run(&coordination, async move {
                    runtime.reserve(scope, request, key).await
                })
                .await?;
            Ok(Response::new(response))
        })
        .await
    }
    async fn put_secret(
        &self,
        request: Request<wire::PutSecretRequest>,
    ) -> Result<Response<wire::PutSecretResponse>, Status> {
        crate::observability::observe(crate::observability::Operation::PutSecret, async {
            let scope = self.runtime.policy.authenticate(&request)?;
            let request = request.into_inner();
            scope.authorize_owner(&owner(request.owner.as_ref())?)?;
            if request.encoded_len() > MESSAGE_LIMIT {
                return Err(Status::resource_exhausted("issuer request exceeds limit"));
            }
            let key = idempotency(&request.idempotency_key)?;
            let coordination = format!("{}:secret-operation:{key}", scope.namespace());
            let runtime = self.runtime.clone();
            let response = self
                .runtime
                .coordinator
                .run(&coordination, async move {
                    runtime.put(scope, request, key).await
                })
                .await?;
            Ok(Response::new(response))
        })
        .await
    }
    async fn delete_secret(
        &self,
        request: Request<wire::DeleteSecretRequest>,
    ) -> Result<Response<wire::DeleteSecretResponse>, Status> {
        crate::observability::observe(crate::observability::Operation::DeleteSecret, async {
            let scope = self.runtime.policy.authenticate(&request)?;
            let request = request.into_inner();
            scope.authorize_owner(&owner(request.owner.as_ref())?)?;
            if request.encoded_len() > MESSAGE_LIMIT {
                return Err(Status::resource_exhausted("issuer request exceeds limit"));
            }
            let key = idempotency(&request.idempotency_key)?;
            let coordination = format!("{}:secret-operation:{key}", scope.namespace());
            let runtime = self.runtime.clone();
            let response = self
                .runtime
                .coordinator
                .run(&coordination, async move {
                    runtime.delete(scope, request, key).await
                })
                .await?;
            Ok(Response::new(response))
        })
        .await
    }
    async fn resolve_secrets(
        &self,
        request: Request<wire::ResolveSecretsRequest>,
    ) -> Result<Response<wire::ResolveSecretsResponse>, Status> {
        crate::observability::observe(crate::observability::Operation::ResolveSecrets, async {
            let scope = self.runtime.policy.authenticate(&request)?;
            if request.get_ref().encoded_len() > MESSAGE_LIMIT {
                return Err(Status::resource_exhausted("issuer request exceeds limit"));
            }
            Ok(Response::new(
                self.runtime.resolve(&scope, request.into_inner()).await?,
            ))
        })
        .await
    }
    type WatchSecretsStream =
        tokio_stream::wrappers::ReceiverStream<Result<wire::WatchSecretsResponse, Status>>;
    async fn watch_secrets(
        &self,
        request: Request<wire::WatchSecretsRequest>,
    ) -> Result<Response<Self::WatchSecretsStream>, Status> {
        crate::observability::observe(crate::observability::Operation::WatchSecrets, async {
            let scope = self.runtime.policy.authenticate(&request)?;
            watch::start(
                self.runtime.clone(),
                scope,
                request.into_inner().after_sequence,
            )
            .await
            .map(Response::new)
        })
        .await
    }
}

#[cfg(test)]
mod tests;
