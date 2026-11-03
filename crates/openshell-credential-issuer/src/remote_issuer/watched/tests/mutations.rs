// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use refresh::credential_refresh_server::{CredentialRefresh, CredentialRefreshServer};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use store::credential_store_server::{CredentialStore, CredentialStoreServer};
use tokio::sync::Notify;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response};
mod replay;

struct Calls {
    allocations: AtomicUsize,
    deny_reservation: AtomicBool,
    started: Notify,
    release: Semaphore,
}
impl Calls {
    async fn allocate(&self) {
        self.allocations.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        self.release.acquire().await.unwrap().forget();
    }
}
#[derive(Clone)]
struct Service(Arc<Calls>);
#[tonic::async_trait]
impl CredentialStore for Service {
    async fn get_capabilities(
        &self,
        _: Request<store::GetCapabilitiesRequest>,
    ) -> Result<Response<store::GetCapabilitiesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn reserve_secret(
        &self,
        _: Request<store::ReserveSecretRequest>,
    ) -> Result<Response<store::ReserveSecretResponse>, Status> {
        self.0.allocate().await;
        if self.0.deny_reservation.load(Ordering::SeqCst) {
            return Err(Status::permission_denied(
                "reservation no longer authorized",
            ));
        }
        Ok(Response::new(store::ReserveSecretResponse {
            reference: "allocated".into(),
            version: 1,
        }))
    }
    async fn put_secret(
        &self,
        _: Request<store::PutSecretRequest>,
    ) -> Result<Response<store::PutSecretResponse>, Status> {
        self.0.allocate().await;
        Ok(Response::new(store::PutSecretResponse {
            reference: "allocated".into(),
            version: 1,
        }))
    }
    async fn delete_secret(
        &self,
        _: Request<store::DeleteSecretRequest>,
    ) -> Result<Response<store::DeleteSecretResponse>, Status> {
        Ok(Response::new(store::DeleteSecretResponse { version: 2 }))
    }
    async fn resolve_secrets(
        &self,
        _: Request<store::ResolveSecretsRequest>,
    ) -> Result<Response<store::ResolveSecretsResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    type WatchSecretsStream =
        tokio_stream::Iter<std::vec::IntoIter<Result<store::WatchSecretsResponse, Status>>>;
    async fn watch_secrets(
        &self,
        _: Request<store::WatchSecretsRequest>,
    ) -> Result<Response<Self::WatchSecretsStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
}
#[tonic::async_trait]
impl CredentialRefresh for Service {
    async fn list_strategies(
        &self,
        _: Request<refresh::ListStrategiesRequest>,
    ) -> Result<Response<refresh::ListStrategiesResponse>, Status> {
        Ok(Response::new(refresh::ListStrategiesResponse {
            supports_pending_reservations: true,
            ..Default::default()
        }))
    }
    async fn create_grant(
        &self,
        _: Request<refresh::CreateGrantRequest>,
    ) -> Result<Response<refresh::CreateGrantResponse>, Status> {
        self.0.allocate().await;
        Ok(Response::new(refresh::CreateGrantResponse {
            grant: "allocated-grant".into(),
            output_references: [
                ("one".into(), "allocated-one".into()),
                ("two".into(), "allocated-two".into()),
            ]
            .into(),
        }))
    }
    async fn reserve_grant(
        &self,
        _: Request<refresh::ReserveGrantRequest>,
    ) -> Result<Response<refresh::ReserveGrantResponse>, Status> {
        self.0.allocate().await;
        if self.0.deny_reservation.load(Ordering::SeqCst) {
            return Err(Status::permission_denied(
                "reservation no longer authorized",
            ));
        }
        Ok(Response::new(refresh::ReserveGrantResponse {
            grant: "allocated-grant".into(),
            output_references: [
                ("one".into(), "allocated-one".into()),
                ("two".into(), "allocated-two".into()),
            ]
            .into(),
        }))
    }
    async fn initialize_grant(
        &self,
        _: Request<refresh::InitializeGrantRequest>,
    ) -> Result<Response<refresh::InitializeGrantResponse>, Status> {
        self.0.allocate().await;
        Ok(Response::new(refresh::InitializeGrantResponse {
            status: Some(refresh::GrantStatus {
                grant: "grant".into(),
                version: 2,
                state: "pending".into(),
                ..Default::default()
            }),
        }))
    }
    async fn get_grant(
        &self,
        request: Request<refresh::GetGrantRequest>,
    ) -> Result<Response<refresh::GetGrantResponse>, Status> {
        Ok(Response::new(refresh::GetGrantResponse {
            status: Some(refresh::GrantStatus {
                grant: request.into_inner().grant,
                version: 2,
                state: "deleting".into(),
                ..Default::default()
            }),
        }))
    }
    async fn delete_grant(
        &self,
        _: Request<refresh::DeleteGrantRequest>,
    ) -> Result<Response<refresh::DeleteGrantResponse>, Status> {
        Ok(Response::new(refresh::DeleteGrantResponse {}))
    }
    async fn detach_grant(
        &self,
        _: Request<refresh::DetachGrantRequest>,
    ) -> Result<Response<refresh::DetachGrantResponse>, Status> {
        Ok(Response::new(refresh::DetachGrantResponse {}))
    }
    async fn rotate_grant(
        &self,
        _: Request<refresh::RotateGrantRequest>,
    ) -> Result<Response<refresh::RotateGrantResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn ensure_fresh(
        &self,
        _: Request<refresh::EnsureFreshRequest>,
    ) -> Result<Response<refresh::EnsureFreshResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    type WatchGrantsStream =
        tokio_stream::Iter<std::vec::IntoIter<Result<refresh::WatchGrantsResponse, Status>>>;
    async fn watch_grants(
        &self,
        _: Request<refresh::WatchGrantsRequest>,
    ) -> Result<Response<Self::WatchGrantsStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
}
struct Server {
    source: WatchedIssuer,
    calls: Arc<Calls>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(Calls {
            allocations: AtomicUsize::new(0),
            deny_reservation: AtomicBool::new(false),
            started: Notify::new(),
            release: Semaphore::new(0),
        });
        let service = Service(calls.clone());
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(CredentialStoreServer::new(service.clone()))
                .add_service(CredentialRefreshServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let channel = Channel::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut inner = inner();
        inner.client.store =
            store::credential_store_client::CredentialStoreClient::new(channel.clone());
        inner.client.refresh =
            refresh::credential_refresh_client::CredentialRefreshClient::new(channel);
        inner.client.capabilities.supports_pending_reservations = true;
        let source = WatchedIssuer {
            inner: Arc::new(inner),
            _workers: Arc::new(Workers(Vec::new())),
        };
        Self {
            source,
            calls,
            task,
        }
    }
    async fn started(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.calls.started.notified())
            .await
            .unwrap();
    }
}
fn owner() -> store::SecretOwner {
    request("ref").secrets.remove(0).owner.unwrap()
}
fn reserve() -> store::ReserveSecretRequest {
    store::ReserveSecretRequest {
        owner: Some(owner()),
        idempotency_key: "reserve".into(),
    }
}
fn outputs() -> std::collections::HashMap<String, String> {
    [("one".into(), "ONE".into()), ("two".into(), "TWO".into())].into()
}
#[tokio::test]
async fn full_tracking_rejects_allocations_before_any_remote_effect() {
    let server = Server::start().await;
    for number in 0..REFERENCES {
        server
            .source
            .track_secret(owner(), format!("active-{number}"))
            .unwrap();
    }
    assert_eq!(
        server
            .source
            .reserve_secret(reserve())
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        server
            .source
            .put_secret(store::PutSecretRequest {
                owner: Some(owner()),
                value: "value".into(),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        server
            .source
            .create_grant(refresh::CreateGrantRequest {
                owner: Some(owner()),
                outputs: outputs(),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        server
            .source
            .reserve_grant(refresh::ReserveGrantRequest {
                owner: Some(owner()),
                outputs: outputs(),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(server.calls.allocations.load(Ordering::SeqCst), 0);
    assert!(server.source.inner.lock().unwrap().grants.is_empty());
}
#[tokio::test]
async fn concurrent_registration_cannot_steal_capacity_from_a_committing_secret() {
    let server = Server::start().await;
    for number in 0..REFERENCES - 1 {
        server
            .source
            .track_secret(owner(), format!("active-{number}"))
            .unwrap();
    }
    let source = server.source.clone();
    let mutation = tokio::spawn(async move { source.reserve_secret(reserve()).await });
    server.started().await;
    assert_eq!(
        server
            .source
            .track_secret(owner(), "competitor".into())
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    server.calls.release.add_permits(1);
    assert_eq!(mutation.await.unwrap().unwrap().reference, "allocated");
    let state = server.source.inner.lock().unwrap();
    assert_eq!(state.secrets.len(), REFERENCES);
    assert_eq!(state.reserved_secrets, 0);
    assert!(state.secrets.contains_key("allocated"));
}
#[tokio::test]
async fn grant_allocation_publishes_all_outputs_using_reserved_capacity() {
    let server = Server::start().await;
    for number in 0..REFERENCES - 2 {
        server
            .source
            .track_secret(owner(), format!("active-{number}"))
            .unwrap();
    }
    for number in 0..GRANTS - 1 {
        server
            .source
            .track_grant(format!("active-{number}"))
            .unwrap();
    }
    let source = server.source.clone();
    let mutation = tokio::spawn(async move {
        source
            .create_grant(refresh::CreateGrantRequest {
                owner: Some(owner()),
                outputs: outputs(),
                ..Default::default()
            })
            .await
    });
    server.started().await;
    assert_eq!(
        server
            .source
            .track_secret(owner(), "competitor".into())
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        server
            .source
            .track_grant("competitor".into())
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    server.calls.release.add_permits(1);
    let response = mutation.await.unwrap().unwrap();
    let state = server.source.inner.lock().unwrap();
    assert!(state.grants.contains_key(&response.grant));
    assert!(
        response
            .output_references
            .values()
            .all(|reference| state.secrets.contains_key(reference))
    );
    assert_eq!(state.secrets["allocated-one"].owner.credential_key, "ONE");
    assert_eq!(state.secrets["allocated-two"].owner.credential_key, "TWO");
}
#[tokio::test]
async fn committed_response_survives_a_local_tracking_failure() {
    let server = Server::start().await;
    let source = server.source.clone();
    let mutation = tokio::spawn(async move { source.reserve_secret(reserve()).await });
    server.started().await;
    // Even unexpected bookkeeping failure cannot report a durable allocation
    // as failed. Poisoned metadata remains fail-closed for every local getter.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = server.source.inner.state.lock().unwrap();
        panic!("simulate local bookkeeping failure");
    }));
    server.calls.release.add_permits(1);
    assert_eq!(mutation.await.unwrap().unwrap().reference, "allocated");
    assert_eq!(
        server
            .source
            .known_secret(&owner(), "allocated")
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
}
#[tokio::test]
async fn concurrent_terminal_grant_event_does_not_hide_successful_initialization() {
    let server = Server::start().await;
    let source = server.source.clone();
    let mutation = tokio::spawn(async move {
        source
            .initialize_grant(refresh::InitializeGrantRequest {
                grant: "grant".into(),
                ..Default::default()
            })
            .await
    });
    server.started().await;
    controller::grant_event(
        &server.source.inner,
        &refresh::WatchGrantsResponse {
            grant: "grant".into(),
            version: 3,
            deleted: true,
            ..Default::default()
        },
    )
    .unwrap();
    server.calls.release.add_permits(1);
    assert_eq!(mutation.await.unwrap().unwrap().status.unwrap().version, 2);
    assert!(server.source.inner.lock().unwrap().grants["grant"].gone);
    assert_eq!(
        server.source.known_grant("grant").unwrap_err().code(),
        Code::NotFound
    );
}
#[tokio::test]
async fn successful_deletion_and_detach_reclaim_tracking_without_waiting_for_watch() {
    let server = Server::start().await;
    server
        .source
        .track_secret(owner(), "deleted".into())
        .unwrap();
    server
        .source
        .track_secret(owner(), "published".into())
        .unwrap();
    server.source.track_grant("deleted".into()).unwrap();
    server.source.track_grant("detached".into()).unwrap();
    server
        .source
        .delete_secret(store::DeleteSecretRequest {
            owner: Some(owner()),
            reference: "deleted".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    server
        .source
        .delete_grant(refresh::DeleteGrantRequest {
            grant: "deleted".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    server
        .source
        .detach_grant(refresh::DetachGrantRequest {
            grant: "detached".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let state = server.source.inner.lock().unwrap();
    assert!(state.secrets["deleted"].gone);
    assert!(state.grants["deleted"].gone);
    assert!(state.grants["detached"].gone);
    assert!(!state.secrets["published"].gone);
}

#[tokio::test]
async fn incomplete_secret_or_grant_capacity_rejects_the_entire_output_bundle() {
    for secrets_full in [true, false] {
        let server = Server::start().await;
        if secrets_full {
            // One free reference cannot admit a two-output grant.
            for number in 0..REFERENCES - 1 {
                server
                    .source
                    .track_secret(owner(), format!("active-{number}"))
                    .unwrap();
            }
        } else {
            // Free reference slots cannot compensate for exhausted grants.
            for number in 0..GRANTS {
                server
                    .source
                    .track_grant(format!("active-{number}"))
                    .unwrap();
            }
        }
        assert_eq!(
            server
                .source
                .create_grant(refresh::CreateGrantRequest {
                    owner: Some(owner()),
                    outputs: outputs(),
                    ..Default::default()
                })
                .await
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
        assert_eq!(
            server
                .source
                .reserve_grant(refresh::ReserveGrantRequest {
                    owner: Some(owner()),
                    outputs: outputs(),
                    ..Default::default()
                })
                .await
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
        assert_eq!(server.calls.allocations.load(Ordering::SeqCst), 0);
        let state = server.source.inner.lock().unwrap();
        assert_eq!(state.reserved_secrets, 0);
        assert_eq!(state.reserved_grants, 0);
    }
}

#[tokio::test]
async fn cancelling_an_inflight_allocation_releases_its_local_capacity_reservation() {
    let server = Server::start().await;
    let source = server.source.clone();
    let mutation = tokio::spawn(async move { source.reserve_secret(reserve()).await });
    server.started().await;
    assert_eq!(server.source.inner.lock().unwrap().reserved_secrets, 1);
    mutation.abort();
    assert!(mutation.await.unwrap_err().is_cancelled());
    assert_eq!(server.source.inner.lock().unwrap().reserved_secrets, 0);
    // The remote effect may already be admitted. Local cancellation does not
    // replay it or claim success; any durable result remains issuer-owned.
    server.calls.release.add_permits(1);
    assert_eq!(server.calls.allocations.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn committed_response_survives_a_concurrent_owner_conflict_and_fails_closed() {
    let server = Server::start().await;
    let source = server.source.clone();
    let mutation = tokio::spawn(async move { source.reserve_secret(reserve()).await });
    server.started().await;
    let mut other = owner();
    other.provider_id = "other".into();
    server
        .source
        .track_secret(other, "allocated".into())
        .unwrap();
    server.calls.release.add_permits(1);
    assert_eq!(mutation.await.unwrap().unwrap().reference, "allocated");
    assert!(!server.source.health().unwrap().synchronized());
    assert_eq!(
        server
            .source
            .known_secret(&owner(), "allocated")
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    assert_eq!(server.source.inner.lock().unwrap().reserved_secrets, 0);
}

#[tokio::test]
async fn authenticated_deleting_status_is_returned_for_local_and_observed_retirement() {
    for locally_retired in [true, false] {
        let server = Server::start().await;
        let before = server
            .source
            .inner
            .observe_secrets(&request("output"))
            .unwrap();
        cache::record(
            &server.source.inner,
            &request("output"),
            &mut response("output", "value"),
            &before,
        )
        .unwrap();
        if locally_retired {
            server.source.track_grant("grant".into()).unwrap();
            server
                .source
                .delete_grant(refresh::DeleteGrantRequest {
                    grant: "grant".into(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let response = server
            .source
            .get_grant(refresh::GetGrantRequest {
                grant: "grant".into(),
            })
            .await
            .unwrap();
        assert_eq!(response.status.unwrap().state, "deleting");
        assert_eq!(
            server.source.known_grant("grant").unwrap_err().code(),
            Code::NotFound
        );
        assert!(server.source.inner.lock().unwrap().grants["grant"].terminal);
        assert!(server.source.inner.lock().unwrap().values.is_empty());
        assert!(
            server.source.inner.lock().unwrap().secrets["output"]
                .metadata
                .is_none()
        );
        server.source.inner.unknown(ChangeKind::Grants).unwrap();
        assert!(server.source.inner.lock().unwrap().grants["grant"].gone);
    }
}
