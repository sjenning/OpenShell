// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use refresh::credential_refresh_server::{CredentialRefresh, CredentialRefreshServer};
use std::sync::atomic::{AtomicUsize, Ordering};
use store::credential_store_server::{CredentialStore, CredentialStoreServer};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response};

struct MetadataCall {
    bindings: Vec<String>,
    release: oneshot::Sender<()>,
}
type SharedReceiver<T> = Arc<Mutex<Option<mpsc::Receiver<Result<T, Status>>>>>;
#[derive(Clone)]
struct Service {
    secrets: SharedReceiver<store::WatchSecretsResponse>,
    grants: SharedReceiver<refresh::WatchGrantsResponse>,
    metadata: mpsc::UnboundedSender<MetadataCall>,
    secret_calls: Arc<AtomicUsize>,
    grant_calls: Arc<AtomicUsize>,
}
impl Service {
    async fn inspect(&self, bindings: Vec<String>) {
        let (release, ready) = oneshot::channel();
        self.metadata
            .send(MetadataCall { bindings, release })
            .unwrap();
        let _ = ready.await;
    }
}
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
        Err(Status::unimplemented("unused"))
    }
    async fn put_secret(
        &self,
        _: Request<store::PutSecretRequest>,
    ) -> Result<Response<store::PutSecretResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn delete_secret(
        &self,
        _: Request<store::DeleteSecretRequest>,
    ) -> Result<Response<store::DeleteSecretResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn resolve_secrets(
        &self,
        request: Request<store::ResolveSecretsRequest>,
    ) -> Result<Response<store::ResolveSecretsResponse>, Status> {
        let request = request.into_inner();
        assert_eq!(
            request.purpose,
            store::ResolvePurpose::MetadataInspection as i32
        );
        self.secret_calls.fetch_add(1, Ordering::SeqCst);
        self.inspect(
            request
                .secrets
                .iter()
                .map(|input| input.reference.clone())
                .collect(),
        )
        .await;
        Ok(Response::new(store::ResolveSecretsResponse {
            secrets: request
                .secrets
                .into_iter()
                .map(|input| store::ResolvedSecret {
                    request_id: input.request_id,
                    version: 1,
                    cache_ttl: Some(prost_types::Duration::default()),
                    ..Default::default()
                })
                .collect(),
        }))
    }
    type WatchSecretsStream = ReceiverStream<Result<store::WatchSecretsResponse, Status>>;
    async fn watch_secrets(
        &self,
        _: Request<store::WatchSecretsRequest>,
    ) -> Result<Response<Self::WatchSecretsStream>, Status> {
        let receiver = self
            .secrets
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| Status::unavailable("reconnect blocked"))?;
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}
#[tonic::async_trait]
impl CredentialRefresh for Service {
    async fn list_strategies(
        &self,
        _: Request<refresh::ListStrategiesRequest>,
    ) -> Result<Response<refresh::ListStrategiesResponse>, Status> {
        Ok(Response::new(refresh::ListStrategiesResponse::default()))
    }
    async fn create_grant(
        &self,
        _: Request<refresh::CreateGrantRequest>,
    ) -> Result<Response<refresh::CreateGrantResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn reserve_grant(
        &self,
        _: Request<refresh::ReserveGrantRequest>,
    ) -> Result<Response<refresh::ReserveGrantResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn initialize_grant(
        &self,
        _: Request<refresh::InitializeGrantRequest>,
    ) -> Result<Response<refresh::InitializeGrantResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn get_grant(
        &self,
        request: Request<refresh::GetGrantRequest>,
    ) -> Result<Response<refresh::GetGrantResponse>, Status> {
        let grant = request.into_inner().grant;
        self.grant_calls.fetch_add(1, Ordering::SeqCst);
        self.inspect(vec![grant.clone()]).await;
        Ok(Response::new(refresh::GetGrantResponse {
            status: Some(refresh::GrantStatus {
                grant,
                version: 1,
                state: "pending".into(),
                ..Default::default()
            }),
        }))
    }
    async fn delete_grant(
        &self,
        _: Request<refresh::DeleteGrantRequest>,
    ) -> Result<Response<refresh::DeleteGrantResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn detach_grant(
        &self,
        _: Request<refresh::DetachGrantRequest>,
    ) -> Result<Response<refresh::DetachGrantResponse>, Status> {
        Err(Status::unimplemented("unused"))
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
    type WatchGrantsStream = ReceiverStream<Result<refresh::WatchGrantsResponse, Status>>;
    async fn watch_grants(
        &self,
        _: Request<refresh::WatchGrantsRequest>,
    ) -> Result<Response<Self::WatchGrantsStream>, Status> {
        let receiver = self
            .grants
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| Status::unavailable("reconnect blocked"))?;
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

struct Server {
    source: WatchedIssuer,
    secrets: mpsc::Sender<Result<store::WatchSecretsResponse, Status>>,
    grants: mpsc::Sender<Result<refresh::WatchGrantsResponse, Status>>,
    metadata: mpsc::UnboundedReceiver<MetadataCall>,
    calls: Service,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start() -> Self {
        let (secrets, secret_receiver) = mpsc::channel(64);
        let (grants, grant_receiver) = mpsc::channel(64);
        let (metadata_sender, metadata) = mpsc::unbounded_channel();
        let calls = Service {
            secrets: Arc::new(Mutex::new(Some(secret_receiver))),
            grants: Arc::new(Mutex::new(Some(grant_receiver))),
            metadata: metadata_sender,
            secret_calls: Arc::new(AtomicUsize::new(0)),
            grant_calls: Arc::new(AtomicUsize::new(0)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = calls.clone();
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
        let mut client = client();
        client.store = super::super::super::transport::Store::remote(channel.clone());
        client.refresh = super::super::super::transport::Refresh::remote(channel);
        let source = WatchedIssuer::new(client);
        Self {
            source,
            secrets,
            grants,
            metadata,
            calls,
            task,
        }
    }
    async fn checkpoint(&self, kind: ChangeKind, sequence: u64) {
        match kind {
            ChangeKind::Secrets => self
                .secrets
                .send(Ok(store::WatchSecretsResponse {
                    checkpoint: true,
                    sequence,
                    ..Default::default()
                }))
                .await
                .unwrap(),
            ChangeKind::Grants => self
                .grants
                .send(Ok(refresh::WatchGrantsResponse {
                    checkpoint: true,
                    sequence,
                    ..Default::default()
                }))
                .await
                .unwrap(),
        }
    }
    async fn reset(&self, kind: ChangeKind, sequence: u64) {
        match kind {
            ChangeKind::Secrets => self
                .secrets
                .send(Ok(store::WatchSecretsResponse {
                    reset_required: true,
                    sequence,
                    ..Default::default()
                }))
                .await
                .unwrap(),
            ChangeKind::Grants => self
                .grants
                .send(Ok(refresh::WatchGrantsResponse {
                    reset_required: true,
                    sequence,
                    ..Default::default()
                }))
                .await
                .unwrap(),
        }
    }
    async fn event(&self, kind: ChangeKind, id: &str, sequence: u64, terminal: bool) {
        match kind {
            ChangeKind::Secrets => self
                .secrets
                .send(Ok(store::WatchSecretsResponse {
                    reference: id.into(),
                    version: 2,
                    sequence,
                    revoked: terminal,
                    ..Default::default()
                }))
                .await
                .unwrap(),
            ChangeKind::Grants => self
                .grants
                .send(Ok(refresh::WatchGrantsResponse {
                    grant: id.into(),
                    version: 2,
                    sequence,
                    deleted: terminal,
                    ..Default::default()
                }))
                .await
                .unwrap(),
        }
    }
    async fn call(&mut self) -> MetadataCall {
        tokio::time::timeout(Duration::from_secs(1), self.metadata.recv())
            .await
            .unwrap()
            .unwrap()
    }
    async fn synchronized(&self) {
        self.source
            .wait_synchronized(Duration::from_secs(1))
            .await
            .unwrap();
    }
    fn track(&self, kind: ChangeKind, id: &str) {
        match kind {
            ChangeKind::Secrets => self
                .source
                .track_secret(request(id).secrets.remove(0).owner.unwrap(), id.into())
                .unwrap(),
            ChangeKind::Grants => self.source.track_grant(id.into()).unwrap(),
        }
    }
    fn known(&self, kind: ChangeKind, id: &str) -> Result<(), Status> {
        match kind {
            ChangeKind::Secrets => self
                .source
                .known_secret(&request(id).secrets.remove(0).owner.unwrap(), id)
                .map(|_| ()),
            ChangeKind::Grants => self.source.known_grant(id).map(|_| ()),
        }
    }
    async fn initialize(&self) {
        self.checkpoint(ChangeKind::Secrets, 0).await;
        self.checkpoint(ChangeKind::Grants, 0).await;
        self.synchronized().await;
    }
    async fn pump(&self) {
        // A real socket round trip gives both watch tasks a deterministic I/O
        // scheduling boundary before the paused clock advances again.
        self.source.list_strategies().await.unwrap();
        tokio::task::yield_now().await;
    }
}

async fn change(receiver: &mut broadcast::Receiver<IssuerChange>) -> IssuerChange {
    tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn controllers_consume_revocations_while_metadata_is_blocked_and_fence_late_results() {
    for kind in [ChangeKind::Secrets, ChangeKind::Grants] {
        let mut server = Server::start().await;
        server.initialize().await;
        server.track(kind, "old");
        server.checkpoint(kind, 0).await;
        server.call().await.release.send(()).unwrap();
        server.synchronized().await;
        // Keep the cached output independent of the grant under test.
        let cached = if kind == ChangeKind::Secrets {
            "old"
        } else {
            "output"
        };
        let before = server
            .source
            .inner
            .observe_secrets(&request(cached))
            .unwrap();
        cache::record(
            &server.source.inner,
            &request(cached),
            &mut response(cached, "cached"),
            &before,
        )
        .unwrap();
        assert!(
            cache::get(&server.source.inner, &request(cached))
                .unwrap()
                .is_some()
        );
        server.track(kind, "slow");
        server.checkpoint(kind, 0).await;
        let slow = server.call().await;
        assert_eq!(slow.bindings, ["slow"]);
        let mut changes = server.source.changes();
        server.event(kind, "old", 1, true).await;
        match (kind, change(&mut changes).await) {
            (ChangeKind::Secrets, IssuerChange::Secret { revoked: true, .. })
            | (ChangeKind::Grants, IssuerChange::Grant { deleted: true, .. }) => {}
            other => panic!("expected terminal event, got {other:?}"),
        }
        assert_eq!(
            server.known(kind, "old").unwrap_err().code(),
            Code::NotFound
        );
        assert!(
            cache::get(&server.source.inner, &request(cached))
                .unwrap()
                .is_none()
        );
        // Its epoch was captured before the event. The late response cannot
        // publish even metadata for this unaffected sibling in the old epoch.
        slow.release.send(()).unwrap();
        server.checkpoint(kind, 1).await;
        let retry = server.call().await;
        assert_eq!(retry.bindings, ["slow"]);
        assert_eq!(
            server.known(kind, "slow").unwrap_err().code(),
            Code::Unavailable
        );
        retry.release.send(()).unwrap();
        server.synchronized().await;
        assert!(server.known(kind, "slow").is_ok());
    }
}

#[tokio::test]
async fn controllers_keep_multibatch_reconciliation_alive_across_heartbeats() {
    for kind in [ChangeKind::Secrets, ChangeKind::Grants] {
        let mut server = Server::start().await;
        server.initialize().await;
        let count = if kind == ChangeKind::Secrets { 65 } else { 2 };
        for number in 0..count {
            server.track(kind, &format!("ref-{number:03}"));
        }
        server.checkpoint(kind, 0).await;
        let first = server.call().await;
        tokio::time::pause();
        assert_eq!(
            first.bindings.len(),
            if kind == ChangeKind::Secrets { 64 } else { 1 }
        );
        // Both batches are individually below the unary deadline; combined,
        // they exceed the watch read watchdog. Heartbeats must remain live.
        tokio::time::advance(Duration::from_secs(5)).await;
        server.checkpoint(ChangeKind::Secrets, 0).await;
        server.checkpoint(ChangeKind::Grants, 0).await;
        tokio::time::resume();
        server.pump().await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(4)).await;
        tokio::time::resume();
        first.release.send(()).unwrap();
        let second = server.call().await;
        tokio::time::pause();
        assert_eq!(second.bindings.len(), 1);
        let partial = server.source.health().unwrap();
        assert_eq!(
            server
                .known(kind, &format!("ref-{:03}", count - 1))
                .unwrap_err()
                .code(),
            Code::Unavailable
        );
        tokio::time::advance(Duration::from_secs(5)).await;
        server.checkpoint(ChangeKind::Secrets, 0).await;
        server.checkpoint(ChangeKind::Grants, 0).await;
        tokio::time::resume();
        server.pump().await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(4)).await;
        tokio::time::resume();
        second.release.send(()).unwrap();
        server.synchronized().await;
        assert_ne!(server.source.health().unwrap(), partial);
        assert!(server.known(kind, &format!("ref-{:03}", count - 1)).is_ok());
        assert_eq!(
            server.calls.secret_calls.load(Ordering::SeqCst),
            if kind == ChangeKind::Secrets { 2 } else { 0 }
        );
        assert_eq!(
            server.calls.grant_calls.load(Ordering::SeqCst),
            if kind == ChangeKind::Grants { 2 } else { 0 }
        );
    }
}

#[tokio::test]
async fn controller_watch_stall_is_bounded_during_multibatch_metadata_work() {
    for kind in [ChangeKind::Secrets, ChangeKind::Grants] {
        let mut server = Server::start().await;
        server.initialize().await;
        // Four bounded RPCs, no further heartbeat. The final RPC is still
        // below its own deadline when the stream reaches its 15-second limit.
        let count = if kind == ChangeKind::Secrets { 193 } else { 4 };
        for number in 0..count {
            server.track(kind, &format!("ref-{number:03}"));
        }
        server.checkpoint(kind, 0).await;
        let mut held = server.call().await;
        let mut changes = server.source.changes();
        for _ in 0..3 {
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(4)).await;
            tokio::time::resume();
            held.release.send(()).unwrap();
            held = server.call().await;
        }
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::time::resume();
        loop {
            if matches!(change(&mut changes).await, IssuerChange::Unknown(observed) if observed == kind)
            {
                break;
            }
        }
        assert!(!server.source.health().unwrap().synchronized());
        assert_eq!(
            server.known(kind, "ref-000").unwrap_err().code(),
            Code::Unavailable
        );
        let _ = held.release.send(());
    }
}

#[tokio::test]
async fn controller_reset_cancels_old_metadata_without_touching_the_other_epoch() {
    for kind in [ChangeKind::Secrets, ChangeKind::Grants] {
        let mut server = Server::start().await;
        server.initialize().await;
        server.track(kind, "slow");
        server.checkpoint(kind, 0).await;
        let old = server.call().await;
        let other = match kind {
            ChangeKind::Secrets => ChangeKind::Grants,
            ChangeKind::Grants => ChangeKind::Secrets,
        };
        let epoch = {
            let state = server.source.inner.lock().unwrap();
            match other {
                ChangeKind::Secrets => state.secret_generation,
                ChangeKind::Grants => state.grant_generation,
            }
        };
        let mut changes = server.source.changes();
        server.reset(kind, 0).await;
        assert!(
            matches!(change(&mut changes).await, IssuerChange::Unknown(observed) if observed == kind)
        );
        assert_eq!(
            server.known(kind, "slow").unwrap_err().code(),
            Code::Unavailable
        );
        {
            let state = server.source.inner.lock().unwrap();
            assert_eq!(
                match other {
                    ChangeKind::Secrets => state.secret_generation,
                    ChangeKind::Grants => state.grant_generation,
                },
                epoch
            );
        }
        let _ = old.release.send(());
        // Replay events invalidate immediately, but must not start metadata or
        // publish recovered health before their checkpoint arrives.
        server.event(kind, "untracked", 1, false).await;
        assert!(matches!(
            change(&mut changes).await,
            IssuerChange::Secret { .. } | IssuerChange::Grant { .. }
        ));
        assert!(server.metadata.try_recv().is_err());
        assert!(!server.source.health().unwrap().synchronized());
        server.checkpoint(kind, 1).await;
        let current = server.call().await;
        assert_eq!(
            server.known(kind, "slow").unwrap_err().code(),
            Code::Unavailable
        );
        current.release.send(()).unwrap();
        server.synchronized().await;
        assert!(server.known(kind, "slow").is_ok());
    }
}
