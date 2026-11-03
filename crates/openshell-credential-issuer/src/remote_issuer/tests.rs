// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use store::credential_store_server::{CredentialStore, CredentialStoreServer};
use tokio_stream::wrappers::TcpListenerStream;

#[derive(Default)]
struct Faults {
    mode: AtomicUsize,
    puts: AtomicUsize,
    resolves: AtomicUsize,
}
#[derive(Clone)]
struct FaultyStore(Arc<Faults>);
#[tonic::async_trait]
impl CredentialStore for FaultyStore {
    async fn get_capabilities(
        &self,
        _: Request<store::GetCapabilitiesRequest>,
    ) -> Result<Response<store::GetCapabilitiesResponse>, Status> {
        Ok(Response::new(store::GetCapabilitiesResponse {
            protocol_version: if self.0.mode.load(Ordering::SeqCst) == 99 {
                2
            } else {
                1
            },
            supports_watch: true,
            supports_expiration: true,
            max_batch_size: 64,
            max_response_bytes: 1024 * 1024,
            supports_metadata_inspection: true,
        }))
    }
    async fn put_secret(
        &self,
        _: Request<store::PutSecretRequest>,
    ) -> Result<Response<store::PutSecretResponse>, Status> {
        self.0.puts.fetch_add(1, Ordering::SeqCst);
        Err(Status::with_details(
            tonic::Code::Unavailable,
            "private-secret-diagnostic",
            b"private-secret-detail".to_vec().into(),
        ))
    }
    async fn delete_secret(
        &self,
        _: Request<store::DeleteSecretRequest>,
    ) -> Result<Response<store::DeleteSecretResponse>, Status> {
        Ok(Response::new(store::DeleteSecretResponse { version: 0 }))
    }
    async fn resolve_secrets(
        &self,
        request: Request<store::ResolveSecretsRequest>,
    ) -> Result<Response<store::ResolveSecretsResponse>, Status> {
        self.0.resolves.fetch_add(1, Ordering::SeqCst);
        let mode = self.0.mode.load(Ordering::SeqCst);
        let input = request.into_inner().secrets.remove(0);
        let value = store::ResolvedSecret {
            request_id: if mode == 1 {
                "unknown".into()
            } else {
                input.request_id
            },
            value: if mode == 8 {
                String::new()
            } else {
                "private-value".into()
            },
            version: if mode == 3 { 3 } else { 2 },
            expiration_time: None,
            cache_ttl: Some(prost_types::Duration {
                seconds: if mode == 6 {
                    61
                } else if mode == 7 {
                    -1
                } else {
                    0
                },
                nanos: 0,
            }),
            pending_value: mode == 4 || mode == 8,
        };
        Ok(Response::new(store::ResolveSecretsResponse {
            secrets: if mode == 2 {
                vec![value.clone(), value]
            } else {
                vec![value]
            },
        }))
    }
    type WatchSecretsStream =
        tokio_stream::Iter<std::vec::IntoIter<Result<store::WatchSecretsResponse, Status>>>;
    async fn watch_secrets(
        &self,
        _: Request<store::WatchSecretsRequest>,
    ) -> Result<Response<Self::WatchSecretsStream>, Status> {
        Ok(Response::new(tokio_stream::iter(vec![
            Ok(store::WatchSecretsResponse {
                reference: if self.0.mode.load(Ordering::SeqCst) == 1 {
                    "unexpected".into()
                } else {
                    String::new()
                },
                version: 0,
                sequence: 0,
                reset_required: true,
                revoked: false,
                checkpoint: false,
            }),
            Ok(store::WatchSecretsResponse {
                reference: String::new(),
                version: 0,
                sequence: 0,
                reset_required: false,
                revoked: false,
                checkpoint: true,
            }),
        ])))
    }
}
struct Server {
    channel: Channel,
    faults: Arc<Faults>,
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
        let faults = Arc::new(Faults::default());
        let implementation = FaultyStore(faults.clone());
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(CredentialStoreServer::new(implementation))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let channel = Channel::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        Self {
            channel,
            faults,
            task,
        }
    }
}
fn resolution() -> store::ResolveSecretsRequest {
    store::ResolveSecretsRequest {
        secrets: vec![store::ResolveSecretRequest {
            request_id: "id".into(),
            reference: "ref".into(),
            owner: Some(store::SecretOwner {
                workspace: "default".into(),
                provider_id: "provider-id".into(),
                credential_key: "TOKEN".into(),
                provider: String::new(),
            }),
            expected_version: Some(2),
        }],
        purpose: store::ResolvePurpose::SandboxDelivery as i32,
    }
}
#[tokio::test]
async fn insecure_configuration_and_incompatible_protocols_never_fall_back() {
    let config = ExtensionChannelConfig::new("http://127.0.0.1:1");
    assert_eq!(
        RemoteIssuer::connect(&config).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    let server = Server::start().await;
    server.faults.mode.store(99, Ordering::SeqCst);
    assert_eq!(
        RemoteIssuer::discover(server.channel.clone())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
}
#[tokio::test]
async fn remote_mutation_errors_are_sanitized_and_never_retried() {
    let server = Server::start().await;
    let client = RemoteIssuer::discover(server.channel.clone())
        .await
        .unwrap();
    let error = client
        .put_secret(store::PutSecretRequest::default())
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert!(!error.message().contains("private"));
    assert!(error.details().is_empty());
    assert_eq!(server.faults.puts.load(Ordering::SeqCst), 1);
    assert_eq!(
        client
            .delete_secret(store::DeleteSecretRequest::default())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::DataLoss
    );
}
#[tokio::test]
async fn resolution_rejects_incomplete_duplicate_mixed_and_secret_bearing_metadata() {
    let server = Server::start().await;
    let client = RemoteIssuer::discover(server.channel.clone())
        .await
        .unwrap();
    assert_eq!(
        client.resolve_secrets(resolution()).await.unwrap().secrets[0].value,
        "private-value"
    );
    for mode in [1, 2, 3, 4, 6, 7] {
        server.faults.mode.store(mode, Ordering::SeqCst);
        let error = client.resolve_secrets(resolution()).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::DataLoss);
        assert!(!format!("{error:?}").contains("private-value"));
    }
    let mut metadata = resolution();
    metadata.purpose = store::ResolvePurpose::MetadataInspection as i32;
    server.faults.mode.store(0, Ordering::SeqCst);
    assert_eq!(
        client
            .resolve_secrets(metadata.clone())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::DataLoss
    );
    server.faults.mode.store(8, Ordering::SeqCst);
    assert!(client.resolve_secrets(metadata).await.unwrap().secrets[0].pending_value);
    let mut invalid = resolution();
    invalid.secrets[0].owner = None;
    let before = server.faults.resolves.load(Ordering::SeqCst);
    assert_eq!(
        client.resolve_secrets(invalid).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(before, server.faults.resolves.load(Ordering::SeqCst));
}
#[tokio::test]
async fn malformed_watch_frames_are_rejected_and_checkpoint_does_not_reconcile() {
    let server = Server::start().await;
    let client = RemoteIssuer::discover(server.channel.clone())
        .await
        .unwrap();
    let mut stream = client.watch_secrets(0).await.unwrap();
    assert!(stream.message().await.unwrap().unwrap().reset_required);
    assert!(stream.message().await.unwrap().unwrap().checkpoint);
    assert_eq!(stream.cursor(), 0);
    assert!(stream.message().await.unwrap().is_none());
    drop(stream);
    server.faults.mode.store(1, Ordering::SeqCst);
    let mut stream = client.watch_secrets(0).await.unwrap();
    assert_eq!(
        stream.message().await.unwrap_err().code(),
        tonic::Code::DataLoss
    );
    assert!(stream.message().await.unwrap().is_none());
}
#[test]
fn catalog_and_grant_metadata_use_the_same_pinned_semantic_id_rules() {
    let mut catalog = refresh::ListStrategiesResponse {
        strategies: vec![
            openshell_core::proto::credentials::minter::v1::StrategyDescriptor {
                name: "custom:acme.sts".into(),
                outputs: vec!["access.token".into()],
                ..Default::default()
            },
        ],
    };
    validation::catalog(&catalog).unwrap();
    catalog.strategies[0].outputs.push("access.token".into());
    assert!(validation::catalog(&catalog).is_err());
    let outputs = std::collections::HashMap::from([
        ("first".into(), "ONE".into()),
        ("second".into(), "TWO".into()),
    ]);
    let created = refresh::CreateGrantResponse {
        grant: "grant".into(),
        output_references: std::collections::HashMap::from([
            ("first".into(), "same".into()),
            ("second".into(), "same".into()),
        ]),
    };
    assert!(validation::created(&outputs, &created).is_err());
    let status = refresh::GrantStatus {
        grant: "grant".into(),
        version: 1,
        state: "refreshed".into(),
        ..Default::default()
    };
    assert!(validation::status("grant", Some(&status)).is_err());
}

#[test]
fn cache_budget_subtracts_elapsed_time_and_clamps_to_expiration() {
    let mut response = store::ResolveSecretsResponse {
        secrets: vec![store::ResolvedSecret {
            cache_ttl: Some(prost_types::Duration {
                seconds: 10,
                nanos: 0,
            }),
            ..Default::default()
        }],
    };
    validation::bound_ttl(&mut response, Duration::from_secs(3)).unwrap();
    assert_eq!(response.secrets[0].cache_ttl.as_ref().unwrap().seconds, 7);
    validation::bound_ttl(&mut response, Duration::from_secs(10)).unwrap();
    assert_eq!(response.secrets[0].cache_ttl.as_ref().unwrap().seconds, 0);
    let seconds = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
        + 60;
    response.secrets[0].expiration_time = Some(prost_types::Timestamp { seconds, nanos: 0 });
    response.secrets[0].cache_ttl = Some(prost_types::Duration {
        seconds: 120,
        nanos: 0,
    });
    validation::bound_ttl(&mut response, Duration::ZERO).unwrap();
    assert!(
        openshell_core::time::duration_to_std(response.secrets[0].cache_ttl.as_ref().unwrap())
            .unwrap()
            <= Duration::from_mins(1)
    );
}
