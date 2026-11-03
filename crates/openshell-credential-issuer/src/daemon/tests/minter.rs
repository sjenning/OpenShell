// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{
    auth::IssuerPolicy,
    hosted_minter::HostedMinter,
    minter::{MintFailure, MintRequest, MintResponse, StrategyDescriptor, TokenMinter},
};
use openshell_core::proto::credentials::refresh::v1 as refresh;
use std::fmt::Write as _;
use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
};
#[derive(Debug, Default)]
struct One(AtomicUsize);
#[tonic::async_trait]
impl TokenMinter for One {
    fn describe(&self) -> StrategyDescriptor {
        StrategyDescriptor {
            name: "custom:test".into(),
            config: vec![],
            secret_material: vec![],
            outputs: vec!["token".into()],
            rotated_secret_material: vec![],
        }
    }
    async fn mint(&self, _request: MintRequest) -> Result<MintResponse, MintFailure> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        Ok(MintResponse {
            outputs: HashMap::from([("token".into(), "custom-issued-value".into())]),
            expiration_time_ms: now + 60_000,
            rotated_secret_material: HashMap::new(),
        })
    }
}
#[tokio::test]
async fn daemon_pins_configured_remote_minter_and_uses_a_separate_issuer_client_identity() {
    let mut fixture = Fixture::new().await;
    let path = fixture.directory.path();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let tls = TlsFiles {
        certificate: path.join("server.pem"),
        key: path.join("server.key"),
        ca: path.join("ca.pem"),
    }
    .load()
    .await
    .unwrap();
    let minter = Arc::new(One::default());
    let hosted = HostedMinter::new(
        minter.clone(),
        IssuerPolicy::new(vec!["spiffe://example.test/issuer/a".into()]).unwrap(),
        1,
    )
    .unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener)
        .map(move |socket| {
            let tls = tls.clone();
            async move { tls.accept(socket.unwrap()).await.ok() }
        })
        .buffer_unordered(4)
        .filter_map(|stream| async move { stream.map(Ok::<_, std::io::Error>) });
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(hosted.into_service())
            .serve_with_incoming(Box::pin(incoming))
            .await
            .unwrap();
    });
    write!(
        fixture.config,
        r"
[openshell.credential_issuer.minters.test]
endpoint = {endpoint:?}
tls_ca_cert_path = {:?}
tls_client_cert_path = {:?}
tls_client_key_path = {:?}
",
        path.join("ca.pem").to_string_lossy(),
        path.join("issuer.pem").to_string_lossy(),
        path.join("issuer.key").to_string_lossy()
    )
    .unwrap();
    let invalid =
        Config::parse(&fixture.config.replace("minters.test]", "minters.wrong]")).unwrap();
    assert!(Daemon::new(invalid).await.is_err());
    let (stop, daemon) = fixture.start().await;
    let client = RemoteIssuer::connect(&fixture.client).await.unwrap();
    assert_eq!(client.list_strategies().await.unwrap().strategies.len(), 5);
    let grant = client
        .create_grant(refresh::CreateGrantRequest {
            owner: Some(owner()),
            strategy: "custom:test".into(),
            outputs: HashMap::from([("token".into(), "TOKEN".into())]),
            idempotency_key: "create-grant".into(),
            refresh_before: Some(prost_types::Duration::default()),
            max_lifetime: Some(prost_types::Duration {
                seconds: 120,
                nanos: 0,
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    client
        .ensure_fresh(refresh::EnsureFreshRequest {
            grant: grant.grant.clone(),
            min_remaining: None,
        })
        .await
        .unwrap();
    let values = client
        .resolve_secrets(wire::ResolveSecretsRequest {
            secrets: vec![wire::ResolveSecretRequest {
                request_id: "token".into(),
                owner: Some(owner()),
                reference: grant.output_references["token"].clone(),
                expected_version: Some(2),
            }],
            purpose: wire::ResolvePurpose::SandboxDelivery as i32,
        })
        .await
        .unwrap();
    assert_eq!(values.secrets[0].value, "custom-issued-value");
    assert_eq!(minter.0.load(Ordering::SeqCst), 1);
    stop.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    task.abort();
}
