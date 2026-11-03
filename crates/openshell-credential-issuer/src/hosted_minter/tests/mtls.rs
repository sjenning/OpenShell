// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use futures::StreamExt;
use openshell_extension_core::{
    ExtensionChannelConfig, ExtensionClientIdentity, ExtensionTlsAcceptor, connect_channel,
};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, SanType};
use tonic::transport::Channel;

struct Server {
    endpoint: String,
    ca: openshell_crypto::pki::Certificate,
    key: openshell_crypto::pki::KeyPair,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start(minter: Arc<TestMinter>) -> Self {
        openshell_crypto::tls::ensure_default_provider();
        let key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = openshell_crypto::pki::self_signed(params, &key).unwrap();
        let server_key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = openshell_crypto::pki::signed_by(params, &server_key, &ca, &key).unwrap();
        let acceptor = ExtensionTlsAcceptor::from_pem(
            cert.pem().as_bytes(),
            server_key.serialize_pem().unwrap().as_bytes(),
            ca.pem().as_bytes(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener)
            .map(move |socket| {
                let acceptor = acceptor.clone();
                async move {
                    match socket {
                        Ok(socket) => acceptor.accept(socket).await.ok(),
                        Err(_) => None,
                    }
                }
            })
            .buffer_unordered(16)
            .filter_map(|socket| async { socket.map(Ok::<_, std::io::Error>) });
        let service = HostedMinter::new(minter, policy(), 1)
            .unwrap()
            .into_service();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(Box::pin(incoming))
                .await
                .unwrap();
        });
        Self {
            endpoint,
            ca,
            key,
            task,
        }
    }
    fn config(&self, id: &str) -> ExtensionChannelConfig {
        let key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![SanType::URI(id.try_into().unwrap())];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = openshell_crypto::pki::signed_by(params, &key, &self.ca, &self.key).unwrap();
        ExtensionChannelConfig::new(self.endpoint.clone())
            .with_custom_ca_pem(self.ca.pem())
            .with_client_identity(ExtensionClientIdentity::Pem {
                certificate: cert.pem().into_bytes(),
                private_key: key.serialize_pem().unwrap().into_bytes(),
            })
    }
    async fn client(&self, id: &str) -> wire::token_minter_client::TokenMinterClient<Channel> {
        wire::token_minter_client::TokenMinterClient::new(
            connect_channel(&self.config(id)).await.unwrap(),
        )
    }
}
const ISSUER: &str = "spiffe://test.example/issuer/a";

#[tokio::test]
async fn hosted_service_and_production_remote_adapter_preserve_attempt_and_rotated_material() {
    let minter = Arc::new(TestMinter::default());
    let server = Server::start(minter.clone()).await;
    let remote = crate::remote_minter::RemoteMinter::connect(&server.config(ISSUER), "test")
        .await
        .unwrap();
    let req = request();
    let response = remote
        .mint(MintRequest {
            strategy: req.strategy,
            config: req.config,
            secret_material: req.secret_material,
            attempt_id: req.attempt_id,
        })
        .await
        .unwrap();
    assert_eq!(response.outputs["access_token"], "minted-secret");
    assert_eq!(
        response.rotated_secret_material["refresh_token"],
        "rotated-secret"
    );
    let requests = minter.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].attempt_id, "stable-attempt");
    assert_eq!(requests[0].secret_material["refresh_token"], "input-secret");
}

#[tokio::test]
async fn gateway_and_unlisted_issuer_certificates_cannot_invoke_or_discover_the_minter() {
    let minter = Arc::new(TestMinter::default());
    let server = Server::start(minter.clone()).await;
    for id in [
        "spiffe://test.example/gateway/a",
        "spiffe://test.example/issuer/b",
    ] {
        let mut client = server.client(id).await;
        let mut req = Request::new(request());
        req.metadata_mut()
            .insert("x-issuer-identity", ISSUER.parse().unwrap());
        assert_eq!(
            client.mint(req).await.unwrap_err().code(),
            Code::PermissionDenied
        );
        assert_eq!(
            client
                .describe(wire::DescribeRequest {})
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
    }
    assert!(minter.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn invalid_inputs_fail_before_contacting_implementation() {
    let minter = Arc::new(TestMinter::default());
    let server = Server::start(minter.clone()).await;
    let mut client = server.client(ISSUER).await;
    for req in [
        wire::MintRequest {
            attempt_id: String::new(),
            ..request()
        },
        wire::MintRequest {
            strategy: "custom:other".to_string(),
            ..request()
        },
        wire::MintRequest {
            secret_material: HashMap::new(),
            ..request()
        },
        wire::MintRequest {
            config: HashMap::from([("undeclared".to_string(), "secret".to_string())]),
            ..request()
        },
    ] {
        let status = client.mint(req).await.unwrap_err();
        let detail = wire::MintFailureDetail::decode(status.details()).unwrap();
        assert_eq!(
            detail.recovery_action,
            wire::RecoveryAction::FixConfiguration as i32
        );
    }
    assert!(minter.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn executing_exchange_survives_disconnect_and_overload_is_explicitly_retryable() {
    let minter = Arc::new(TestMinter::default());
    minter.mode.store(1, Ordering::SeqCst);
    let server = Server::start(minter.clone()).await;
    let mut client = server.client(ISSUER).await;
    let mut first = client.clone();
    let call = tokio::spawn(async move { first.mint(request()).await });
    tokio::time::timeout(Duration::from_secs(3), minter.started.notified())
        .await
        .unwrap();
    let status = client.mint(request()).await.unwrap_err();
    assert_eq!(status.code(), Code::ResourceExhausted);
    let detail = wire::MintFailureDetail::decode(status.details()).unwrap();
    assert_eq!(detail.recovery_action, wire::RecoveryAction::Retry as i32);
    assert_eq!(detail.retry_schedule, wire::RetrySchedule::Short as i32);
    call.abort();
    let _ = call.await;
    minter.release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), minter.finished.notified())
        .await
        .unwrap();
    assert_eq!(minter.requests.lock().unwrap().len(), 1);
}
