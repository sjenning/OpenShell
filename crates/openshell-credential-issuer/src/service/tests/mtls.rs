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
    async fn start(service: CredentialStoreService) -> Self {
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
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service.into_service())
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
    async fn client(
        &self,
        identity: &str,
    ) -> wire::credential_store_client::CredentialStoreClient<Channel> {
        let key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![SanType::URI(identity.try_into().unwrap())];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = openshell_crypto::pki::signed_by(params, &key, &self.ca, &self.key).unwrap();
        let config = ExtensionChannelConfig::new(self.endpoint.clone())
            .with_custom_ca_pem(self.ca.pem())
            .with_client_identity(ExtensionClientIdentity::Pem {
                certificate: cert.pem().into_bytes(),
                private_key: key.serialize_pem().unwrap().into_bytes(),
            });
        wire::credential_store_client::CredentialStoreClient::new(
            connect_channel(&config).await.unwrap(),
        )
    }
}

#[tokio::test]
async fn authenticated_store_rpc_isolates_gateways_despite_matching_owner_and_forged_headers() {
    let fixture = Fixture::new().await;
    let server = Server::start(fixture.service.clone()).await;
    let mut a = server.client(A).await;
    let mut b = server.client(B).await;
    let caps = a
        .get_capabilities(wire::GetCapabilitiesRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(caps.supports_metadata_inspection);
    assert!(caps.supports_watch);
    let first = a.put_secret(put()).await.unwrap().into_inner();
    assert_eq!(a.put_secret(put()).await.unwrap().into_inner(), first);
    let mut forged = Request::new(resolve(
        &first.reference,
        wire::ResolvePurpose::OperatorExport,
    ));
    forged
        .metadata_mut()
        .insert("x-gateway-identity", A.parse().unwrap());
    assert_eq!(
        b.resolve_secrets(forged).await.unwrap_err().code(),
        Code::NotFound
    );
    let second = b
        .put_secret(wire::PutSecretRequest {
            value: "b-private".to_string(),
            ..put()
        })
        .await
        .unwrap()
        .into_inner();
    assert_ne!(first.reference, second.reference);
    assert_eq!(
        a.resolve_secrets(resolve(
            &first.reference,
            wire::ResolvePurpose::SandboxDelivery
        ))
        .await
        .unwrap()
        .into_inner()
        .secrets[0]
            .value,
        "private-value"
    );
    assert_eq!(
        b.resolve_secrets(resolve(
            &second.reference,
            wire::ResolvePurpose::SandboxDelivery
        ))
        .await
        .unwrap()
        .into_inner()
        .secrets[0]
            .value,
        "b-private"
    );
    let before = fixture.driver.resolves.load(Ordering::SeqCst);
    let metadata = a
        .resolve_secrets(resolve(
            &first.reference,
            wire::ResolvePurpose::MetadataInspection,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(metadata.secrets[0].value.is_empty());
    assert_eq!(before, fixture.driver.resolves.load(Ordering::SeqCst));
    let mut unauthorized = server
        .client("spiffe://test.example/issuer/not-a-gateway")
        .await;
    assert_eq!(
        unauthorized
            .get_capabilities(wire::GetCapabilitiesRequest {})
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        unauthorized.put_secret(put()).await.unwrap_err().code(),
        Code::PermissionDenied
    );
}

#[tokio::test]
async fn rpc_watch_replays_durable_change_sequences_and_revocation() {
    let fixture = Fixture::new().await;
    let server = Server::start(fixture.service.clone()).await;
    let mut client = server.client(A).await;
    let mut stream = client
        .watch_secrets(wire::WatchSecretsRequest { after_sequence: 0 })
        .await
        .unwrap()
        .into_inner();
    assert!(stream.message().await.unwrap().unwrap().reset_required);
    assert!(stream.message().await.unwrap().unwrap().checkpoint);
    let first = client.put_secret(put()).await.unwrap().into_inner();
    let event = tokio::time::timeout(Duration::from_secs(3), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(event.reference, first.reference);
    assert_eq!(event.sequence, 1);
    drop(stream);
    client
        .delete_secret(wire::DeleteSecretRequest {
            owner: Some(wire_owner()),
            reference: first.reference.clone(),
            expected_version: Some(1),
            idempotency_key: "delete".to_string(),
        })
        .await
        .unwrap();
    let mut replay = client
        .watch_secrets(wire::WatchSecretsRequest { after_sequence: 1 })
        .await
        .unwrap()
        .into_inner();
    let event = replay.message().await.unwrap().unwrap();
    assert!(event.revoked);
    assert_eq!(event.version, 2);
    assert_eq!(event.sequence, 2);
    assert_eq!(
        client
            .resolve_secrets(resolve(
                &first.reference,
                wire::ResolvePurpose::SandboxDelivery
            ))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
}
