// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::{connect_channel, validate_config};
use super::*;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tower::{Service, ServiceExt};

type Error = Box<dyn std::error::Error + Send + Sync>;
struct Certificates {
    ca: String,
    server: String,
    server_key: String,
    client: String,
    client_key: String,
}
fn certificates() -> Certificates {
    openshell_crypto::tls::ensure_default_provider();
    let ca_key = openshell_crypto::pki::generate_keypair().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = openshell_crypto::pki::self_signed(params, &ca_key).unwrap();
    let server_key = openshell_crypto::pki::generate_keypair().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server = openshell_crypto::pki::signed_by(params, &server_key, &ca, &ca_key).unwrap();
    let client_key = openshell_crypto::pki::generate_keypair().unwrap();
    let mut params = CertificateParams::new(vec!["gateway.test".to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client = openshell_crypto::pki::signed_by(params, &client_key, &ca, &ca_key).unwrap();
    Certificates {
        ca: ca.pem(),
        server: server.pem(),
        server_key: server_key.serialize_pem().unwrap(),
        client: client.pem(),
        client_key: client_key.serialize_pem().unwrap(),
    }
}
async fn server(certs: &Certificates, client_ca: &str) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(&certs.server, &certs.server_key))
        .client_ca_root(tonic::transport::Certificate::from_pem(client_ca));
    let task = tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(super::super::tests::NoopGrpcService)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    (format!("https://localhost:{port}"), task)
}
async fn request(config: &ExtensionChannelConfig) -> Result<(), Error> {
    let mut channel = connect_channel(config).await?;
    channel.ready().await?;
    let response = channel
        .call(
            http::Request::post(format!("{}/openshell.test.Noop/Call", config.endpoint()))
                .body(tonic::body::Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), http::StatusCode::OK);
    Ok(())
}
fn identity(certs: &Certificates) -> ExtensionClientIdentity {
    ExtensionClientIdentity::Pem {
        certificate: certs.client.as_bytes().to_vec(),
        private_key: certs.client_key.as_bytes().to_vec(),
    }
}
#[tokio::test]
async fn mtls_authenticates_both_peers_and_preserves_hostname_checks() {
    let certs = certificates();
    let rogue = certificates();
    let (endpoint, task) = server(&certs, &certs.ca).await;
    let config = ExtensionChannelConfig::new(&endpoint).with_custom_ca_pem(certs.ca.as_bytes());
    assert!(request(&config).await.is_err());
    request(&config.clone().with_client_identity(identity(&certs)))
        .await
        .unwrap();
    assert!(
        request(&config.clone().with_client_identity(identity(&rogue)))
            .await
            .is_err()
    );
    let wrong_host = ExtensionChannelConfig::new(endpoint.replace("localhost", "127.0.0.1"))
        .with_custom_ca_pem(certs.ca.as_bytes())
        .with_client_identity(identity(&certs));
    assert!(request(&wrong_host).await.is_err());
    let wrong_server_ca = ExtensionChannelConfig::new(&endpoint)
        .with_custom_ca_pem(rogue.ca.as_bytes())
        .with_client_identity(identity(&certs));
    assert!(request(&wrong_server_ca).await.is_err());
    task.abort();
}
#[tokio::test]
async fn file_identities_are_reloaded_without_falling_back_to_old_credentials() {
    let certs = certificates();
    let rotated = certificates();
    let (endpoint, task) = server(&certs, &format!("{}{}", certs.ca, rotated.ca)).await;
    let dir = tempfile::tempdir().unwrap();
    let certificate = dir.path().join("tls.crt");
    let private_key = dir.path().join("tls.key");
    tokio::fs::write(&certificate, &certs.client).await.unwrap();
    tokio::fs::write(&private_key, &certs.client_key)
        .await
        .unwrap();
    let config = ExtensionChannelConfig::new(endpoint)
        .with_custom_ca_pem(certs.ca.as_bytes())
        .with_client_identity(ExtensionClientIdentity::PemFiles {
            certificate: certificate.clone(),
            private_key: private_key.clone(),
        });
    request(&config).await.unwrap();
    // A partial replacement must fail instead of sending the old identity.
    tokio::fs::write(&private_key, &rotated.client_key)
        .await
        .unwrap();
    assert!(request(&config).await.is_err());
    tokio::fs::write(&certificate, &rotated.client)
        .await
        .unwrap();
    request(&config).await.unwrap();
    tokio::fs::write(&private_key, b"malformed-private-key-marker")
        .await
        .unwrap();
    let error = connect_channel(&config).await.unwrap_err();
    assert!(!format!("{error:?}").contains("malformed-private-key-marker"));
    tokio::fs::remove_file(&private_key).await.unwrap();
    assert!(connect_channel(&config).await.is_err());
    task.abort();
}
#[test]
fn client_identity_never_uses_plaintext_or_leaks_pem_in_debug() {
    let id = ExtensionClientIdentity::Pem {
        certificate: b"certificate-marker".to_vec(),
        private_key: b"private-key-marker".to_vec(),
    };
    for endpoint in ["http://localhost:50051", "unix:///tmp/extension.sock"] {
        let config = ExtensionChannelConfig::new(endpoint).with_client_identity(id.clone());
        assert!(matches!(
            validate_config(&config),
            Err(TransportError::ClientIdentityRequiresHttps)
        ));
        assert!(!format!("{config:?}").contains("marker"));
    }
}
