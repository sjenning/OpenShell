// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::remote_issuer::RemoteIssuer;
use openshell_core::proto::credentials::store::v1 as wire;
use openshell_extension_core::ExtensionClientIdentity;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, SanType};
mod minter;
mod postgres;
struct Fixture {
    directory: tempfile::TempDir,
    config: String,
    client: ExtensionChannelConfig,
    unknown: ExtensionChannelConfig,
    key: Vec<u8>,
    listener: Option<TcpListener>,
}
impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let ca_key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = openshell_crypto::pki::self_signed(params, &ca_key).unwrap();
        let server_key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = openshell_crypto::pki::signed_by(params, &server_key, &ca, &ca_key).unwrap();
        let key = server_key.serialize_pem().unwrap().into_bytes();
        std::fs::write(path.join("server.pem"), server.pem()).unwrap();
        std::fs::write(path.join("server.key"), &key).unwrap();
        std::fs::write(path.join("ca.pem"), ca.pem()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = format!("https://localhost:{}", address.port());
        let client = |id: &str| {
            let key = openshell_crypto::pki::generate_keypair().unwrap();
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.subject_alt_names = vec![SanType::URI(id.try_into().unwrap())];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let certificate = openshell_crypto::pki::signed_by(params, &key, &ca, &ca_key).unwrap();
            ExtensionChannelConfig::new(&endpoint)
                .with_custom_ca_pem(ca.pem())
                .with_client_identity(ExtensionClientIdentity::Pem {
                    certificate: certificate.pem().into_bytes(),
                    private_key: key.serialize_pem().unwrap().into_bytes(),
                })
        };
        let issuer_key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![SanType::URI(
            "spiffe://example.test/issuer/a".try_into().unwrap(),
        )];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let issuer = openshell_crypto::pki::signed_by(params, &issuer_key, &ca, &ca_key).unwrap();
        std::fs::write(path.join("issuer.pem"), issuer.pem()).unwrap();
        std::fs::write(path.join("issuer.key"), issuer_key.serialize_pem().unwrap()).unwrap();
        let config = format!(
            r#"[openshell.credential_issuer]
listen = "{address}"
database_url = "sqlite://{}?mode=rwc"
key_encryption_key_path = {:?}
tls_cert_path = {:?}
tls_key_path = {:?}
tls_client_ca_path = {:?}
refresh_interval_seconds = 3600
shutdown_timeout_seconds = 3
[openshell.credential_issuer.gateway_identities]
"spiffe://example.test/gateway/a" = ["default"]
"#,
            path.join("issuer.db").display(),
            path.join("encryption.key").to_string_lossy(),
            path.join("server.pem").to_string_lossy(),
            path.join("server.key").to_string_lossy(),
            path.join("ca.pem").to_string_lossy()
        );
        let trusted = client("spiffe://example.test/gateway/a");
        let unknown = client("spiffe://example.test/gateway/unknown");
        Self {
            directory,
            config,
            client: trusted,
            unknown,
            key,
            listener: Some(listener),
        }
    }
    async fn start(
        &mut self,
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<(), Status>>,
    ) {
        let daemon = Daemon::new(Config::parse(&self.config).unwrap())
            .await
            .unwrap();
        let listener = match self.listener.take() {
            Some(listener) => listener,
            None => TcpListener::bind(
                Config::parse(&self.config)
                    .unwrap()
                    .openshell
                    .credential_issuer
                    .listen,
            )
            .await
            .unwrap(),
        };
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            daemon
                .serve_on(listener, async {
                    let _ = stopped.await;
                })
                .await
        });
        (stop, task)
    }
}
fn owner() -> wire::SecretOwner {
    wire::SecretOwner {
        workspace: "default".into(),
        provider_id: "provider-id".into(),
        credential_key: "TOKEN".into(),
        provider: "display".into(),
    }
}
#[tokio::test]
async fn configured_daemon_authenticates_stores_and_reopens_its_own_encrypted_database() {
    let mut fixture = Fixture::new().await;
    let (stop, task) = fixture.start().await;
    let client = RemoteIssuer::connect(&fixture.client).await.unwrap();
    assert_eq!(client.list_strategies().await.unwrap().strategies.len(), 4);
    assert!(RemoteIssuer::connect(&fixture.unknown).await.is_err());
    let reservation = wire::ReserveSecretRequest {
        owner: Some(owner()),
        idempotency_key: "reserve".into(),
    };
    let reserved = client.reserve_secret(reservation.clone()).await.unwrap();
    assert_eq!(reserved.version, 1);
    let metadata = client
        .resolve_secrets(wire::ResolveSecretsRequest {
            purpose: wire::ResolvePurpose::MetadataInspection as i32,
            secrets: vec![wire::ResolveSecretRequest {
                request_id: "pending".into(),
                owner: Some(owner()),
                reference: reserved.reference.clone(),
                expected_version: Some(1),
            }],
        })
        .await
        .unwrap();
    assert!(metadata.secrets[0].pending_value);
    assert!(metadata.secrets[0].value.is_empty());
    let stored = client
        .put_secret(wire::PutSecretRequest {
            owner: Some(owner()),
            reference: reserved.reference.clone(),
            expected_version: Some(1),
            value: "not-in-sqlite-plaintext".into(),
            idempotency_key: "put".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    drop(client);
    assert!(
        !std::fs::read(fixture.directory.path().join("issuer.db"))
            .unwrap()
            .windows(b"not-in-sqlite-plaintext".len())
            .any(|window| window == b"not-in-sqlite-plaintext")
    );
    let (stop, task) = fixture.start().await;
    let client = RemoteIssuer::connect(&fixture.client).await.unwrap();
    assert_eq!(client.reserve_secret(reservation).await.unwrap(), reserved);
    let result = client
        .resolve_secrets(wire::ResolveSecretsRequest {
            secrets: vec![wire::ResolveSecretRequest {
                request_id: "one".into(),
                owner: Some(owner()),
                reference: stored.reference,
                expected_version: Some(2),
            }],
            purpose: wire::ResolvePurpose::SandboxDelivery as i32,
        })
        .await
        .unwrap();
    assert_eq!(result.secrets[0].value, "not-in-sqlite-plaintext");
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}
#[tokio::test]
async fn new_handshakes_reload_files_and_failed_clients_do_not_kill_the_listener() {
    use tokio::io::AsyncWriteExt as _;
    let mut fixture = Fixture::new().await;
    let (stop, task) = fixture.start().await;
    let address = Config::parse(&fixture.config)
        .unwrap()
        .openshell
        .credential_issuer
        .listen;
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket.write_all(b"not a TLS handshake").await.unwrap();
    drop(socket);
    let client = RemoteIssuer::connect(&fixture.client).await.unwrap();
    std::fs::write(fixture.directory.path().join("server.key"), b"invalid-key").unwrap();
    assert!(RemoteIssuer::connect(&fixture.client).await.is_err());
    assert!(client.list_strategies().await.is_ok());
    std::fs::write(fixture.directory.path().join("server.key"), &fixture.key).unwrap();
    assert!(RemoteIssuer::connect(&fixture.client).await.is_ok());
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}
