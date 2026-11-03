// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use futures::StreamExt;
use openshell_credential_issuer::{
    auth::GatewayPolicy,
    backend::CredentialDriver,
    mint_spool::MintResultSpool,
    minter::MinterRegistry,
    remote_issuer::{RemoteIssuer, WatchedIssuer},
    repository::Repository,
    service::{CredentialRefreshService, CredentialStoreService},
    storage::CredentialStorage,
};
use openshell_driver_db_credstore::{
    DbCredstoreCredentialDriver, EncryptedGatewayCredentialStoreCrypto,
};
use openshell_extension_core::{
    ExtensionChannelConfig, ExtensionClientIdentity, ExtensionTlsAcceptor,
};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, SanType};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

pub struct Issuer {
    pub raw: RemoteIssuer,
    pub watched: WatchedIssuer,
    task: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}
impl Drop for Issuer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Issuer {
    pub async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let repository = Repository::open("sqlite::memory:").await.unwrap();
        let config = toml::Table::from_iter([(
            "key_encryption_key_path".into(),
            toml::Value::String(directory.path().join("key").display().to_string()),
        )]);
        let driver: Arc<dyn CredentialDriver> = Arc::new(
            DbCredstoreCredentialDriver::from_config(repository.backend_objects(), &config)
                .unwrap(),
        );
        let storage =
            CredentialStorage::new(BTreeMap::from([("db".into(), driver)]), "db".into()).unwrap();
        let identity = "spiffe://test.example/gateway/source";
        let policy =
            GatewayPolicy::new(BTreeMap::from([(identity.into(), vec!["default".into()])]))
                .unwrap();
        let store =
            CredentialStoreService::new(repository, storage, policy, Duration::from_mins(1))
                .unwrap();
        let refresh = CredentialRefreshService::new(
            &store,
            Arc::new(MinterRegistry::default()),
            MintResultSpool::new(
                EncryptedGatewayCredentialStoreCrypto::from_config(&config).unwrap(),
            ),
        )
        .unwrap();
        let key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = openshell_crypto::pki::self_signed(params, &key).unwrap();
        let server_key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = openshell_crypto::pki::signed_by(params, &server_key, &ca, &key).unwrap();
        let acceptor = ExtensionTlsAcceptor::from_pem(
            certificate.pem().as_bytes(),
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
                .add_service(store.into_service())
                .add_service(refresh.into_service())
                .serve_with_incoming(Box::pin(incoming))
                .await
                .unwrap();
        });
        let client_key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![SanType::URI(identity.try_into().unwrap())];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let certificate = openshell_crypto::pki::signed_by(params, &client_key, &ca, &key).unwrap();
        let config = ExtensionChannelConfig::new(endpoint)
            .with_custom_ca_pem(ca.pem())
            .with_client_identity(ExtensionClientIdentity::Pem {
                certificate: certificate.pem().into_bytes(),
                private_key: client_key.serialize_pem().unwrap().into_bytes(),
            });
        let raw = RemoteIssuer::connect(&config).await.unwrap();
        let watched = WatchedIssuer::new(raw.clone());
        Self {
            raw,
            watched,
            task,
            _directory: directory,
        }
    }
}
