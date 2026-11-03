// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use futures::StreamExt;
use openshell_core::proto::{
    CredentialHandle,
    credentials::v1::{
        DeleteCredentialRequest, ResolveCredentialRequest, ResolvedCredential,
        StoreCredentialRequest,
    },
};
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
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tonic::Status;
#[derive(Debug)]
struct Driver {
    inner: DbCredstoreCredentialDriver,
    resolves: Arc<AtomicUsize>,
    fail: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl CredentialDriver for Driver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        self.inner.store_credential(request).await
    }
    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        self.inner.delete_credential(request).await
    }
    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        self.resolves.fetch_add(requests.len(), Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(Status::unavailable("private backend failure"));
        }
        self.inner.resolve_credentials(requests).await
    }
}

pub struct Issuer {
    pub raw: RemoteIssuer,
    pub watched: WatchedIssuer,
    pub resolves: Arc<AtomicUsize>,
    pub fail_resolves: Arc<AtomicBool>,
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
        Self::with_minters(Arc::new(MinterRegistry::default())).await
    }
    pub async fn with_minters(minters: Arc<MinterRegistry>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let repository = Repository::open("sqlite::memory:").await.unwrap();
        let config = toml::Table::from_iter([(
            "key_encryption_key_path".into(),
            toml::Value::String(directory.path().join("key").display().to_string()),
        )]);
        let resolves = Arc::new(AtomicUsize::new(0));
        let fail_resolves = Arc::new(AtomicBool::new(false));
        let driver: Arc<dyn CredentialDriver> = Arc::new(Driver {
            inner: DbCredstoreCredentialDriver::from_config(repository.backend_objects(), &config)
                .unwrap(),
            resolves: resolves.clone(),
            fail: fail_resolves.clone(),
        });
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
            minters,
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
            resolves,
            fail_resolves,
            task,
            _directory: directory,
        }
    }
}
