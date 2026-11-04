// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Standalone issuer composition. No gateway database, public RPCs, or auth path.
mod config;
use crate::{
    auth::GatewayPolicy,
    backend::CredentialDriver,
    builtins,
    mint_spool::MintResultSpool,
    remote_minter::RemoteMinter,
    repository::Repository,
    service::{CredentialRefreshService, CredentialStoreService},
    storage::CredentialStorage,
};
pub use config::{Config, Minter as MinterConfig};
use futures::StreamExt as _;
use openshell_driver_db_credstore::{
    DbCredstoreCredentialDriver, EncryptedGatewayCredentialStoreCrypto,
};
use openshell_extension_core::{ExtensionChannelConfig, ExtensionTlsAcceptor};
use std::{
    collections::BTreeMap,
    future::Future,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{io::AsyncReadExt as _, net::TcpListener};
use tonic::Status;
const FILE_LIMIT: u64 = 256 * 1024;
struct TlsFiles {
    certificate: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}
async fn read(path: &Path) -> Result<Vec<u8>, Status> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| Status::unavailable("issuer identity or trust file unavailable"))?;
    let mut bytes = Vec::new();
    file.take(FILE_LIMIT + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| Status::unavailable("issuer identity or trust file unavailable"))?;
    if bytes.is_empty() || bytes.len() > usize::try_from(FILE_LIMIT).expect("bounded file limit") {
        return Err(Status::invalid_argument(
            "issuer identity or trust file exceeds limits",
        ));
    }
    Ok(bytes)
}
impl TlsFiles {
    async fn load(&self) -> Result<ExtensionTlsAcceptor, Status> {
        for _ in 0..3 {
            let cert = read(&self.certificate).await?;
            let key = read(&self.key).await?;
            let ca = read(&self.ca).await?;
            if cert == read(&self.certificate).await?
                && key == read(&self.key).await?
                && ca == read(&self.ca).await?
            {
                return ExtensionTlsAcceptor::from_pem(&cert, &key, &ca)
                    .map_err(|_| Status::invalid_argument("issuer mTLS configuration is invalid"));
            }
        }
        Err(Status::unavailable(
            "issuer mTLS files changed while loading",
        ))
    }
}
/// Owns issuer persistence, registered storage, minters, and authenticated RPCs.
/// Debug deliberately omits backend config, URLs, keys, and secret material.
pub struct Daemon {
    store: CredentialStoreService,
    refresh: CredentialRefreshService,
    tls: Arc<TlsFiles>,
    listen: std::net::SocketAddr,
    metrics_bind_address: Option<std::net::SocketAddr>,
    interval: Duration,
    shutdown_timeout: Duration,
}
impl Daemon {
    pub async fn new(config: Config) -> Result<Self, Status> {
        config.validate()?;
        let options = &config.openshell.credential_issuer;
        let tls = Arc::new(TlsFiles {
            certificate: options.tls_cert_path.clone(),
            key: options.tls_key_path.clone(),
            ca: options.tls_client_ca_path.clone(),
        });
        tls.load().await?;
        if options.replicas > 1 && !options.key_encryption_key_path.is_file() {
            return Err(Status::invalid_argument(
                "replicated issuers require a provisioned shared encryption key",
            ));
        }
        let crypto_config = toml::Table::from_iter([(
            "key_encryption_key_path".into(),
            toml::Value::String(
                options
                    .key_encryption_key_path
                    .to_str()
                    .ok_or_else(|| Status::invalid_argument("invalid issuer encryption key path"))?
                    .into(),
            ),
        )]);
        let repository = Repository::open(&options.database_url)
            .await
            .map_err(|_| Status::unavailable("issuer database initialization failed"))?;
        let mut drivers: BTreeMap<String, Arc<dyn CredentialDriver>> = BTreeMap::new();
        drivers.insert(
            DbCredstoreCredentialDriver::NAME.into(),
            Arc::new(
                DbCredstoreCredentialDriver::from_config(
                    repository.backend_objects(),
                    &crypto_config,
                )
                .map_err(|_| {
                    Status::unavailable("issuer encrypted storage initialization failed")
                })?,
            ),
        );
        for (name, table) in &config.openshell.credential_drivers {
            let driver:Arc<dyn CredentialDriver>=match name.as_str() {
                openshell_driver_vault::VaultCredentialDriver::NAME=>Arc::new(openshell_driver_vault::VaultCredentialDriver::from_config(table).map_err(|_|Status::unavailable("issuer Vault storage initialization failed"))?),
                openshell_driver_kubernetes_secrets::KubernetesSecretsCredentialDriver::NAME=>Arc::new(Box::pin(openshell_driver_kubernetes_secrets::KubernetesSecretsCredentialDriver::from_config(table)).await.map_err(|_|Status::unavailable("issuer Kubernetes storage initialization failed"))?),
                DbCredstoreCredentialDriver::NAME=>continue,
                _=>return Err(Status::invalid_argument("unsupported issuer storage registration")),
            };
            drivers.insert(name.clone(), driver);
        }
        let storage = CredentialStorage::new(drivers, options.storage_driver.clone())?;
        let policy = GatewayPolicy::new(options.gateway_identities.clone())?;
        let store = CredentialStoreService::new(
            repository,
            storage,
            policy,
            Duration::from_secs(options.cache_ttl_seconds),
        )?;
        let mut registry = builtins::registry();
        register_minters(&mut registry, &options.minters).await?;
        let spool = MintResultSpool::new(
            EncryptedGatewayCredentialStoreCrypto::from_config(&crypto_config)
                .map_err(|_| Status::unavailable("issuer mint spool initialization failed"))?,
        );
        let refresh = CredentialRefreshService::new(&store, Arc::new(registry), spool)?;
        Ok(Self {
            store,
            refresh,
            tls,
            listen: options.listen,
            metrics_bind_address: options.metrics_bind_address,
            interval: Duration::from_secs(options.refresh_interval_seconds),
            shutdown_timeout: Duration::from_secs(options.shutdown_timeout_seconds),
        })
    }
    pub async fn serve(self, shutdown: impl Future<Output = ()> + Send) -> Result<(), Status> {
        let listener = TcpListener::bind(self.listen)
            .await
            .map_err(|_| Status::unavailable("issuer listener could not bind"))?;
        self.serve_on(listener, shutdown).await
    }
    async fn serve_on(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send,
    ) -> Result<(), Status> {
        let address = listener
            .local_addr()
            .map_err(|_| Status::unavailable("issuer listener unavailable"))?;
        let _metrics = self
            .metrics_bind_address
            .map(crate::observability::start_exporter)
            .transpose()?;
        let tls = self.tls.clone();
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener)
            .map(move |socket| {
                let tls = tls.clone();
                async move {
                    let socket = socket?;
                    // Bound both file reads and incomplete handshakes. Failed clients
                    // never terminate the listener or retain a previous identity.
                    let handshake = tokio::time::timeout(Duration::from_secs(10), async move {
                        let acceptor = tls.load().await.ok()?;
                        acceptor.accept(socket).await.ok()
                    })
                    .await;
                    let stream = handshake.ok().flatten();
                    if stream.is_none() {
                        crate::observability::authentication_denied();
                    }
                    Ok::<_, std::io::Error>(stream)
                }
            })
            .buffer_unordered(32)
            .filter_map(|result| async move {
                match result {
                    Ok(Some(stream)) => Some(Ok(stream)),
                    Ok(None) => None,
                    Err(error) => Some(Err(error)),
                }
            });
        let worker = Worker(self.refresh.spawn_worker(self.interval)?);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tonic::transport::Server::builder()
            .add_service(self.store.clone().into_service())
            .add_service(self.refresh.clone().into_service())
            .serve_with_incoming_shutdown(Box::pin(incoming), async {
                let _ = stopped.await;
            });
        tokio::pin!(server);
        tokio::pin!(shutdown);
        tracing::info!(%address,"credential issuer listening with mandatory mTLS");
        let ended = tokio::select! {result=&mut server=>Some(result),()=&mut shutdown=>None};
        worker.0.abort();
        self.store.stop_admission();
        let _ = stop.send(());
        tokio::time::timeout(self.shutdown_timeout, async {
            let result = if let Some(result) = ended {
                self.store.drain().await;
                result
            } else {
                let (result, ()) = tokio::join!(&mut server, self.store.drain());
                result
            };
            result.map_err(|_| Status::unavailable("issuer transport stopped"))
        })
        .await
        .map_err(|_| {
            Status::deadline_exceeded(
                "issuer shutdown deadline elapsed; inspect uncertain operations",
            )
        })?
    }
}
struct Worker(tokio::task::JoinHandle<()>);
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuerDaemon(<redacted>)")
    }
}
#[cfg(test)]
mod tests;

/// Share operator-registered custom minters across in-process and standalone
/// hosting. Registrations never bypass the private-CA/client-identity boundary.
pub async fn register_minters(
    registry: &mut crate::minter::MinterRegistry,
    minters: &BTreeMap<String, MinterConfig>,
) -> Result<(), Status> {
    if minters.len() > 60 {
        return Err(Status::invalid_argument(
            "issuer minter registration limit exceeded",
        ));
    }
    for (name, minter) in minters {
        if !crate::minter::valid_id(name) || !minter.tls_ca_cert_path.is_absolute() {
            return Err(Status::invalid_argument(
                "invalid issuer minter registration",
            ));
        }
        let channel = ExtensionChannelConfig::new(&minter.endpoint)
            .with_custom_ca_pem(read(&minter.tls_ca_cert_path).await?)
            .with_client_identity(minter.identity()?);
        let remote = RemoteMinter::connect(&channel, name).await?;
        registry.register_custom(Arc::new(remote))?;
    }
    Ok(())
}
