// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Embedded hosting composes the identical issuer handlers without a listener.
use super::{RemoteProviderSource, startup::register_existing};
use crate::{credentials::CredentialRuntime, persistence::Store};
use openshell_credential_issuer::{
    mint_spool::MintResultSpool,
    remote_issuer::{RemoteIssuer, WatchedIssuer},
    repository::Repository,
    service::{CredentialRefreshService, CredentialStoreService},
    storage::CredentialStorage,
};
use std::{sync::Arc, time::Duration};
use tonic::Status;
pub mod grants;
pub(crate) mod migration;

pub struct EmbeddedIssuer {
    pub source: RemoteProviderSource,
    pub store: CredentialStoreService,
    pub refresh: CredentialRefreshService,
    workers: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for EmbeddedIssuer {
    fn drop(&mut self) {
        for worker in &self.workers {
            worker.abort();
        }
    }
}
impl EmbeddedIssuer {
    pub async fn new(
        database_url: &str,
        gateway: &Store,
        legacy: &CredentialRuntime,
        crypto_config: &toml::Table,
        custom_minters: &std::collections::BTreeMap<
            String,
            openshell_credential_issuer::daemon::MinterConfig,
        >,
    ) -> Result<Self, Status> {
        let repository = Repository::open(database_url).await?;
        let (drivers, default) = legacy.issuer_drivers();
        let storage = CredentialStorage::new(drivers, default)?;
        let store = CredentialStoreService::embedded(repository, storage, Duration::from_mins(1))?;
        let crypto =
            openshell_driver_db_credstore::EncryptedGatewayCredentialStoreCrypto::from_config(
                crypto_config,
            )
            .map_err(|_| Status::unavailable("embedded issuer encryption configuration failed"))?;
        let mut minters = openshell_credential_issuer::builtins::registry();
        openshell_credential_issuer::daemon::register_minters(&mut minters, custom_minters).await?;
        let refresh =
            CredentialRefreshService::new(&store, Arc::new(minters), MintResultSpool::new(crypto))?;
        let client = RemoteIssuer::embedded(store.clone(), refresh.clone()).await?;
        let source = RemoteProviderSource::new("embedded", WatchedIssuer::new(client))?
            .with_gateway_store(Arc::new(gateway.clone()));
        migration::providers(gateway, legacy, &store, &refresh, &source).await?;
        migration::internal(gateway, legacy, &store, &source).await?;
        register_existing(gateway, &source).await?;
        source
            .issuer()
            .wait_synchronized(Duration::from_secs(30))
            .await?;
        let workers = vec![
            store.spawn_maintenance(Duration::from_secs(10))?,
            refresh.spawn_worker(Duration::from_secs(10))?,
        ];
        Ok(Self {
            source,
            store,
            refresh,
            workers,
        })
    }
    pub async fn drain(&self) {
        for worker in &self.workers {
            worker.abort();
        }
        self.store.drain().await;
    }
}

#[cfg(test)]
mod tests;
