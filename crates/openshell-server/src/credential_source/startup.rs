// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Explicit, fail-closed remote provider selection; internal secrets stay local.
use super::RemoteProviderSource;
use crate::persistence::{ObjectListQuery, Store};
use openshell_core::{ObjectId as _, ObjectName as _, ObjectWorkspace as _, proto::Provider};
use openshell_credential_issuer::remote_issuer::{RemoteIssuer, WatchedIssuer};
use openshell_extension_core::{ExtensionChannelConfig, ExtensionClientIdentity};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::AsyncReadExt as _;
use tonic::Status;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    pub name: String,
    pub endpoint: String,
    pub server_ca_path: PathBuf,
    pub client_cert_path: Option<PathBuf>,
    pub client_key_path: Option<PathBuf>,
    pub workload_api_endpoint: Option<String>,
    pub spiffe_id: Option<String>,
    #[serde(default = "startup_default")]
    pub startup_timeout_seconds: u32,
    #[serde(default = "cleanup_default")]
    pub cleanup_idle_seconds: u32,
}
const fn startup_default() -> u32 {
    30
}
const fn cleanup_default() -> u32 {
    300
}
impl std::fmt::Debug for RemoteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RemoteCredentialIssuer(<redacted>)")
    }
}
fn invalid() -> Status {
    Status::invalid_argument("invalid remote credential issuer configuration")
}
impl RemoteConfig {
    pub fn validate(&self) -> Result<(), Status> {
        let endpoint = url::Url::parse(&self.endpoint).map_err(|_| invalid())?;
        if !super::valid_registration(&self.name)
            || endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || !self.server_ca_path.is_absolute()
            || !(1..=300).contains(&self.startup_timeout_seconds)
            || !(60..=3600).contains(&self.cleanup_idle_seconds)
        {
            return Err(invalid());
        }
        self.identity()?;
        Ok(())
    }
    fn identity(&self) -> Result<ExtensionClientIdentity, Status> {
        match (
            &self.client_cert_path,
            &self.client_key_path,
            &self.workload_api_endpoint,
            &self.spiffe_id,
        ) {
            (Some(cert), Some(key), None, None) if cert.is_absolute() && key.is_absolute() => {
                Ok(ExtensionClientIdentity::PemFiles {
                    certificate: cert.clone(),
                    private_key: key.clone(),
                })
            }
            (None, None, Some(endpoint), Some(id)) => {
                let parsed = spiffe::SpiffeId::try_from(id.as_str()).map_err(|_| invalid())?;
                if parsed.to_string() != *id
                    || !endpoint
                        .strip_prefix("unix://")
                        .is_some_and(|path| Path::new(path).is_absolute())
                {
                    return Err(invalid());
                }
                Ok(ExtensionClientIdentity::Spiffe {
                    endpoint: endpoint.clone(),
                    spiffe_id: id.clone(),
                })
            }
            _ => Err(invalid()),
        }
    }
    pub async fn connect(&self, store: &Store) -> Result<RemoteProviderSource, Status> {
        self.validate()?;
        tokio::time::timeout(
            Duration::from_secs(u64::from(self.startup_timeout_seconds)),
            async {
                let ca = read_ca(&self.server_ca_path).await?;
                let channel = ExtensionChannelConfig::new(self.endpoint.clone())
                    .with_custom_ca_pem(ca)
                    .with_client_identity(self.identity()?);
                let client = RemoteIssuer::connect(&channel).await?;
                if !client.capabilities().supports_pending_reservations
                    || !client
                        .list_strategies()
                        .await?
                        .supports_pending_reservations
                {
                    return Err(Status::failed_precondition(
                        "credential issuer requires reservation capabilities",
                    ));
                }
                let source = RemoteProviderSource::new(&self.name, WatchedIssuer::new(client))?;
                register_existing(store, &source).await?;
                source
                    .client
                    .wait_synchronized(Duration::from_secs(u64::from(self.startup_timeout_seconds)))
                    .await?;
                Ok(source)
            },
        )
        .await
        .map_err(|_| Status::unavailable("credential issuer startup timed out"))?
    }
}
async fn read_ca(path: &Path) -> Result<Vec<u8>, Status> {
    let failure = || Status::failed_precondition("credential issuer server CA is unavailable");
    if !tokio::fs::metadata(path)
        .await
        .map_err(|_| failure())?
        .is_file()
    {
        return Err(failure());
    }
    let file = tokio::fs::File::open(path).await.map_err(|_| failure())?;
    let mut bytes = Vec::new();
    file.take(256 * 1024 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| failure())?;
    if bytes.is_empty() || bytes.len() > 256 * 1024 {
        return Err(failure());
    }
    Ok(bytes)
}
/// Paged, metadata-only registration. Remote mode never adopts local handles,
/// reads provider values, rewrites records, or starts an embedded refresh worker.
pub async fn register_existing(store: &Store, source: &RemoteProviderSource) -> Result<(), Status> {
    let page = store
        .list_object_page(
            "provider_credential_refresh_state",
            ObjectListQuery::AllWorkspaces,
            None,
            1,
        )
        .await
        .map_err(|_| Status::unavailable("credential issuer startup inventory failed"))?;
    if !page.records.is_empty() {
        return Err(Status::failed_precondition(
            "embedded refresh grants require explicit issuer migration",
        ));
    }
    let mut cursor = None;
    loop {
        let page = store
            .list_object_page(
                "provider",
                ObjectListQuery::AllWorkspaces,
                cursor.as_ref(),
                128,
            )
            .await
            .map_err(|_| Status::unavailable("credential issuer startup inventory failed"))?;
        for row in page.records {
            let provider = Provider::decode(row.payload.as_slice())
                .map_err(|_| Status::data_loss("invalid provider during issuer startup"))?;
            if provider.object_id() != row.id
                || provider.object_workspace() != row.workspace
                || provider.object_name() != row.name
            {
                return Err(Status::data_loss("invalid provider during issuer startup"));
            }
            source.register_provider(&provider)?;
        }
        let Some(next) = page.next_cursor else {
            return Ok(());
        };
        cursor = Some(next);
    }
}
#[cfg(test)]
mod tests;
