// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Strict, secret-redacted standalone issuer configuration.
use crate::auth::GatewayPolicy;
use openshell_extension_core::ExtensionClientIdentity;
use serde::Deserialize;
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};
use tonic::Status;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub(super) openshell: OpenShell,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OpenShell {
    pub credential_issuer: Issuer,
    #[serde(default)]
    pub credential_drivers: BTreeMap<String, toml::Table>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Issuer {
    pub listen: SocketAddr,
    pub database_url: String,
    #[serde(default = "one")]
    pub replicas: u32,
    pub key_encryption_key_path: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub tls_client_ca_path: PathBuf,
    pub gateway_identities: BTreeMap<String, Vec<String>>,
    #[serde(default = "database_driver")]
    pub storage_driver: String,
    #[serde(default = "cache_ttl")]
    pub cache_ttl_seconds: u64,
    #[serde(default = "refresh_interval")]
    pub refresh_interval_seconds: u64,
    #[serde(default = "shutdown_timeout")]
    pub shutdown_timeout_seconds: u64,
    #[serde(default)]
    pub minters: BTreeMap<String, Minter>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Minter {
    pub endpoint: String,
    pub tls_ca_cert_path: PathBuf,
    pub tls_client_cert_path: Option<PathBuf>,
    pub tls_client_key_path: Option<PathBuf>,
    pub workload_api_endpoint: Option<String>,
    pub spiffe_id: Option<String>,
}
fn one() -> u32 {
    1
}
fn database_driver() -> String {
    openshell_driver_db_credstore::DbCredstoreCredentialDriver::NAME.into()
}
fn cache_ttl() -> u64 {
    60
}
fn refresh_interval() -> u64 {
    10
}
fn shutdown_timeout() -> u64 {
    180
}
fn invalid() -> Status {
    Status::invalid_argument("invalid credential issuer configuration")
}
impl Config {
    /// Parsing errors deliberately exclude TOML excerpts, database credentials,
    /// native backend config, and cryptographic file contents.
    pub fn parse(input: &str) -> Result<Self, Status> {
        if input.len() > 1024 * 1024 {
            return Err(invalid());
        }
        let config: Self = toml::from_str(input).map_err(|_| invalid())?;
        config.validate()?;
        Ok(config)
    }
    pub(super) fn validate(&self) -> Result<(), Status> {
        let config = &self.openshell.credential_issuer;
        GatewayPolicy::new(config.gateway_identities.clone())?;
        let database = reqwest::Url::parse(&config.database_url).map_err(|_| invalid())?;
        if !matches!(database.scheme(), "postgres" | "postgresql" | "sqlite")
            || config.replicas == 0
            || (config.replicas > 1 && !matches!(database.scheme(), "postgres" | "postgresql"))
            || config.database_url.contains(":memory:")
            || (database.scheme() == "sqlite"
                && database
                    .query_pairs()
                    .any(|(key, value)| key == "mode" && value == "memory"))
        {
            return Err(Status::invalid_argument(
                "issuer requires durable SQL storage; multiple replicas require PostgreSQL",
            ));
        }
        for path in [
            &config.key_encryption_key_path,
            &config.tls_cert_path,
            &config.tls_key_path,
            &config.tls_client_ca_path,
        ] {
            if !path.is_absolute() {
                return Err(invalid());
            }
        }
        if config.cache_ttl_seconds > 60
            || !(1..=3600).contains(&config.refresh_interval_seconds)
            || !(1..=300).contains(&config.shutdown_timeout_seconds)
            || config.minters.len() > 60
        {
            return Err(invalid());
        }
        let known = [
            openshell_driver_db_credstore::DbCredstoreCredentialDriver::NAME,
            openshell_driver_vault::VaultCredentialDriver::NAME,
            openshell_driver_kubernetes_secrets::KubernetesSecretsCredentialDriver::NAME,
        ];
        for (name, table) in &self.openshell.credential_drivers {
            if !known.contains(&name.as_str()) || (name == known[0] && !table.is_empty()) {
                return Err(Status::invalid_argument(
                    "unsupported issuer storage registration; configure the shared encryption key in credential_issuer",
                ));
            }
        }
        if config.storage_driver != known[0]
            && !self
                .openshell
                .credential_drivers
                .contains_key(&config.storage_driver)
        {
            return Err(invalid());
        }
        for (name, minter) in &config.minters {
            if !crate::minter::valid_id(name) {
                return Err(invalid());
            }
            minter.identity()?;
            let endpoint = reqwest::Url::parse(&minter.endpoint).map_err(|_| invalid())?;
            if endpoint.scheme() != "https"
                || endpoint.host_str().is_none()
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
                || !matches!(endpoint.path(), "" | "/")
                || !minter.tls_ca_cert_path.is_absolute()
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
impl Minter {
    pub(super) fn identity(&self) -> Result<ExtensionClientIdentity, Status> {
        match (
            &self.tls_client_cert_path,
            &self.tls_client_key_path,
            &self.workload_api_endpoint,
            &self.spiffe_id,
        ) {
            (Some(certificate), Some(private_key), None, None)
                if certificate.is_absolute() && private_key.is_absolute() =>
            {
                Ok(ExtensionClientIdentity::PemFiles {
                    certificate: certificate.clone(),
                    private_key: private_key.clone(),
                })
            }
            (None, None, Some(endpoint), Some(id)) => {
                let parsed = spiffe::SpiffeId::try_from(id.as_str()).map_err(|_| invalid())?;
                if parsed.to_string() != *id
                    || !endpoint
                        .strip_prefix("unix://")
                        .is_some_and(|path| std::path::Path::new(path).is_absolute())
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
}
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuerConfig(<redacted>)")
    }
}
#[cfg(test)]
mod tests;
