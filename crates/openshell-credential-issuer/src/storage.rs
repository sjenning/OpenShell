// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Namespace-bound physical addressing over legacy credential drivers.

use crate::{SecretOwner, auth::GatewayScope, backend::CredentialDriver};
use openshell_core::proto::{
    CredentialHandle,
    credentials::v1::{DeleteCredentialRequest, ResolveCredentialRequest, StoreCredentialRequest},
};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Write as _, sync::Arc};
use tonic::{Code, Status};

#[derive(Clone)]
pub struct CredentialStorage {
    drivers: BTreeMap<String, Arc<dyn CredentialDriver>>,
    default_driver: String,
}
impl std::fmt::Debug for CredentialStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStorage")
            .field("drivers", &self.drivers.keys().collect::<Vec<_>>())
            .field("default_driver", &self.default_driver)
            .finish()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Backing {
    version: u32,
    registration: String,
    handle: Vec<u8>,
    purpose: String,
    #[serde(default)]
    allocation: Option<String>,
}
struct DecodedBacking<'a> {
    handle: CredentialHandle,
    driver: &'a Arc<dyn CredentialDriver>,
    allocation: Option<String>,
}
struct Address {
    provider: String,
    workspace: String,
    provider_id: String,
}

pub struct ResolvedBacking {
    pub value: String,
    pub expiration_time_ms: Option<i64>,
}
impl std::fmt::Debug for ResolvedBacking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedBacking")
            .field("value", &"<redacted>")
            .field("expiration_time_ms", &self.expiration_time_ms)
            .finish()
    }
}
fn error(status: Status) -> Status {
    let code = match status.code() {
        Code::NotFound
        | Code::AlreadyExists
        | Code::Aborted
        | Code::FailedPrecondition
        | Code::ResourceExhausted
        | Code::DataLoss => status.code(),
        _ => Code::Unavailable,
    };
    Status::new(code, "issuer credential backend operation failed")
}
fn encode_error() -> Status {
    Status::data_loss("invalid issuer credential backing")
}
fn address(
    scope: &GatewayScope,
    owner: &SecretOwner,
    purpose: &str,
    allocation: Option<&str>,
) -> Result<Address, Status> {
    scope.authorize_owner(owner)?;
    if purpose.is_empty() || purpose.len() > 512 || purpose.chars().any(char::is_control) {
        return Err(Status::invalid_argument("invalid issuer storage purpose"));
    }
    // Canonical tuple encoding avoids delimiter ambiguity. This is non-secret
    // identity hashing through the crypto facade, not a credential fingerprint.
    let encoded = allocation
        .map_or_else(
            // Preserve reads/deletions of version-one backings exactly.
            || {
                serde_json::to_vec(&(
                    "openshell.issuer.backend-owner.v1",
                    scope.namespace(),
                    owner,
                    purpose,
                ))
            },
            |allocation| {
                serde_json::to_vec(&(
                    "openshell.issuer.backend-owner.v2",
                    scope.namespace(),
                    owner,
                    purpose,
                    allocation,
                ))
            },
        )
        .map_err(|_| encode_error())?;
    let digest = openshell_crypto::sha256(&encoded)
        .map_err(|_| Status::unavailable("issuer backend identity unavailable"))?;
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(hex, "{byte:02x}").expect("String writing cannot fail");
    }
    // A UUID-shaped protocol identifier, not a fresh random allocation. All
    // legacy owner fields use safe opaque names, never mutable display names.
    let id = uuid::Uuid::from_bytes(digest[..16].try_into().expect("SHA-256 prefix"));
    Ok(Address {
        provider: format!("issuer-{}", &hex[..48]),
        workspace: format!("issuer-{}", &hex[..48]),
        provider_id: id.to_string(),
    })
}
impl CredentialStorage {
    pub fn new(
        drivers: BTreeMap<String, Arc<dyn CredentialDriver>>,
        default_driver: String,
    ) -> Result<Self, Status> {
        if !drivers.contains_key(&default_driver)
            || drivers.keys().any(|name| {
                name.is_empty()
                    || name.len() > 128
                    || name.trim() != *name
                    || name.chars().any(char::is_control)
            })
        {
            return Err(Status::invalid_argument(
                "issuer credential drivers require an explicit registered default",
            ));
        }
        Ok(Self {
            drivers,
            default_driver,
        })
    }
    /// Always allocate a fresh immutable candidate. The caller retains cleanup
    /// ownership until a native metadata transaction takes over that ownership.
    pub async fn stage(
        &self,
        scope: &GatewayScope,
        owner: &SecretOwner,
        purpose: &str,
        value: String,
    ) -> Result<Vec<u8>, Status> {
        let allocation = uuid::Uuid::new_v4().to_string();
        let address = address(scope, owner, purpose, Some(&allocation))?;
        let driver = &self.drivers[&self.default_driver];
        let mut handle = driver
            .store_credential(StoreCredentialRequest {
                provider: address.provider,
                credential_key: "VALUE".to_string(),
                value,
                existing_handle: None,
                workspace: address.workspace,
                provider_id: address.provider_id,
                object_id: allocation.clone(),
            })
            .await
            .map_err(error)?;
        if handle.handle.trim().is_empty() {
            return Err(encode_error());
        }
        if handle.driver.is_empty() {
            handle.driver.clone_from(&self.default_driver);
        }
        serde_json::to_vec(&Backing {
            version: 2,
            registration: self.default_driver.clone(),
            handle: handle.encode_to_vec(),
            purpose: purpose.to_string(),
            allocation: Some(allocation),
        })
        .map_err(|_| encode_error())
    }
    fn decode<'a>(&'a self, bytes: &[u8], purpose: &str) -> Result<DecodedBacking<'a>, Status> {
        let backing: Backing = serde_json::from_slice(bytes).map_err(|_| encode_error())?;
        let valid_allocation = match (backing.version, backing.allocation.as_deref()) {
            (1, None) => true,
            (2, Some(id)) => uuid::Uuid::parse_str(id)
                .is_ok_and(|value| !value.is_nil() && value.to_string() == id),
            _ => false,
        };
        if !valid_allocation || backing.purpose != purpose {
            return Err(encode_error());
        }
        let handle =
            CredentialHandle::decode(backing.handle.as_slice()).map_err(|_| encode_error())?;
        if handle.handle.trim().is_empty() {
            return Err(encode_error());
        }
        let driver = self.drivers.get(&backing.registration).ok_or_else(|| {
            Status::failed_precondition("issuer backing driver is not configured")
        })?;
        Ok(DecodedBacking {
            handle,
            driver,
            allocation: backing.allocation,
        })
    }
    pub async fn resolve(
        &self,
        scope: &GatewayScope,
        owner: &SecretOwner,
        purpose: &str,
        backing: &[u8],
    ) -> Result<ResolvedBacking, Status> {
        scope.authorize_owner(owner)?;
        let DecodedBacking {
            handle,
            driver,
            allocation,
        } = self.decode(backing, purpose)?;
        let address = address(scope, owner, purpose, allocation.as_deref())?;
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut values = driver
            .resolve_credentials(vec![ResolveCredentialRequest {
                request_id: request_id.clone(),
                provider: address.provider,
                credential_key: "VALUE".to_string(),
                handle: Some(handle),
                workspace: address.workspace,
                provider_id: address.provider_id,
            }])
            .await
            .map_err(error)?;
        if values.len() != 1 || values[0].request_id != request_id {
            return Err(Status::data_loss(
                "issuer backend returned an invalid resolution batch",
            ));
        }
        let value = values.pop().expect("one resolved value");
        let expiration_time_ms = value
            .expiration_time
            .as_ref()
            .map(openshell_core::time::timestamp_to_millis)
            .transpose()
            .map_err(|_| encode_error())?;
        Ok(ResolvedBacking {
            value: value.value,
            expiration_time_ms,
        })
    }
    pub async fn delete(
        &self,
        scope: &GatewayScope,
        owner: &SecretOwner,
        purpose: &str,
        backing: &[u8],
    ) -> Result<(), Status> {
        scope.authorize_owner(owner)?;
        let DecodedBacking {
            handle,
            driver,
            allocation,
        } = self.decode(backing, purpose)?;
        let address = address(scope, owner, purpose, allocation.as_deref())?;
        driver
            .delete_credential(DeleteCredentialRequest {
                provider: address.provider,
                credential_key: "VALUE".to_string(),
                handle: Some(handle),
                workspace: address.workspace,
                provider_id: address.provider_id,
            })
            .await
            .map_err(error)
    }
}

#[cfg(test)]
mod tests;
