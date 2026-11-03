// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypted known-success mint results for revision-fenced grant publication.
//!
//! Persist the sealed bytes in the grant's native transaction before external
//! output/material staging. Recovery can then finish publication without minting
//! again or losing a rotated refresh token during a backend outage.

use crate::{auth::GatewayScope, grant::GrantIdentity, minter::MintResponse};
use openshell_driver_db_credstore::EncryptedGatewayCredentialStoreCrypto;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Write as _};
use tonic::Status;

const MAX_SOURCE: usize = 1024 * 1024;
const MAX_PLAINTEXT: usize = 8 * 1024 * 1024;
const MAX_ENVELOPE: usize = 16 * 1024 * 1024;
const KEY: &str = "MINT_RESULT";

#[derive(Clone)]
pub struct MintResultSpool {
    crypto: EncryptedGatewayCredentialStoreCrypto,
}
impl std::fmt::Debug for MintResultSpool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MintResultSpool(<redacted>)")
    }
}
#[derive(Serialize)]
struct WritePayload<'a> {
    version: u32,
    attempt_id: &'a str,
    outputs: &'a HashMap<String, String>,
    expiration_time_ms: i64,
    rotated_secret_material: &'a HashMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadPayload {
    version: u32,
    attempt_id: String,
    outputs: HashMap<String, String>,
    expiration_time_ms: i64,
    rotated_secret_material: HashMap<String, String>,
}

fn binding(scope: &GatewayScope, grant: &GrantIdentity, attempt: &str) -> Result<String, Status> {
    scope.authorize_owner(&grant.owner)?;
    if [&grant.id, &grant.authorization_epoch, attempt]
        .into_iter()
        .any(|part| part.is_empty() || part.len() > 128 || part.chars().any(char::is_control))
    {
        return Err(Status::invalid_argument(
            "mint spool requires a complete immutable grant attempt",
        ));
    }
    let tuple = (
        "openshell.issuer.mint-result.v1",
        scope.namespace(),
        &grant.id,
        &grant.authorization_epoch,
        &grant.owner,
        attempt,
    );
    let bytes = serde_json::to_vec(&tuple)
        .map_err(|_| Status::internal("mint spool binding encoding failed"))?;
    let digest = openshell_crypto::sha256(&bytes)
        .map_err(|_| Status::unavailable("mint spool identity unavailable"))?;
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(hex, "{byte:02x}").expect("writing String cannot fail");
    }
    Ok(hex)
}
impl MintResultSpool {
    /// Reuses the encrypted-database driver's facade-owned AES-GCM envelope and
    /// key loading. Replicas must share this configured key; no crypto fallback.
    pub fn new(crypto: EncryptedGatewayCredentialStoreCrypto) -> Self {
        Self { crypto }
    }
    pub fn seal(
        &self,
        scope: &GatewayScope,
        grant: &GrantIdentity,
        attempt: &str,
        response: &MintResponse,
    ) -> Result<Vec<u8>, Status> {
        let owner = binding(scope, grant, attempt)?;
        let mut fields = response
            .outputs
            .iter()
            .chain(response.rotated_secret_material.iter());
        let source_size = fields.try_fold(0usize, |size, (key, value)| {
            size.checked_add(key.len())?.checked_add(value.len())
        });
        if response.outputs.len() > 64
            || response.rotated_secret_material.len() > 64
            || source_size.is_none_or(|size| size > MAX_SOURCE)
        {
            return Err(Status::resource_exhausted(
                "mint spool response exceeds limit",
            ));
        }
        let payload = serde_json::to_string(&WritePayload {
            version: 1,
            attempt_id: attempt,
            outputs: &response.outputs,
            expiration_time_ms: response.expiration_time_ms,
            rotated_secret_material: &response.rotated_secret_material,
        })
        .map_err(|_| Status::internal("mint spool response encoding failed"))?;
        if payload.len() > MAX_PLAINTEXT {
            return Err(Status::resource_exhausted(
                "mint spool response exceeds limit",
            ));
        }
        // The context digest is an authenticated envelope identity, not a
        // backend object allocation. Encryption still generates fresh keys and
        // nonces through the existing crypto facade on every seal.
        let envelope = self
            .crypto
            .encrypt_envelope(&owner, &owner, KEY, &payload)
            .map_err(|_| Status::unavailable("mint spool encryption failed"))?;
        EncryptedGatewayCredentialStoreCrypto::serialize_envelope(&envelope)
            .map_err(|_| Status::internal("mint spool envelope encoding failed"))
    }
    pub fn open(
        &self,
        scope: &GatewayScope,
        grant: &GrantIdentity,
        attempt: &str,
        bytes: &[u8],
    ) -> Result<MintResponse, Status> {
        let owner = binding(scope, grant, attempt)?;
        if bytes.len() > MAX_ENVELOPE {
            return Err(Status::data_loss("mint spool envelope exceeds limit"));
        }
        let envelope =
            EncryptedGatewayCredentialStoreCrypto::deserialize_envelope(bytes, "mint result")
                .map_err(|_| Status::data_loss("invalid mint spool envelope"))?;
        EncryptedGatewayCredentialStoreCrypto::ensure_envelope_owner(
            &envelope, &owner, &owner, KEY,
        )
        .map_err(|_| {
            Status::permission_denied(
                "mint spool belongs to another caller, grant, epoch, or attempt",
            )
        })?;
        let payload = self
            .crypto
            .decrypt_envelope(&envelope)
            .map_err(|_| Status::data_loss("mint spool decryption failed"))?;
        if payload.len() > MAX_PLAINTEXT {
            return Err(Status::data_loss("mint spool response exceeds limit"));
        }
        let response: ReadPayload = serde_json::from_str(&payload)
            .map_err(|_| Status::data_loss("invalid mint spool response"))?;
        if response.version != 1 || response.attempt_id != attempt {
            return Err(Status::data_loss(
                "mint spool attempt or format does not match",
            ));
        }
        // Expired outputs are intentionally recoverable: preserve any rotated
        // material before deciding whether another mint is necessary.
        Ok(MintResponse {
            outputs: response.outputs,
            expiration_time_ms: response.expiration_time_ms,
            rotated_secret_material: response.rotated_secret_material,
        })
    }
}

#[cfg(test)]
mod tests;
