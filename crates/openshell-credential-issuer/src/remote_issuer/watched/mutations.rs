// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Pre-effect admission, and best-effort local bookkeeping after remote commit.
use super::{Inner, cache, refresh, store, tracking};
use prost::Message as _;
use std::{collections::HashMap, time::Duration};
use tonic::Status;

fn bounded(request: &impl prost::Message) -> Result<(), Status> {
    if request.encoded_len() > super::super::LIMIT {
        return Err(Status::resource_exhausted(
            "remote issuer request exceeds limit",
        ));
    }
    Ok(())
}
fn fingerprint(bytes: &[u8]) -> Result<[u8; 32], Status> {
    openshell_crypto::sha256(bytes)
        .map_err(|_| Status::unavailable("issuer reservation intent unavailable"))
}
fn duration(value: Option<&prost_types::Duration>, default: Duration) -> Result<Duration, Status> {
    value
        .map(openshell_core::time::duration_to_std)
        .transpose()
        .map_err(|_| Status::invalid_argument("invalid grant duration"))
        .map(|value| value.unwrap_or(default))
}
pub(super) fn secret_intent(
    request: &store::ReserveSecretRequest,
    owner: &store::SecretOwner,
) -> Result<[u8; 32], Status> {
    bounded(request)?;
    // Audit display names are not part of the issuer's immutable owner.
    fingerprint(
        &store::ReserveSecretRequest {
            owner: Some(owner.clone()),
            idempotency_key: request.idempotency_key.clone(),
        }
        .encode_to_vec(),
    )
}
pub(super) fn grant_intent(request: &refresh::ReserveGrantRequest) -> Result<[u8; 32], Status> {
    bounded(request)?;
    let owner = tracking::owner(
        request
            .owner
            .clone()
            .ok_or_else(|| Status::invalid_argument("issuer owner is required"))?,
    )?;
    let mut canonical = request.clone();
    canonical.owner = Some(owner);
    // Match the issuer's value-free intent: defaults, millisecond-ceiling
    // refresh windows and second-ceiling lifetimes are semantically identical.
    let refresh = duration(canonical.refresh_before.as_ref(), Duration::from_mins(5))?;
    let refresh_ms = i64::try_from(refresh.as_millis().saturating_add(u128::from(
        !refresh.subsec_nanos().is_multiple_of(1_000_000),
    )))
    .map_err(|_| Status::invalid_argument("issuer duration exceeds limit"))?;
    let lifetime = duration(canonical.max_lifetime.as_ref(), Duration::from_hours(1))?;
    if lifetime.is_zero() || lifetime > Duration::from_hours(12) {
        return Err(Status::invalid_argument("invalid grant lifetime"));
    }
    let lifetime_seconds = lifetime.as_secs() + u64::from(lifetime.subsec_nanos() != 0);
    canonical.refresh_before = None;
    canonical.max_lifetime = None;
    let outputs = std::mem::take(&mut canonical.outputs);
    // Protobuf map iteration is not canonical. Length-prefix both the base
    // message and every sorted output field so different intents cannot alias.
    let mut bytes = canonical.encode_length_delimited_to_vec();
    bytes.extend_from_slice(&refresh_ms.to_be_bytes());
    bytes.extend_from_slice(&lifetime_seconds.to_be_bytes());
    let mut sorted_outputs: Vec<_> = outputs.into_iter().collect();
    sorted_outputs.sort_unstable();
    for output in sorted_outputs {
        for field in <[String; 2]>::from(output) {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
    }
    fingerprint(&bytes)
}

pub(super) fn output_owners(
    owner: Option<store::SecretOwner>,
    outputs: &HashMap<String, String>,
) -> Result<HashMap<String, store::SecretOwner>, Status> {
    let owner = tracking::owner(
        owner.ok_or_else(|| Status::invalid_argument("issuer owner is required"))?,
    )?;
    if outputs.is_empty()
        || outputs.len() > 64
        || outputs.keys().any(|name| !crate::minter::valid_id(name))
    {
        return Err(Status::invalid_argument("invalid issuer grant outputs"));
    }
    outputs
        .iter()
        .map(|(id, key)| {
            Ok((
                id.clone(),
                tracking::owner(store::SecretOwner {
                    credential_key: key.clone(),
                    ..owner.clone()
                })?,
            ))
        })
        .collect()
}
pub(super) fn bindings(
    owners: &HashMap<String, store::SecretOwner>,
    references: &HashMap<String, String>,
) -> Vec<(String, store::SecretOwner)> {
    // RemoteIssuer validates the complete output ID set before returning success.
    references
        .iter()
        .map(|(id, reference)| (reference.clone(), owners[id].clone()))
        .collect()
}
impl Inner {
    pub fn mutation_status(
        &self,
        mut before: tracking::Observation,
        status: Option<&refresh::GrantStatus>,
        invalidate: bool,
    ) -> Result<(), Status> {
        {
            // Preserve fences for concurrent grant observations, but let this
            // mutation publish its own validated status. Secret and grant
            // checkpoints must not invalidate each other's metadata reads.
            let mut state = self.lock()?;
            let unchanged = state.grant_generation == before.metadata_generation;
            state.grant_generation = state.grant_generation.wrapping_add(1);
            if unchanged {
                before.metadata_generation = state.grant_generation;
            }
            if invalidate {
                state.clear_values();
                state.secret_generation = state.secret_generation.wrapping_add(1);
                state.secrets_reconciled = false;
                for entry in state.secrets.values_mut() {
                    entry.metadata = None;
                }
            }
        }
        if invalidate {
            self.send(super::IssuerChange::Unknown(super::ChangeKind::Secrets));
        }
        if let Some(status) = status {
            cache::grant(self, status, &before)?;
        }
        Ok(())
    }
}
