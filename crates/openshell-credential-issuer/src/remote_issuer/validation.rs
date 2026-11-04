// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{invalid, refresh, store};
use openshell_core::{
    proto::credentials::minter::v1 as minter,
    time::{duration_to_std, timestamp_to_millis},
};
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use tonic::Status;

pub(super) fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
use crate::minter::valid_id as field;
fn unique<'a>(mut values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = HashSet::new();
    values.all(|value| field(value) && seen.insert(value))
}
fn timestamp(value: Option<&prost_types::Timestamp>) -> Result<(), Status> {
    if let Some(value) = value {
        timestamp_to_millis(value).map_err(|_| invalid())?;
    }
    Ok(())
}
pub(super) fn requests(request: &store::ResolveSecretsRequest, max: u32) -> Result<(), Status> {
    let mut ids = HashSet::new();
    if request.secrets.is_empty()
        || request.secrets.len() > usize::try_from(max).map_err(|_| invalid())?
        || !matches!(
            store::ResolvePurpose::try_from(request.purpose),
            Ok(store::ResolvePurpose::SandboxDelivery
                | store::ResolvePurpose::OperatorExport
                | store::ResolvePurpose::Refresh
                | store::ResolvePurpose::MetadataInspection)
        )
        || request.secrets.iter().any(|item| {
            !crate::service::valid_resolution_request_id(&item.request_id)
                || !id(&item.reference)
                || !ids.insert(&item.request_id)
                || item
                    .owner
                    .as_ref()
                    .is_none_or(|owner| crate::SecretOwner::from_wire(owner).is_err())
        })
    {
        return Err(Status::invalid_argument(
            "invalid remote issuer resolution batch",
        ));
    }
    Ok(())
}
pub(super) fn resolved(
    request: &store::ResolveSecretsRequest,
    response: &store::ResolveSecretsResponse,
) -> Result<(), Status> {
    if request.secrets.len() != response.secrets.len() {
        return Err(invalid());
    }
    let expected: HashMap<_, _> = request
        .secrets
        .iter()
        .map(|value| (value.request_id.as_str(), value))
        .collect();
    let mut seen = HashSet::new();
    for value in &response.secrets {
        let input = expected
            .get(value.request_id.as_str())
            .ok_or_else(invalid)?;
        if !seen.insert(&value.request_id)
            || value.version == 0
            || input
                .expected_version
                .is_some_and(|expected| expected != value.version)
        {
            return Err(invalid());
        }
        timestamp(value.expiration_time.as_ref())?;
        let ttl = value
            .cache_ttl
            .as_ref()
            .map(duration_to_std)
            .transpose()
            .map_err(|_| invalid())?
            .unwrap_or_default();
        let metadata = request.purpose == store::ResolvePurpose::MetadataInspection as i32;
        if ttl > Duration::from_mins(1)
            || (metadata && (!value.value.is_empty() || !ttl.is_zero()))
            || (!metadata && value.pending_value)
            || (value.pending_value && value.expiration_time.is_some())
        {
            return Err(invalid());
        }
        // Expired metadata is valid. A value that expired in transit cannot
        // be delivered; the advertised TTL is clamped separately on receipt.
        if !metadata && let Some(expiration) = value.expiration_time.as_ref() {
            let expiration = timestamp_to_millis(expiration).map_err(|_| invalid())?;
            if expiration <= now_ms()? {
                return Err(Status::failed_precondition(
                    "remote issuer credential expired in transit",
                ));
            }
        }
    }
    Ok(())
}
fn now_ms() -> Result<i64, Status> {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_millis(),
    )
    .map_err(|_| invalid())
}
pub(super) fn bound_ttl(
    response: &mut store::ResolveSecretsResponse,
    elapsed: Duration,
) -> Result<(), Status> {
    let now = now_ms()?;
    for value in &mut response.secrets {
        let mut ttl = value
            .cache_ttl
            .as_ref()
            .map(duration_to_std)
            .transpose()
            .map_err(|_| invalid())?
            .unwrap_or_default()
            .saturating_sub(elapsed);
        if let Some(expiration) = value.expiration_time.as_ref() {
            let remaining = timestamp_to_millis(expiration)
                .map_err(|_| invalid())?
                .saturating_sub(now)
                .max(0);
            ttl = ttl.min(Duration::from_millis(
                u64::try_from(remaining).map_err(|_| invalid())?,
            ));
        }
        value.cache_ttl = Some(prost_types::Duration {
            seconds: i64::try_from(ttl.as_secs()).map_err(|_| invalid())?,
            nanos: i32::try_from(ttl.subsec_nanos()).map_err(|_| invalid())?,
        });
    }
    Ok(())
}
pub(super) fn catalog(response: &refresh::ListStrategiesResponse) -> Result<(), Status> {
    let mut names = HashSet::new();
    if response.strategies.len() > 64 {
        return Err(invalid());
    }
    for descriptor in &response.strategies {
        let name = descriptor
            .name
            .strip_prefix("custom:")
            .unwrap_or(&descriptor.name);
        if !field(name)
            || !names.insert(&descriptor.name)
            || descriptor.config.len() + descriptor.secret_material.len() > 128
            || descriptor.outputs.is_empty()
            || descriptor.outputs.len() > 64
            || descriptor.rotated_secret_material.len() > 128
            || !unique(
                descriptor
                    .config
                    .iter()
                    .chain(&descriptor.secret_material)
                    .map(|value| value.name.as_str()),
            )
            || !unique(descriptor.outputs.iter().map(String::as_str))
            || !unique(
                descriptor
                    .rotated_secret_material
                    .iter()
                    .map(String::as_str),
            )
            || descriptor.rotated_secret_material.iter().any(|name| {
                !descriptor
                    .secret_material
                    .iter()
                    .any(|field| field.name == *name)
            })
        {
            return Err(invalid());
        }
    }
    Ok(())
}
pub(super) fn created(
    outputs: &HashMap<String, String>,
    response: &refresh::CreateGrantResponse,
) -> Result<(), Status> {
    let mut refs = HashSet::new();
    if !id(&response.grant)
        || response.output_references.len() != outputs.len()
        || outputs.is_empty()
        || outputs.len() > 64
        || response.output_references.iter().any(|(name, reference)| {
            !outputs.contains_key(name) || !id(reference) || !refs.insert(reference)
        })
    {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn status(expected: &str, status: Option<&refresh::GrantStatus>) -> Result<(), Status> {
    let status = status.ok_or_else(invalid)?;
    if status.grant != expected
        || !id(&status.grant)
        || status.version == 0
        || (status.state == "refreshed" && status.expiration_time.is_none())
        || !field(&status.state)
        || status.failure_code.len() > 128
        || !status
            .failure_code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        || minter::RecoveryAction::try_from(status.recovery_action).is_err()
    {
        return Err(invalid());
    }
    timestamp(status.expiration_time.as_ref())?;
    timestamp(status.next_refresh_time.as_ref())?;
    for history in [
        status.last_refresh_time.as_ref(),
        status.last_error_time.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        timestamp(Some(history))?;
        if timestamp_to_millis(history).map_err(|_| invalid())? <= 0 {
            return Err(invalid());
        }
    }
    if !status.provider_error_subtype.is_empty()
        && crate::observability::recognized_provider_error_subtype(
            &status.failure_code,
            &status.provider_error_subtype,
        )
        .is_none()
    {
        return Err(invalid());
    }
    Ok(())
}
