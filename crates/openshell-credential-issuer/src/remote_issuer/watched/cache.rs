// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::{
    CachedCredential, Inner, VALUE_BYTES, VALUES, WatchHealth, refresh, same_owner, store,
};
use prost::Message;
use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tonic::Status;
fn invalid() -> Status {
    super::super::invalid()
}
fn now_ms() -> Result<i64, Status> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_millis(),
    )
    .map_err(|_| invalid())
}
fn duration(value: Duration) -> Result<prost_types::Duration, Status> {
    openshell_core::time::duration_from_std(value).map_err(|_| invalid())
}
pub(super) fn prune(inner: &Inner) -> Result<(), Status> {
    let mut state = inner.lock()?;
    let now = Instant::now();
    let wall = now_ms()?;
    state.values.retain(|_, value| {
        value.deadline > now
            && value
                .value
                .expiration_time
                .as_ref()
                .is_none_or(|expiration| {
                    openshell_core::time::timestamp_to_millis(expiration)
                        .is_ok_and(|expiration| expiration > wall)
                })
    });
    state.bytes = state
        .values
        .values()
        .map(|value| value.value.value.len())
        .sum();
    Ok(())
}
pub(super) fn get(
    inner: &Inner,
    request: &store::ResolveSecretsRequest,
) -> Result<Option<store::ResolveSecretsResponse>, Status> {
    if request.purpose == store::ResolvePurpose::MetadataInspection as i32 {
        return Ok(None);
    }
    let mut state = inner.lock()?;
    if !state.health.synchronized() {
        return Ok(None);
    }
    let now = Instant::now();
    let wall = now_ms()?;
    let mut values = Vec::with_capacity(request.secrets.len());
    let mut touched = Vec::new();
    for input in &request.secrets {
        let key = (input.reference.clone(), request.purpose);
        let Some(metadata) = state.secrets.get(&input.reference) else {
            return Ok(None);
        };
        let Some(owner) = input.owner.as_ref() else {
            return Ok(None);
        };
        if !same_owner(owner, &metadata.owner) || metadata.gone || metadata.metadata.is_none() {
            return Ok(None);
        }
        let Some(value) = state.values.get(&key) else {
            return Ok(None);
        };
        if input.expected_version != Some(value.value.version)
            || metadata.version != value.value.version
            || value.deadline <= now
        {
            return Ok(None);
        }
        let mut ttl = value.deadline.saturating_duration_since(now);
        if let Some(expiration) = &value.value.expiration_time {
            let expiration =
                openshell_core::time::timestamp_to_millis(expiration).map_err(|_| invalid())?;
            if expiration <= wall {
                return Ok(None);
            }
            ttl = ttl.min(Duration::from_millis(
                u64::try_from(expiration - wall).map_err(|_| invalid())?,
            ));
        }
        let mut resolved = value.value.clone();
        resolved.request_id.clone_from(&input.request_id);
        resolved.cache_ttl = Some(duration(ttl)?);
        values.push(resolved);
        touched.push(key);
    }
    let response = store::ResolveSecretsResponse { secrets: values };
    if response.encoded_len()
        > usize::try_from(inner.client.capabilities().max_response_bytes).map_err(|_| invalid())?
    {
        return Ok(None);
    }
    for key in touched {
        if let Some(value) = state.values.get_mut(&key) {
            value.touched = now;
        }
    }
    Ok(Some(response))
}
pub(super) fn record(
    inner: &Inner,
    request: &store::ResolveSecretsRequest,
    response: &mut store::ResolveSecretsResponse,
    before: WatchHealth,
) -> Result<(), Status> {
    let received = Instant::now();
    let inputs: HashMap<_, _> = request
        .secrets
        .iter()
        .map(|value| (value.request_id.as_str(), value))
        .collect();
    for value in &response.secrets {
        let input = inputs.get(value.request_id.as_str()).ok_or_else(invalid)?;
        inner.track_secret(
            input.owner.clone().ok_or_else(invalid)?,
            input.reference.clone(),
        )?;
    }
    let mut state = inner.lock()?;
    let unchanged = before.generation == state.health.generation;
    let healthy = unchanged && before.synchronized() && state.health.synchronized();
    // A watch observation after RPC admission fences the whole returned batch.
    for value in &response.secrets {
        let input = inputs.get(value.request_id.as_str()).ok_or_else(invalid)?;
        if request.purpose != store::ResolvePurpose::MetadataInspection as i32
            && let Some(expiration) = &value.expiration_time
            && openshell_core::time::timestamp_to_millis(expiration).map_err(|_| invalid())?
                <= now_ms()?
        {
            return Err(Status::failed_precondition(
                "issuer credential expired during resolution",
            ));
        }
        let entry = state.secrets.get(&input.reference).ok_or_else(invalid)?;
        if entry.version > value.version || entry.gone {
            return Err(Status::aborted(
                "issuer reference changed during resolution",
            ));
        }
    }
    let now = Instant::now();
    for value in &mut response.secrets {
        let input = inputs.get(value.request_id.as_str()).ok_or_else(invalid)?;
        if unchanged {
            let entry = state
                .secrets
                .get_mut(&input.reference)
                .ok_or_else(invalid)?;
            entry.version = value.version;
            let mut metadata = value.clone();
            metadata.value = String::new();
            metadata.request_id = String::new();
            metadata.cache_ttl = Some(prost_types::Duration::default());
            entry.metadata = Some(metadata);
        }
        let mut ttl = value
            .cache_ttl
            .as_ref()
            .map(openshell_core::time::duration_to_std)
            .transpose()
            .map_err(|_| invalid())?
            .unwrap_or_default()
            .saturating_sub(received.elapsed());
        if let Some(expiration) = &value.expiration_time {
            let remaining = openshell_core::time::timestamp_to_millis(expiration)
                .map_err(|_| invalid())?
                .saturating_sub(now_ms()?)
                .max(0);
            ttl = ttl.min(Duration::from_millis(
                u64::try_from(remaining).map_err(|_| invalid())?,
            ));
        }
        value.cache_ttl = Some(duration(ttl)?);
        if !healthy {
            value.cache_ttl = Some(prost_types::Duration::default());
            continue;
        }
        if ttl.is_zero() || request.purpose == store::ResolvePurpose::MetadataInspection as i32 {
            continue;
        }
        let key = (input.reference.clone(), request.purpose);
        if let Some(old) = state.values.remove(&key) {
            state.bytes = state.bytes.saturating_sub(old.value.value.len());
        }
        while state.values.len() >= VALUES
            || state.bytes.saturating_add(value.value.len()) > VALUE_BYTES
        {
            let Some(oldest) = state
                .values
                .iter()
                .min_by_key(|(_, value)| value.touched)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(old) = state.values.remove(&oldest) {
                state.bytes = state.bytes.saturating_sub(old.value.value.len());
            }
        }
        if value.value.len() > VALUE_BYTES {
            continue;
        }
        state.bytes += value.value.len();
        state.values.insert(
            key,
            CachedCredential {
                value: value.clone(),
                deadline: now.checked_add(ttl).ok_or_else(invalid)?,
                touched: now,
            },
        );
    }
    inner.health.send_replace(state.health);
    Ok(())
}
pub(super) fn grant(inner: &Inner, status: &refresh::GrantStatus) -> Result<(), Status> {
    inner.track_grant(status.grant.clone())?;
    let mut state = inner.lock()?;
    let entry = state.grants.get_mut(&status.grant).ok_or_else(invalid)?;
    if !entry.gone && entry.version <= status.version {
        entry.version = status.version;
        entry.metadata = Some(status.clone());
    }
    inner.health.send_replace(state.health);
    Ok(())
}
