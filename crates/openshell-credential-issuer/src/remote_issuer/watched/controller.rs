// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::{ChangeKind, Inner, IssuerChange, cache, refresh, store};
use std::{sync::Arc, time::Duration};
use tonic::{Code, Status};
fn missing(error: &Status) -> bool {
    matches!(error.code(), Code::NotFound | Code::PermissionDenied)
}
async fn reconcile_secret(
    inner: &Inner,
    inputs: Vec<store::ResolveSecretRequest>,
) -> Result<(), Status> {
    let request = store::ResolveSecretsRequest {
        secrets: inputs.clone(),
        purpose: store::ResolvePurpose::MetadataInspection as i32,
    };
    match inner.client.resolve_secrets(request).await {
        Ok(response) => {
            let mut state = inner.lock()?;
            for value in response.secrets {
                let input = inputs
                    .iter()
                    .find(|input| input.request_id == value.request_id)
                    .ok_or_else(super::super::invalid)?;
                if let Some(entry) = state.secrets.get_mut(&input.reference)
                    && !entry.gone
                    && value.version >= entry.version
                {
                    entry.version = value.version;
                    entry.metadata = Some(value);
                }
            }
            Ok(())
        }
        Err(error) if missing(&error) => {
            // The wire batch is all-or-nothing. Identify individually missing
            // bindings; never turn one tombstone into unrelated revocations.
            for input in inputs {
                match inner
                    .client
                    .resolve_secrets(store::ResolveSecretsRequest {
                        secrets: vec![input.clone()],
                        purpose: store::ResolvePurpose::MetadataInspection as i32,
                    })
                    .await
                {
                    Ok(response) => {
                        let mut state = inner.lock()?;
                        if let Some(entry) = state.secrets.get_mut(&input.reference) {
                            let value = response
                                .secrets
                                .into_iter()
                                .next()
                                .ok_or_else(super::super::invalid)?;
                            if !entry.gone && value.version >= entry.version {
                                entry.version = value.version;
                                entry.metadata = Some(value);
                            }
                        }
                    }
                    Err(error) if missing(&error) => {
                        if let Some(entry) = inner.lock()?.secrets.get_mut(&input.reference) {
                            entry.gone = true;
                            entry.metadata = None;
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}
async fn reconcile_secrets(inner: &Inner) -> Result<(), Status> {
    cache::prune(inner)?;
    let inputs: Vec<_> = inner
        .lock()?
        .secrets
        .iter()
        .filter(|(_, entry)| !entry.gone && entry.metadata.is_none())
        .map(|(reference, entry)| store::ResolveSecretRequest {
            request_id: reference.clone(),
            owner: Some(entry.owner.clone()),
            reference: reference.clone(),
            expected_version: None,
        })
        .collect();
    let batch = usize::try_from(inner.client.capabilities().max_batch_size)
        .map_err(|_| super::super::invalid())?;
    for inputs in inputs.chunks(batch) {
        reconcile_secret(inner, inputs.to_vec()).await?;
    }
    Ok(())
}
async fn reconcile_grants(inner: &Inner) -> Result<(), Status> {
    let grants: Vec<_> = inner
        .lock()?
        .grants
        .iter()
        .filter(|(_, entry)| !entry.gone && entry.metadata.is_none())
        .map(|(id, _)| id.clone())
        .collect();
    for id in grants {
        match inner
            .client
            .get_grant(refresh::GetGrantRequest { grant: id.clone() })
            .await
        {
            Ok(response) => cache::grant(
                inner,
                response.status.as_ref().ok_or_else(super::super::invalid)?,
            )?,
            Err(error) if missing(&error) => {
                if let Some(entry) = inner.lock()?.grants.get_mut(&id) {
                    entry.gone = true;
                    entry.metadata = None;
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn secret_event(inner: &Inner, event: &store::WatchSecretsResponse) -> Result<(), Status> {
    let mut state = inner.lock()?;
    state.health.generation = state.health.generation.wrapping_add(1);
    state
        .values
        .retain(|(reference, _), _| reference != &event.reference);
    state.bytes = state
        .values
        .values()
        .map(|value| value.value.value.len())
        .sum();
    if let Some(entry) = state.secrets.get_mut(&event.reference)
        && event.version >= entry.version
    {
        entry.version = event.version;
        entry.metadata = None;
        entry.gone |= event.revoked;
    }
    drop(state);
    inner.send(IssuerChange::Secret {
        reference: event.reference.clone(),
        version: event.version,
        revoked: event.revoked,
    });
    Ok(())
}
fn grant_event(inner: &Inner, event: &refresh::WatchGrantsResponse) -> Result<(), Status> {
    let mut state = inner.lock()?;
    state.health.generation = state.health.generation.wrapping_add(1);
    state.values.clear();
    state.bytes = 0;
    if let Some(entry) = state.grants.get_mut(&event.grant)
        && event.version >= entry.version
    {
        entry.version = event.version;
        entry.metadata = None;
        entry.gone |= event.deleted;
    }
    drop(state);
    inner.send(IssuerChange::Grant {
        grant: event.grant.clone(),
        version: event.version,
        deleted: event.deleted,
    });
    Ok(())
}
pub(super) async fn secrets(inner: Arc<Inner>) {
    let mut cursor = 0;
    let mut backoff = Duration::from_secs(1);
    if inner.unknown(ChangeKind::Secrets).is_err() {
        return;
    }
    loop {
        if let Ok(mut stream) = inner.client.watch_secrets(cursor).await {
            loop {
                let Ok(Some(event)) = stream.message().await else {
                    break;
                };
                cursor = stream.cursor();
                let result = if event.reset_required {
                    inner.unknown(ChangeKind::Secrets)
                } else if event.checkpoint {
                    match reconcile_secrets(&inner).await {
                        Ok(()) => {
                            backoff = Duration::from_secs(1);
                            inner.ready(ChangeKind::Secrets)
                        }
                        Err(error) => Err(error),
                    }
                } else {
                    secret_event(&inner, &event)
                };
                if result.is_err() {
                    break;
                }
            }
        }
        if inner.unknown(ChangeKind::Secrets).is_err() {
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}
pub(super) async fn grants(inner: Arc<Inner>) {
    let mut cursor = 0;
    let mut backoff = Duration::from_secs(1);
    if inner.unknown(ChangeKind::Grants).is_err() {
        return;
    }
    loop {
        if let Ok(mut stream) = inner.client.watch_grants(cursor).await {
            loop {
                let Ok(Some(event)) = stream.message().await else {
                    break;
                };
                cursor = stream.cursor();
                let result = if event.reset_required {
                    inner.unknown(ChangeKind::Grants)
                } else if event.checkpoint {
                    match reconcile_grants(&inner).await {
                        Ok(()) => {
                            backoff = Duration::from_secs(1);
                            inner.ready(ChangeKind::Grants)
                        }
                        Err(error) => Err(error),
                    }
                } else {
                    grant_event(&inner, &event)
                };
                if result.is_err() {
                    break;
                }
            }
        }
        if inner.unknown(ChangeKind::Grants).is_err() {
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}
