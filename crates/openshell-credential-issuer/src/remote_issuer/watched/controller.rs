// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::{ChangeKind, Inner, IssuerChange, cache, refresh, store, tracking::Observation};
use std::{sync::Arc, time::Duration};
use tonic::{Code, Status};
pub(super) fn missing(error: &Status) -> bool {
    matches!(error.code(), Code::NotFound | Code::PermissionDenied)
}
fn reconciled(result: Result<(), Status>) -> Result<(), Status> {
    match result {
        // A concurrent mutation/retirement won. Leave its metadata unknown;
        // the next checkpoint inspects the current binding instead.
        Err(error) if error.code() == Code::Aborted => Ok(()),
        result => result,
    }
}
async fn reconcile_secret(
    inner: &Inner,
    inputs: Vec<store::ResolveSecretRequest>,
    before: &Observation,
) -> Result<(), Status> {
    let request = store::ResolveSecretsRequest {
        secrets: inputs.clone(),
        purpose: store::ResolvePurpose::MetadataInspection as i32,
    };
    match inner.client.resolve_secrets(request.clone()).await {
        Ok(mut response) => reconciled(cache::record(inner, &request, &mut response, before)),
        Err(error) if missing(&error) => {
            // The wire batch is all-or-nothing. Identify individually missing
            // bindings; never turn one tombstone into unrelated revocations.
            for input in inputs {
                let request = store::ResolveSecretsRequest {
                    secrets: vec![input.clone()],
                    purpose: store::ResolvePurpose::MetadataInspection as i32,
                };
                match inner.client.resolve_secrets(request.clone()).await {
                    Ok(mut response) => {
                        reconciled(cache::record(inner, &request, &mut response, before))?;
                    }
                    Err(error) if missing(&error) => {
                        let mut state = inner.lock()?;
                        if before.metadata_generation == state.secret_generation
                            && state.secrets.get(&input.reference).is_some_and(|entry| {
                                !entry.gone && before.secret_matches(&input.reference, entry)
                            })
                        {
                            state.retire_secret(&input.reference, 0);
                            // A denied/missing registration may become authorized
                            // after reconnect. Only explicit terminal observations
                            // survive resets permanently.
                            state
                                .secrets
                                .get_mut(&input.reference)
                                .expect("checked binding")
                                .terminal = false;
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
    let (inputs, before) = {
        let state = inner.lock()?;
        let inputs: Vec<_> = state
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
        let before = state.secret_observation(inputs.iter().map(|input| input.reference.clone()));
        (inputs, before)
    };
    let batch = usize::try_from(inner.client.capabilities().max_batch_size)
        .map_err(|_| super::super::invalid())?;
    for inputs in inputs.chunks(batch) {
        reconcile_secret(inner, inputs.to_vec(), &before).await?;
    }
    Ok(())
}
async fn reconcile_grants(inner: &Inner) -> Result<(), Status> {
    let (grants, before) = {
        let state = inner.lock()?;
        let grants: Vec<_> = state
            .grants
            .iter()
            .filter(|(_, entry)| !entry.gone && entry.metadata.is_none())
            .map(|(id, _)| id.clone())
            .collect();
        let before = state.grant_observation(grants.iter().cloned());
        (grants, before)
    };
    for id in grants {
        match inner
            .client
            .get_grant(refresh::GetGrantRequest { grant: id.clone() })
            .await
        {
            Ok(response) => reconciled(cache::grant(
                inner,
                response.status.as_ref().ok_or_else(super::super::invalid)?,
                &before,
            ))?,
            Err(error) if missing(&error) => {
                let mut state = inner.lock()?;
                if before.metadata_generation == state.grant_generation
                    && state
                        .grants
                        .get(&id)
                        .is_some_and(|entry| !entry.gone && before.grant_matches(&id, entry))
                {
                    state.retire_grant(&id, 0);
                    state.grants.get_mut(&id).expect("checked binding").terminal = false;
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
pub(super) fn secret_event(
    inner: &Inner,
    event: &store::WatchSecretsResponse,
) -> Result<(), Status> {
    let mut state = inner.lock()?;
    state.secret_generation = state.secret_generation.wrapping_add(1);
    state.secrets_reconciled = false;
    state.values_changed();
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
        entry.terminal |= event.revoked;
    }
    drop(state);
    inner.send(IssuerChange::Secret {
        reference: event.reference.clone(),
        version: event.version,
        revoked: event.revoked,
    });
    Ok(())
}
pub(super) fn grant_event(
    inner: &Inner,
    event: &refresh::WatchGrantsResponse,
) -> Result<(), Status> {
    let mut state = inner.lock()?;
    state.grant_generation = state.grant_generation.wrapping_add(1);
    state.grants_reconciled = false;
    state.clear_values();
    if let Some(entry) = state.grants.get_mut(&event.grant)
        && event.version >= entry.version
    {
        entry.version = event.version;
        entry.metadata = None;
        // An earlier authenticated NOT_FOUND may precede trusted embedded
        // import activation. Its nonterminal absence is superseded by a real
        // creation event; explicit deletion/detachment remains irreversible.
        entry.gone = entry.terminal || event.deleted;
        entry.terminal |= event.deleted;
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
