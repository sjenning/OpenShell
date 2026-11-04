// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Restartable startup upgrade. Secret values never enter upgrade journals.
use super::{
    Arc, CredentialRefreshService, CredentialRuntime, CredentialStoreService, Duration,
    RemoteProviderSource, Status, Store, grants,
};
use crate::{
    credential_source::{DRIVER, IssuerReferenceBinding, handoff::StaticHandoff},
    credentials::references,
    persistence::{AtomicWrite, ObjectListQuery},
};
use openshell_core::{
    ObjectId as _, ObjectName as _, ObjectWorkspace as _,
    proto::{CredentialHandle, Provider, ProviderCredentialRefreshStrategy as Strategy},
};
use openshell_credential_issuer::{ReferenceState, SecretOwner, service::LegacyReference};
use prost::Message as _;
use std::collections::{BTreeMap, BTreeSet};
fn failed(_: impl std::fmt::Display) -> Status {
    Status::unavailable("embedded issuer migration persistence failed")
}

pub(super) async fn providers(
    gateway: &Store,
    legacy: &CredentialRuntime,
    host: &CredentialStoreService,
    refresh: &CredentialRefreshService,
    source: &RemoteProviderSource,
) -> Result<(), Status> {
    // Prove orphaned native preparations before rewriting any legacy provider
    // to static issuer handles; those new handles must not obscure the original
    // no-publication proof. Repeat after the pass for postcommit activation.
    recover_activations(gateway, refresh, source).await?;
    let mut cursor = None;
    loop {
        let page = gateway
            .list_object_page(
                "provider",
                ObjectListQuery::AllWorkspaces,
                cursor.as_ref(),
                128,
            )
            .await
            .map_err(failed)?;
        for row in page.records {
            let mut provider = Provider::decode(row.payload.as_slice())
                .map_err(|_| Status::data_loss("invalid provider during issuer upgrade"))?;
            let states = crate::provider_refresh::list_refresh_states_for_provider(
                gateway,
                provider.object_id(),
            )
            .await?;
            if provider.credentials.is_empty()
                && provider
                    .credential_handles
                    .values()
                    .all(|handle| handle.driver == DRIVER)
                && states.is_empty()
            {
                continue;
            }
            // Match legacy refresh ordering: grant exclusion precedes the
            // workspace publication lock. Keep every grant on one connection.
            let keys = states
                .iter()
                .map(|state| state.credential_key.as_str())
                .collect::<Vec<_>>();
            let _refresh = gateway
                .acquire_refresh_guards(provider.object_id(), &keys)
                .await
                .map_err(failed)?;
            let mut locks = crate::persistence::MutationLockSet::default();
            locks.insert(
                crate::persistence::MutationLockKey::Global,
                crate::persistence::LockMode::Shared,
            );
            locks.insert(
                crate::persistence::MutationLockKey::Workspace(provider.object_workspace()),
                crate::persistence::LockMode::Exclusive,
            );
            let _workspace = gateway
                .acquire_distributed_mutation_guard(
                    &locks,
                    tokio::time::Instant::now() + Duration::from_secs(40),
                )
                .await
                .map_err(failed)?;
            let row = gateway
                .get("provider", &row.id)
                .await
                .map_err(failed)?
                .ok_or_else(|| Status::aborted("legacy provider disappeared"))?;
            provider = Provider::decode(row.payload.as_slice())
                .map_err(|_| Status::data_loss("invalid provider during issuer upgrade"))?;
            let latest = crate::provider_refresh::list_refresh_states_for_provider(
                gateway,
                provider.object_id(),
            )
            .await?;
            if latest
                .iter()
                .any(|state| !keys.contains(&state.credential_key.as_str()))
            {
                return Err(Status::aborted(
                    "legacy refresh set changed during issuer upgrade; retry startup",
                ));
            }
            let mut states = Vec::new();
            for state in latest {
                let strategy = Strategy::try_from(state.strategy)
                    .map_err(|_| Status::failed_precondition("unknown legacy refresh strategy"))?;
                if matches!(
                    strategy,
                    Strategy::Static | Strategy::External | Strategy::Unspecified
                ) || state.status == "deleting"
                    || state
                        .metadata
                        .as_ref()
                        .is_some_and(|metadata| metadata.deletion_time.is_some())
                {
                    // Non-mintable DTOs and deletion tombstones own cleanup,
                    // not output revocation. A prior startup may have prepared
                    // dormant native copies before reconfiguration/deletion;
                    // retire them with proof while this DTO still exists.
                    grants::abandon(gateway, refresh, &provider, &state).await?;
                    // Legacy refresh deletion preserves provider outputs. Its
                    // tombstone remains the durable cleanup owner until every
                    // protected handle is idempotently deleted. Never resolve
                    // already-deleted material or turn this into native grant
                    // deletion (which would instead revoke those outputs).
                    crate::provider_refresh::delete_observed_refresh_state_with_credentials(
                        gateway, legacy, state,
                    )
                    .await?;
                } else {
                    states.push(state);
                }
            }
            if provider.credentials.is_empty()
                && provider
                    .credential_handles
                    .values()
                    .all(|handle| handle.driver == DRIVER)
                && states.is_empty()
            {
                continue;
            }
            let original = provider.clone();
            let mut reference_fences = Vec::new();
            let mut refs = BTreeMap::new();
            for (key, handle) in &original.credential_handles {
                if handle.driver == DRIVER {
                    refs.insert(key.clone(), source.decode(handle)?.reference);
                    continue;
                }
                let reference = references::reference_key(handle)?;
                let owner = SecretOwner {
                    workspace: provider.object_workspace().into(),
                    provider_id: provider.object_id().into(),
                    credential_key: key.clone(),
                    ..Default::default()
                };
                let registry = references::new_registry(Arc::new(gateway.clone()));
                if gateway
                    .get(references::OBJECT_TYPE, &reference)
                    .await
                    .map_err(failed)?
                    .is_none()
                {
                    registry
                        .adopt(&reference, &owner, handle.encode_to_vec())
                        .await?;
                }
                let reference_row = gateway
                    .get(references::OBJECT_TYPE, &reference)
                    .await
                    .map_err(failed)?
                    .ok_or_else(|| Status::aborted("legacy reference disappeared"))?;
                let state: ReferenceState =
                    serde_json::from_slice(&reference_row.payload).map_err(failed)?;
                if state.owner != owner {
                    return Err(Status::permission_denied("legacy reference owner changed"));
                }
                reference_fences.push(AtomicWrite::Check {
                    object_type: references::OBJECT_TYPE.into(),
                    id: reference.clone(),
                    expected_version: reference_row.resource_version,
                });
                host.import_legacy_reference(LegacyReference {
                    reference: reference.clone(),
                    state,
                    registration: if handle.driver.is_empty() {
                        legacy.issuer_drivers().1
                    } else {
                        handle.driver.clone()
                    },
                    physical_provider: provider.object_name().into(),
                    physical_owner_id: provider.object_id().into(),
                    physical_key: key.clone(),
                })
                .await?;
                provider
                    .credential_handles
                    .insert(key.clone(), source.reference_handle(&reference, None)?);
                refs.insert(key.clone(), reference);
            }
            for (key, value) in &original.credentials {
                if original.credential_handles.contains_key(key) {
                    continue;
                }
                let owner = super::super::owner(&provider, key)?;
                let identity = serde_json::to_vec(&(
                    provider.object_workspace(),
                    provider.object_id(),
                    row.resource_version,
                    key,
                ))
                .map_err(failed)?;
                let intent = format!(
                    "upgrade-inline:{}",
                    hex::encode(openshell_crypto::sha256(&identity).map_err(failed)?)
                );
                let reservation = source
                    .issuer()
                    .reserve_secret(super::super::wire::ReserveSecretRequest {
                        owner: Some(owner.clone()),
                        idempotency_key: intent.clone(),
                    })
                    .await?;
                source
                    .issuer()
                    .put_secret(super::super::wire::PutSecretRequest {
                        owner: Some(owner),
                        reference: reservation.reference.clone(),
                        value: value.clone(),
                        expiration_time: provider.credential_expiration_times.get(key).copied(),
                        expected_version: Some(1),
                        idempotency_key: format!("{intent}:fill"),
                    })
                    .await?;
                provider.credential_handles.insert(
                    key.clone(),
                    source.reference_handle(&reservation.reference, None)?,
                );
                refs.insert(key.clone(), reservation.reference);
            }
            provider.credentials.clear();
            let mut writes = reference_fences;
            let mut granted = BTreeSet::new();
            let mut activations = Vec::new();
            for state in &states {
                let Some((plan, id, epoch, schedule)) =
                    grants::prepare(gateway, legacy, host, refresh, &original, state, &mut refs)
                        .await?
                else {
                    continue;
                };
                let keys = plan.outputs.values().cloned().collect::<Vec<_>>();
                for key in &keys {
                    if !granted.insert(key.clone()) {
                        return Err(Status::failed_precondition(
                            "overlapping legacy refresh outputs",
                        ));
                    }
                    let reference = refs.get(key).ok_or_else(|| {
                        Status::failed_precondition("legacy refresh output missing")
                    })?;
                    let mut handle = source.reference_handle(reference, Some(&id))?;
                    let mut binding: IssuerReferenceBinding =
                        serde_json::from_str(&handle.handle).map_err(failed)?;
                    binding.authorization_epoch = Some(epoch.clone());
                    handle.handle = serde_json::to_string(&binding).map_err(failed)?;
                    provider.credential_handles.insert(key.clone(), handle);
                }
                activations.push(openshell_credential_issuer::grant::GrantIdentity {
                    id: id.clone(),
                    authorization_epoch: epoch,
                    owner: SecretOwner {
                        workspace: provider.object_workspace().into(),
                        provider_id: provider.object_id().into(),
                        credential_key: plan.credential_key.clone(),
                        ..Default::default()
                    },
                });
                writes.push(StaticHandoff::migration_write(
                    source,
                    &provider,
                    &keys,
                    Some((plan, id, schedule)),
                )?);
            }
            let static_keys = provider
                .credential_handles
                .keys()
                .filter(|key| !granted.contains(*key))
                .cloned()
                .collect::<Vec<_>>();
            for keys in static_keys.chunks(64) {
                writes.push(StaticHandoff::migration_write(
                    source, &provider, keys, None,
                )?);
            }
            for state in &states {
                writes.push(AtomicWrite::Delete {
                    object_type: "provider_credential_refresh_state".into(),
                    id: state.object_id().into(),
                    expected_version: state
                        .metadata
                        .as_ref()
                        .map_or(0, |meta| meta.resource_version),
                });
            }
            writes.push(AtomicWrite::Update {
                object_type: "provider".into(),
                id: row.id,
                payload: provider.encode_to_vec(),
                expected_version: row.resource_version,
            });
            gateway.write_atomically(&writes).await.map_err(failed)?;
            // Other issuer peers cannot discover a prepared grant before the
            // gateway's reference/ownership transaction has committed.
            for identity in activations {
                refresh.activate_legacy_grant(identity).await?;
            }
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        cursor = Some(next);
    }
    recover_activations(gateway, refresh, source).await
}

async fn recover_activations(
    gateway: &Store,
    refresh: &CredentialRefreshService,
    source: &RemoteProviderSource,
) -> Result<(), Status> {
    let mut after = None;
    loop {
        let page = refresh.pending_legacy_grants(after.as_deref(), 128).await?;
        for activation in page.grants {
            let _refresh = gateway
                .acquire_refresh_guards(
                    &activation.identity.owner.provider_id,
                    &[activation.identity.owner.credential_key.as_str()],
                )
                .await
                .map_err(failed)?;
            let mut locks = crate::persistence::MutationLockSet::default();
            locks.insert(
                crate::persistence::MutationLockKey::Global,
                crate::persistence::LockMode::Shared,
            );
            locks.insert(
                crate::persistence::MutationLockKey::Workspace(
                    &activation.identity.owner.workspace,
                ),
                crate::persistence::LockMode::Exclusive,
            );
            let _workspace = gateway
                .acquire_distributed_mutation_guard(
                    &locks,
                    tokio::time::Instant::now() + Duration::from_secs(40),
                )
                .await
                .map_err(failed)?;
            if StaticHandoff::legacy_activation_published(gateway, source, &activation).await? {
                refresh.activate_legacy_grant(activation.identity).await?;
            } else {
                grants::abandon_orphan(gateway, refresh, &activation).await?;
            }
        }
        let Some(next) = page.after else {
            break;
        };
        after = Some(next);
    }
    Ok(())
}

pub(super) async fn internal(
    gateway: &Store,
    legacy: &CredentialRuntime,
    host: &CredentialStoreService,
    source: &RemoteProviderSource,
) -> Result<(), Status> {
    crate::ssh_identity::migrate_issuer(gateway, legacy, host, source).await?;
    crate::supervisor_pool::migrate_issuer(gateway, legacy, host, source).await
}

pub async fn internal_handle(
    legacy: &CredentialRuntime,
    host: &CredentialStoreService,
    source: &RemoteProviderSource,
    owner: crate::credentials::InternalSecretOwner<'_>,
    physical_owner_id: &str,
    key: &str,
    handle: &CredentialHandle,
) -> Result<CredentialHandle, Status> {
    if handle.driver == DRIVER {
        source.register_internal(owner, key, handle)?;
        return Ok(handle.clone());
    }
    let reference = references::reference_key(handle)?;
    let state = ReferenceState {
        owner: SecretOwner {
            workspace: owner.workspace.into(),
            provider_id: owner.id.into(),
            credential_key: key.into(),
            kind: owner.kind,
        },
        version: 1,
        backing: handle.encode_to_vec(),
        expiration_time_ms: None,
        revoked: false,
        pending_value: false,
        pending_deletions: Vec::new(),
    };
    host.import_legacy_reference(LegacyReference {
        reference: reference.clone(),
        state,
        registration: if handle.driver.is_empty() {
            legacy.issuer_drivers().1
        } else {
            handle.driver.clone()
        },
        physical_provider: owner.name.into(),
        physical_owner_id: physical_owner_id.into(),
        physical_key: key.into(),
    })
    .await?;
    let imported = source.reference_handle(&reference, None)?;
    source.register_internal(owner, key, &imported)?;
    Ok(imported)
}
