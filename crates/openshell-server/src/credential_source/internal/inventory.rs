// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Candidate ownership comes from immutable owner/scope, never candidate name.
use super::{SSH_CANDIDATE, SSH_KEY, SUPERVISOR_CANDIDATE, intent};
use crate::persistence::{ObjectListQuery, ObjectRecord, Store};
use crate::{
    credential_source::{RemoteProviderSource, invalid},
    credentials::InternalSecretOwner,
};
use openshell_core::proto::CredentialHandle;
use openshell_core::{ObjectId as _, ObjectWorkspace as _, proto::Sandbox};
use openshell_credential_issuer::SecretOwnerKind;
use prost::Message as _;
use std::{collections::BTreeSet, sync::Arc};
use tonic::Status;

fn handle(row: &ObjectRecord, field: &str) -> Result<CredentialHandle, Status> {
    let value: serde_json::Value = serde_json::from_slice(&row.payload).map_err(|_| invalid())?;
    let bytes = value
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(invalid)?;
    let bytes = bytes
        .iter()
        .map(|byte| {
            byte.as_u64()
                .and_then(|byte| u8::try_from(byte).ok())
                .ok_or_else(invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    CredentialHandle::decode(bytes.as_slice()).map_err(|_| invalid())
}
/// `ObjectRecord` intentionally does not expose its generic scope. Read through
/// the scoped pager to prove association instead of guessing from row.name.
async fn scoped_candidate(
    store: &Store,
    sandbox_id: &str,
    candidate_id: &str,
) -> Result<Option<ObjectRecord>, Status> {
    let mut cursor = None;
    loop {
        let page = store
            .list_object_page(
                SSH_CANDIDATE,
                ObjectListQuery::Scope(sandbox_id),
                cursor.as_ref(),
                128,
            )
            .await
            .map_err(|_| Status::unavailable("SSH issuer candidate scope unavailable"))?;
        if let Some(row) = page.records.into_iter().find(|row| row.id == candidate_id) {
            return Ok(Some(row));
        }
        let Some(next) = page.next_cursor else {
            return Ok(None);
        };
        cursor = Some(next);
    }
}
pub(super) async fn candidate_binding(
    store: &Store,
    row: &ObjectRecord,
    identity: InternalSecretOwner<'_>,
) -> Result<(String, CredentialHandle), Status> {
    match identity.kind {
        SecretOwnerKind::Sandbox => {
            let scoped = scoped_candidate(store, identity.id, &row.id)
                .await?
                .ok_or_else(invalid)?;
            if row.object_type != SSH_CANDIDATE
                || scoped.resource_version != row.resource_version
                || row.workspace != identity.workspace
            {
                return Err(invalid());
            }
            Ok((identity.id.into(), handle(row, "credential_handle")?))
        }
        SecretOwnerKind::SupervisorInstance => {
            let value: serde_json::Value =
                serde_json::from_slice(&row.payload).map_err(|_| invalid())?;
            if row.object_type != SUPERVISOR_CANDIDATE
                || value.get("workspace").and_then(serde_json::Value::as_str)
                    != Some(identity.workspace)
                || value.get("route").and_then(serde_json::Value::as_str) != Some(identity.id)
            {
                return Err(invalid());
            }
            Ok((identity.id.into(), handle(row, "material_handle")?))
        }
        SecretOwnerKind::Provider => Err(invalid()),
    }
}

async fn register_journaled_orphan(
    store: &Store,
    source: &RemoteProviderSource,
    candidate: &ObjectRecord,
) -> Result<(), Status> {
    let handle = handle(candidate, "credential_handle")?;
    let binding = source.decode(&handle)?;
    let mut cursor = None;
    loop {
        let page = store
            .list_object_page(
                intent::KIND,
                ObjectListQuery::AllWorkspaces,
                cursor.as_ref(),
                128,
            )
            .await
            .map_err(|_| Status::unavailable("SSH issuer ownership inventory unavailable"))?;
        for row in page.records {
            let intent = intent::Intent::from_record(Arc::new(store.clone()), row)?;
            if let Some((workspace, sandbox)) =
                intent.ssh_candidate_owner(source, &candidate.id, &binding.reference)
                && let Some(scoped) = scoped_candidate(store, &sandbox, &candidate.id).await?
            {
                if scoped.resource_version != candidate.resource_version
                    || workspace != candidate.workspace
                {
                    return Err(invalid());
                }
                return source.register_internal(
                    InternalSecretOwner {
                        kind: SecretOwnerKind::Sandbox,
                        workspace: &workspace,
                        id: &sandbox,
                        name: "",
                    },
                    SSH_KEY,
                    &handle,
                );
            }
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        cursor = Some(next);
    }
    Err(Status::failed_precondition(
        "SSH issuer candidates without a registered owning sandbox require explicit recovery",
    ))
}

pub(super) async fn register_ssh_candidates(
    store: &Store,
    source: &RemoteProviderSource,
) -> Result<(), Status> {
    if store
        .list_object_page(SSH_CANDIDATE, ObjectListQuery::AllWorkspaces, None, 1)
        .await
        .map_err(|_| Status::unavailable("SSH issuer candidate inventory unavailable"))?
        .records
        .is_empty()
    {
        return Ok(());
    }
    let mut registered = BTreeSet::new();
    let mut sandboxes = None;
    loop {
        let page = store
            .list_object_page(
                "sandbox",
                ObjectListQuery::AllWorkspaces,
                sandboxes.as_ref(),
                128,
            )
            .await
            .map_err(|_| Status::unavailable("SSH issuer owner inventory unavailable"))?;
        for row in page.records {
            let sandbox = Sandbox::decode(row.payload.as_slice()).map_err(|_| invalid())?;
            if sandbox.object_id() != row.id || sandbox.object_workspace() != row.workspace {
                return Err(invalid());
            }
            let identity = InternalSecretOwner {
                kind: SecretOwnerKind::Sandbox,
                workspace: &row.workspace,
                id: &row.id,
                name: "",
            };
            let mut cursor = None;
            loop {
                let candidates = store
                    .list_object_page(
                        SSH_CANDIDATE,
                        ObjectListQuery::Scope(&row.id),
                        cursor.as_ref(),
                        128,
                    )
                    .await
                    .map_err(|_| {
                        Status::unavailable("SSH issuer candidate inventory unavailable")
                    })?;
                for candidate in candidates.records {
                    if candidate.workspace != row.workspace {
                        return Err(invalid());
                    }
                    source
                        .register_internal(
                            identity,
                            SSH_KEY,
                            &handle(&candidate, "credential_handle")?,
                        )
                        .map_err(|_| {
                            Status::failed_precondition(
                                "existing SSH candidates require explicit issuer migration",
                            )
                        })?;
                    registered.insert(candidate.id);
                    if registered.len() > 16_384 {
                        return Err(Status::resource_exhausted(
                            "SSH issuer candidate inventory exceeds tracked capacity",
                        ));
                    }
                }
                let Some(next) = candidates.next_cursor else {
                    break;
                };
                cursor = Some(next);
            }
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        sandboxes = Some(next);
    }
    // Do not silently skip old candidates whose owning sandbox is absent. The
    // row's scope cannot be reconstructed from its random candidate name, and
    // remote selection must not adopt/read a legacy backend to guess it.
    let mut cursor = None;
    loop {
        let page = store
            .list_object_page(
                SSH_CANDIDATE,
                ObjectListQuery::AllWorkspaces,
                cursor.as_ref(),
                128,
            )
            .await
            .map_err(|_| Status::unavailable("SSH issuer candidate inventory unavailable"))?;
        for row in page.records {
            if registered.contains(&row.id) {
                continue;
            }
            // A v2 intent retains its typed owner even after parent deletion.
            // Still prove the candidate's actual persisted scope before use.
            register_journaled_orphan(store, source, &row).await?;
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        cursor = Some(next);
    }
    Ok(())
}
