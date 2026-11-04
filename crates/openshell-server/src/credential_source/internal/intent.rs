// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Value-free ownership before allocation, and a native publication fence.
//!
//! A candidate is not publication authority. The caller must include
//! `publication_writes` in the SAME transaction that publishes its SSH identity
//! or supervisor assignment. Recovery CASes `Staging` -> `Closing` before touching
//! the issuer, so a timed-out writer can never publish a reclaimed reference.
use super::{
    SSH_CANDIDATE, SSH_KEY, SUPERVISOR_CANDIDATE, SUPERVISOR_KEY, candidate_binding, owner,
};
use crate::{
    credential_source::{RemoteProviderSource, id, invalid, valid_registration},
    credentials::InternalSecretOwner,
    persistence::{AtomicWrite, ObjectRecord, Store, WriteCondition},
};
use openshell_core::proto::CredentialHandle;
use openshell_credential_issuer::{SecretOwner, SecretOwnerKind};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tonic::Status;
pub(super) const KIND: &str = "credential_issuer_internal_intent_v1";
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    #[default]
    Staging,
    Published,
    Closing,
    Closed,
}
fn legacy_format() -> u32 {
    1
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    #[serde(default = "legacy_format")]
    format: u32,
    source: String,
    owner: SecretOwner,
    operation: String,
    references: BTreeMap<String, Option<String>>,
    #[serde(default)]
    phase: Phase,
}
pub(super) struct Intent {
    pub(super) store: Arc<Store>,
    pub(super) id: String,
    pub(super) state: State,
    pub(super) revision: u64,
}
fn journal_owner(identity: InternalSecretOwner<'_>) -> SecretOwner {
    SecretOwner {
        workspace: identity.workspace.into(),
        provider_id: identity.id.into(),
        credential_key: "INTERNAL".into(),
        kind: identity.kind,
    }
}
fn identifier(source: &str, owner: &SecretOwner, operation: &str) -> Result<String, Status> {
    let bytes = serde_json::to_vec(&(source, owner, operation)).map_err(|_| invalid())?;
    Ok(format!(
        "internal-{}",
        hex::encode(openshell_crypto::sha256(&bytes).map_err(|_| invalid())?)
    ))
}
/// The operation key is derived only from identity, never a value or its hash.
pub(super) fn reservation_key(
    identity: InternalSecretOwner<'_>,
    operation: &str,
    key: &str,
) -> Result<String, Status> {
    let bytes = serde_json::to_vec(&(
        identity.workspace,
        identity.id,
        identity.kind,
        operation,
        key,
    ))
    .map_err(|_| invalid())?;
    Ok(hex::encode(
        openshell_crypto::sha256(&bytes).map_err(|_| invalid())?,
    ))
}
impl Intent {
    pub(super) async fn begin(
        source: &RemoteProviderSource,
        identity: InternalSecretOwner<'_>,
        operation: &str,
        values: &HashMap<String, String>,
    ) -> Result<Self, Status> {
        if !id(operation)
            || operation.len() > 128
            || values.is_empty()
            || values.len() > source.max_batch
        {
            return Err(invalid());
        }
        for key in values.keys() {
            SecretOwner::from_wire(&owner(identity, key)?)?;
        }
        let store = source.gateway.clone().ok_or_else(|| {
            Status::failed_precondition("internal issuer requires durable gateway ownership")
        })?;
        let owner = journal_owner(identity);
        let id = identifier(&source.name, &owner, operation)?;
        let expected = State {
            format: 2,
            source: source.name.to_string(),
            owner,
            operation: operation.into(),
            references: values.keys().map(|key| (key.clone(), None)).collect(),
            phase: Phase::Staging,
        };
        let payload = serde_json::to_vec(&expected).map_err(|_| invalid())?;
        match store
            .put_if(
                KIND,
                &id,
                &id,
                identity.workspace,
                &payload,
                None,
                WriteCondition::MustCreate,
            )
            .await
        {
            Ok(receipt) => Ok(Self {
                store,
                id,
                state: expected,
                revision: receipt.resource_version,
            }),
            Err(error) if error.is_expected() => {
                let row = store
                    .get(KIND, &id)
                    .await
                    .map_err(|_| invalid())?
                    .ok_or_else(invalid)?;
                let intent = Self::from_record(store, row)?;
                if intent.state.source != expected.source
                    || intent.state.owner != expected.owner
                    || intent.state.operation != operation
                    || intent
                        .state
                        .references
                        .keys()
                        .ne(expected.references.keys())
                {
                    return Err(invalid());
                }
                if intent.state.phase != Phase::Staging {
                    return Err(Status::failed_precondition(
                        "internal secret operation is already fenced or published",
                    ));
                }
                Ok(intent)
            }
            Err(_) => Err(Status::unavailable(
                "internal issuer ownership journal unavailable",
            )),
        }
    }
    pub(super) fn from_record(store: Arc<Store>, row: ObjectRecord) -> Result<Self, Status> {
        let state: State = serde_json::from_slice(&row.payload).map_err(|_| invalid())?;
        if row.object_type != KIND
            || row.resource_version == 0
            || !matches!(state.format, 1 | 2)
            || state.owner.kind == SecretOwnerKind::Provider
            || state.owner.credential_key != "INTERNAL"
            || state.references.is_empty()
            || state.references.len() > 64
            || !valid_registration(&state.source)
            || !id(&state.operation)
            || state.operation.len() > 128
            || row.workspace != state.owner.workspace
            || row.name != row.id
            || identifier(&state.source, &state.owner, &state.operation)? != row.id
            || state.references.iter().any(|(key, reference)| {
                !id(key) || reference.as_deref().is_some_and(|reference| !id(reference))
            })
        {
            return Err(invalid());
        }
        for key in state.references.keys() {
            SecretOwner::from_wire(&owner(state.identity(), key)?)?;
        }
        Ok(Self {
            store,
            id: row.id,
            state,
            revision: row.resource_version,
        })
    }
    pub(super) fn ssh_candidate_owner(
        &self,
        source: &RemoteProviderSource,
        candidate_id: &str,
        reference: &str,
    ) -> Option<(String, String)> {
        let bound = self.state.references.get(SSH_KEY)?;
        (self.state.format == 2
            && self.state.source == source.name.as_ref()
            && self.state.owner.kind == SecretOwnerKind::Sandbox
            && self.state.operation == candidate_id
            && self.state.references.len() == 1
            && (bound.as_deref() == Some(reference)
                || self.state.phase == Phase::Closed && bound.is_none()))
        .then(|| {
            (
                self.state.owner.workspace.clone(),
                self.state.owner.provider_id.clone(),
            )
        })
    }
    pub(super) async fn persist(&mut self) -> Result<(), Status> {
        let payload = serde_json::to_vec(&self.state).map_err(|_| invalid())?;
        self.revision = self
            .store
            .put_if(
                KIND,
                &self.id,
                &self.id,
                &self.state.owner.workspace,
                &payload,
                None,
                WriteCondition::MatchResourceVersion(self.revision),
            )
            .await
            .map_err(|_| Status::aborted("internal issuer ownership changed"))?
            .resource_version;
        Ok(())
    }
    pub(super) async fn bind(&mut self, key: &str, reference: &str) -> Result<(), Status> {
        // Even a replayed binding must CAS the journal before a value fill.
        // Otherwise the old fast path could ignore a recovery claim.
        if self.state.phase != Phase::Staging {
            return Err(invalid());
        }
        let slot = self.state.references.get_mut(key).ok_or_else(invalid)?;
        if slot.as_ref().is_some_and(|old| old != reference) {
            return Err(invalid());
        }
        *slot = Some(reference.into());
        self.persist().await
    }
    pub(super) async fn publication_writes(
        source: &RemoteProviderSource,
        identity: InternalSecretOwner<'_>,
        operation: &str,
        candidate_id: &str,
        handles: &HashMap<String, CredentialHandle>,
    ) -> Result<Vec<AtomicWrite>, Status> {
        let store = source.gateway.clone().ok_or_else(invalid)?;
        let id = identifier(&source.name, &journal_owner(identity), operation)?;
        let row = store
            .get(KIND, &id)
            .await
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        let mut intent = Self::from_record(store.clone(), row)?;
        if intent.state.format != 2
            || intent.state.phase != Phase::Staging
            || intent.state.owner != journal_owner(identity)
            || intent.state.source != source.name.as_ref()
            || handles.len() != intent.state.references.len()
        {
            return Err(Status::aborted("internal secret publication is fenced"));
        }
        for (key, handle) in handles {
            let binding = source.decode(handle)?;
            if binding.grant.is_some()
                || intent.state.references.get(key) != Some(&Some(binding.reference))
            {
                return Err(invalid());
            }
        }
        let (candidate_kind, key) = match identity.kind {
            SecretOwnerKind::Sandbox => (SSH_CANDIDATE, SSH_KEY),
            SecretOwnerKind::SupervisorInstance => (SUPERVISOR_CANDIDATE, SUPERVISOR_KEY),
            SecretOwnerKind::Provider => return Err(invalid()),
        };
        if handles.len() != 1 {
            return Err(invalid());
        }
        let candidate = store
            .get(candidate_kind, candidate_id)
            .await
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        let expected = handles.get(key).ok_or_else(invalid)?;
        match identity.kind {
            SecretOwnerKind::Sandbox if candidate_id != operation => return Err(invalid()),
            SecretOwnerKind::SupervisorInstance => {
                let payload: serde_json::Value =
                    serde_json::from_slice(&candidate.payload).map_err(|_| invalid())?;
                if payload.get("writer").and_then(serde_json::Value::as_str) != Some(operation) {
                    return Err(invalid());
                }
            }
            _ => {}
        }
        let (candidate_owner, handle) = candidate_binding(&store, &candidate, identity).await?;
        if candidate_owner != identity.id || &handle != expected {
            return Err(invalid());
        }
        intent.state.phase = Phase::Published;
        let payload = serde_json::to_vec(&intent.state).map_err(|_| invalid())?;
        Ok(vec![
            AtomicWrite::Check {
                object_type: candidate_kind.into(),
                id: candidate.id,
                expected_version: candidate.resource_version,
            },
            AtomicWrite::Update {
                object_type: KIND.into(),
                id: intent.id,
                expected_version: intent.revision,
                payload,
            },
        ])
    }
}
impl State {
    fn identity(&self) -> InternalSecretOwner<'_> {
        InternalSecretOwner {
            kind: self.owner.kind,
            workspace: &self.owner.workspace,
            id: &self.owner.provider_id,
            name: "",
        }
    }
}

pub(super) mod recovery;
