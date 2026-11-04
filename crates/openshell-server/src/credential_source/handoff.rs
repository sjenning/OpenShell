// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Value-free gateway ownership journal for issuer credentials.
//!
//! Provider publication joins the journal fence in the gateway database; issuer values
//! and secret-dependent request fingerprints never enter this journal.
use super::{RemoteProviderSource, wire};
use crate::persistence::{AtomicWrite, Store, WriteCondition};
use openshell_core::{ObjectId as _, ObjectName as _, ObjectWorkspace as _, proto::Provider};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use tonic::Status;
mod grants;
mod migration;
mod partial;
pub use grants::GrantPlan;
pub(crate) use grants::LegacyGrantSchedule;
pub(crate) use grants::publication::PublishedGrant;
pub(crate) use partial::ExpirationIntent;
mod recovery;
mod retirement;
pub use recovery::{HandoffPage, HandoffReconciler, RecoveryPage};

const KIND: &str = "credential_issuer_handoff_v1";
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    Preparing,
    Filling,
    Ready,
    Aborting,
    Published,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    reference: Option<String>,
    filled: bool,
    #[serde(default)]
    retiring: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    format: u32,
    id: String,
    source: String,
    workspace: String,
    provider_id: String,
    provider_name: String,
    expected_provider_version: Option<u64>,
    phase: Phase,
    slots: BTreeMap<String, Slot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant: Option<grants::GrantSlot>,
}
/// The payload contains only immutable ownership, operation IDs, and references.
/// Clones may become stale: every write and publication fences their revision.
#[derive(Debug, Clone)]
pub struct StaticHandoff {
    state: State,
    revision: u64,
}
fn invalid() -> Status {
    Status::failed_precondition("invalid issuer credential handoff")
}
fn storage(error: crate::persistence::PersistenceError) -> Status {
    match error {
        crate::persistence::PersistenceError::Conflict { .. } => {
            Status::aborted("issuer handoff changed")
        }
        crate::persistence::PersistenceError::UniqueViolation { .. } => {
            Status::already_exists("issuer handoff resource exists")
        }
        _ => Status::unavailable("issuer handoff journal operation failed"),
    }
}
fn encode(state: &State) -> Result<Vec<u8>, Status> {
    serde_json::to_vec(state).map_err(|_| invalid())
}
impl StaticHandoff {
    /// Persist ownership before contacting the issuer. The caller must allocate
    /// the immutable provider ID first. None means a new provider; Some fences
    /// replacement of the exact existing resource version.
    pub async fn begin(
        store: &Store,
        source: &RemoteProviderSource,
        provider: &Provider,
        keys: &[String],
        expected_provider_version: Option<u64>,
    ) -> Result<Self, Status> {
        Self::begin_inner(
            store,
            source,
            provider,
            keys,
            expected_provider_version,
            None,
        )
        .await
    }
    async fn begin_inner(
        store: &Store,
        source: &RemoteProviderSource,
        provider: &Provider,
        keys: &[String],
        expected_provider_version: Option<u64>,
        grant: Option<grants::GrantSlot>,
    ) -> Result<Self, Status> {
        if !source.client.capabilities().supports_pending_reservations {
            return Err(Status::failed_precondition(
                "issuer requires pending reservation support",
            ));
        }
        if provider.object_id().is_empty()
            || provider.object_workspace().is_empty()
            || provider.object_name().is_empty()
            || keys.is_empty()
            || keys.len() > source.max_batch
            || expected_provider_version == Some(0)
        {
            return Err(invalid());
        }
        if let Some(expected) = expected_provider_version {
            let record = store
                .get("provider", provider.object_id())
                .await
                .map_err(storage)?
                .ok_or_else(|| Status::not_found("handoff provider not found"))?;
            if record.workspace != provider.object_workspace()
                || record.name != provider.object_name()
            {
                return Err(invalid());
            }
            if record.resource_version != expected {
                return Err(Status::aborted("handoff provider changed"));
            }
        }
        let mut slots = BTreeMap::new();
        for key in keys {
            let mut bytes = key.bytes();
            if key.len() > 256
                || !bytes
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
                || !bytes.all(|c| c.is_ascii_alphanumeric() || c == b'_')
                || slots
                    .insert(
                        key.clone(),
                        Slot {
                            reference: None,
                            filled: false,
                            retiring: false,
                        },
                    )
                    .is_some()
            {
                return Err(invalid());
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        let state = State {
            format: 1,
            id: id.clone(),
            source: source.name.to_string(),
            workspace: provider.object_workspace().into(),
            provider_id: provider.object_id().into(),
            provider_name: provider.object_name().into(),
            expected_provider_version,
            phase: Phase::Preparing,
            slots,
            grant,
        };
        let result = store
            .put_if(
                KIND,
                &id,
                &id,
                &state.workspace,
                &encode(&state)?,
                None,
                WriteCondition::MustCreate,
            )
            .await
            .map_err(storage)?;
        Ok(Self {
            state,
            revision: result.resource_version,
        })
    }
    pub fn id(&self) -> &str {
        &self.state.id
    }
    pub async fn load(store: &Store, id: &str) -> Result<Option<Self>, Status> {
        let Some(record) = store.get(KIND, id).await.map_err(storage)? else {
            return Ok(None);
        };
        Self::from_record(record).map(Some)
    }
    fn from_record(record: crate::persistence::ObjectRecord) -> Result<Self, Status> {
        let state: State = serde_json::from_slice(&record.payload).map_err(|_| invalid())?;
        if state.format != 1
            || state.id != record.id
            || state.workspace != record.workspace
            || state.slots.is_empty()
            || state.slots.len() > 64
            || state
                .grant
                .as_ref()
                .is_some_and(|grant| !grant.valid(&state))
            || state
                .slots
                .values()
                .any(|slot| slot.filled && slot.reference.is_none())
            || matches!(state.phase, Phase::Ready | Phase::Published)
                && state.slots.values().any(|slot| !slot.filled)
            || state.phase == Phase::Published && state.slots.values().all(|slot| slot.retiring)
            || !matches!(state.phase, Phase::Published | Phase::Aborting)
                && state.slots.values().any(|slot| slot.retiring)
        {
            return Err(invalid());
        }
        Ok(Self {
            state,
            revision: record.resource_version,
        })
    }
    fn source(&self, source: &RemoteProviderSource) -> Result<(), Status> {
        if self.state.source == source.name.as_ref() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
    fn operation(&self, key: &str, action: &str) -> Result<String, Status> {
        let digest = openshell_crypto::sha256(key.as_bytes())
            .map_err(|_| Status::unavailable("issuer handoff identity unavailable"))?;
        Ok(format!(
            "{}:{action}:{}",
            self.state.id,
            hex::encode(digest)
        ))
    }
    fn owner(&self, key: &str) -> wire::SecretOwner {
        wire::SecretOwner {
            workspace: self.state.workspace.clone(),
            provider_id: self.state.provider_id.clone(),
            credential_key: key.into(),
            provider: self.state.provider_name.clone(),
            ..Default::default()
        }
    }
    async fn check(&self, store: &Store) -> Result<(), Status> {
        store
            .write_atomically(&[AtomicWrite::Check {
                object_type: KIND.into(),
                id: self.state.id.clone(),
                expected_version: self.revision,
            }])
            .await
            .map_err(storage)?;
        Ok(())
    }
    async fn save(&mut self, store: &Store) -> Result<(), Status> {
        let result = store
            .put_if(
                KIND,
                &self.state.id,
                &self.state.id,
                &self.state.workspace,
                &encode(&self.state)?,
                None,
                WriteCondition::MatchResourceVersion(self.revision),
            )
            .await
            .map_err(storage)?;
        self.revision = result.resource_version;
        Ok(())
    }
    /// Establish every durable binding before transmitting any provider value.
    /// An uncertain reservation can be replayed later using metadata alone.
    pub async fn reserve(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
    ) -> Result<(), Status> {
        self.source(source)?;
        if self.state.phase != Phase::Preparing {
            return Err(invalid());
        }
        if self.state.grant.is_some() {
            return self.reserve_grant(store, source).await;
        }
        let keys: Vec<_> = self.state.slots.keys().cloned().collect();
        for key in keys {
            if self.state.slots[&key].reference.is_some() {
                continue;
            }
            self.check(store).await?;
            let result = source
                .client
                .reserve_secret(wire::ReserveSecretRequest {
                    owner: Some(self.owner(&key)),
                    idempotency_key: self.operation(&key, "reserve")?,
                })
                .await?;
            self.state
                .slots
                .get_mut(&key)
                .expect("known slot")
                .reference = Some(result.reference);
            self.save(store).await?;
        }
        Ok(())
    }
    /// Values stay in this caller's memory and are transmitted only after the
    /// complete reservation set is journaled. Fill is one-shot: any interrupted
    /// or failed fill must recover by revoking the known reference set. This
    /// avoids persisting a whole-request secret-dependent fingerprint locally.
    pub async fn fill(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
        values: &HashMap<String, String>,
        expirations: &HashMap<String, prost_types::Timestamp>,
    ) -> Result<(), Status> {
        self.source(source)?;
        if self.state.phase != Phase::Preparing
            || self.state.grant.is_some()
            || values.len() != self.state.slots.len()
            || values.keys().any(|key| !self.state.slots.contains_key(key))
            || self
                .state
                .slots
                .values()
                .any(|slot| slot.reference.is_none())
            || expirations.keys().any(|key| !values.contains_key(key))
        {
            return Err(invalid());
        }
        for expiration in expirations.values() {
            openshell_core::time::timestamp_to_millis(expiration).map_err(|_| invalid())?;
        }
        self.state.phase = Phase::Filling;
        self.save(store).await?;
        for (key, value) in values {
            self.check(store).await?;
            let reference = self.state.slots[key]
                .reference
                .clone()
                .ok_or_else(invalid)?;
            let result = source
                .client
                .put_secret(wire::PutSecretRequest {
                    owner: Some(self.owner(key)),
                    reference: reference.clone(),
                    expected_version: Some(1),
                    value: value.clone(),
                    expiration_time: expirations.get(key).copied(),
                    idempotency_key: self.operation(key, "fill")?,
                })
                .await?;
            if result.reference != reference || result.version != 2 {
                return Err(invalid());
            }
            self.state.slots.get_mut(key).expect("known slot").filled = true;
            self.save(store).await?;
        }
        self.state.phase = Phase::Ready;
        self.save(store).await
    }
    pub fn handles(
        &self,
        source: &RemoteProviderSource,
    ) -> Result<HashMap<String, openshell_core::proto::CredentialHandle>, Status> {
        self.source(source)?;
        if self.state.phase != Phase::Ready {
            return Err(invalid());
        }
        self.state
            .slots
            .iter()
            .map(|(key, slot)| {
                Ok((
                    key.clone(),
                    source.reference_handle(
                        slot.reference.as_deref().ok_or_else(invalid)?,
                        self.grant_id(),
                    )?,
                ))
            })
            .collect()
    }
    /// Join an exact provider write with the journal publication fence. Raw
    /// provider values are rejected. A cleanup claim invalidates stale owners.
    /// The label index is derived from the validated provider payload and joined
    /// to the same transaction, including removal of all previous labels.
    pub async fn publish(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
        provider_write: AtomicWrite,
    ) -> Result<(), Status> {
        self.publish_replacing(store, source, provider_write, &[])
            .await
    }
    /// Publish a replacement and claim old journals for retirement atomically.
    /// Reload claimed journals before calling abort; stale published owners may
    /// neither delete the old values nor republish their previous bindings.
    pub async fn publish_replacing(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
        provider_write: AtomicWrite,
        retiring: &[Self],
    ) -> Result<(), Status> {
        self.publish_replacing_with_expiration_intent(store, source, provider_write, retiring, None)
            .await
    }
    pub(crate) async fn publish_replacing_with_expiration_intent(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
        provider_write: AtomicWrite,
        retiring: &[Self],
        expiration_intent: Option<&ExpirationIntent>,
    ) -> Result<(), Status> {
        self.source(source)?;
        if self.state.phase != Phase::Ready {
            return Err(invalid());
        }
        let (object_type, id, payload, expected) = match &provider_write {
            AtomicWrite::Create {
                object_type,
                id,
                payload,
                workspace,
                name,
            } if workspace == &self.state.workspace && name == &self.state.provider_name => {
                (object_type, id, payload, None)
            }
            AtomicWrite::Update {
                object_type,
                id,
                payload,
                expected_version,
            } => (object_type, id, payload, Some(*expected_version)),
            _ => return Err(invalid()),
        };
        let provider = Provider::decode(payload.as_slice()).map_err(|_| invalid())?;
        if object_type != "provider"
            || id != &self.state.provider_id
            || expected != self.state.expected_provider_version
            || provider.object_id() != self.state.provider_id
            || provider.object_workspace() != self.state.workspace
            || provider.object_name() != self.state.provider_name
            || !provider.credentials.is_empty()
            || self
                .handles(source)?
                .iter()
                .any(|(key, handle)| provider.credential_handles.get(key) != Some(handle))
        {
            return Err(invalid());
        }
        let mut retained_expiration_provider = None;
        let mut writes = if let Some(expected) = expected {
            let row = store
                .get("provider", &self.state.provider_id)
                .await
                .map_err(storage)?
                .ok_or_else(|| Status::not_found("handoff provider not found"))?;
            if row.resource_version != expected {
                return Err(Status::aborted("handoff provider changed"));
            }
            let old = Provider::decode(row.payload.as_slice()).map_err(|_| invalid())?;
            if old.object_id() != self.state.provider_id
                || old.object_workspace() != self.state.workspace
                || row.workspace != self.state.workspace
            {
                return Err(invalid());
            }
            // New bindings come only from this handoff; all other bindings
            // must preserve an exact, non-retiring old immutable reference.
            for (key, handle) in &provider.credential_handles {
                if !self.state.slots.contains_key(key)
                    && old.credential_handles.get(key) != Some(handle)
                {
                    return Err(invalid());
                }
            }
            let writes = retirement::claims(source, &old, Some(&provider), retiring)?;
            retained_expiration_provider = Some(old);
            writes
        } else {
            if !retiring.is_empty() || provider.credential_handles.len() != self.state.slots.len() {
                return Err(invalid());
            }
            Vec::new()
        };
        if retiring
            .iter()
            .flat_map(|old| old.state.slots.values())
            .any(|old| {
                self.state
                    .slots
                    .values()
                    .any(|new| new.reference == old.reference)
            })
        {
            return Err(invalid());
        }
        let metadata = source
            .client
            .resolve_secrets(wire::ResolveSecretsRequest {
                purpose: wire::ResolvePurpose::MetadataInspection as i32,
                secrets: self
                    .state
                    .slots
                    .iter()
                    .map(|(key, slot)| {
                        Ok(wire::ResolveSecretRequest {
                            request_id: key.clone(),
                            owner: Some(self.owner(key)),
                            reference: slot.reference.clone().ok_or_else(invalid)?,
                            expected_version: if self.state.grant.is_some() {
                                None
                            } else {
                                Some(2)
                            },
                        })
                    })
                    .collect::<Result<Vec<_>, Status>>()?,
            })
            .await?;
        if metadata.secrets.iter().any(|secret| {
            if secret.pending_value {
                !(self.allows_pending_publication() && secret.version == 1)
            } else {
                secret.version < 2
            }
        }) {
            return Err(invalid());
        }
        let labels = provider
            .metadata
            .as_ref()
            .ok_or_else(invalid)?
            .labels
            .clone();
        let provider_write = match provider_write {
            AtomicWrite::Create {
                object_type,
                id,
                name,
                workspace,
                payload,
            } => AtomicWrite::CreateLabeled {
                object_type,
                id,
                name,
                workspace,
                payload,
                labels,
            },
            AtomicWrite::Update {
                object_type,
                id,
                payload,
                expected_version,
            } => AtomicWrite::UpdateLabeled {
                object_type,
                id,
                payload,
                expected_version,
                labels,
            },
            _ => return Err(invalid()),
        };
        let mut published = self.state.clone();
        published.phase = Phase::Published;
        writes.push(provider_write);
        writes.push(AtomicWrite::Update {
            object_type: KIND.into(),
            id: self.state.id.clone(),
            payload: encode(&published)?,
            expected_version: self.revision,
        });
        if let Some(old) = retained_expiration_provider {
            Self::check_retained_expirations(source, &old, &provider, self.state.slots.keys())
                .await?;
        }
        if let Some(intent) = expiration_intent {
            intent.check(source, &provider).await?;
        }
        store.write_atomically(&writes).await.map_err(storage)?;
        self.state = published;
        self.revision = self.revision.checked_add(1).ok_or_else(invalid)?;
        Ok(())
    }
    /// Claim abandonment before contacting the issuer. Replay value-free
    /// reservations to discover unknown responses, then revoke each reference.
    /// Ownership remains journaled through every uncertain cleanup response.
    pub async fn abort(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
    ) -> Result<(), Status> {
        self.source(source)?;
        if self.state.phase == Phase::Published {
            return Err(invalid());
        }
        self.state.phase = Phase::Aborting;
        self.save(store).await?;
        if self.state.grant.is_some() {
            return self.abort_grant(store, source).await;
        }
        let keys: Vec<_> = self.state.slots.keys().cloned().collect();
        for key in keys {
            self.check(store).await?;
            // Converted grant outputs have durable reference ownership but no
            // static reservation receipt. Discover only unknown references.
            let reference = if let Some(reference) = &self.state.slots[&key].reference {
                reference.clone()
            } else {
                source
                    .client
                    .reserve_secret(wire::ReserveSecretRequest {
                        owner: Some(self.owner(&key)),
                        idempotency_key: self.operation(&key, "reserve")?,
                    })
                    .await?
                    .reference
            };
            self.state
                .slots
                .get_mut(&key)
                .expect("known slot")
                .reference = Some(reference.clone());
            self.save(store).await?;
            source
                .client
                .delete_secret(wire::DeleteSecretRequest {
                    owner: Some(self.owner(&key)),
                    reference,
                    expected_version: None,
                    idempotency_key: self.operation(&key, "abort")?,
                })
                .await?;
        }
        store
            .write_atomically(&[AtomicWrite::Delete {
                object_type: KIND.into(),
                id: self.state.id.clone(),
                expected_version: self.revision,
            }])
            .await
            .map_err(storage)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests;
