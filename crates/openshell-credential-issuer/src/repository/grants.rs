// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Issuer-owned grant metadata; no gateway DTOs or inline plaintext secrets.
use super::{Change, Mutation, Record, Repository, ScopedRepository};
use crate::{
    SecretOwner,
    auth::GatewayScope,
    grant::{GrantCheckpoint, GrantIdentity},
    minter::{RecoveryAction, StrategyDescriptor},
    scheduler::GrantSchedule,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tonic::Status;

pub const KIND: &str = "refresh-grant-v1";
pub const OUTPUT_BINDING_KIND: &str = "reference-grant-binding-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputBinding {
    pub credential_key: String,
    pub reference: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantDefinition {
    pub identity: GrantIdentity,
    pub descriptor: StrategyDescriptor,
    pub config_backing: Vec<u8>,
    pub outputs: BTreeMap<String, OutputBinding>,
    pub refresh_before_ms: i64,
    pub max_lifetime_seconds: i64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantPhase {
    Pending,
    Refreshing,
    Publishing,
    Refreshed,
    Failed,
    Parked,
    Deleting,
    Deleted,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct GrantAttempt {
    pub id: String,
    /// Encrypted known-success result, never a plaintext mint response.
    pub encrypted_result: Option<Vec<u8>>,
    pub expected_output_versions: BTreeMap<String, u64>,
    pub output_candidates: BTreeMap<String, Vec<u8>>,
    pub material_candidates: BTreeMap<String, Vec<u8>>,
    pub rotation_receipt: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct RetiredBacking {
    pub owner: SecretOwner,
    pub purpose: String,
    pub backing: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct GrantState {
    pub format_version: u32,
    pub definition: GrantDefinition,
    pub material: BTreeMap<String, Vec<u8>>,
    pub version: u64,
    pub phase: GrantPhase,
    pub expiration_time_ms: Option<i64>,
    pub next_refresh_at_ms: i64,
    pub recovery_action: Option<RecoveryAction>,
    pub failure_code: String,
    pub attempt: Option<GrantAttempt>,
    pub completed_attempt: Option<String>,
    pub retired: Vec<RetiredBacking>,
}
impl std::fmt::Debug for GrantState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantState")
            .field("id", &self.definition.identity.id)
            .field("version", &self.version)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}
impl GrantState {
    pub fn checkpoint(&self) -> GrantCheckpoint {
        let status = match self.phase {
            GrantPhase::Pending => "configured",
            GrantPhase::Refreshing => "refresh_in_progress",
            GrantPhase::Publishing => "refresh_committing",
            GrantPhase::Refreshed => "refreshed",
            GrantPhase::Failed => "failed",
            GrantPhase::Parked => "parked",
            GrantPhase::Deleting => "deleting",
            GrantPhase::Deleted => "deleted",
        };
        GrantCheckpoint {
            identity: self.definition.identity.clone(),
            status: status.to_string(),
            failure_code: self.failure_code.clone(),
            completed_attempt: self.completed_attempt.clone(),
            schedule: GrantSchedule {
                next_refresh_at_ms: self.next_refresh_at_ms,
                recovery_action: self.recovery_action,
                rotation_requested: false,
                deleting: matches!(self.phase, GrantPhase::Deleting | GrantPhase::Deleted),
                pending_cleanup: !self.retired.is_empty() || self.phase == GrantPhase::Publishing,
            },
        }
    }
    fn validate(&self) -> Result<(), Status> {
        let definition = &self.definition;
        let identity = &definition.identity;
        let outputs = &definition.outputs;
        let output_names = definition
            .descriptor
            .outputs
            .iter()
            .collect::<BTreeSet<_>>();
        if self.format_version != 1
            || self.version == 0
            || identity.id.is_empty()
            || identity.authorization_epoch.is_empty()
            || definition.descriptor.name.is_empty()
            || definition.config_backing.is_empty()
            || definition.refresh_before_ms < 0
            || definition.max_lifetime_seconds <= 0
            || outputs.is_empty()
            || outputs.len() > 64
            || output_names.len() != definition.descriptor.outputs.len()
            || outputs.keys().collect::<BTreeSet<_>>() != output_names
            || outputs
                .values()
                .any(|binding| binding.reference.is_empty() || binding.credential_key.is_empty())
            || outputs
                .values()
                .map(|binding| &binding.reference)
                .collect::<BTreeSet<_>>()
                .len()
                != outputs.len()
            || outputs
                .values()
                .map(|binding| &binding.credential_key)
                .collect::<BTreeSet<_>>()
                .len()
                != outputs.len()
        {
            return Err(Status::data_loss("invalid immutable grant definition"));
        }
        if self.material.iter().any(|(name, backing)| {
            backing.is_empty()
                || !definition
                    .descriptor
                    .secret_material
                    .iter()
                    .any(|field| field.name == *name)
        }) || definition
            .descriptor
            .secret_material
            .iter()
            .any(|field| field.required && !self.material.contains_key(&field.name))
            || self
                .expiration_time_ms
                .is_some_and(|expiration| expiration <= 0)
            || self.failure_code.len() > 128
            || self
                .failure_code
                .chars()
                .any(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_')
            || self
                .completed_attempt
                .as_ref()
                .is_some_and(String::is_empty)
        {
            return Err(Status::data_loss(
                "invalid durable grant material or status",
            ));
        }
        if matches!(self.phase, GrantPhase::Refreshing | GrantPhase::Publishing)
            && self.attempt.is_none()
            || self.phase == GrantPhase::Refreshed && self.completed_attempt.is_none()
            || self.phase == GrantPhase::Parked
                && (self.next_refresh_at_ms != i64::MAX
                    || !matches!(
                        self.recovery_action,
                        Some(RecoveryAction::Investigate | RecoveryAction::Reauthorize)
                    ))
        {
            return Err(Status::data_loss("invalid durable grant phase"));
        }
        if let Some(attempt) = &self.attempt
            && (attempt.id.is_empty()
                || attempt
                    .expected_output_versions
                    .keys()
                    .collect::<BTreeSet<_>>()
                    != output_names
                || attempt
                    .expected_output_versions
                    .values()
                    .any(|version| *version == 0)
                || attempt
                    .output_candidates
                    .iter()
                    .any(|(name, backing)| !outputs.contains_key(name) || backing.is_empty())
                || attempt.material_candidates.iter().any(|(name, backing)| {
                    !definition.descriptor.rotated_secret_material.contains(name)
                        || backing.is_empty()
                })
                || (self.phase == GrantPhase::Publishing
                    && attempt.encrypted_result.as_ref().is_none_or(Vec::is_empty))
                || (self.phase == GrantPhase::Refreshing && attempt.encrypted_result.is_some()))
        {
            return Err(Status::data_loss("invalid durable grant attempt"));
        }
        if self.retired.iter().any(|retired| {
            retired.backing.is_empty()
                || retired.purpose.is_empty()
                || retired.owner.workspace != identity.owner.workspace
                || retired.owner.provider_id != identity.owner.provider_id
        }) {
            return Err(Status::data_loss("invalid grant cleanup ownership"));
        }
        Ok(())
    }
    fn completes(&self, old: &Self) -> bool {
        old.phase == GrantPhase::Publishing
            && self.phase == GrantPhase::Refreshed
            && self.attempt.is_none()
            && old.attempt.as_ref().is_some_and(|attempt| {
                self.completed_attempt.as_deref() == Some(attempt.id.as_str())
                    && attempt.encrypted_result.is_some()
                    && attempt.output_candidates.keys().collect::<BTreeSet<_>>()
                        == old.definition.outputs.keys().collect::<BTreeSet<_>>()
                    && attempt
                        .material_candidates
                        .iter()
                        .all(|(name, backing)| self.material.get(name) == Some(backing))
            })
    }

    fn same_status(&self, other: &Self) -> bool {
        self.phase == other.phase
            && self.expiration_time_ms == other.expiration_time_ms
            && self.next_refresh_at_ms == other.next_refresh_at_ms
            && self.recovery_action == other.recovery_action
            && self.failure_code == other.failure_code
            && self.completed_attempt == other.completed_attempt
    }
    fn allows(&self, next: GrantPhase) -> bool {
        use GrantPhase::{
            Deleted, Deleting, Failed, Parked, Pending, Publishing, Refreshed, Refreshing,
        };
        self.phase == next
            || match self.phase {
                Pending | Failed | Refreshed => {
                    matches!(next, Refreshing | Failed | Parked | Deleting)
                }
                Refreshing => matches!(next, Publishing | Failed | Parked | Deleting),
                Publishing => matches!(next, Refreshed | Deleting),
                Parked => {
                    next == Deleting
                        || self.recovery_action == Some(RecoveryAction::Reauthorize)
                            && self.failure_code != "oauth_refresh_exchange_uncertain"
                            && next == Refreshing
                }
                Deleting => next == Deleted,
                Deleted => false,
            }
    }
}
#[derive(Debug, Clone)]
pub struct StoredGrant {
    pub state: GrantState,
    pub revision: u64,
}
#[derive(Debug)]
pub struct GrantPage {
    pub grants: Vec<StoredGrant>,
    /// Last scanned key, including workspace-filtered records. Continue until
    /// None rather than stopping on a page with no authorized grants.
    pub after: Option<String>,
}

#[derive(Clone)]
pub struct GrantRepository {
    repository: ScopedRepository,
    scope: GatewayScope,
}
impl Repository {
    pub fn grants(self: &Arc<Self>, scope: &GatewayScope) -> GrantRepository {
        GrantRepository {
            repository: self.for_gateway(scope),
            scope: scope.clone(),
        }
    }
}
impl GrantRepository {
    pub async fn load(&self, id: &str) -> Result<Option<StoredGrant>, Status> {
        let Some(record) = self.repository.load(KIND, id).await? else {
            return Ok(None);
        };
        self.decode(id, record).map(Some)
    }

    fn decode(&self, id: &str, record: Record) -> Result<StoredGrant, Status> {
        let state: GrantState = serde_json::from_slice(&record.payload)
            .map_err(|_| Status::data_loss("invalid durable grant record"))?;
        self.scope
            .authorize_owner(&state.definition.identity.owner)?;
        state.validate()?;
        if state.definition.identity.id != id {
            return Err(Status::data_loss(
                "durable grant key does not match identity",
            ));
        }
        Ok(StoredGrant {
            state,
            revision: record.revision,
        })
    }
    pub async fn list(&self, after: Option<&str>, limit: u32) -> Result<GrantPage, Status> {
        let records = self.repository.list(KIND, after, limit).await?;
        let cursor = records.last().map(|(key, _)| key.clone());
        let mut grants = Vec::new();
        for (key, record) in records {
            match self.decode(&key, record) {
                Ok(grant) => grants.push(grant),
                Err(error) if error.code() == tonic::Code::PermissionDenied => {}
                Err(error) => return Err(error),
            }
        }
        Ok(GrantPage {
            grants,
            after: cursor,
        })
    }

    /// Prepare a revision-fenced write for a native transaction with output
    /// references, binding records, receipts, candidate ownership and events.
    pub async fn prepare(
        &self,
        expected: Option<u64>,
        state: &GrantState,
    ) -> Result<(Mutation, Option<Change>), Status> {
        self.scope
            .authorize_owner(&state.definition.identity.owner)?;
        state.validate()?;
        let id = &state.definition.identity.id;
        let old = self.load(id).await?;
        if old.as_ref().map(|old| old.revision) != expected {
            return Err(Status::aborted("issuer grant revision changed"));
        }
        let changed = if let Some(old) = old {
            if old.state.definition != state.definition {
                return Err(Status::aborted("immutable grant definition changed"));
            }
            if matches!(
                old.state.phase,
                GrantPhase::Refreshing | GrantPhase::Publishing
            ) && matches!(state.phase, GrantPhase::Refreshing | GrantPhase::Publishing)
                && old.state.attempt.as_ref().map(|attempt| &attempt.id)
                    != state.attempt.as_ref().map(|attempt| &attempt.id)
            {
                return Err(Status::aborted("immutable grant attempt changed"));
            }
            if let Some(attempt) = &old.state.attempt {
                for backing in attempt
                    .output_candidates
                    .values()
                    .chain(attempt.material_candidates.values())
                {
                    let retained = state.attempt.as_ref().is_some_and(|next| {
                        next.output_candidates
                            .values()
                            .chain(next.material_candidates.values())
                            .any(|candidate| candidate == backing)
                    }) || state
                        .retired
                        .iter()
                        .any(|retired| &retired.backing == backing)
                        || state.completes(&old.state);
                    if !retained {
                        return Err(Status::failed_precondition(
                            "grant update lost staged candidate ownership",
                        ));
                    }
                }
            }
            if (old.state.completed_attempt != state.completed_attempt
                || (old.state.phase != GrantPhase::Refreshed
                    && state.phase == GrantPhase::Refreshed))
                && !state.completes(&old.state)
            {
                return Err(Status::failed_precondition(
                    "grant completion requires the exact staged mint receipt",
                ));
            }
            if old.state.material.iter().any(|(name, backing)| {
                state.material.get(name) != Some(backing)
                    && !state
                        .retired
                        .iter()
                        .any(|retired| retired.backing == *backing)
            }) {
                return Err(Status::failed_precondition(
                    "grant rotation lost retired material ownership",
                ));
            }
            if old.state.material != state.material && old.state.phase != GrantPhase::Publishing {
                return Err(Status::failed_precondition(
                    "grant material requires a known completed mint",
                ));
            }
            let late_known_result = old.state.phase == GrantPhase::Parked
                && old.state.recovery_action == Some(RecoveryAction::Investigate)
                && state.phase == GrantPhase::Publishing
                && old
                    .state
                    .attempt
                    .as_ref()
                    .zip(state.attempt.as_ref())
                    .is_some_and(|(before, after)| {
                        before.id == after.id && after.encrypted_result.is_some()
                    });
            if !old.state.allows(state.phase) && !late_known_result {
                return Err(Status::failed_precondition(
                    "issuer grant phase cannot be replayed or resurrected",
                ));
            }
            let changed = !old.state.same_status(state);
            let version = if changed {
                old.state
                    .version
                    .checked_add(1)
                    .ok_or_else(|| Status::resource_exhausted("issuer grant version exhausted"))?
            } else {
                old.state.version
            };
            if state.version != version {
                return Err(Status::failed_precondition(
                    "issuer grant status version transition is invalid",
                ));
            }
            changed
        } else {
            if state.version != 1
                || state.phase != GrantPhase::Pending
                || state.attempt.is_some()
                || state.completed_attempt.is_some()
            {
                return Err(Status::failed_precondition(
                    "new issuer grants must be pending at version one",
                ));
            }
            true
        };
        let payload = serde_json::to_vec(state)
            .map_err(|_| Status::internal("issuer grant encoding failed"))?;
        let event = changed.then(|| Change {
            kind: "grant".to_string(),
            key: id.clone(),
            version: state.version,
            deleted: state.phase == GrantPhase::Deleted,
        });
        Ok((
            Mutation::Put {
                kind: KIND.to_string(),
                key: id.clone(),
                expected,
                payload,
            },
            event,
        ))
    }
}

#[cfg(test)]
mod tests;
