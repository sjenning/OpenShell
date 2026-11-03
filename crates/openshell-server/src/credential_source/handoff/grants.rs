// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Grant bundles share the static journal's publication and abandonment fences.
use super::{
    AtomicWrite, KIND, Phase, Provider, RemoteProviderSource, State, StaticHandoff, Store, invalid,
    storage,
};
use openshell_core::proto::credentials::refresh::v1 as refresh;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    time::Duration,
};
use tonic::Status;
mod detach;
pub(super) mod publication;
mod status;
/// Value-free immutable request recipe. Never add configuration or material here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantPlan {
    pub credential_key: String,
    pub strategy: String,
    pub outputs: BTreeMap<String, String>,
    pub refresh_before_ms: u64,
    pub max_lifetime_seconds: u32,
}
impl GrantPlan {
    fn valid(&self) -> bool {
        !self.strategy.is_empty()
            && self.strategy.len() <= 128
            && !self.strategy.chars().any(char::is_control)
            && (1..=43_200).contains(&self.max_lifetime_seconds)
            && self.refresh_before_ms <= 43_200_000
            && !self.outputs.is_empty()
            && self.outputs.len() <= 64
            && self.outputs.values().any(|key| key == &self.credential_key)
            && self.outputs.values().all(|key| {
                let mut bytes = key.bytes();
                key.len() <= 128
                    && bytes
                        .next()
                        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
                    && bytes.all(|c| c.is_ascii_alphanumeric() || c == b'_')
            })
            && self.outputs.values().collect::<BTreeSet<_>>().len() == self.outputs.len()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GrantSlot {
    plan: GrantPlan,
    id: Option<String>,
    #[serde(default)]
    pending_publication: bool,
    #[serde(default)]
    detaching: bool,
}
impl GrantSlot {
    pub(super) fn valid(&self, state: &State) -> bool {
        self.plan.valid()
            && (!self.detaching
                || state.phase == Phase::Published
                    && state.slots.values().all(|slot| !slot.retiring))
            && (!self.pending_publication || state.phase != Phase::Preparing)
            && self.plan.outputs.values().collect::<BTreeSet<_>>()
                == state.slots.keys().collect::<BTreeSet<_>>()
            && self.id.as_ref().is_none_or(|id| {
                !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control)
            })
            && state
                .slots
                .values()
                .all(|slot| slot.reference.is_some() == self.id.is_some())
            && (!matches!(
                state.phase,
                Phase::Filling | Phase::Ready | Phase::Published
            ) || self.id.is_some())
            && (!matches!(state.phase, Phase::Preparing | Phase::Filling)
                || state.slots.values().all(|slot| !slot.filled))
            && (!state.slots.values().any(|slot| slot.filled)
                || state.slots.values().all(|slot| slot.filled))
            && (!state.slots.values().any(|slot| slot.retiring)
                || state.slots.values().all(|slot| slot.retiring))
    }
}
impl StaticHandoff {
    pub fn grant_id(&self) -> Option<&str> {
        self.state
            .grant
            .as_ref()
            .and_then(|grant| grant.id.as_deref())
    }
    pub(super) fn allows_pending_publication(&self) -> bool {
        self.state
            .grant
            .as_ref()
            .is_some_and(|grant| grant.pending_publication)
    }
    /// Persist the complete value-free allocation recipe before reserving any
    /// issuer resource. Discovery does not allocate or transmit credential values.
    pub async fn begin_grant(
        store: &Store,
        source: &RemoteProviderSource,
        provider: &Provider,
        plan: GrantPlan,
        expected_provider_version: Option<u64>,
    ) -> Result<Self, Status> {
        if !plan.valid() {
            return Err(invalid());
        }
        let catalog = source.client.list_strategies().await?;
        if !catalog.supports_pending_reservations {
            return Err(Status::failed_precondition(
                "issuer requires pending grant reservation support",
            ));
        }
        if !catalog.strategies.iter().any(|descriptor| {
            descriptor.name == plan.strategy
                && descriptor.outputs.iter().collect::<BTreeSet<_>>()
                    == plan.outputs.keys().collect::<BTreeSet<_>>()
        }) {
            return Err(Status::failed_precondition(
                "issuer grant strategy or output bindings are unavailable",
            ));
        }
        let keys = plan.outputs.values().cloned().collect::<Vec<_>>();
        Self::begin_inner(
            store,
            source,
            provider,
            &keys,
            expected_provider_version,
            Some(GrantSlot {
                plan,
                id: None,
                pending_publication: false,
                detaching: false,
            }),
        )
        .await
    }
    pub(super) async fn reserve_grant(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
    ) -> Result<(), Status> {
        self.source(source)?;
        if !matches!(self.state.phase, Phase::Preparing | Phase::Aborting) {
            return Err(invalid());
        }
        let grant = self.state.grant.as_ref().ok_or_else(invalid)?;
        let request = refresh::ReserveGrantRequest {
            owner: Some(self.owner(&grant.plan.credential_key)),
            strategy: grant.plan.strategy.clone(),
            outputs: grant.plan.outputs.clone().into_iter().collect(),
            refresh_before: Some(
                openshell_core::time::duration_from_std(Duration::from_millis(
                    grant.plan.refresh_before_ms,
                ))
                .map_err(|_| invalid())?,
            ),
            max_lifetime: Some(
                openshell_core::time::duration_from_std(Duration::from_secs(u64::from(
                    grant.plan.max_lifetime_seconds,
                )))
                .map_err(|_| invalid())?,
            ),
            idempotency_key: self.operation(&grant.plan.credential_key, "reserve-grant")?,
        };
        self.check(store).await?;
        let response = source.client.reserve_grant(request).await?;
        let grant = self.state.grant.as_mut().ok_or_else(invalid)?;
        if grant.id.as_ref().is_some_and(|id| id != &response.grant) {
            return Err(invalid());
        }
        for (name, key) in &grant.plan.outputs {
            let reference = response.output_references.get(name).ok_or_else(invalid)?;
            if self.state.slots[key]
                .reference
                .as_ref()
                .is_some_and(|known| known != reference)
            {
                return Err(invalid());
            }
        }
        grant.id = Some(response.grant);
        for (name, key) in &grant.plan.outputs {
            self.state.slots.get_mut(key).ok_or_else(invalid)?.reference =
                Some(response.output_references[name].clone());
        }
        self.save(store).await
    }
    /// One-shot material handoff: persist Filling before transmitting inputs.
    /// An uncertain initialization or mint is abandoned, never resumed with
    /// caller-supplied replacement inputs or a locally persisted fingerprint.
    pub async fn fill_grant(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
        config: &HashMap<String, String>,
        material: &HashMap<String, String>,
    ) -> Result<(), Status> {
        self.prepare_grant_inner(store, source, config, material, true)
            .await
    }
    /// Initialize a grant without requesting an upstream mint. Its pending
    /// references can be published atomically; delivery remains unavailable
    /// until the issuer scheduler or a freshness request publishes first values.
    pub async fn prepare_grant(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
        config: &HashMap<String, String>,
        material: &HashMap<String, String>,
    ) -> Result<(), Status> {
        self.prepare_grant_inner(store, source, config, material, false)
            .await
    }
    async fn prepare_grant_inner(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
        config: &HashMap<String, String>,
        material: &HashMap<String, String>,
        first_value: bool,
    ) -> Result<(), Status> {
        self.source(source)?;
        if self.state.phase != Phase::Preparing {
            return Err(invalid());
        }
        let id = self.grant_id().ok_or_else(invalid)?.to_owned();
        let key = self
            .state
            .grant
            .as_ref()
            .ok_or_else(invalid)?
            .plan
            .credential_key
            .clone();
        if self
            .state
            .slots
            .values()
            .any(|slot| slot.reference.is_none())
        {
            return Err(invalid());
        }
        self.state
            .grant
            .as_mut()
            .ok_or_else(invalid)?
            .pending_publication = !first_value;
        self.state.phase = Phase::Filling;
        self.save(store).await?;
        source
            .client
            .initialize_grant(refresh::InitializeGrantRequest {
                grant: id.clone(),
                config: config.clone(),
                secret_material: material.clone(),
                idempotency_key: self.operation(&key, "initialize-grant")?,
            })
            .await?;
        self.check(store).await?;
        if first_value {
            let response = source
                .client
                .ensure_fresh(refresh::EnsureFreshRequest {
                    grant: id,
                    min_remaining: None,
                })
                .await?;
            let status = response.status.ok_or_else(invalid)?;
            if status.state != "refreshed"
                || status.expiration_time.as_ref().is_none_or(|time| {
                    openshell_core::time::timestamp_to_millis(time)
                        .ok()
                        .is_none_or(|time| time <= crate::persistence::current_time_ms())
                })
            {
                return Err(invalid());
            }
        }
        for slot in self.state.slots.values_mut() {
            slot.filled = true;
        }
        self.state.phase = Phase::Ready;
        self.save(store).await
    }
    pub(super) async fn abort_grant(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
    ) -> Result<(), Status> {
        self.source(source)?;
        if self.state.phase != Phase::Aborting {
            return Err(invalid());
        }
        // The complete allocation was already journaled atomically. Replaying
        // its reservation is unnecessary and can prevent cleanup when tracking
        // is full (including after restart, when no replay receipt is cached).
        if self.grant_id().is_none() {
            self.reserve_grant(store, source).await?;
        }
        self.check(store).await?;
        let grant = self.state.grant.as_ref().ok_or_else(invalid)?;
        source
            .client
            .delete_grant(refresh::DeleteGrantRequest {
                grant: grant.id.clone().ok_or_else(invalid)?,
                idempotency_key: self.operation(&grant.plan.credential_key, "abort-grant")?,
            })
            .await?;
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
