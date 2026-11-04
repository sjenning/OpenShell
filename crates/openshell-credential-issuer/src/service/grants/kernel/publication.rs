// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::super::{CANDIDATE_KIND, VALUE_PURPOSE, decode, encode};
use super::{
    GrantRuntime, MINT_RECEIPT_KIND, Purpose, Snapshot, grant_status, material_purpose,
    mint_receipt_key, next_version, now_ms, output_owner, retire, wire,
};
use crate::{
    ReferenceReplacement,
    grant::GrantIdentity,
    minter::MintResponse,
    repository::{
        Mutation,
        grants::{GrantPhase, StoredGrant},
    },
    scheduler,
};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use tonic::{Code, Status};

#[derive(Serialize, Deserialize)]
struct MintReceipt {
    identity: GrantIdentity,
    attempt: String,
    status: Vec<u8>,
    output_versions: BTreeMap<String, u64>,
}
fn retryable(error: &Status) -> bool {
    matches!(
        error.code(),
        Code::Unavailable | Code::Aborted | Code::DeadlineExceeded
    )
}
impl GrantRuntime {
    async fn completed(&self, snapshot: &Snapshot) -> Result<Option<Snapshot>, Status> {
        let attempt = snapshot
            .loaded
            .state
            .attempt
            .as_ref()
            .ok_or_else(|| Status::data_loss("mint publication attempt is missing"))?;
        let store = self.store.repository.for_gateway(&snapshot.scope);
        let Some(record) = store
            .load(
                MINT_RECEIPT_KIND,
                &mint_receipt_key(&snapshot.loaded.state, &attempt.id),
            )
            .await?
        else {
            return Ok(None);
        };
        let receipt: MintReceipt = decode(&record.payload)?;
        if receipt.identity != snapshot.loaded.state.definition.identity
            || receipt.attempt != attempt.id
            || receipt.output_versions.keys().collect::<BTreeSet<_>>()
                != snapshot
                    .loaded
                    .state
                    .definition
                    .outputs
                    .keys()
                    .collect::<BTreeSet<_>>()
            || receipt.output_versions.iter().any(|(name, version)| {
                attempt
                    .expected_output_versions
                    .get(name)
                    .and_then(|old| old.checked_add(1))
                    != Some(*version)
            })
        {
            return Err(Status::data_loss(
                "mint completion receipt does not match exact publication",
            ));
        }
        let status = wire::GrantStatus::decode(receipt.status.as_slice())
            .map_err(|_| Status::data_loss("invalid completed mint status"))?;
        let result = if matches!(snapshot.purpose, Purpose::Rotation { .. }) {
            Some(
                wire::RotateGrantResponse {
                    status: Some(status),
                }
                .encode_to_vec(),
            )
        } else {
            None
        };
        Ok(Some(Snapshot {
            loaded: self.load(&snapshot.scope, &receipt.identity.id).await?,
            result,
            ..snapshot.clone()
        }))
    }
    async fn live_publication(&self, snapshot: &Snapshot) -> Result<StoredGrant, Status> {
        let loaded = self
            .load(
                &snapshot.scope,
                &snapshot.loaded.state.definition.identity.id,
            )
            .await?;
        if loaded.state.definition != snapshot.loaded.state.definition
            || loaded.state.phase != GrantPhase::Publishing
            || loaded.state.attempt.as_ref().map(|attempt| &attempt.id)
                != snapshot
                    .loaded
                    .state
                    .attempt
                    .as_ref()
                    .map(|attempt| &attempt.id)
        {
            return Err(Status::aborted(
                "grant publication was deleted or superseded",
            ));
        }
        Ok(loaded)
    }
    pub(super) async fn persist_known(
        self: &Arc<Self>,
        snapshot: Snapshot,
        mut response: MintResponse,
    ) -> Result<Snapshot, Status> {
        let id = snapshot
            .loaded
            .state
            .attempt
            .as_ref()
            .ok_or_else(|| Status::data_loss("mint attempt is missing"))?
            .id
            .clone();
        let mut sealed = None;
        loop {
            let operation = async {
                if let Some(done) = self.completed(&snapshot).await? {
                    return Ok(Some(done));
                }
                let current = self
                    .load(
                        &snapshot.scope,
                        &snapshot.loaded.state.definition.identity.id,
                    )
                    .await?;
                if current.state.definition != snapshot.loaded.state.definition
                    || !matches!(
                        current.state.phase,
                        GrantPhase::Refreshing | GrantPhase::Parked | GrantPhase::Publishing
                    )
                    || current
                        .state
                        .attempt
                        .as_ref()
                        .map(|attempt| attempt.id.as_str())
                        != Some(id.as_str())
                {
                    return Err(Status::failed_precondition(
                        "grant authorization ended before known-result persistence",
                    ));
                }
                if current.state.phase == GrantPhase::Publishing {
                    return Ok(Some(Snapshot {
                        loaded: current,
                        ..snapshot.clone()
                    }));
                }
                if sealed.is_none() {
                    // Bound the issuer's serving/scheduling window, even if a
                    // custom upstream issues a longer-lived credential.
                    let limit = now_ms()?.saturating_add(
                        current
                            .state
                            .definition
                            .max_lifetime_seconds
                            .saturating_mul(1000),
                    );
                    response.expiration_time_ms = response.expiration_time_ms.min(limit);
                    sealed = Some(self.spool.seal(
                        &snapshot.scope,
                        &current.state.definition.identity,
                        &id,
                        &response,
                    )?);
                }
                let mut state = current.state;
                state.phase = GrantPhase::Publishing;
                state
                    .attempt
                    .as_mut()
                    .unwrap()
                    .encrypted_result
                    .clone_from(&sealed);
                state.recovery_action = None;
                state.failure_code.clear();
                state.provider_error_subtype.clear();
                next_version(&mut state)?;
                let loaded = self
                    .save(&snapshot.scope, current.revision, &state, Vec::new())
                    .await?;
                Ok(Some(Snapshot {
                    loaded,
                    ..snapshot.clone()
                }))
            }
            .await;
            match operation {
                Ok(Some(known)) if known.loaded.state.phase == GrantPhase::Publishing => {
                    return self.finish_known(known).await;
                }
                Ok(Some(done)) => return Ok(done),
                Ok(None) => unreachable!(),
                // Once the upstream returned, retain its result in this detached
                // worker until the native spool commits. Never repeat minting.
                Err(error) if retryable(&error) => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }
    async fn stage_known(
        &self,
        snapshot: &Snapshot,
        name: &str,
        value: &str,
        material: bool,
    ) -> Result<(), Status> {
        loop {
            if self.completed(snapshot).await?.is_some() {
                return Ok(());
            }
            let current = self.live_publication(snapshot).await?;
            let attempt = current.state.attempt.as_ref().unwrap();
            let candidates = if material {
                &attempt.material_candidates
            } else {
                &attempt.output_candidates
            };
            if candidates.contains_key(name) {
                return Ok(());
            }
            let owner = if material {
                current.state.definition.identity.owner.clone()
            } else {
                output_owner(&current.state, name)?
            };
            let purpose = if material {
                material_purpose(&current.state, name)
            } else {
                VALUE_PURPOSE.into()
            };
            let operation = format!("grant:{}", current.state.definition.identity.id);
            let (candidate, backing) = self
                .store
                .stage_candidate(
                    &snapshot.scope,
                    &owner,
                    &operation,
                    &purpose,
                    value.to_string(),
                )
                .await?;
            let latest = self.live_publication(snapshot).await?;
            let mut state = latest.state;
            let attempt = state.attempt.as_mut().unwrap();
            let candidates = if material {
                &mut attempt.material_candidates
            } else {
                &mut attempt.output_candidates
            };
            if candidates.contains_key(name) {
                return Ok(());
            }
            candidates.insert(name.into(), backing);
            match self
                .save(
                    &snapshot.scope,
                    latest.revision,
                    &state,
                    vec![Mutation::Delete {
                        kind: CANDIDATE_KIND.into(),
                        key: candidate,
                        expected: 1,
                    }],
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(error) if error.code() == Code::Aborted => {}
                Err(error) => return Err(error),
            }
        }
    }
    pub(super) async fn finish_known(
        self: &Arc<Self>,
        snapshot: Snapshot,
    ) -> Result<Snapshot, Status> {
        if let Some(done) = self.completed(&snapshot).await? {
            return Ok(done);
        }
        let attempt = snapshot
            .loaded
            .state
            .attempt
            .as_ref()
            .ok_or_else(|| Status::data_loss("known mint attempt is missing"))?;
        let bytes = attempt
            .encrypted_result
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("known mint spool is missing"))?;
        let response = self.spool.open(
            &snapshot.scope,
            &snapshot.loaded.state.definition.identity,
            &attempt.id,
            bytes,
        )?;
        let descriptor = &snapshot.loaded.state.definition.descriptor;
        if response.expiration_time_ms <= 0
            || response.outputs.keys().collect::<BTreeSet<_>>()
                != descriptor.outputs.iter().collect::<BTreeSet<_>>()
            || response
                .outputs
                .values()
                .any(|value| value.trim().is_empty())
            || response
                .rotated_secret_material
                .iter()
                .any(|(name, value)| {
                    !descriptor.rotated_secret_material.contains(name) || value.trim().is_empty()
                })
        {
            return Err(Status::data_loss(
                "known mint result violates pinned strategy",
            ));
        }
        for (name, value) in &response.rotated_secret_material {
            self.stage_known(&snapshot, name, value, true).await?;
        }
        for (name, value) in &response.outputs {
            self.stage_known(&snapshot, name, value, false).await?;
        }
        loop {
            if let Some(done) = self.completed(&snapshot).await? {
                return Ok(done);
            }
            let current = self.live_publication(&snapshot).await?;
            let mut state = current.state.clone();
            let attempt = state.attempt.clone().unwrap();
            for (name, backing) in &attempt.material_candidates {
                if let Some(old) = state.material.insert(name.clone(), backing.clone()) {
                    let purpose = material_purpose(&state, name);
                    let owner = state.definition.identity.owner.clone();
                    retire(&mut state, owner, purpose, old);
                }
            }
            let mut replacements = Vec::new();
            let mut versions = BTreeMap::new();
            for (name, binding) in &state.definition.outputs {
                let backing = attempt
                    .output_candidates
                    .get(name)
                    .ok_or_else(|| {
                        Status::failed_precondition("mint output staging is incomplete")
                    })?
                    .clone();
                let expected = *attempt
                    .expected_output_versions
                    .get(name)
                    .ok_or_else(|| Status::data_loss("mint output version fence is missing"))?;
                versions.insert(
                    name.clone(),
                    expected.checked_add(1).ok_or_else(|| {
                        Status::resource_exhausted("issuer value version exhausted")
                    })?,
                );
                replacements.push(ReferenceReplacement {
                    reference: binding.reference.clone(),
                    owner: output_owner(&state, name)?,
                    expected_version: expected,
                    backing,
                    expiration_time_ms: Some(response.expiration_time_ms),
                });
            }
            let refs = self.store.repository.references(&snapshot.scope);
            let writes = refs.registry().prepare_replacements(&replacements).await?;
            let (mut mutations, mut events) = refs.prepare_many(&writes).await?;
            mutations.extend(self.binding_fences(&snapshot.scope, &state).await?);
            state.phase = GrantPhase::Refreshed;
            state.last_refresh_time_ms = Some(now_ms()?);
            state.expiration_time_ms = Some(response.expiration_time_ms);
            state.next_refresh_at_ms = scheduler::next_refresh_at_ms(
                response.expiration_time_ms,
                Some(Duration::from_millis(
                    u64::try_from(state.definition.refresh_before_ms)
                        .map_err(|_| Status::data_loss("invalid grant lead time"))?,
                )),
            );
            state.completed_attempt = Some(attempt.id.clone());
            state.recovery_action = None;
            state.failure_code.clear();
            state.provider_error_subtype.clear();
            next_version(&mut state)?;
            if let Some(receipt) = self
                .rotate_receipt(&snapshot.scope, &state, Code::Ok)
                .await?
            {
                mutations.push(receipt);
            }
            state.attempt = None;
            let (mutation, event) = self
                .store
                .repository
                .grants(&snapshot.scope)
                .prepare(Some(current.revision), &state)
                .await?;
            mutations.push(mutation);
            events.extend(event);
            let status = grant_status(&state)?;
            let receipt = MintReceipt {
                identity: state.definition.identity.clone(),
                attempt: attempt.id.clone(),
                status: status.encode_to_vec(),
                output_versions: versions,
            };
            mutations.push(Mutation::Put {
                kind: MINT_RECEIPT_KIND.into(),
                key: mint_receipt_key(&state, &attempt.id),
                expected: None,
                payload: encode(&receipt)?,
            });
            match self
                .store
                .repository
                .for_gateway(&snapshot.scope)
                .commit(&mutations, &events)
                .await
            {
                Ok(_) => {
                    crate::observability::grant_transition(&snapshot.scope, &state);
                    return Ok(Snapshot {
                        loaded: StoredGrant {
                            state,
                            revision: current.revision + 1,
                        },
                        result: if matches!(snapshot.purpose, Purpose::Rotation { .. }) {
                            Some(
                                wire::RotateGrantResponse {
                                    status: Some(status),
                                }
                                .encode_to_vec(),
                            )
                        } else {
                            None
                        },
                        ..snapshot
                    });
                }
                Err(error) if retryable(&error) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }
}
