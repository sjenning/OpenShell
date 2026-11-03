// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    CANDIDATE_KIND, IDEMPOTENCY_KIND, Receipt, decode, encode, hex_digest, unexpired,
};
use super::operations::{output_owner, retire};
use super::{
    GrantRuntime, config_purpose, grant_status, material_purpose, now_ms, receipt_result, wire,
};
use crate::{
    auth::GatewayScope,
    engine::{Preparation, RefreshEngine, RefreshSink, RefreshStateStore, RefreshTrigger},
    grant::GrantAdmission,
    minter::{MintFailure, MintRequest, MintResponse, RecoveryAction, RetrySchedule},
    repository::{
        Mutation, RefreshLease,
        grants::{GrantAttempt, GrantPhase, GrantState, StoredGrant},
    },
    scheduler,
};
use prost::Message as _;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tonic::{Code, Status};

mod publication;

const MINT_RECEIPT_KIND: &str = "grant-mint-receipt-v1";
#[derive(Clone)]
pub(super) enum Purpose {
    Ensure(i64),
    Rotation { key: String, fingerprint: String },
    Scheduled,
    Recovery,
}
#[derive(Clone)]
pub(super) struct Snapshot {
    pub scope: GatewayScope,
    pub loaded: StoredGrant,
    pub purpose: Purpose,
    pub result: Option<Vec<u8>>,
}
struct NativeStore {
    runtime: Arc<GrantRuntime>,
}
struct Sink;
#[tonic::async_trait]
impl RefreshSink<Snapshot> for Sink {
    async fn committed(&self, _snapshot: &Snapshot) {}
}
fn next_version(state: &mut GrantState) -> Result<(), Status> {
    state.version = state
        .version
        .checked_add(1)
        .ok_or_else(|| Status::resource_exhausted("issuer grant version exhausted"))?;
    Ok(())
}
fn remaining(state: &GrantState, minimum: i64, now: i64) -> bool {
    state.phase != GrantPhase::Pending
        && state
            .expiration_time_ms
            .is_some_and(|expiry| expiry > now.saturating_add(minimum))
}
fn mint_receipt_key(state: &GrantState, attempt: &str) -> String {
    format!("{}:{attempt}", state.definition.identity.id)
}
fn failed_material() -> MintFailure {
    MintFailure {
        status: Status::unavailable("issuer grant material is unavailable"),
        recovery_action: RecoveryAction::Retry,
        failure_code: "grant_material_unavailable",
        provider_error_subtype: None,
        retry_schedule: RetrySchedule::Short,
    }
}
impl GrantRuntime {
    pub(super) async fn execute(
        self: &Arc<Self>,
        snapshot: Snapshot,
        trigger: RefreshTrigger,
    ) -> Result<Snapshot, Status> {
        if snapshot.loaded.state.phase == GrantPhase::Reserved {
            return Err(Status::failed_precondition(
                "issuer grant is awaiting initialization",
            ));
        }
        RefreshEngine::new(
            Arc::new(NativeStore {
                runtime: self.clone(),
            }),
            self.minters.clone(),
            Arc::new(Sink),
            self.store.coordinator.clone(),
        )
        .refresh(snapshot, trigger)
        .await
        .map_err(|error| {
            Status::new(
                if error.code() == Code::Ok {
                    Code::Unknown
                } else {
                    error.code()
                },
                "credential refresh failed; inspect grant status",
            )
        })
    }
    pub(super) async fn ensure(
        self: &Arc<Self>,
        scope: GatewayScope,
        id: String,
        minimum: i64,
    ) -> Result<wire::GrantStatus, Status> {
        let loaded = self.load(&scope, &id).await?;
        if minimum
            >= loaded
                .state
                .definition
                .max_lifetime_seconds
                .saturating_mul(1000)
        {
            return Err(Status::invalid_argument(
                "minimum remaining duration must be less than grant lifetime",
            ));
        }
        let snapshot = self
            .execute(
                Snapshot {
                    scope,
                    loaded,
                    purpose: Purpose::Ensure(minimum),
                    result: None,
                },
                RefreshTrigger::Automatic,
            )
            .await?;
        if !remaining(&snapshot.loaded.state, minimum, now_ms()?) {
            return Err(Status::failed_precondition(
                "minted output does not meet the requested remaining lifetime",
            ));
        }
        grant_status(&snapshot.loaded.state)
    }
    pub(super) async fn rotate(
        self: &Arc<Self>,
        scope: GatewayScope,
        id: String,
        key: String,
    ) -> Result<wire::RotateGrantResponse, Status> {
        let loaded = self.load(&scope, &id).await?;
        if loaded.state.phase == GrantPhase::Reserved {
            return Err(Status::failed_precondition(
                "issuer grant is awaiting initialization",
            ));
        }
        let fingerprint = hex_digest(&encode(&(
            "rotate-grant-v1",
            &loaded.state.definition.identity,
        ))?)?;
        if let Some(receipt) = self
            .store
            .replay(
                &scope,
                &key,
                "rotate_grant",
                &loaded.state.definition.identity.owner,
                &fingerprint,
            )
            .await?
            && receipt.completed
        {
            return receipt_result(&receipt);
        }
        let result = self
            .execute(
                Snapshot {
                    scope,
                    loaded,
                    purpose: Purpose::Rotation { key, fingerprint },
                    result: None,
                },
                RefreshTrigger::ExplicitRotation,
            )
            .await?;
        if let Some(result) = result.result {
            wire::RotateGrantResponse::decode(result.as_slice())
                .map_err(|_| Status::data_loss("invalid saved grant rotation result"))
        } else {
            Ok(wire::RotateGrantResponse {
                status: Some(grant_status(&result.loaded.state)?),
            })
        }
    }
    pub(super) async fn save(
        &self,
        scope: &GatewayScope,
        expected: u64,
        state: &GrantState,
        mut mutations: Vec<Mutation>,
    ) -> Result<StoredGrant, Status> {
        let (mutation, event) = self
            .store
            .repository
            .grants(scope)
            .prepare(Some(expected), state)
            .await?;
        mutations.push(mutation);
        self.store
            .repository
            .for_gateway(scope)
            .commit(&mutations, &event.into_iter().collect::<Vec<_>>())
            .await?;
        Ok(StoredGrant {
            state: state.clone(),
            revision: expected + 1,
        })
    }
    async fn rotate_receipt(
        &self,
        scope: &GatewayScope,
        state: &GrantState,
        result_code: Code,
    ) -> Result<Option<Mutation>, Status> {
        let Some(key) = state
            .attempt
            .as_ref()
            .and_then(|attempt| attempt.rotation_receipt.as_ref())
        else {
            return Ok(None);
        };
        let record = self
            .store
            .repository
            .for_gateway(scope)
            .load(IDEMPOTENCY_KIND, key)
            .await?
            .ok_or_else(|| Status::data_loss("grant rotation intent is missing"))?;
        let mut receipt: Receipt = decode(&record.payload)?;
        if receipt.operation != "rotate_grant"
            || receipt.reference != state.definition.identity.id
            || receipt.owner != state.definition.identity.owner
            || receipt.completed
        {
            return Err(Status::failed_precondition(
                "grant rotation intent does not match attempt",
            ));
        }
        receipt.completed = true;
        receipt.result_code = result_code as i32;
        receipt.version = state.version;
        receipt.response = if result_code == Code::Ok {
            wire::RotateGrantResponse {
                status: Some(grant_status(state)?),
            }
            .encode_to_vec()
        } else {
            Vec::new()
        };
        Ok(Some(Mutation::Put {
            kind: IDEMPOTENCY_KIND.into(),
            key: key.clone(),
            expected: Some(record.revision),
            payload: encode(&receipt)?,
        }))
    }
    async fn fulfill_current(&self, snapshot: &mut Snapshot) -> Result<(), Status> {
        let Purpose::Rotation { key, fingerprint } = &snapshot.purpose else {
            return Ok(());
        };
        let state = &snapshot.loaded.state;
        let supplied = &state.definition.identity.owner;
        if let Some(receipt) = self
            .store
            .replay(&snapshot.scope, key, "rotate_grant", supplied, fingerprint)
            .await?
        {
            snapshot.result =
                Some(receipt_result::<wire::RotateGrantResponse>(&receipt)?.encode_to_vec());
            return Ok(());
        }
        let operation = format!("grant:{}", state.definition.identity.id);
        let (candidate, backing) = self
            .store
            .stage_candidate(
                &snapshot.scope,
                supplied,
                &operation,
                &format!("request-fingerprint-v1:{key}"),
                fingerprint.clone(),
            )
            .await?;
        let response = wire::RotateGrantResponse {
            status: Some(grant_status(state)?),
        }
        .encode_to_vec();
        let receipt = Receipt {
            operation: "rotate_grant".into(),
            owner: supplied.clone(),
            reference: state.definition.identity.id.clone(),
            version: state.version,
            fingerprint: backing,
            created_at_ms: now_ms()?,
            completed: true,
            response: response.clone(),
            result_code: 0,
        };
        let mutations = [
            Mutation::Check {
                kind: crate::repository::grants::KIND.into(),
                key: state.definition.identity.id.clone(),
                expected: snapshot.loaded.revision,
            },
            Mutation::Put {
                kind: IDEMPOTENCY_KIND.into(),
                key: key.clone(),
                expected: None,
                payload: encode(&receipt)?,
            },
            Mutation::Delete {
                kind: CANDIDATE_KIND.into(),
                key: candidate,
                expected: 1,
            },
        ];
        self.store
            .repository
            .for_gateway(&snapshot.scope)
            .commit(&mutations, &[])
            .await?;
        snapshot.result = Some(response);
        Ok(())
    }
}
#[tonic::async_trait]
impl RefreshStateStore for NativeStore {
    type Snapshot = Snapshot;
    type Attempt = Snapshot;
    type Lease = RefreshLease;
    fn coordination_key(&self, snapshot: &Snapshot) -> String {
        GrantRuntime::coordination_key(
            &snapshot.scope,
            &snapshot.loaded.state.definition.identity.id,
        )
    }
    async fn acquire_lease(&self, snapshot: &Snapshot) -> Result<RefreshLease, Status> {
        self.runtime
            .store
            .repository
            .for_gateway(&snapshot.scope)
            .acquire_refresh_lease(&format!(
                "grant:{}",
                snapshot.loaded.state.definition.identity.id
            ))
            .await
    }
    async fn prepare(
        &self,
        observed: Snapshot,
        trigger: RefreshTrigger,
        attempt_id: &str,
    ) -> Result<Preparation<Snapshot, Snapshot>, Status> {
        let mut live = Snapshot {
            loaded: self
                .runtime
                .load(
                    &observed.scope,
                    &observed.loaded.state.definition.identity.id,
                )
                .await?,
            ..observed.clone()
        };
        live.loaded
            .state
            .checkpoint()
            .admit(&observed.loaded.state.checkpoint())?;
        if let Purpose::Rotation { key, fingerprint } = &live.purpose
            && let Some(receipt) = self
                .runtime
                .store
                .replay(
                    &live.scope,
                    key,
                    "rotate_grant",
                    &live.loaded.state.definition.identity.owner,
                    fingerprint,
                )
                .await?
            && receipt.completed
        {
            live.result =
                Some(receipt_result::<wire::RotateGrantResponse>(&receipt)?.encode_to_vec());
            return Ok(Preparation::Current(live));
        }
        if live.loaded.state.phase == GrantPhase::Publishing {
            live = self.runtime.finish_known(live).await?;
        }
        let now = now_ms()?;
        let current = match live.purpose {
            Purpose::Ensure(minimum) => remaining(&live.loaded.state, minimum, now),
            Purpose::Recovery => true,
            Purpose::Scheduled => !live.loaded.state.checkpoint().schedule.due(now),
            Purpose::Rotation { .. } => {
                live.loaded
                    .state
                    .checkpoint()
                    .admit(&observed.loaded.state.checkpoint())?
                    == GrantAdmission::Current
                    && remaining(&live.loaded.state, 0, now)
            }
        };
        if current {
            self.runtime.fulfill_current(&mut live).await?;
            return Ok(Preparation::Current(live));
        }
        live.loaded
            .state
            .checkpoint()
            .ensure_mintable(trigger, now)?;
        if self
            .runtime
            .minters
            .describe()
            .find(|descriptor| descriptor.name == live.loaded.state.definition.descriptor.name)
            != Some(&live.loaded.state.definition.descriptor)
        {
            if matches!(
                live.loaded.state.phase,
                GrantPhase::Pending | GrantPhase::Failed | GrantPhase::Refreshed
            ) {
                let mut state = live.loaded.state.clone();
                state.phase = GrantPhase::Failed;
                state.recovery_action = Some(RecoveryAction::FixConfiguration);
                state.failure_code = "strategy_descriptor_changed".into();
                state.next_refresh_at_ms =
                    scheduler::retry_at_ms(now, RetrySchedule::Configuration);
                next_version(&mut state)?;
                self.runtime
                    .save(&live.scope, live.loaded.revision, &state, Vec::new())
                    .await?;
            }
            return Err(Status::failed_precondition(
                "grant strategy descriptor changed; reconfigure the grant",
            ));
        }
        let mut mutations = self
            .runtime
            .binding_fences(&live.scope, &live.loaded.state)
            .await?;
        let mut versions = BTreeMap::new();
        let refs = self.runtime.store.repository.references(&live.scope);
        for (name, binding) in &live.loaded.state.definition.outputs {
            let state = refs
                .registry()
                .observe(&binding.reference, &output_owner(&live.loaded.state, name)?)
                .await?
                .ok_or_else(|| Status::failed_precondition("grant output is missing"))?;
            versions.insert(name.clone(), state.version);
        }
        let rotation = if let Purpose::Rotation { key, fingerprint } = &live.purpose {
            let owner = &live.loaded.state.definition.identity.owner;
            let (candidate, backing) = self
                .runtime
                .store
                .stage_candidate(
                    &live.scope,
                    owner,
                    &format!("grant:{}", live.loaded.state.definition.identity.id),
                    &format!("request-fingerprint-v1:{key}"),
                    fingerprint.clone(),
                )
                .await?;
            let receipt = Receipt {
                operation: "rotate_grant".into(),
                owner: owner.clone(),
                reference: live.loaded.state.definition.identity.id.clone(),
                version: live.loaded.state.version,
                fingerprint: backing,
                created_at_ms: now,
                completed: false,
                response: Vec::new(),
                result_code: 0,
            };
            mutations.push(Mutation::Put {
                kind: IDEMPOTENCY_KIND.into(),
                key: key.clone(),
                expected: None,
                payload: encode(&receipt)?,
            });
            mutations.push(Mutation::Delete {
                kind: CANDIDATE_KIND.into(),
                key: candidate,
                expected: 1,
            });
            Some(key.clone())
        } else {
            None
        };
        let mut state = live.loaded.state.clone();
        state.phase = GrantPhase::Refreshing;
        next_version(&mut state)?;
        state.recovery_action = None;
        state.failure_code.clear();
        state.attempt = Some(GrantAttempt {
            id: attempt_id.into(),
            encrypted_result: None,
            expected_output_versions: versions,
            output_candidates: BTreeMap::new(),
            material_candidates: BTreeMap::new(),
            rotation_receipt: rotation,
        });
        live.loaded = self
            .runtime
            .save(&live.scope, live.loaded.revision, &state, mutations)
            .await?;
        Ok(Preparation::Ready(live))
    }
    async fn mint_request(&self, attempt: &Snapshot) -> Result<MintRequest, MintFailure> {
        let state = &attempt.loaded.state;
        let owner = &state.definition.identity.owner;
        let config = self
            .runtime
            .store
            .storage
            .resolve(
                &attempt.scope,
                owner,
                &config_purpose(state),
                &state.definition.config_backing,
            )
            .await
            .map_err(|_| failed_material())?;
        unexpired(
            config.expiration_time_ms,
            now_ms().map_err(|_| failed_material())?,
        )
        .map_err(|_| failed_material())?;
        let config: HashMap<String, String> =
            serde_json::from_str(&config.value).map_err(|_| failed_material())?;
        let mut material = HashMap::new();
        for (name, backing) in &state.material {
            let value = self
                .runtime
                .store
                .storage
                .resolve(
                    &attempt.scope,
                    owner,
                    &material_purpose(state, name),
                    backing,
                )
                .await
                .map_err(|_| failed_material())?;
            unexpired(
                value.expiration_time_ms,
                now_ms().map_err(|_| failed_material())?,
            )
            .map_err(|_| failed_material())?;
            material.insert(name.clone(), value.value);
        }
        Ok(MintRequest {
            strategy: state.definition.descriptor.name.clone(),
            config,
            secret_material: material,
            attempt_id: state
                .attempt
                .as_ref()
                .ok_or_else(failed_material)?
                .id
                .clone(),
        })
    }
    async fn record_failure(&self, attempt: &Snapshot, failure: MintFailure) -> Result<(), Status> {
        let current = self
            .runtime
            .load(&attempt.scope, &attempt.loaded.state.definition.identity.id)
            .await?;
        if current.state.definition != attempt.loaded.state.definition
            || current.state.phase != GrantPhase::Refreshing
            || current.state.attempt.as_ref().map(|value| &value.id)
                != attempt.loaded.state.attempt.as_ref().map(|value| &value.id)
        {
            return Err(Status::aborted(
                "grant attempt changed while recording failure",
            ));
        }
        let mut state = current.state;
        state.phase = if failure.retry_schedule == RetrySchedule::Parked {
            GrantPhase::Parked
        } else {
            GrantPhase::Failed
        };
        state.recovery_action = Some(failure.recovery_action);
        state.failure_code = failure.failure_code.into();
        state.next_refresh_at_ms = scheduler::retry_at_ms(now_ms()?, failure.retry_schedule);
        next_version(&mut state)?;
        let receipt = self
            .runtime
            .rotate_receipt(&attempt.scope, &state, failure.status.code())
            .await?;
        self.runtime
            .save(
                &attempt.scope,
                current.revision,
                &state,
                receipt.into_iter().collect(),
            )
            .await?;
        Ok(())
    }
    async fn commit(&self, attempt: Snapshot, response: MintResponse) -> Result<Snapshot, Status> {
        self.runtime.persist_known(attempt, response).await
    }
}
