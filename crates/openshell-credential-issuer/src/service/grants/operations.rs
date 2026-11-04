// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    CANDIDATE_KIND, IDEMPOTENCY_KIND, Receipt, VALUE_PURPOSE, decode, encode, hex_digest, now_ms,
    owner,
};
use super::{
    GrantRuntime, OutputOwner, config_purpose, duration_ms, material_purpose, receipt_result, wire,
};
use crate::{
    ReferenceState, ReferenceStateStore, SecretOwner,
    auth::GatewayScope,
    grant::GrantIdentity,
    minter::MaterialDescriptor,
    repository::{
        Mutation,
        grants::{
            GrantDefinition, GrantPhase, GrantState, OUTPUT_BINDING_KIND, OutputBinding,
            RetiredBacking,
        },
    },
};
use prost::Message as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use tonic::Status;

pub(super) fn validate_inputs(
    fields: &[MaterialDescriptor],
    values: &BTreeMap<String, String>,
) -> Result<(), Status> {
    if values.len() > 64
        || fields.iter().any(|field| {
            field.required
                && values
                    .get(&field.name)
                    .is_none_or(|value| value.trim().is_empty())
        })
        || values
            .keys()
            .any(|key| !fields.iter().any(|field| field.name == *key))
    {
        return Err(Status::invalid_argument(
            "grant inputs do not match the pinned strategy",
        ));
    }
    Ok(())
}
pub(super) fn parsed_duration(
    value: Option<&prost_types::Duration>,
    default: Duration,
) -> Result<Duration, Status> {
    value
        .map(openshell_core::time::duration_to_std)
        .transpose()
        .map_err(|_| Status::invalid_argument("invalid grant duration"))
        .map(|value| value.unwrap_or(default))
}
pub(super) fn output_owner(state: &GrantState, name: &str) -> Result<SecretOwner, Status> {
    let binding = state
        .definition
        .outputs
        .get(name)
        .ok_or_else(|| Status::data_loss("grant output binding is missing"))?;
    Ok(SecretOwner {
        credential_key: binding.credential_key.clone(),
        ..state.definition.identity.owner.clone()
    })
}
pub(super) fn retire(
    state: &mut GrantState,
    owner: SecretOwner,
    purpose: String,
    backing: Vec<u8>,
) {
    if backing.is_empty() {
        return;
    }
    if !state
        .retired
        .iter()
        .any(|retired| retired.backing == backing)
    {
        state.retired.push(RetiredBacking {
            owner,
            purpose,
            backing,
        });
    }
}
impl GrantRuntime {
    pub(super) async fn binding_fences(
        &self,
        scope: &GatewayScope,
        state: &GrantState,
    ) -> Result<Vec<Mutation>, Status> {
        let store = self.store.repository.for_gateway(scope);
        let mut checks = Vec::new();
        for binding in state.definition.outputs.values() {
            let record = store
                .load(OUTPUT_BINDING_KIND, &binding.reference)
                .await?
                .ok_or_else(|| {
                    Status::failed_precondition("grant output ownership is unavailable")
                })?;
            let owner: OutputOwner = decode(&record.payload)?;
            if owner.grant != state.definition.identity.id
                || owner.authorization_epoch != state.definition.identity.authorization_epoch
            {
                return Err(Status::permission_denied(
                    "grant output belongs to another authorization",
                ));
            }
            checks.push(Mutation::Check {
                kind: OUTPUT_BINDING_KIND.into(),
                key: binding.reference.clone(),
                expected: record.revision,
            });
        }
        Ok(checks)
    }
    pub(super) async fn create(
        self: Arc<Self>,
        scope: GatewayScope,
        request: wire::CreateGrantRequest,
        key: String,
    ) -> Result<wire::CreateGrantResponse, Status> {
        let supplied = owner(request.owner.as_ref())?;
        scope.authorize_owner(&supplied)?;
        let refresh_before = duration_ms(parsed_duration(
            request.refresh_before.as_ref(),
            Duration::from_mins(5),
        )?)?;
        let lifetime = parsed_duration(request.max_lifetime.as_ref(), Duration::from_hours(1))?;
        if lifetime.is_zero() || lifetime > Duration::from_hours(12) {
            return Err(Status::invalid_argument(
                "grant lifetime must be positive and at most twelve hours",
            ));
        }
        let seconds = lifetime
            .as_secs()
            .saturating_add(u64::from(lifetime.subsec_nanos() != 0));
        let seconds = i64::try_from(seconds)
            .map_err(|_| Status::invalid_argument("grant lifetime exceeds limit"))?;
        let mut config = request.config.into_iter().collect::<BTreeMap<_, _>>();
        if !request.strategy.starts_with("custom:") {
            if config
                .get("max_lifetime_seconds")
                .is_some_and(|value| value != &seconds.to_string())
            {
                return Err(Status::invalid_argument(
                    "set builtin lifetime through max_lifetime",
                ));
            }
            config.insert("max_lifetime_seconds".into(), seconds.to_string());
        }
        let material = request
            .secret_material
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let outputs = request.outputs.into_iter().collect::<BTreeMap<_, _>>();
        let fingerprint = hex_digest(&encode(&(
            "create-grant-v1",
            &supplied,
            &request.strategy,
            &config,
            &material,
            &outputs,
            refresh_before,
            seconds,
        ))?)?;
        let operation = format!("secret-operation:{key}");
        let store = self.store.repository.for_gateway(&scope);
        let _lease = store.acquire_refresh_lease(&operation).await?;
        if let Some(receipt) = self
            .store
            .replay(&scope, &key, "create_grant", &supplied, &fingerprint)
            .await?
        {
            return receipt_result(&receipt);
        }
        let descriptor = self
            .minters
            .describe()
            .find(|descriptor| descriptor.name == request.strategy)
            .cloned()
            .ok_or_else(|| Status::invalid_argument("issuer strategy is not registered"))?;
        if descriptor.outputs.iter().collect::<BTreeSet<_>>()
            != outputs.keys().collect::<BTreeSet<_>>()
            || outputs.values().any(|key| {
                key.is_empty()
                    || key.len() > 128
                    || key.trim() != key
                    || key.chars().any(char::is_control)
            })
            || outputs.values().collect::<BTreeSet<_>>().len() != outputs.len()
        {
            return Err(Status::invalid_argument(
                "grant outputs must bind every semantic output to a distinct credential key",
            ));
        }
        validate_inputs(&descriptor.config, &config)?;
        validate_inputs(&descriptor.secret_material, &material)?;
        let identity = GrantIdentity {
            id: uuid::Uuid::new_v4().to_string(),
            authorization_epoch: uuid::Uuid::new_v4().to_string(),
            owner: supplied.clone(),
        };
        let output_bindings = outputs
            .into_iter()
            .map(|(name, credential_key)| {
                (
                    name,
                    OutputBinding {
                        credential_key,
                        reference: uuid::Uuid::new_v4().to_string(),
                    },
                )
            })
            .collect();
        let mut state = GrantState {
            format_version: 1,
            definition: GrantDefinition {
                identity,
                descriptor,
                config_backing: Vec::new(),
                outputs: output_bindings,
                refresh_before_ms: refresh_before,
                max_lifetime_seconds: seconds,
            },
            material: BTreeMap::new(),
            version: 1,
            phase: GrantPhase::Pending,
            expiration_time_ms: None,
            next_refresh_at_ms: 0,
            recovery_action: None,
            failure_code: String::new(),
            last_refresh_time_ms: None,
            last_error_time_ms: None,
            provider_error_subtype: String::new(),
            attempt: None,
            completed_attempt: None,
            retired: Vec::new(),
        };
        let mut candidates = Vec::new();
        let (candidate, backing) = self
            .store
            .stage_candidate(
                &scope,
                &supplied,
                &operation,
                &config_purpose(&state),
                String::from_utf8(encode(&config)?)
                    .map_err(|_| Status::internal("grant config encoding failed"))?,
            )
            .await?;
        candidates.push(candidate);
        state.definition.config_backing = backing;
        for (name, value) in material {
            let (candidate, backing) = self
                .store
                .stage_candidate(
                    &scope,
                    &supplied,
                    &operation,
                    &material_purpose(&state, &name),
                    value,
                )
                .await?;
            candidates.push(candidate);
            state.material.insert(name, backing);
        }
        let (candidate, fp) = self
            .store
            .stage_candidate(
                &scope,
                &supplied,
                &operation,
                &format!("request-fingerprint-v1:{key}"),
                fingerprint,
            )
            .await?;
        candidates.push(candidate);
        let response = wire::CreateGrantResponse {
            grant: state.definition.identity.id.clone(),
            output_references: state
                .definition
                .outputs
                .iter()
                .map(|(name, binding)| (name.clone(), binding.reference.clone()))
                .collect(),
        };
        let receipt = Receipt {
            operation: "create_grant".into(),
            owner: supplied,
            reference: response.grant.clone(),
            version: 1,
            fingerprint: fp,
            created_at_ms: now_ms()?,
            completed: true,
            response: response.encode_to_vec(),
            result_code: 0,
        };
        let (mutation, event) = self
            .store
            .repository
            .grants(&scope)
            .prepare(None, &state)
            .await?;
        let mut mutations = vec![mutation];
        let mut events = event.into_iter().collect::<Vec<_>>();
        let refs = self.store.repository.references(&scope);
        for (name, binding) in &state.definition.outputs {
            let (mutation, event) = refs
                .prepare(
                    &binding.reference,
                    None,
                    &ReferenceState::reserved(output_owner(&state, name)?),
                )
                .await?;
            mutations.push(mutation);
            events.extend(event);
            mutations.push(Mutation::Put {
                kind: OUTPUT_BINDING_KIND.into(),
                key: binding.reference.clone(),
                expected: None,
                payload: encode(&OutputOwner {
                    grant: response.grant.clone(),
                    authorization_epoch: state.definition.identity.authorization_epoch.clone(),
                })?,
            });
        }
        mutations.push(Mutation::Put {
            kind: IDEMPOTENCY_KIND.into(),
            key,
            expected: None,
            payload: encode(&receipt)?,
        });
        mutations.extend(candidates.into_iter().map(|key| Mutation::Delete {
            kind: CANDIDATE_KIND.into(),
            key,
            expected: 1,
        }));
        store.commit(&mutations, &events).await?;
        if events.iter().any(|event| event.kind == "grant") {
            crate::observability::grant_transition(&scope, &state);
        }
        Ok(response)
    }
    pub(super) async fn delete(
        self: Arc<Self>,
        scope: GatewayScope,
        id: String,
        key: String,
    ) -> Result<wire::DeleteGrantResponse, Status> {
        let store = self.store.repository.for_gateway(&scope);
        let _lease = store.acquire_refresh_lease(&format!("grant:{id}")).await?;
        let loaded = self.load(&scope, &id).await?;
        let mut state = loaded.state;
        let supplied = state.definition.identity.owner.clone();
        let fingerprint = hex_digest(&encode(&("delete-grant-v1", &state.definition.identity))?)?;
        if state.phase == GrantPhase::Detached {
            return Err(Status::failed_precondition(
                "detached outputs require static credential deletion",
            ));
        }
        if let Some(receipt) = self
            .store
            .replay(&scope, &key, "delete_grant", &supplied, &fingerprint)
            .await?
        {
            return receipt_result(&receipt);
        }
        let (candidate, fp) = self
            .store
            .stage_candidate(
                &scope,
                &supplied,
                &format!("grant:{id}"),
                &format!("request-fingerprint-v1:{key}"),
                fingerprint,
            )
            .await?;
        let mut mutations = self.binding_fences(&scope, &state).await?;
        let mut events = Vec::new();
        let refs = self.store.repository.references(&scope);
        if !matches!(state.phase, GrantPhase::Deleting | GrantPhase::Deleted) {
            for (name, binding) in &state.definition.outputs {
                let record = refs.load(&binding.reference).await?.ok_or_else(|| {
                    Status::failed_precondition("grant output reference is missing")
                })?;
                scope.authorize_bound_owner(
                    scope.identity(),
                    &record.state.owner,
                    &output_owner(&state, name)?,
                )?;
                if !record.state.revoked {
                    let mut revoked = record.state;
                    revoked.revoked = true;
                    revoked.version = revoked.version.checked_add(1).ok_or_else(|| {
                        Status::resource_exhausted("issuer value version exhausted")
                    })?;
                    if !revoked.backing.is_empty()
                        && !revoked.pending_deletions.contains(&revoked.backing)
                    {
                        revoked.pending_deletions.push(revoked.backing.clone());
                    }
                    let (mutation, event) = refs
                        .prepare(&binding.reference, Some(record.revision), &revoked)
                        .await?;
                    mutations.push(mutation);
                    events.extend(event);
                }
            }
            if let Some(attempt) = state.attempt.take() {
                for (name, backing) in attempt.output_candidates {
                    let owner = output_owner(&state, &name)?;
                    retire(&mut state, owner, VALUE_PURPOSE.into(), backing);
                }
                for (name, backing) in attempt.material_candidates {
                    let purpose = material_purpose(&state, &name);
                    retire(&mut state, supplied.clone(), purpose, backing);
                }
            }
            for (name, backing) in state.material.clone() {
                let purpose = material_purpose(&state, &name);
                retire(&mut state, supplied.clone(), purpose, backing);
            }
            let purpose = config_purpose(&state);
            let backing = state.definition.config_backing.clone();
            retire(&mut state, supplied.clone(), purpose, backing);
            state.phase = GrantPhase::Deleting;
            state.version = state
                .version
                .checked_add(1)
                .ok_or_else(|| Status::resource_exhausted("issuer grant version exhausted"))?;
        }
        let (mutation, event) = self
            .store
            .repository
            .grants(&scope)
            .prepare(Some(loaded.revision), &state)
            .await?;
        mutations.push(mutation);
        events.extend(event);
        let response = wire::DeleteGrantResponse {};
        let receipt = Receipt {
            operation: "delete_grant".into(),
            owner: supplied,
            reference: id,
            version: state.version,
            fingerprint: fp,
            created_at_ms: now_ms()?,
            completed: true,
            response: response.encode_to_vec(),
            result_code: 0,
        };
        mutations.push(Mutation::Put {
            kind: IDEMPOTENCY_KIND.into(),
            key,
            expected: None,
            payload: encode(&receipt)?,
        });
        mutations.push(Mutation::Delete {
            kind: CANDIDATE_KIND.into(),
            key: candidate,
            expected: 1,
        });
        store.commit(&mutations, &events).await?;
        if events.iter().any(|event| event.kind == "grant") {
            crate::observability::grant_transition(&scope, &state);
        }
        Ok(response)
    }
}
