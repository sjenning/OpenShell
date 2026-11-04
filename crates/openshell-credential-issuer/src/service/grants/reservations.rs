// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Value-free grant identities followed by one-shot encrypted initialization.
use super::super::{
    CANDIDATE_KIND, IDEMPOTENCY_KIND, Receipt, decode, encode, hex_digest, now_ms, owner,
};
use super::operations::{output_owner, parsed_duration, validate_inputs};
use super::{
    GrantPhase, GrantRuntime, GrantState, OutputOwner, config_purpose, duration_ms, grant_status,
    material_purpose, wire,
};
use crate::{
    ReferenceState,
    auth::GatewayScope,
    grant::GrantIdentity,
    repository::{
        Mutation,
        grants::{GrantDefinition, OUTPUT_BINDING_KIND, OutputBinding},
    },
};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use tonic::Status;
#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct Intent {
    strategy: String,
    outputs: BTreeMap<String, String>,
    refresh_before_ms: i64,
    lifetime_seconds: i64,
}
#[derive(Serialize, Deserialize)]
struct Reserved {
    intent: Intent,
    grant: String,
    outputs: BTreeMap<String, String>,
}
impl Reserved {
    fn response(&self) -> wire::ReserveGrantResponse {
        wire::ReserveGrantResponse {
            grant: self.grant.clone(),
            output_references: self.outputs.clone().into_iter().collect(),
        }
    }
}
impl GrantRuntime {
    pub(super) async fn reserve(
        self: Arc<Self>,
        scope: GatewayScope,
        request: wire::ReserveGrantRequest,
        key: String,
    ) -> Result<wire::ReserveGrantResponse, Status> {
        let supplied = owner(request.owner.as_ref())?;
        scope.authorize_owner(&supplied)?;
        let refresh_before_ms = duration_ms(parsed_duration(
            request.refresh_before.as_ref(),
            Duration::from_mins(5),
        )?)?;
        let lifetime = parsed_duration(request.max_lifetime.as_ref(), Duration::from_hours(1))?;
        if lifetime.is_zero() || lifetime > Duration::from_hours(12) {
            return Err(Status::invalid_argument(
                "grant lifetime must be positive and at most twelve hours",
            ));
        }
        let lifetime_seconds = i64::try_from(
            lifetime
                .as_secs()
                .saturating_add(u64::from(lifetime.subsec_nanos() != 0)),
        )
        .map_err(|_| Status::invalid_argument("grant lifetime exceeds limit"))?;
        let intent = Intent {
            strategy: request.strategy,
            outputs: request.outputs.into_iter().collect(),
            refresh_before_ms,
            lifetime_seconds,
        };
        let store = self.store.repository.for_gateway(&scope);
        let _lease = store
            .acquire_refresh_lease(&format!("secret-operation:{key}"))
            .await?;
        if let Some(record) = store.load(IDEMPOTENCY_KIND, &key).await? {
            let receipt: Receipt = decode(&record.payload)?;
            if receipt.operation != "reserve_grant" || receipt.owner != supplied {
                return Err(Status::already_exists(
                    "issuer operation key is already bound",
                ));
            }
            receipt.require_completed()?;
            if !receipt.fingerprint.is_empty() || receipt.version != 1 {
                return Err(Status::data_loss("invalid grant reservation receipt"));
            }
            let reserved: Reserved = decode(&receipt.response)?;
            if reserved.intent != intent {
                return Err(Status::already_exists(
                    "issuer operation key is already bound",
                ));
            }
            if reserved.grant != receipt.reference {
                return Err(Status::data_loss("invalid grant reservation receipt"));
            }
            if reserved.outputs.keys().ne(intent.outputs.keys())
                || reserved.outputs.values().collect::<BTreeSet<_>>().len() != intent.outputs.len()
                || std::iter::once(&reserved.grant)
                    .chain(reserved.outputs.values())
                    .any(|id| super::valid_reference(id).is_err())
            {
                return Err(Status::data_loss("invalid grant reservation receipt"));
            }
            return Ok(reserved.response());
        }
        let descriptor = self
            .minters
            .describe()
            .find(|descriptor| descriptor.name == intent.strategy)
            .cloned()
            .ok_or_else(|| Status::invalid_argument("issuer strategy is not registered"))?;
        if descriptor.outputs.iter().collect::<BTreeSet<_>>()
            != intent.outputs.keys().collect::<BTreeSet<_>>()
            || intent.outputs.values().any(|key| {
                key.is_empty()
                    || key.len() > 256
                    || key.trim() != key
                    || key.chars().any(char::is_control)
            })
            || intent.outputs.values().collect::<BTreeSet<_>>().len() != intent.outputs.len()
        {
            return Err(Status::invalid_argument(
                "grant outputs must bind every semantic output to a distinct credential key",
            ));
        }
        let state = GrantState {
            format_version: 1,
            definition: GrantDefinition {
                identity: GrantIdentity {
                    id: uuid::Uuid::new_v4().to_string(),
                    authorization_epoch: uuid::Uuid::new_v4().to_string(),
                    owner: supplied.clone(),
                },
                descriptor,
                config_backing: Vec::new(),
                outputs: intent
                    .outputs
                    .iter()
                    .map(|(name, key)| {
                        (
                            name.clone(),
                            OutputBinding {
                                credential_key: key.clone(),
                                reference: uuid::Uuid::new_v4().to_string(),
                            },
                        )
                    })
                    .collect(),
                refresh_before_ms,
                max_lifetime_seconds: lifetime_seconds,
            },
            material: BTreeMap::new(),
            version: 1,
            phase: GrantPhase::Reserved,
            expiration_time_ms: None,
            next_refresh_at_ms: i64::MAX,
            recovery_action: None,
            failure_code: String::new(),
            last_refresh_time_ms: None,
            last_error_time_ms: None,
            provider_error_subtype: String::new(),
            attempt: None,
            completed_attempt: None,
            retired: Vec::new(),
        };
        let reserved = Reserved {
            grant: state.definition.identity.id.clone(),
            outputs: state
                .definition
                .outputs
                .iter()
                .map(|(name, binding)| (name.clone(), binding.reference.clone()))
                .collect(),
            intent,
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
                    grant: reserved.grant.clone(),
                    authorization_epoch: state.definition.identity.authorization_epoch.clone(),
                })?,
            });
        }
        let receipt = Receipt {
            operation: "reserve_grant".into(),
            owner: supplied,
            reference: reserved.grant.clone(),
            version: 1,
            fingerprint: Vec::new(),
            created_at_ms: now_ms()?,
            completed: true,
            response: encode(&reserved)?,
            result_code: 0,
        };
        mutations.push(Mutation::Put {
            kind: IDEMPOTENCY_KIND.into(),
            key,
            expected: None,
            payload: encode(&receipt)?,
        });
        store.commit(&mutations, &events).await?;
        if events.iter().any(|event| event.kind == "grant") {
            crate::observability::grant_transition(&scope, &state);
        }
        Ok(reserved.response())
    }
    pub(super) async fn initialize(
        self: Arc<Self>,
        scope: GatewayScope,
        request: wire::InitializeGrantRequest,
        key: String,
    ) -> Result<wire::InitializeGrantResponse, Status> {
        let store = self.store.repository.for_gateway(&scope);
        let _operation = store
            .acquire_refresh_lease(&format!("secret-operation:{key}"))
            .await?;
        let operation = format!("grant:{}", request.grant);
        let _lease = store.acquire_refresh_lease(&operation).await?;
        let loaded = self.load(&scope, &request.grant).await?;
        let mut state = loaded.state;
        let supplied = state.definition.identity.owner.clone();
        let mut config = request.config.into_iter().collect::<BTreeMap<_, _>>();
        let material = request
            .secret_material
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        if !state.definition.descriptor.name.starts_with("custom:") {
            let seconds = state.definition.max_lifetime_seconds.to_string();
            if config
                .get("max_lifetime_seconds")
                .is_some_and(|value| value != &seconds)
            {
                return Err(Status::invalid_argument(
                    "set builtin lifetime through max_lifetime",
                ));
            }
            config.insert("max_lifetime_seconds".into(), seconds);
        }
        let fingerprint = hex_digest(&encode(&(
            "initialize-grant-v1",
            &state.definition.identity,
            &config,
            &material,
        ))?)?;
        if let Some(receipt) = self
            .store
            .replay(&scope, &key, "initialize_grant", &supplied, &fingerprint)
            .await?
        {
            return super::receipt_result(&receipt);
        }
        if state.phase != GrantPhase::Reserved {
            return Err(Status::failed_precondition(
                "issuer grant is not awaiting initialization",
            ));
        }
        if self
            .minters
            .describe()
            .find(|descriptor| descriptor.name == state.definition.descriptor.name)
            != Some(&state.definition.descriptor)
        {
            return Err(Status::failed_precondition(
                "reserved issuer strategy descriptor changed",
            ));
        }
        validate_inputs(&state.definition.descriptor.config, &config)?;
        validate_inputs(&state.definition.descriptor.secret_material, &material)?;
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
        let (candidate, fingerprint) = self
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
        state.phase = GrantPhase::Pending;
        state.next_refresh_at_ms = 0;
        state.version = state
            .version
            .checked_add(1)
            .ok_or_else(|| Status::resource_exhausted("issuer grant version exhausted"))?;
        let response = wire::InitializeGrantResponse {
            status: Some(grant_status(&state)?),
        };
        let receipt = Receipt {
            operation: "initialize_grant".into(),
            owner: supplied,
            reference: request.grant,
            version: state.version,
            fingerprint,
            created_at_ms: now_ms()?,
            completed: true,
            response: response.encode_to_vec(),
            result_code: 0,
        };
        let mut mutations = self.binding_fences(&scope, &state).await?;
        let (mutation, event) = self
            .store
            .repository
            .grants(&scope)
            .prepare(Some(loaded.revision), &state)
            .await?;
        mutations.push(mutation);
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
        store
            .commit(&mutations, &event.into_iter().collect::<Vec<_>>())
            .await?;
        crate::observability::grant_transition(&scope, &state);
        Ok(response)
    }
}
