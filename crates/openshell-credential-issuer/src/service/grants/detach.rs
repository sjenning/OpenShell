// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Value-free, lease-fenced transfer of a complete published bundle to static ownership.
use super::super::{CANDIDATE_KIND, IDEMPOTENCY_KIND, Receipt, VALUE_PURPOSE, encode, hex_digest};
use super::operations::{output_owner, retire};
use super::{GrantRuntime, config_purpose, material_purpose, now_ms, receipt_result, wire};
use crate::{
    ReferenceStateStore,
    auth::GatewayScope,
    repository::{
        Mutation,
        grants::{GrantPhase, OUTPUT_BINDING_KIND},
    },
};
use prost::Message as _;
use std::sync::Arc;
use tonic::Status;

impl GrantRuntime {
    pub(super) async fn detach(
        self: Arc<Self>,
        scope: GatewayScope,
        id: String,
        key: String,
    ) -> Result<wire::DetachGrantResponse, Status> {
        let store = self.store.repository.for_gateway(&scope);
        let _lease = store.acquire_refresh_lease(&format!("grant:{id}")).await?;
        let loaded = self.load(&scope, &id).await?;
        let mut state = loaded.state;
        let supplied = state.definition.identity.owner.clone();
        let fingerprint = hex_digest(&encode(&("detach-grant-v1", &state.definition.identity))?)?;
        if let Some(receipt) = self
            .store
            .replay(&scope, &key, "detach_grant", &supplied, &fingerprint)
            .await?
        {
            return receipt_result(&receipt);
        }
        let mut mutations = Vec::new();
        let mut events = Vec::new();
        if state.phase != GrantPhase::Detached {
            if matches!(
                state.phase,
                GrantPhase::Reserved | GrantPhase::Deleting | GrantPhase::Deleted
            ) {
                return Err(Status::failed_precondition(
                    "grant has no detachable published output bundle",
                ));
            }
            let refs = self.store.repository.references(&scope);
            // The same lease excludes every mint publication and deletion. Check
            // reference revisions too: transfer must never resurrect revoked or
            // pending outputs, extend token expiry, or read backend secret values.
            for (name, binding) in &state.definition.outputs {
                let record = refs.load(&binding.reference).await?.ok_or_else(|| {
                    Status::failed_precondition("grant output reference is missing")
                })?;
                scope.authorize_bound_owner(
                    scope.identity(),
                    &record.state.owner,
                    &output_owner(&state, name)?,
                )?;
                if record.state.revoked
                    || record.state.pending_value
                    || record.state.backing.is_empty()
                {
                    return Err(Status::failed_precondition(
                        "grant outputs must have published values before detaching",
                    ));
                }
                mutations.push(Mutation::Check {
                    kind: crate::repository::references::KIND.into(),
                    key: binding.reference.clone(),
                    expected: record.revision,
                });
            }
            for fence in self.binding_fences(&scope, &state).await? {
                let Mutation::Check {
                    kind,
                    key,
                    expected,
                } = fence
                else {
                    return Err(Status::internal("invalid grant ownership fence"));
                };
                if kind != OUTPUT_BINDING_KIND {
                    return Err(Status::internal("invalid grant ownership fence"));
                }
                mutations.push(Mutation::Delete {
                    kind,
                    key,
                    expected,
                });
            }
            // Abandon only unpublished candidates. Current reference backings
            // stay owned by their unchanged reference records, never by cleanup.
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
            state.phase = GrantPhase::Detached;
            state.version = state
                .version
                .checked_add(1)
                .ok_or_else(|| Status::resource_exhausted("issuer grant version exhausted"))?;
            state.next_refresh_at_ms = i64::MAX;
            state.recovery_action = None;
            state.failure_code.clear();
            let (mutation, event) = self
                .store
                .repository
                .grants(&scope)
                .prepare(Some(loaded.revision), &state)
                .await?;
            mutations.push(mutation);
            events.extend(event);
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
        let response = wire::DetachGrantResponse {};
        let receipt = Receipt {
            operation: "detach_grant".into(),
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
        Ok(response)
    }
}
