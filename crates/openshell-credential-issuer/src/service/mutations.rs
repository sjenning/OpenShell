// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{
    CANDIDATE_KIND, Candidate, IDEMPOTENCY_KIND, Receipt, Runtime, VALUE_PURPOSE, decode, encode,
    hex_digest, now_ms, owner, valid_reference, wire,
};
use crate::{
    ReferenceState, ReferenceStateStore, SecretOwner,
    auth::GatewayScope,
    repository::{Mutation, ScopedRepository},
};
use std::sync::Arc;
use tonic::Status;

impl Runtime {
    async fn replay(
        &self,
        scope: &GatewayScope,
        key: &str,
        operation: &str,
        supplied: &SecretOwner,
        fingerprint: &str,
    ) -> Result<Option<Receipt>, Status> {
        let Some(record) = self
            .repository
            .for_gateway(scope)
            .load(IDEMPOTENCY_KIND, key)
            .await?
        else {
            return Ok(None);
        };
        let receipt: Receipt = decode(&record.payload)?;
        if receipt.operation != operation || receipt.owner != *supplied {
            return Err(Status::already_exists(
                "issuer idempotency key belongs to different intent",
            ));
        }
        scope.authorize_owner(&receipt.owner)?;
        let stored = self
            .storage
            .resolve(
                scope,
                &receipt.owner,
                &format!("request-fingerprint-v1:{key}"),
                &receipt.fingerprint,
            )
            .await?;
        if stored.value != fingerprint {
            return Err(Status::already_exists(
                "issuer idempotency key belongs to different intent",
            ));
        }
        Ok(Some(receipt))
    }
    async fn stage_candidate(
        &self,
        scope: &GatewayScope,
        owner: &SecretOwner,
        operation_key: &str,
        purpose: &str,
        value: String,
    ) -> Result<(String, Vec<u8>), Status> {
        let backing = self.storage.stage(scope, owner, purpose, value).await?;
        let key = uuid::Uuid::new_v4().to_string();
        let candidate = Candidate {
            operation_key: operation_key.to_string(),
            owner: owner.clone(),
            purpose: purpose.to_string(),
            backing: backing.clone(),
        };
        // If journaling is uncertain, retain the physical candidate. Never
        // delete it based only on a transport/database error.
        self.repository
            .for_gateway(scope)
            .commit(
                &[Mutation::Put {
                    kind: CANDIDATE_KIND.to_string(),
                    key: key.clone(),
                    expected: None,
                    payload: encode(&candidate)?,
                }],
                &[],
            )
            .await?;
        Ok((key, backing))
    }
    async fn check_static(&self, store: &ScopedRepository, reference: &str) -> Result<(), Status> {
        if store
            .load("reference-grant-binding-v1", reference)
            .await?
            .is_some()
        {
            return Err(Status::failed_precondition(
                "issuer reference is managed by a refresh grant",
            ));
        }
        Ok(())
    }
    pub(super) async fn put(
        self: Arc<Self>,
        scope: GatewayScope,
        request: wire::PutSecretRequest,
        key: String,
    ) -> Result<wire::PutSecretResponse, Status> {
        let supplied = owner(request.owner.as_ref())?;
        let expiration = request
            .expiration_time
            .as_ref()
            .map(openshell_core::time::timestamp_to_millis)
            .transpose()
            .map_err(|_| Status::invalid_argument("invalid issuer expiration"))?;
        if request.expected_version == Some(0)
            || (request.reference.is_empty() && request.expected_version.is_some())
        {
            return Err(Status::invalid_argument(
                "invalid expected credential version",
            ));
        }
        let fingerprint = hex_digest(&encode(&(
            "put-v1",
            &supplied,
            &request.reference,
            &request.value,
            expiration,
            request.expected_version,
        ))?)?;
        let store = self.repository.for_gateway(&scope);
        let operation_key = format!("secret-operation:{key}");
        let _lease = store.acquire_refresh_lease(&operation_key).await?;
        if let Some(receipt) = self
            .replay(&scope, &key, "put", &supplied, &fingerprint)
            .await?
        {
            return Ok(wire::PutSecretResponse {
                reference: receipt.reference,
                version: receipt.version,
            });
        }
        let refs = self.repository.references(&scope);
        let reference = if request.reference.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            valid_reference(&request.reference)?;
            request.reference.clone()
        };
        self.check_static(&store, &reference).await?;
        let old = refs.load(&reference).await?;
        if !request.reference.is_empty() && old.is_none() {
            return Err(Status::not_found("issuer credential reference not found"));
        }
        if let Some(old) = &old {
            scope.authorize_bound_owner(scope.identity(), &old.state.owner, &supplied)?;
            if old.state.revoked {
                return Err(Status::not_found("issuer credential reference is revoked"));
            }
            if request
                .expected_version
                .is_some_and(|version| version != old.state.version)
            {
                return Err(Status::aborted("issuer credential version changed"));
            }
        }
        let (fp_candidate, fp_backing) = self
            .stage_candidate(
                &scope,
                &supplied,
                &operation_key,
                &format!("request-fingerprint-v1:{key}"),
                fingerprint,
            )
            .await?;
        let (value_candidate, backing) = self
            .stage_candidate(
                &scope,
                &supplied,
                &operation_key,
                VALUE_PURPOSE,
                request.value,
            )
            .await?;
        let mut state = if let Some(old) = &old {
            let mut state = old.state.clone();
            state.version = state
                .version
                .checked_add(1)
                .ok_or_else(|| Status::resource_exhausted("issuer credential version exhausted"))?;
            if !state.pending_deletions.contains(&state.backing) {
                state.pending_deletions.push(state.backing.clone());
            }
            state.backing = backing;
            state
        } else {
            ReferenceState {
                owner: supplied.clone(),
                version: 1,
                backing,
                expiration_time_ms: None,
                revoked: false,
                pending_deletions: Vec::new(),
            }
        };
        state.expiration_time_ms = expiration;
        let (mutation, event) = refs
            .prepare(&reference, old.as_ref().map(|old| old.revision), &state)
            .await?;
        let receipt = Receipt {
            operation: "put".to_string(),
            owner: supplied,
            reference: reference.clone(),
            version: state.version,
            fingerprint: fp_backing,
            created_at_ms: now_ms()?,
        };
        let mutations = [
            mutation,
            Mutation::Put {
                kind: IDEMPOTENCY_KIND.to_string(),
                key,
                expected: None,
                payload: encode(&receipt)?,
            },
            Mutation::Delete {
                kind: CANDIDATE_KIND.to_string(),
                key: fp_candidate,
                expected: 1,
            },
            Mutation::Delete {
                kind: CANDIDATE_KIND.to_string(),
                key: value_candidate,
                expected: 1,
            },
        ];
        store
            .commit(&mutations, &event.into_iter().collect::<Vec<_>>())
            .await?;
        tracing::info!(
            gateway = scope.identity(),
            operation = "put",
            version = state.version,
            "issuer credential mutation committed"
        );
        Ok(wire::PutSecretResponse {
            reference,
            version: state.version,
        })
    }
    pub(super) async fn delete(
        self: Arc<Self>,
        scope: GatewayScope,
        request: wire::DeleteSecretRequest,
        key: String,
    ) -> Result<wire::DeleteSecretResponse, Status> {
        valid_reference(&request.reference)?;
        let supplied = owner(request.owner.as_ref())?;
        if request.expected_version == Some(0) {
            return Err(Status::invalid_argument(
                "invalid expected credential version",
            ));
        }
        let fingerprint = hex_digest(&encode(&(
            "delete-v1",
            &supplied,
            &request.reference,
            request.expected_version,
        ))?)?;
        let store = self.repository.for_gateway(&scope);
        let operation_key = format!("secret-operation:{key}");
        let _lease = store.acquire_refresh_lease(&operation_key).await?;
        if let Some(receipt) = self
            .replay(&scope, &key, "delete", &supplied, &fingerprint)
            .await?
        {
            return Ok(wire::DeleteSecretResponse {
                version: receipt.version,
            });
        }
        self.check_static(&store, &request.reference).await?;
        let refs = self.repository.references(&scope);
        let old = refs
            .load(&request.reference)
            .await?
            .ok_or_else(|| Status::not_found("issuer credential reference not found"))?;
        scope.authorize_bound_owner(scope.identity(), &old.state.owner, &supplied)?;
        if request
            .expected_version
            .is_some_and(|version| version != old.state.version)
        {
            return Err(Status::aborted("issuer credential version changed"));
        }
        let (candidate, backing) = self
            .stage_candidate(
                &scope,
                &supplied,
                &operation_key,
                &format!("request-fingerprint-v1:{key}"),
                fingerprint,
            )
            .await?;
        let mut state = old.state;
        let mut mutations = Vec::new();
        let mut events = Vec::new();
        if !state.revoked {
            state.version = state
                .version
                .checked_add(1)
                .ok_or_else(|| Status::resource_exhausted("issuer credential version exhausted"))?;
            state.revoked = true;
            if !state.pending_deletions.contains(&state.backing) {
                state.pending_deletions.push(state.backing.clone());
            }
        }
        // Fence even an already-deleted reference in the receipt transaction.
        let (mutation, event) = refs
            .prepare(&request.reference, Some(old.revision), &state)
            .await?;
        mutations.push(mutation);
        events.extend(event);
        let receipt = Receipt {
            operation: "delete".to_string(),
            owner: supplied,
            reference: request.reference,
            version: state.version,
            fingerprint: backing,
            created_at_ms: now_ms()?,
        };
        mutations.push(Mutation::Put {
            kind: IDEMPOTENCY_KIND.to_string(),
            key,
            expected: None,
            payload: encode(&receipt)?,
        });
        mutations.push(Mutation::Delete {
            kind: CANDIDATE_KIND.to_string(),
            key: candidate,
            expected: 1,
        });
        store.commit(&mutations, &events).await?;
        tracing::info!(
            gateway = scope.identity(),
            operation = "delete",
            version = state.version,
            "issuer credential mutation committed"
        );
        Ok(wire::DeleteSecretResponse {
            version: state.version,
        })
    }
}
