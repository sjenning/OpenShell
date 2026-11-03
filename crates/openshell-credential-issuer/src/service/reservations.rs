// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Value-free allocation lets a gateway journal reference ownership before
//! transmitting values. An uncertain conditional fill can then be revoked
//! through the known identity, without persisting provider values in a gateway.
use super::{
    IDEMPOTENCY_KIND, Receipt, Runtime, decode, encode, now_ms, owner, valid_reference, wire,
};
use crate::{ReferenceState, auth::GatewayScope, repository::Mutation};
use std::sync::Arc;
use tonic::Status;
impl Runtime {
    pub(super) async fn reserve(
        self: Arc<Self>,
        scope: GatewayScope,
        request: wire::ReserveSecretRequest,
        key: String,
    ) -> Result<wire::ReserveSecretResponse, Status> {
        let supplied = owner(request.owner.as_ref())?;
        scope.authorize_owner(&supplied)?;
        let store = self.repository.for_gateway(&scope);
        let _lease = store
            .acquire_refresh_lease(&format!("secret-operation:{key}"))
            .await?;
        if let Some(record) = store.load(IDEMPOTENCY_KIND, &key).await? {
            let receipt: Receipt = decode(&record.payload)?;
            if receipt.operation != "reserve" || receipt.owner != supplied {
                return Err(Status::already_exists(
                    "issuer idempotency key belongs to different intent",
                ));
            }
            receipt.require_completed()?;
            if receipt.version != 1
                || !receipt.fingerprint.is_empty()
                || valid_reference(&receipt.reference).is_err()
            {
                return Err(Status::data_loss("invalid issuer reservation receipt"));
            }
            // No secret-dependent fingerprint: every request field affecting
            // this value-free operation is checked as immutable owner metadata.
            return Ok(wire::ReserveSecretResponse {
                reference: receipt.reference,
                version: receipt.version,
            });
        }
        let reference = uuid::Uuid::new_v4().to_string();
        let state = ReferenceState::reserved(supplied.clone());
        let (mutation, event) = self
            .repository
            .references(&scope)
            .prepare(&reference, None, &state)
            .await?;
        let receipt = Receipt {
            operation: "reserve".into(),
            owner: supplied,
            reference: reference.clone(),
            version: state.version,
            fingerprint: Vec::new(),
            created_at_ms: now_ms()?,
            completed: true,
            response: Vec::new(),
            result_code: 0,
        };
        store
            .commit(
                &[
                    mutation,
                    Mutation::Put {
                        kind: IDEMPOTENCY_KIND.into(),
                        key,
                        expected: None,
                        payload: encode(&receipt)?,
                    },
                ],
                &event.into_iter().collect::<Vec<_>>(),
            )
            .await?;
        tracing::info!(
            gateway = scope.identity(),
            operation = "reserve",
            version = state.version,
            "issuer credential reservation committed"
        );
        Ok(wire::ReserveSecretResponse {
            reference,
            version: state.version,
        })
    }
}
