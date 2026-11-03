// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{CredentialStoreService, MESSAGE_LIMIT, Runtime, idempotency, now_ms, valid_reference};
use crate::{
    auth::GatewayScope,
    mint_spool::MintResultSpool,
    minter::{MinterRegistry, RecoveryAction},
    repository::grants::{GrantPhase, GrantState, StoredGrant},
};
use openshell_core::proto::credentials::{minter::v1 as minter_wire, refresh::v1 as wire};
use std::{sync::Arc, time::Duration};
use tonic::{Request, Response, Status};

mod kernel;
mod maintenance;
mod operations;
mod watch;

#[derive(serde::Serialize, serde::Deserialize)]
struct OutputOwner {
    grant: String,
    authorization_epoch: String,
}
fn config_purpose(state: &GrantState) -> String {
    format!(
        "grant-config-v1:{}:{}",
        state.definition.identity.id, state.definition.identity.authorization_epoch
    )
}
fn material_purpose(state: &GrantState, name: &str) -> String {
    format!(
        "grant-material-v1:{}:{}:{name}",
        state.definition.identity.id, state.definition.identity.authorization_epoch
    )
}
fn receipt_result<M: prost::Message + Default>(receipt: &super::Receipt) -> Result<M, Status> {
    receipt.require_completed()?;
    M::decode(receipt.response.as_slice())
        .map_err(|_| Status::data_loss("invalid issuer operation result"))
}
fn duration_ms(duration: Duration) -> Result<i64, Status> {
    i64::try_from(duration.as_millis().saturating_add(u128::from(
        !duration.subsec_nanos().is_multiple_of(1_000_000),
    )))
    .map_err(|_| Status::invalid_argument("issuer duration exceeds limit"))
}

#[derive(Clone)]
pub struct CredentialRefreshService {
    runtime: Arc<GrantRuntime>,
}
impl std::fmt::Debug for CredentialRefreshService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialRefreshService(<redacted>)")
    }
}
struct GrantRuntime {
    store: Arc<Runtime>,
    minters: Arc<MinterRegistry>,
    spool: MintResultSpool,
}
impl CredentialRefreshService {
    pub fn new(
        store: &CredentialStoreService,
        minters: Arc<MinterRegistry>,
        spool: MintResultSpool,
    ) -> Result<Self, Status> {
        if minters.describe().count() > 64 {
            return Err(Status::invalid_argument(
                "issuer strategy catalog exceeds limit",
            ));
        }
        Ok(Self {
            runtime: Arc::new(GrantRuntime {
                store: store.runtime.clone(),
                minters,
                spool,
            }),
        })
    }
    pub fn into_service(self) -> wire::credential_refresh_server::CredentialRefreshServer<Self> {
        wire::credential_refresh_server::CredentialRefreshServer::new(self)
            .max_decoding_message_size(MESSAGE_LIMIT)
            .max_encoding_message_size(MESSAGE_LIMIT)
    }
    pub fn spawn_worker(&self, interval: Duration) -> Result<tokio::task::JoinHandle<()>, Status> {
        self.runtime.clone().spawn_worker(interval)
    }
}
fn grant_status(state: &GrantState) -> Result<wire::GrantStatus, Status> {
    let stamp = |value| {
        openshell_core::time::timestamp_from_millis(value)
            .map_err(|_| Status::data_loss("invalid issuer grant timestamp"))
    };
    let state_name = match state.phase {
        GrantPhase::Pending => "pending",
        GrantPhase::Refreshing | GrantPhase::Publishing => "refreshing",
        GrantPhase::Refreshed => "refreshed",
        GrantPhase::Failed => "failed",
        GrantPhase::Parked => "parked",
        GrantPhase::Deleting => "deleting",
        GrantPhase::Deleted => "deleted",
    };
    let action = match state.recovery_action {
        None => minter_wire::RecoveryAction::Unspecified,
        Some(RecoveryAction::Retry) => minter_wire::RecoveryAction::Retry,
        Some(RecoveryAction::FixConfiguration) => minter_wire::RecoveryAction::FixConfiguration,
        Some(RecoveryAction::Reauthorize) => minter_wire::RecoveryAction::Reauthorize,
        Some(RecoveryAction::Investigate) => minter_wire::RecoveryAction::Investigate,
    };
    Ok(wire::GrantStatus {
        grant: state.definition.identity.id.clone(),
        state: state_name.into(),
        expiration_time: state.expiration_time_ms.map(stamp).transpose()?,
        next_refresh_time: if state.next_refresh_at_ms > 0 && state.next_refresh_at_ms != i64::MAX {
            Some(stamp(state.next_refresh_at_ms)?)
        } else {
            None
        },
        failure_code: state.failure_code.clone(),
        recovery_action: action as i32,
        version: state.version,
    })
}
fn check_size<M: prost::Message>(request: &M) -> Result<(), Status> {
    if request.encoded_len() > MESSAGE_LIMIT {
        Err(Status::resource_exhausted("issuer request exceeds limit"))
    } else {
        Ok(())
    }
}
impl GrantRuntime {
    async fn load(&self, scope: &GatewayScope, id: &str) -> Result<StoredGrant, Status> {
        valid_reference(id)?;
        self.store
            .repository
            .grants(scope)
            .load(id)
            .await?
            .ok_or_else(|| Status::not_found("issuer grant not found"))
    }
    fn coordination_key(scope: &GatewayScope, id: &str) -> String {
        format!("{}:grant:{id}", scope.namespace())
    }
}
#[tonic::async_trait]
impl wire::credential_refresh_server::CredentialRefresh for CredentialRefreshService {
    async fn list_strategies(
        &self,
        request: Request<wire::ListStrategiesRequest>,
    ) -> Result<Response<wire::ListStrategiesResponse>, Status> {
        self.runtime.store.policy.authenticate(&request)?;
        let strategies = self
            .runtime
            .minters
            .describe()
            .map(|descriptor| {
                let field =
                    |field: &crate::minter::MaterialDescriptor| minter_wire::MaterialDescriptor {
                        name: field.name.clone(),
                        required: field.required,
                    };
                minter_wire::StrategyDescriptor {
                    name: descriptor.name.clone(),
                    config: descriptor.config.iter().map(field).collect(),
                    secret_material: descriptor.secret_material.iter().map(field).collect(),
                    outputs: descriptor.outputs.clone(),
                    rotated_secret_material: descriptor.rotated_secret_material.clone(),
                }
            })
            .collect();
        let result = wire::ListStrategiesResponse { strategies };
        check_size(&result)?;
        Ok(Response::new(result))
    }
    async fn create_grant(
        &self,
        request: Request<wire::CreateGrantRequest>,
    ) -> Result<Response<wire::CreateGrantResponse>, Status> {
        let scope = self.runtime.store.policy.authenticate(&request)?;
        let request = request.into_inner();
        check_size(&request)?;
        let key = idempotency(&request.idempotency_key)?;
        let runtime = self.runtime.clone();
        let coordination = format!("{}:secret-operation:{key}", scope.namespace());
        let result = self
            .runtime
            .store
            .coordinator
            .run(
                &coordination,
                Box::pin(async move { runtime.create(scope, request, key).await }),
            )
            .await?;
        Ok(Response::new(result))
    }
    async fn get_grant(
        &self,
        request: Request<wire::GetGrantRequest>,
    ) -> Result<Response<wire::GetGrantResponse>, Status> {
        let scope = self.runtime.store.policy.authenticate(&request)?;
        let request = request.into_inner();
        check_size(&request)?;
        let grant = self.runtime.load(&scope, &request.grant).await?;
        Ok(Response::new(wire::GetGrantResponse {
            status: Some(grant_status(&grant.state)?),
        }))
    }
    async fn delete_grant(
        &self,
        request: Request<wire::DeleteGrantRequest>,
    ) -> Result<Response<wire::DeleteGrantResponse>, Status> {
        let scope = self.runtime.store.policy.authenticate(&request)?;
        let request = request.into_inner();
        check_size(&request)?;
        valid_reference(&request.grant)?;
        let key = idempotency(&request.idempotency_key)?;
        let coordination = GrantRuntime::coordination_key(&scope, &request.grant);
        let runtime = self.runtime.clone();
        let result = self
            .runtime
            .store
            .coordinator
            .run(
                &coordination,
                Box::pin(async move { runtime.delete(scope, request.grant, key).await }),
            )
            .await?;
        Ok(Response::new(result))
    }
    async fn rotate_grant(
        &self,
        request: Request<wire::RotateGrantRequest>,
    ) -> Result<Response<wire::RotateGrantResponse>, Status> {
        let scope = self.runtime.store.policy.authenticate(&request)?;
        let request = request.into_inner();
        check_size(&request)?;
        let key = idempotency(&request.idempotency_key)?;
        let result = self.runtime.rotate(scope, request.grant, key).await?;
        Ok(Response::new(result))
    }
    async fn ensure_fresh(
        &self,
        request: Request<wire::EnsureFreshRequest>,
    ) -> Result<Response<wire::EnsureFreshResponse>, Status> {
        let scope = self.runtime.store.policy.authenticate(&request)?;
        let request = request.into_inner();
        check_size(&request)?;
        let remaining = request
            .min_remaining
            .as_ref()
            .map(openshell_core::time::duration_to_std)
            .transpose()
            .map_err(|_| Status::invalid_argument("invalid minimum remaining duration"))?
            .unwrap_or_default();
        let remaining = duration_ms(remaining)?;
        let status = self.runtime.ensure(scope, request.grant, remaining).await?;
        Ok(Response::new(wire::EnsureFreshResponse {
            status: Some(status),
        }))
    }
    type WatchGrantsStream =
        tokio_stream::wrappers::ReceiverStream<Result<wire::WatchGrantsResponse, Status>>;
    async fn watch_grants(
        &self,
        request: Request<wire::WatchGrantsRequest>,
    ) -> Result<Response<Self::WatchGrantsStream>, Status> {
        let scope = self.runtime.store.policy.authenticate(&request)?;
        let request = request.into_inner();
        check_size(&request)?;
        Ok(Response::new(
            self.runtime
                .clone()
                .watch_grants(scope, request.after_sequence)
                .await?,
        ))
    }
}

#[cfg(test)]
mod tests;
