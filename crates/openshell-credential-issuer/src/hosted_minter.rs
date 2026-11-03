// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authenticated, bounded host adapter for one stateless custom minter.

use crate::{
    auth::IssuerPolicy,
    minter::{
        MintFailure, MintRequest, MinterRegistry, RecoveryAction, RetrySchedule,
        StrategyDescriptor, TokenMinter,
    },
};
use openshell_core::proto::credentials::minter::v1 as wire;
use prost::Message as _;
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tonic::{Code, Request, Response, Status};

const MESSAGE_LIMIT: usize = 1024 * 1024;

#[derive(Clone)]
pub struct HostedMinter {
    registry: Arc<MinterRegistry>,
    descriptor: StrategyDescriptor,
    policy: IssuerPolicy,
    slots: Arc<Semaphore>,
}
impl std::fmt::Debug for HostedMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedMinter")
            .field("strategy", &self.descriptor.name)
            .finish_non_exhaustive()
    }
}
impl HostedMinter {
    pub fn new(
        minter: Arc<dyn TokenMinter>,
        policy: IssuerPolicy,
        concurrency: usize,
    ) -> Result<Self, Status> {
        if concurrency == 0 || concurrency > 64 {
            return Err(Status::invalid_argument(
                "minter concurrency must be between 1 and 64",
            ));
        }
        let mut registry = MinterRegistry::default();
        registry.register_custom(minter)?;
        let descriptor = registry
            .describe()
            .next()
            .expect("registered one minter")
            .clone();
        if descriptor.config.len() + descriptor.secret_material.len() > 128
            || descriptor.outputs.len() > 64
            || descriptor.rotated_secret_material.len() > 128
        {
            return Err(Status::invalid_argument(
                "minter descriptor exceeds protocol limits",
            ));
        }
        Ok(Self {
            registry: Arc::new(registry),
            descriptor,
            policy,
            slots: Arc::new(Semaphore::new(concurrency)),
        })
    }
    /// Serve over a mandatory-client-auth listener. Authorization never falls
    /// back to headers or a supplied issuer identity.
    pub fn into_service(self) -> wire::token_minter_server::TokenMinterServer<Self> {
        wire::token_minter_server::TokenMinterServer::new(self)
            .max_decoding_message_size(MESSAGE_LIMIT)
            .max_encoding_message_size(MESSAGE_LIMIT)
    }
}

fn classified(code: Code, action: wire::RecoveryAction, schedule: wire::RetrySchedule) -> Status {
    let (message, failure_code) = match action {
        wire::RecoveryAction::Retry => ("minter temporarily unavailable", "minter_retry"),
        wire::RecoveryAction::FixConfiguration => (
            "minter configuration requires correction",
            "minter_configuration",
        ),
        wire::RecoveryAction::Reauthorize => {
            ("minter requires reauthorization", "minter_reauthorize")
        }
        _ => (
            "minter outcome is uncertain; investigate the attempt",
            "minter_outcome_unknown",
        ),
    };
    Status::with_details(
        code,
        message,
        wire::MintFailureDetail {
            recovery_action: action as i32,
            retry_schedule: schedule as i32,
            failure_code: failure_code.to_string(),
            provider_error_subtype: String::new(),
        }
        .encode_to_vec()
        .into(),
    )
}
fn unknown() -> Status {
    classified(
        Code::FailedPrecondition,
        wire::RecoveryAction::Investigate,
        wire::RetrySchedule::Parked,
    )
}
fn configuration() -> Status {
    classified(
        Code::InvalidArgument,
        wire::RecoveryAction::FixConfiguration,
        wire::RetrySchedule::Configuration,
    )
}
fn failure_status(failure: MintFailure) -> Status {
    // Do not reflect arbitrary plugin/upstream diagnostics, including nominally
    // static strings, status details, codes, or provider error subtypes.
    match (
        failure.status.code(),
        failure.recovery_action,
        failure.retry_schedule,
    ) {
        (
            code @ (Code::Unavailable | Code::ResourceExhausted),
            RecoveryAction::Retry,
            RetrySchedule::Short,
        ) => classified(
            code,
            wire::RecoveryAction::Retry,
            wire::RetrySchedule::Short,
        ),
        (
            code @ (Code::InvalidArgument | Code::FailedPrecondition),
            RecoveryAction::FixConfiguration,
            RetrySchedule::Configuration,
        ) => classified(
            code,
            wire::RecoveryAction::FixConfiguration,
            wire::RetrySchedule::Configuration,
        ),
        (Code::FailedPrecondition, RecoveryAction::Reauthorize, RetrySchedule::Parked) => {
            classified(
                Code::FailedPrecondition,
                wire::RecoveryAction::Reauthorize,
                wire::RetrySchedule::Parked,
            )
        }
        _ => unknown(),
    }
}

#[tonic::async_trait]
impl wire::token_minter_server::TokenMinter for HostedMinter {
    async fn describe(
        &self,
        request: Request<wire::DescribeRequest>,
    ) -> Result<Response<wire::DescribeResponse>, Status> {
        self.policy.authenticate(&request)?;
        let field = |field: &crate::minter::MaterialDescriptor| wire::MaterialDescriptor {
            name: field.name.clone(),
            required: field.required,
        };
        Ok(Response::new(wire::DescribeResponse {
            strategies: vec![wire::StrategyDescriptor {
                name: self.descriptor.name.clone(),
                config: self.descriptor.config.iter().map(field).collect(),
                secret_material: self.descriptor.secret_material.iter().map(field).collect(),
                outputs: self.descriptor.outputs.clone(),
                rotated_secret_material: self.descriptor.rotated_secret_material.clone(),
            }],
        }))
    }
    async fn mint(
        &self,
        request: Request<wire::MintRequest>,
    ) -> Result<Response<wire::MintResponse>, Status> {
        self.policy.authenticate(&request)?;
        let request = request.into_inner();
        if request.encoded_len() > MESSAGE_LIMIT
            || request.strategy != self.descriptor.name
            || request.attempt_id.trim().is_empty()
            || request.attempt_id.len() > 128
            || request.attempt_id.chars().any(char::is_control)
            || request.config.keys().any(|key| {
                !self
                    .descriptor
                    .config
                    .iter()
                    .any(|field| field.name == *key)
            })
            || request.secret_material.keys().any(|key| {
                !self
                    .descriptor
                    .secret_material
                    .iter()
                    .any(|field| field.name == *key)
            })
        {
            return Err(configuration());
        }
        let permit = self.slots.clone().try_acquire_owned().map_err(|_| {
            classified(
                Code::ResourceExhausted,
                wire::RecoveryAction::Retry,
                wire::RetrySchedule::Short,
            )
        })?;
        let registry = self.registry.clone();
        // A disconnected issuer must not cancel an already admitted exchange.
        // No automatic replay or in-memory exactly-once guarantee is implied.
        let task = tokio::spawn(async move {
            let _permit = permit;
            registry
                .mint(MintRequest {
                    strategy: request.strategy,
                    config: request.config,
                    secret_material: request.secret_material,
                    attempt_id: request.attempt_id,
                })
                .await
        });
        let response = tokio::time::timeout(Duration::from_secs(110), task)
            .await
            .map_err(|_| unknown())?
            .map_err(|_| unknown())?
            .map_err(failure_status)?;
        let expiration_time =
            openshell_core::time::timestamp_from_millis(response.expiration_time_ms)
                .map_err(|_| unknown())?;
        let response = wire::MintResponse {
            outputs: response.outputs,
            expiration_time: Some(expiration_time),
            rotated_secret_material: response.rotated_secret_material,
        };
        if response.encoded_len() > MESSAGE_LIMIT {
            return Err(unknown());
        }
        Ok(Response::new(response))
    }
}

#[cfg(test)]
mod tests;
