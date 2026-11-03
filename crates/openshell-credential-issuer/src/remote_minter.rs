// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authenticated remote minter adapter with pinned discovery and fail-closed errors.

use crate::minter::{
    MaterialDescriptor, MintFailure, MintRequest, MintResponse, MinterRegistry, RecoveryAction,
    RetrySchedule, StrategyDescriptor, TokenMinter,
};
use async_trait::async_trait;
use openshell_core::proto::credentials::minter::v1 as wire;
use openshell_extension_core::{ExtensionChannelConfig, connect_channel};
use prost::Message;
use std::{sync::Arc, time::Duration};
use tonic::{Code, Status, transport::Channel};

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const MINT_TIMEOUT: Duration = Duration::from_mins(2);

#[derive(Debug)]
pub struct RemoteMinter {
    descriptor: StrategyDescriptor,
    client: wire::token_minter_client::TokenMinterClient<Channel>,
}

impl RemoteMinter {
    /// Connect using private-CA mTLS and pin the one configured registration.
    /// Descriptors are checked by the same registry as embedded minters.
    pub async fn connect(
        config: &ExtensionChannelConfig,
        registration: &str,
    ) -> Result<Self, Status> {
        if !config.endpoint().starts_with("https://")
            || !config.has_custom_ca()
            || !config.has_client_identity()
        {
            return Err(Status::invalid_argument(
                "remote minters require private-CA HTTPS and a client identity",
            ));
        }
        let channel = connect_channel(config)
            .await
            .map_err(|_| Status::unavailable("remote minter connection failed"))?;
        Self::discover(channel, registration).await
    }

    async fn discover(channel: Channel, registration: &str) -> Result<Self, Status> {
        let mut client = wire::token_minter_client::TokenMinterClient::new(channel)
            .max_decoding_message_size(1024 * 1024);
        let mut request = tonic::Request::new(wire::DescribeRequest {});
        request.set_timeout(DISCOVERY_TIMEOUT);
        let response = client
            .describe(request)
            .await
            .map_err(|_| Status::unavailable("remote minter discovery failed"))?
            .into_inner();
        let expected = format!("custom:{registration}");
        if response.strategies.len() != 1 || response.strategies[0].name != expected {
            return Err(Status::failed_precondition(
                "remote minter registration does not match its descriptor",
            ));
        }
        let descriptor = response
            .strategies
            .into_iter()
            .next()
            .expect("one descriptor");
        if descriptor.config.len() + descriptor.secret_material.len() > 128
            || descriptor.outputs.len() > 64
            || descriptor.rotated_secret_material.len() > 128
        {
            return Err(Status::failed_precondition(
                "remote minter descriptor exceeds limits",
            ));
        }
        let descriptor = StrategyDescriptor {
            name: descriptor.name,
            config: descriptor.config.into_iter().map(material).collect(),
            secret_material: descriptor
                .secret_material
                .into_iter()
                .map(material)
                .collect(),
            outputs: descriptor.outputs,
            rotated_secret_material: descriptor.rotated_secret_material,
        };
        let minter = Self { descriptor, client };
        // Reuse registry validation; never accept a descriptor here that the
        // engine would later reject or allow a remote to replace a built-in.
        let mut validation = MinterRegistry::default();
        validation.register_custom(Arc::new(Self {
            descriptor: minter.descriptor.clone(),
            client: minter.client.clone(),
        }))?;
        Ok(minter)
    }
}

fn material(value: wire::MaterialDescriptor) -> MaterialDescriptor {
    MaterialDescriptor {
        name: value.name,
        required: value.required,
    }
}

fn uncertain_response() -> MintFailure {
    MintFailure {
        status: Status::failed_precondition(
            "remote minter outcome is uncertain; investigate the attempt",
        ),
        recovery_action: RecoveryAction::Investigate,
        failure_code: "remote_minter_outcome_unknown",
        provider_error_subtype: None,
        retry_schedule: RetrySchedule::Parked,
    }
}

/// Never persist arbitrary remote messages, bodies, or diagnostic strings.
fn remote_failure(status: &Status) -> MintFailure {
    let Ok(detail) = wire::MintFailureDetail::decode(status.details()) else {
        return uncertain_response();
    };
    let classified = match (
        status.code(),
        wire::RecoveryAction::try_from(detail.recovery_action),
        wire::RetrySchedule::try_from(detail.retry_schedule),
    ) {
        (
            Code::Unavailable | Code::ResourceExhausted,
            Ok(wire::RecoveryAction::Retry),
            Ok(wire::RetrySchedule::Short),
        ) => (
            RecoveryAction::Retry,
            RetrySchedule::Short,
            "remote_minter_retry",
        ),
        (
            Code::InvalidArgument | Code::FailedPrecondition,
            Ok(wire::RecoveryAction::FixConfiguration),
            Ok(wire::RetrySchedule::Configuration),
        ) => (
            RecoveryAction::FixConfiguration,
            RetrySchedule::Configuration,
            "remote_minter_configuration",
        ),
        (
            Code::FailedPrecondition,
            Ok(wire::RecoveryAction::Reauthorize),
            Ok(wire::RetrySchedule::Parked),
        ) => (
            RecoveryAction::Reauthorize,
            RetrySchedule::Parked,
            "remote_minter_reauthorize",
        ),
        (
            Code::FailedPrecondition,
            Ok(wire::RecoveryAction::Investigate),
            Ok(wire::RetrySchedule::Parked),
        ) => (
            RecoveryAction::Investigate,
            RetrySchedule::Parked,
            "remote_minter_investigate",
        ),
        _ => return uncertain_response(),
    };
    MintFailure {
        status: Status::new(status.code(), "remote minter rejected the attempt"),
        recovery_action: classified.0,
        retry_schedule: classified.1,
        failure_code: classified.2,
        provider_error_subtype: None,
    }
}

#[async_trait]
impl TokenMinter for RemoteMinter {
    fn describe(&self) -> StrategyDescriptor {
        self.descriptor.clone()
    }
    async fn mint(&self, request: MintRequest) -> Result<MintResponse, MintFailure> {
        let mut client = self.client.clone();
        let mut request = tonic::Request::new(wire::MintRequest {
            strategy: request.strategy,
            config: request.config,
            secret_material: request.secret_material,
            attempt_id: request.attempt_id,
        });
        request.set_timeout(MINT_TIMEOUT);
        // No automatic replay: a connection failure or deadline may follow an
        // upstream exchange that rotated irreplaceable refresh material.
        let response = client
            .mint(request)
            .await
            .map_err(|status| remote_failure(&status))?
            .into_inner();
        let expiration_time_ms = response
            .expiration_time
            .as_ref()
            .and_then(|time| openshell_core::time::timestamp_to_millis(time).ok())
            .ok_or_else(uncertain_response)?;
        Ok(MintResponse {
            outputs: response.outputs,
            expiration_time_ms,
            rotated_secret_material: response.rotated_secret_material,
        })
    }
}

#[cfg(test)]
mod tests;
