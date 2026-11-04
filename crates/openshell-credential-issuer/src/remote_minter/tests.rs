// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod mtls;
mod timeouts;

use super::*;
use std::{collections::HashMap, sync::Mutex, time::SystemTime};
use tokio_stream::wrappers::TcpListenerStream;

struct Fake {
    descriptor: wire::StrategyDescriptor,
    response: Result<wire::MintResponse, Status>,
    received: Arc<Mutex<Vec<wire::MintRequest>>>,
}
#[tonic::async_trait]
impl wire::token_minter_server::TokenMinter for Fake {
    async fn describe(
        &self,
        _: tonic::Request<wire::DescribeRequest>,
    ) -> Result<tonic::Response<wire::DescribeResponse>, Status> {
        Ok(tonic::Response::new(wire::DescribeResponse {
            strategies: vec![self.descriptor.clone()],
        }))
    }
    async fn mint(
        &self,
        request: tonic::Request<wire::MintRequest>,
    ) -> Result<tonic::Response<wire::MintResponse>, Status> {
        self.received.lock().unwrap().push(request.into_inner());
        self.response.clone().map(tonic::Response::new)
    }
}
fn descriptor() -> wire::StrategyDescriptor {
    wire::StrategyDescriptor {
        name: "custom:test".to_string(),
        outputs: vec!["access_token".to_string()],
        secret_material: vec![wire::MaterialDescriptor {
            name: "refresh_token".to_string(),
            required: true,
        }],
        rotated_secret_material: vec!["refresh_token".to_string()],
        ..Default::default()
    }
}
fn response() -> wire::MintResponse {
    wire::MintResponse {
        outputs: HashMap::from([("access_token".to_string(), "minted-secret".to_string())]),
        rotated_secret_material: HashMap::from([(
            "refresh_token".to_string(),
            "rotated-secret".to_string(),
        )]),
        expiration_time: Some(
            openshell_core::time::timestamp_from_system_time(
                SystemTime::now() + Duration::from_mins(1),
            )
            .unwrap(),
        ),
    }
}
fn request() -> MintRequest {
    MintRequest {
        strategy: "custom:test".to_string(),
        config: HashMap::new(),
        secret_material: HashMap::from([("refresh_token".to_string(), "input-secret".to_string())]),
        attempt_id: "durable-attempt".to_string(),
    }
}
async fn start(fake: Fake) -> (Channel, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(wire::token_minter_server::TokenMinterServer::new(fake))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    // Only this private test helper bypasses production mTLS construction.
    let channel = Channel::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (channel, task)
}

#[tokio::test]
async fn remote_mints_preserve_attempts_and_rotated_material_through_registry_validation() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let (channel, task) = start(Fake {
        descriptor: descriptor(),
        response: Ok(response()),
        received: received.clone(),
    })
    .await;
    let minter = RemoteMinter::discover(channel, "test").await.unwrap();
    assert_eq!(minter.describe().outputs, ["access_token"]);
    let mut registry = MinterRegistry::default();
    registry.register_custom(Arc::new(minter)).unwrap();
    let result = registry.mint(request()).await.unwrap();
    assert_eq!(result.outputs["access_token"], "minted-secret");
    assert_eq!(
        result.rotated_secret_material["refresh_token"],
        "rotated-secret"
    );
    let requests = received.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].attempt_id, "durable-attempt");
    assert_eq!(requests[0].secret_material["refresh_token"], "input-secret");
    assert!(!format!("{:?}", requests[0]).contains("input-secret"));
    task.abort();
}

#[tokio::test]
async fn mismatched_or_malformed_remote_descriptors_cannot_register() {
    for name in ["custom:other", "oauth2_refresh_token", "custom:"] {
        let mut description = descriptor();
        description.name = name.to_string();
        let (channel, task) = start(Fake {
            descriptor: description,
            response: Ok(response()),
            received: Arc::default(),
        })
        .await;
        assert!(RemoteMinter::discover(channel, "test").await.is_err());
        task.abort();
    }
    let mut description = descriptor();
    description.outputs = vec!["duplicate".to_string(), "duplicate".to_string()];
    let (channel, task) = start(Fake {
        descriptor: description,
        response: Ok(response()),
        received: Arc::default(),
    })
    .await;
    assert!(RemoteMinter::discover(channel, "test").await.is_err());
    task.abort();
}

#[tokio::test]
async fn remote_descriptor_cardinality_is_bounded_before_registry_validation() {
    let mut description = descriptor();
    description.config = (0..129)
        .map(|index| wire::MaterialDescriptor {
            name: format!("field_{index}"),
            required: false,
        })
        .collect();
    let (channel, task) = start(Fake {
        descriptor: description,
        response: Ok(response()),
        received: Arc::default(),
    })
    .await;
    let error = RemoteMinter::discover(channel, "test").await.unwrap_err();
    assert!(error.message().contains("exceeds limits"));
    task.abort();
}

#[test]
fn only_explicit_valid_failure_classifications_allow_automatic_retry() {
    for (code, action, schedule, expected) in [
        (
            Code::Unavailable,
            wire::RecoveryAction::Retry,
            wire::RetrySchedule::Short,
            RecoveryAction::Retry,
        ),
        (
            Code::InvalidArgument,
            wire::RecoveryAction::FixConfiguration,
            wire::RetrySchedule::Configuration,
            RecoveryAction::FixConfiguration,
        ),
        (
            Code::FailedPrecondition,
            wire::RecoveryAction::Reauthorize,
            wire::RetrySchedule::Parked,
            RecoveryAction::Reauthorize,
        ),
        (
            Code::FailedPrecondition,
            wire::RecoveryAction::Investigate,
            wire::RetrySchedule::Parked,
            RecoveryAction::Investigate,
        ),
    ] {
        let details = wire::MintFailureDetail {
            recovery_action: action as i32,
            retry_schedule: schedule as i32,
            failure_code: "secret-diagnostic".to_string(),
            provider_error_subtype: "secret-diagnostic".to_string(),
        };
        let status =
            Status::with_details(code, "secret-diagnostic", details.encode_to_vec().into());
        let failure = remote_failure(&status);
        assert_eq!(failure.recovery_action, expected);
        assert!(!format!("{failure:?}").contains("secret-diagnostic"));
    }
    for status in [
        Status::unavailable("unknown"),
        Status::deadline_exceeded("unknown"),
        Status::with_details(Code::Unavailable, "unknown", vec![255].into()),
        Status::with_details(
            Code::Unavailable,
            "unknown",
            wire::MintFailureDetail {
                recovery_action: i32::MAX,
                retry_schedule: wire::RetrySchedule::Short as i32,
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
        ),
        Status::with_details(
            Code::Unavailable,
            "unknown",
            wire::MintFailureDetail {
                recovery_action: wire::RecoveryAction::Retry as i32,
                retry_schedule: wire::RetrySchedule::Parked as i32,
                ..Default::default()
            }
            .encode_to_vec()
            .into(),
        ),
    ] {
        let failure = remote_failure(&status);
        assert_eq!(failure.recovery_action, RecoveryAction::Investigate);
        assert_eq!(failure.retry_schedule, RetrySchedule::Parked);
    }
}

#[tokio::test]
async fn unknown_remote_errors_and_invalid_responses_are_parked_without_replay() {
    for response in [
        Err(Status::unavailable("upstream-secret")),
        Ok(wire::MintResponse {
            expiration_time: None,
            ..response()
        }),
        Ok(wire::MintResponse {
            outputs: HashMap::from([("unexpected".to_string(), "secret".to_string())]),
            ..response()
        }),
    ] {
        let received = Arc::new(Mutex::new(Vec::new()));
        let (channel, task) = start(Fake {
            descriptor: descriptor(),
            response,
            received: received.clone(),
        })
        .await;
        let mut registry = MinterRegistry::default();
        registry
            .register_custom(Arc::new(
                RemoteMinter::discover(channel, "test").await.unwrap(),
            ))
            .unwrap();
        let failure = registry.mint(request()).await.unwrap_err();
        assert_eq!(failure.retry_schedule, RetrySchedule::Parked);
        assert_eq!(received.lock().unwrap().len(), 1);
        assert!(!format!("{failure:?}").contains("upstream-secret"));
        task.abort();
    }
}

#[tokio::test]
async fn production_remote_minters_require_private_ca_and_client_identity() {
    for endpoint in [
        "http://127.0.0.1:1",
        "https://localhost:1",
        "unix:///tmp/minter.sock",
    ] {
        assert_eq!(
            RemoteMinter::connect(&ExtensionChannelConfig::new(endpoint), "test")
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
    }
}
