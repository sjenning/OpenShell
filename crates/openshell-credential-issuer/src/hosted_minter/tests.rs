// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::minter::{MaterialDescriptor, MintResponse};
use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicU8, Ordering},
    },
};
use wire::token_minter_server::TokenMinter as _;

mod mtls;

#[derive(Default)]
struct TestMinter {
    requests: Mutex<Vec<MintRequest>>,
    mode: AtomicU8,
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
    finished: tokio::sync::Notify,
}
impl std::fmt::Debug for TestMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestMinter")
    }
}
#[tonic::async_trait]
impl TokenMinter for TestMinter {
    fn describe(&self) -> StrategyDescriptor {
        StrategyDescriptor {
            name: "custom:test".to_string(),
            config: vec![MaterialDescriptor {
                name: "client_id".to_string(),
                required: true,
            }],
            secret_material: vec![MaterialDescriptor {
                name: "refresh_token".to_string(),
                required: true,
            }],
            outputs: vec!["access_token".to_string()],
            rotated_secret_material: vec!["refresh_token".to_string()],
        }
    }
    async fn mint(&self, request: MintRequest) -> Result<MintResponse, MintFailure> {
        self.requests.lock().unwrap().push(request);
        if self.mode.load(Ordering::SeqCst) == 1 {
            self.started.notify_one();
            self.release.notified().await;
            self.finished.notify_one();
        }
        Ok(MintResponse {
            outputs: HashMap::from([("access_token".to_string(), "minted-secret".to_string())]),
            expiration_time_ms: openshell_core::time::now_ms() + 60_000,
            rotated_secret_material: HashMap::from([(
                "refresh_token".to_string(),
                "rotated-secret".to_string(),
            )]),
        })
    }
}
fn policy() -> IssuerPolicy {
    IssuerPolicy::new(vec!["spiffe://test.example/issuer/a".to_string()]).unwrap()
}
fn request() -> wire::MintRequest {
    wire::MintRequest {
        strategy: "custom:test".to_string(),
        config: HashMap::from([("client_id".to_string(), "client".to_string())]),
        secret_material: HashMap::from([("refresh_token".to_string(), "input-secret".to_string())]),
        attempt_id: "stable-attempt".to_string(),
    }
}

#[tokio::test]
async fn plaintext_and_forged_headers_are_denied_before_mint() {
    let minter = Arc::new(TestMinter::default());
    let hosted = HostedMinter::new(minter.clone(), policy(), 1).unwrap();
    let mut req = Request::new(request());
    req.metadata_mut().insert(
        "x-issuer-identity",
        "spiffe://test.example/issuer/a".parse().unwrap(),
    );
    assert_eq!(
        hosted.mint(req).await.unwrap_err().code(),
        Code::Unauthenticated
    );
    assert_eq!(
        hosted
            .describe(Request::new(wire::DescribeRequest {}))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    assert!(minter.requests.lock().unwrap().is_empty());
}

#[test]
fn failure_diagnostics_and_invalid_classifications_never_cross_the_wire() {
    for (code, action, schedule, expected) in [
        (
            Code::Unavailable,
            RecoveryAction::Retry,
            RetrySchedule::Short,
            wire::RecoveryAction::Retry,
        ),
        (
            Code::ResourceExhausted,
            RecoveryAction::Retry,
            RetrySchedule::Short,
            wire::RecoveryAction::Retry,
        ),
        (
            Code::FailedPrecondition,
            RecoveryAction::FixConfiguration,
            RetrySchedule::Configuration,
            wire::RecoveryAction::FixConfiguration,
        ),
        (
            Code::FailedPrecondition,
            RecoveryAction::Reauthorize,
            RetrySchedule::Parked,
            wire::RecoveryAction::Reauthorize,
        ),
        (
            Code::Unavailable,
            RecoveryAction::Investigate,
            RetrySchedule::Short,
            wire::RecoveryAction::Investigate,
        ),
        (
            Code::Internal,
            RecoveryAction::Retry,
            RetrySchedule::Short,
            wire::RecoveryAction::Investigate,
        ),
    ] {
        let status = failure_status(MintFailure {
            status: Status::new(code, "secret-diagnostic"),
            recovery_action: action,
            retry_schedule: schedule,
            failure_code: "secret-code",
            provider_error_subtype: Some("secret-subtype"),
        });
        let detail = wire::MintFailureDetail::decode(status.details()).unwrap();
        assert_eq!(detail.recovery_action, expected as i32);
        assert!(!status.message().contains("secret"));
        assert!(!String::from_utf8_lossy(status.details()).contains("secret"));
    }
}

#[test]
fn caller_bindings_and_concurrency_are_explicit_and_bounded() {
    assert!(IssuerPolicy::new(vec![]).is_err());
    for id in ["*", "spiffe://", "https://test.example/issuer"] {
        assert!(IssuerPolicy::new(vec![id.to_string()]).is_err());
    }
    for concurrency in [0, 65, usize::MAX] {
        assert!(HostedMinter::new(Arc::new(TestMinter::default()), policy(), concurrency).is_err());
    }
}
