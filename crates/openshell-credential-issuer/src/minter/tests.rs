// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::sync::Mutex;
use tonic::Code;

#[derive(Debug, Clone, Copy)]
enum ResponseKind {
    Valid,
    Missing,
    Extra,
    Empty,
    Expired,
    UndeclaredRotation,
    EmptyRotation,
    Uncertain,
}

#[derive(Debug)]
struct FakeMinter {
    descriptor: StrategyDescriptor,
    requests: Arc<Mutex<Vec<MintRequest>>>,
    response: ResponseKind,
}

fn descriptor(name: &str) -> StrategyDescriptor {
    StrategyDescriptor {
        name: name.to_string(),
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

fn request(name: &str) -> MintRequest {
    MintRequest {
        strategy: name.to_string(),
        config: HashMap::from([("client_id".to_string(), "client".to_string())]),
        secret_material: HashMap::from([("refresh_token".to_string(), "input-secret".to_string())]),
        attempt_id: "durable-attempt-123".to_string(),
    }
}

fn response() -> MintResponse {
    MintResponse {
        outputs: HashMap::from([("access_token".to_string(), "output-secret".to_string())]),
        expiration_time_ms: i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
            + 60_000,
        rotated_secret_material: HashMap::from([(
            "refresh_token".to_string(),
            "replacement-secret".to_string(),
        )]),
    }
}

#[async_trait]
impl TokenMinter for FakeMinter {
    fn describe(&self) -> StrategyDescriptor {
        self.descriptor.clone()
    }

    async fn mint(&self, request: MintRequest) -> Result<MintResponse, MintFailure> {
        self.requests.lock().unwrap().push(request);
        let mut result = response();
        match self.response {
            ResponseKind::Valid => {}
            ResponseKind::Missing => result.outputs.clear(),
            ResponseKind::Extra => {
                result
                    .outputs
                    .insert("unexpected".to_string(), "value".to_string());
            }
            ResponseKind::Empty => {
                result
                    .outputs
                    .insert("access_token".to_string(), "  ".to_string());
            }
            ResponseKind::Expired => result.expiration_time_ms = 1,
            ResponseKind::UndeclaredRotation => {
                result
                    .rotated_secret_material
                    .insert("private_key".to_string(), "key".to_string());
            }
            ResponseKind::EmptyRotation => {
                result
                    .rotated_secret_material
                    .insert("refresh_token".to_string(), String::new());
            }
            ResponseKind::Uncertain => {
                return Err(MintFailure {
                    status: Status::failed_precondition("exchange outcome uncertain"),
                    recovery_action: RecoveryAction::Reauthorize,
                    failure_code: "oauth_refresh_exchange_uncertain",
                    provider_error_subtype: None,
                    retry_schedule: RetrySchedule::Parked,
                });
            }
        }
        Ok(result)
    }
}

fn registry(kind: ResponseKind) -> (MinterRegistry, Arc<Mutex<Vec<MintRequest>>>) {
    let requests = Arc::default();
    let mut registry = MinterRegistry::default();
    registry
        .register_custom(Arc::new(FakeMinter {
            descriptor: descriptor("custom:example"),
            requests: Arc::clone(&requests),
            response: kind,
        }))
        .unwrap();
    (registry, requests)
}

#[tokio::test]
async fn custom_minter_needs_no_enum_variant_and_receives_the_attempt_identity() {
    let (registry, requests) = registry(ResponseKind::Valid);
    assert!(registry.supports("custom:example"));
    assert!(!registry.supports("custom:unknown"));
    assert_eq!(
        registry
            .describe()
            .map(|item| item.name.as_str())
            .collect::<Vec<_>>(),
        vec!["custom:example"]
    );
    let result = registry.mint(request("custom:example")).await.unwrap();
    assert_eq!(result.outputs["access_token"], "output-secret");
    assert_eq!(
        result.rotated_secret_material["refresh_token"],
        "replacement-secret"
    );
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].attempt_id, "durable-attempt-123");
    assert_eq!(requests[0].config["client_id"], "client");
    assert_eq!(requests[0].secret_material["refresh_token"], "input-secret");
}

#[tokio::test]
async fn unknown_strategy_and_invalid_requests_fail_before_calling_a_minter() {
    let (registry, requests) = registry(ResponseKind::Valid);
    let mut missing_attempt = request("custom:example");
    missing_attempt.attempt_id.clear();
    let mut duplicate_material = request("custom:example");
    duplicate_material
        .config
        .insert("refresh_token".to_string(), "shadow-secret".to_string());
    let mut missing_required = request("custom:example");
    missing_required.secret_material.clear();
    let mut secret_in_config = request("custom:example");
    let secret = secret_in_config
        .secret_material
        .remove("refresh_token")
        .unwrap();
    secret_in_config
        .config
        .insert("refresh_token".to_string(), secret);
    for request in [
        request("unknown"),
        missing_attempt,
        duplicate_material,
        missing_required,
        secret_in_config,
    ] {
        let error = registry.mint(request).await.unwrap_err();
        assert_eq!(error.recovery_action, RecoveryAction::FixConfiguration);
        assert_eq!(error.retry_schedule, RetrySchedule::Configuration);
    }
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn malformed_responses_are_parked_instead_of_retried_or_published() {
    for kind in [
        ResponseKind::Missing,
        ResponseKind::Extra,
        ResponseKind::Empty,
        ResponseKind::Expired,
        ResponseKind::UndeclaredRotation,
        ResponseKind::EmptyRotation,
    ] {
        let (registry, requests) = registry(kind);
        let error = registry.mint(request("custom:example")).await.unwrap_err();
        assert_eq!(error.failure_code, "minter_response_invalid", "{kind:?}");
        assert_eq!(error.recovery_action, RecoveryAction::Investigate);
        assert_eq!(error.retry_schedule, RetrySchedule::Parked);
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn uncertain_exchange_classification_is_not_flattened_to_transport_error() {
    let (registry, _) = registry(ResponseKind::Uncertain);
    let error = registry.mint(request("custom:example")).await.unwrap_err();
    assert_eq!(error.recovery_action, RecoveryAction::Reauthorize);
    assert_eq!(error.failure_code, "oauth_refresh_exchange_uncertain");
    assert_eq!(error.retry_schedule, RetrySchedule::Parked);
}

#[test]
fn namespace_descriptor_and_duplicate_registration_validation() {
    let mut registry = MinterRegistry::default();
    let make = |descriptor| -> Arc<dyn TokenMinter> {
        Arc::new(FakeMinter {
            descriptor,
            requests: Arc::default(),
            response: ResponseKind::Valid,
        })
    };
    registry
        .register_builtin(make(descriptor("oauth2_refresh_token")))
        .unwrap();
    assert_eq!(
        registry
            .register_builtin(make(descriptor("oauth2_refresh_token")))
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    for name in [
        "oauth2_refresh_token",
        "custom:",
        "custom:a:b",
        "custom:UPPER",
        "custom:bad/name",
    ] {
        assert_eq!(
            registry
                .register_custom(make(descriptor(name)))
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
    }
    assert_eq!(
        registry
            .register_builtin(make(descriptor("custom:example")))
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    for outputs in [
        Vec::new(),
        vec!["x".to_string(), "x".to_string()],
        vec!["INVALID".to_string()],
    ] {
        let mut invalid = descriptor("custom:invalid");
        invalid.outputs = outputs;
        assert_eq!(
            registry.register_custom(make(invalid)).unwrap_err().code(),
            Code::InvalidArgument
        );
    }
    registry
        .register_custom(make(descriptor("custom:acme-sts")))
        .unwrap();
    assert!(registry.supports("custom:acme-sts"));
    registry
        .register_custom(make(descriptor("custom:example")))
        .unwrap();
    assert_eq!(
        registry
            .register_custom(make(descriptor("custom:example")))
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
}

#[test]
fn debug_output_never_contains_request_or_response_values() {
    let request = request("custom:example");
    let response = response();
    let debug = format!("{request:?} {response:?}");
    for value in [
        "input-secret",
        "output-secret",
        "replacement-secret",
        "client_id",
    ] {
        assert!(!debug.contains(value));
    }
    assert!(debug.contains("[REDACTED]"));
}
