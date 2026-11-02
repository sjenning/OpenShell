// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::proto::ObjectMeta;
use std::sync::Mutex;

#[derive(Debug)]
struct RecordingMinter {
    descriptor: StrategyDescriptor,
    requests: Arc<Mutex<Vec<MintRequest>>>,
}

#[async_trait]
impl TokenMinter for RecordingMinter {
    fn describe(&self) -> StrategyDescriptor {
        self.descriptor.clone()
    }

    async fn mint(&self, request: MintRequest) -> Result<MintResponse, MintFailure> {
        self.requests.lock().unwrap().push(request);
        Ok(MintResponse {
            outputs: self
                .descriptor
                .outputs
                .iter()
                .map(|id| (id.clone(), format!("value-{id}")))
                .collect(),
            expiration_time_ms: crate::persistence::current_time_ms() + 60_000,
            rotated_secret_material: HashMap::new(),
        })
    }
}

fn state(strategy: ProviderCredentialRefreshStrategy) -> StoredProviderCredentialRefreshState {
    StoredProviderCredentialRefreshState {
        metadata: Some(ObjectMeta {
            annotations: HashMap::from([(
                ATTEMPT_ANNOTATION.to_string(),
                "persisted-attempt".to_string(),
            )]),
            ..Default::default()
        }),
        strategy: strategy as i32,
        token_url: "https://example.test/token".to_string(),
        scopes: vec!["scope-one".to_string(), "scope-two".to_string()],
        max_lifetime: Some(prost_types::Duration {
            seconds: 60,
            nanos: 0,
        }),
        ..Default::default()
    }
}

fn registry(strategy: &str) -> (MinterRegistry, Arc<Mutex<Vec<MintRequest>>>) {
    let requests = Arc::default();
    let mut registry = MinterRegistry::default();
    let descriptor = MINTERS
        .describe()
        .find(|item| item.name == strategy)
        .unwrap()
        .clone();
    registry
        .register_builtin(Arc::new(RecordingMinter {
            descriptor,
            requests: Arc::clone(&requests),
        }))
        .unwrap();
    (registry, requests)
}

#[test]
fn builtin_registry_matches_legacy_profile_eligibility() {
    for strategy in [
        ProviderCredentialRefreshStrategy::Unspecified,
        ProviderCredentialRefreshStrategy::Static,
        ProviderCredentialRefreshStrategy::External,
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
        ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt,
        ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
    ] {
        assert_eq!(
            MINTERS.supports(refresh_strategy_name(strategy as i32)),
            openshell_providers::is_gateway_mintable_strategy(strategy)
        );
    }
    assert_eq!(MINTERS.describe().count(), 4);
}

#[tokio::test]
async fn adapter_separates_secret_values_and_passes_the_durable_attempt() {
    let (registry, requests) = registry("oauth2_refresh_token");
    let mut state = state(ProviderCredentialRefreshStrategy::Oauth2RefreshToken);
    state.material = HashMap::from([
        ("client_id".to_string(), "client".to_string()),
        ("client_secret".to_string(), "client-secret".to_string()),
        ("refresh_token".to_string(), "refresh-secret".to_string()),
        ("extra_secret".to_string(), "profile-secret".to_string()),
    ]);
    // Known secrets must be separated even when the API omitted their labels.
    state.secret_material_keys = vec!["extra_secret".to_string()];
    let before = state.clone();
    let result = mint_with_registry(&registry, &state).await.unwrap();
    assert_eq!(result.access_token, "value-access_token");
    assert_eq!(state, before);
    let requests = requests.lock().unwrap();
    let request = &requests[0];
    assert_eq!(request.attempt_id, "persisted-attempt");
    assert_eq!(request.config["client_id"], "client");
    assert_eq!(request.config["scope"], "scope-one scope-two");
    assert_eq!(request.config["max_lifetime_seconds"], "60");
    assert_eq!(request.config["token_url"], "https://example.test/token");
    assert_eq!(request.secret_material.len(), 3);
    for key in ["refresh_token", "client_secret", "extra_secret"] {
        assert!(!request.config.contains_key(key));
        assert!(request.secret_material.contains_key(key));
    }
}

#[tokio::test]
async fn adapter_maps_semantic_aws_outputs_to_pinned_profile_keys() {
    let (registry, requests) = registry("aws_sts_assume_role");
    let mut state = state(ProviderCredentialRefreshStrategy::AwsStsAssumeRole);
    state.additional_output_keys = HashMap::from([
        (
            "secret_access_key".to_string(),
            "CUSTOM_AWS_SECRET".to_string(),
        ),
        (
            "session_token".to_string(),
            "CUSTOM_AWS_SESSION".to_string(),
        ),
    ]);
    let result = mint_with_registry(&registry, &state).await.unwrap();
    assert_eq!(result.access_token, "value-access_key_id");
    assert_eq!(
        result.additional_credentials,
        HashMap::from([
            (
                "CUSTOM_AWS_SECRET".to_string(),
                "value-secret_access_key".to_string()
            ),
            (
                "CUSTOM_AWS_SESSION".to_string(),
                "value-session_token".to_string()
            ),
        ])
    );
    assert!(!format!("{:?}", requests.lock().unwrap()[0]).contains("CUSTOM_AWS"));
}

#[tokio::test]
async fn missing_durable_attempt_never_calls_the_minter() {
    let (registry, requests) = registry("oauth2_refresh_token");
    let mut state = state(ProviderCredentialRefreshStrategy::Oauth2RefreshToken);
    state.metadata.as_mut().unwrap().annotations.clear();
    let error = mint_with_registry(&registry, &state).await.unwrap_err();
    assert_eq!(error.status.code(), tonic::Code::FailedPrecondition);
    assert!(requests.lock().unwrap().is_empty());
}

#[test]
fn failure_bridge_preserves_recovery_classification_and_safe_subtypes() {
    for failure in [
        RefreshFailure::retryable(Status::unavailable("transient"), "retry"),
        RefreshFailure::investigate(Status::unknown("unclassified"), "investigate"),
        RefreshFailure::fix_configuration(
            Status::failed_precondition("configuration"),
            "configuration",
        ),
        RefreshFailure::reauthorize(
            Status::failed_precondition("reauthorize"),
            "reauthorize",
            Some("invalid_rapt"),
        ),
    ] {
        let expected = (
            failure.status.code(),
            failure.status.message().to_string(),
            failure.recovery_action,
            failure.failure_code,
            failure.provider_error_subtype,
            failure.retry_schedule,
        );
        let restored = RefreshFailure::from(MintFailure::from(failure));
        assert_eq!(
            (
                restored.status.code(),
                restored.status.message().to_string(),
                restored.recovery_action,
                restored.failure_code,
                restored.provider_error_subtype,
                restored.retry_schedule
            ),
            expected
        );
    }
}
