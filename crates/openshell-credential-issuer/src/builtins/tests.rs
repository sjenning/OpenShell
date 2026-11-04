// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::minter::RecoveryAction;

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn request(strategy: &str, url: &str) -> MintRequest {
    MintRequest {
        strategy: strategy.to_string(),
        config: HashMap::from([
            ("token_url".to_string(), url.to_string()),
            ("max_lifetime_seconds".to_string(), "60".to_string()),
            ("client_id".to_string(), "client".to_string()),
            ("scope".to_string(), "scope-a scope-b".to_string()),
        ]),
        secret_material: HashMap::from([
            ("client_secret".to_string(), "client-secret".to_string()),
            ("refresh_token".to_string(), "old-refresh".to_string()),
        ]),
        attempt_id: "durable-attempt".to_string(),
    }
}

#[tokio::test]
async fn refresh_minter_returns_semantic_output_and_rotated_material_without_a_gateway() {
    let mock = MockServer::start().await;
    Mock::given(method("POST")).and(path("/token")).and(body_string_contains("refresh_token=old-refresh"))
        .and(body_string_contains("scope=scope-a+scope-b"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"access_token":"access", "refresh_token":"rotated", "expires_in":3600})))
        .expect(1).mount(&mock).await;
    let before = now_ms();
    let result = registry()
        .mint(request(
            "oauth2_refresh_token",
            &format!("{}/token", mock.uri()),
        ))
        .await
        .unwrap();
    assert_eq!(
        result.outputs,
        HashMap::from([("access_token".to_string(), "access".to_string())])
    );
    assert_eq!(result.rotated_secret_material["refresh_token"], "rotated");
    assert!(result.expiration_time_ms >= before + 60_000);
    assert!(result.expiration_time_ms <= now_ms() + 60_000);
}

#[tokio::test]
async fn malformed_refresh_success_remains_terminal_and_redacted() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("sensitive response"))
        .expect(1)
        .mount(&mock)
        .await;
    let error = registry()
        .mint(request(
            "oauth2_refresh_token",
            &format!("{}/token", mock.uri()),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.recovery_action, RecoveryAction::Reauthorize);
    assert_eq!(error.failure_code, "oauth_refresh_exchange_uncertain");
    assert!(!error.status.message().contains("sensitive response"));
}

#[tokio::test]
async fn production_registry_never_honors_an_sts_endpoint_even_with_test_support_enabled() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock)
        .await;
    let mut req = request("aws_sts_assume_role", "");
    req.config
        .insert("sts_endpoint_url".to_string(), mock.uri());
    let error = registry().mint(req).await.unwrap_err();
    assert_eq!(error.status.code(), tonic::Code::InvalidArgument);
    assert_eq!(error.recovery_action, RecoveryAction::FixConfiguration);
}

#[tokio::test]
async fn test_registry_also_rejects_non_loopback_sts_endpoints_before_upstream_contact() {
    for endpoint in ["https://example.test", "http://example.test", "not-a-url"] {
        let mut req = request("aws_sts_assume_role", "");
        req.config
            .insert("sts_endpoint_url".to_string(), endpoint.to_string());
        assert_eq!(
            registry_with_loopback_sts_for_tests()
                .mint(req)
                .await
                .unwrap_err()
                .status
                .code(),
            tonic::Code::InvalidArgument
        );
    }
}

#[tokio::test]
async fn incomplete_aws_credentials_never_fall_back_to_the_issuer_identity() {
    for (key, value) in [
        ("aws_access_key_id", "only-access"),
        ("aws_session_token", "only-session"),
    ] {
        let mut req = request("aws_sts_assume_role", "");
        req.config.insert(
            "role_arn".to_string(),
            "arn:aws:iam::123456789012:role/test".to_string(),
        );
        if key == "aws_session_token" {
            req.secret_material
                .insert(key.to_string(), value.to_string());
        } else {
            req.config.insert(key.to_string(), value.to_string());
        }
        let error = registry().mint(req).await.unwrap_err();
        assert_eq!(error.status.code(), tonic::Code::InvalidArgument);
        assert_eq!(error.recovery_action, RecoveryAction::FixConfiguration);
    }
}

#[tokio::test]
async fn imported_long_oauth_lifetime_is_not_replaced_with_native_twelve_hour_cap() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "long-lived", "expires_in": 172_800
        })))
        .expect(2)
        .mount(&mock)
        .await;
    for lifetime in [86_400_i64, i64::from(u32::MAX) + 1] {
        let mut input = request(
            "oauth2_client_credentials",
            &format!("{}/token", mock.uri()),
        );
        input
            .config
            .insert("max_lifetime_seconds".into(), lifetime.to_string());
        let before = now_ms();
        let result = registry().mint(input).await.unwrap();
        let expected_seconds = lifetime.min(172_800);
        assert!(result.expiration_time_ms >= before + expected_seconds * 1000);
        assert!(result.expiration_time_ms <= now_ms() + expected_seconds * 1000);
    }
}
