// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::minter::{RecoveryAction, RetrySchedule};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
#[test]
fn oauth_invalid_grant_requires_user_reauthorization_without_exposing_description() {
    let failure = classify_oauth_token_error(
            reqwest::StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_grant","error_subtype":"invalid_rapt","error_description":"sensitive provider detail"}"#,
            OAuthGrantKind::UserRefreshToken,
        );

    assert_eq!(failure.recovery_action, RecoveryAction::Reauthorize);
    assert_eq!(failure.failure_code, "oauth_invalid_grant");
    assert_eq!(failure.provider_error_subtype, Some("invalid_rapt"));
    assert_eq!(failure.retry_schedule, RetrySchedule::Parked);
    assert!(
        failure
            .status
            .message()
            .contains("interactive reauthorization")
    );
    assert!(
        !failure
            .status
            .message()
            .contains("sensitive provider detail")
    );
}

#[test]
fn oauth_invalid_grant_ignores_non_string_optional_subtype() {
    let failure = classify_oauth_token_error(
        reqwest::StatusCode::BAD_REQUEST,
        br#"{"error":"invalid_grant","error_subtype":{"vendor":"value"}}"#,
        OAuthGrantKind::UserRefreshToken,
    );

    assert_eq!(failure.recovery_action, RecoveryAction::Reauthorize);
    assert_eq!(failure.failure_code, "oauth_invalid_grant");
    assert_eq!(failure.provider_error_subtype, None);
    assert_eq!(failure.retry_schedule, RetrySchedule::Parked);
}

#[test]
fn oauth_noninteractive_invalid_grant_requires_configuration_fix() {
    let failure = classify_oauth_token_error(
        reqwest::StatusCode::BAD_REQUEST,
        br#"{"error":"invalid_grant"}"#,
        OAuthGrantKind::NonInteractive,
    );

    assert_eq!(failure.recovery_action, RecoveryAction::FixConfiguration);
    assert_eq!(failure.failure_code, "oauth_invalid_grant");
    assert_eq!(failure.retry_schedule, RetrySchedule::Configuration);
}

#[test]
fn oauth_admin_policy_subtype_requires_configuration_fix() {
    let failure = classify_oauth_token_error(
        reqwest::StatusCode::BAD_REQUEST,
        br#"{"error":"access_denied","error_subtype":"admin_policy_enforced"}"#,
        OAuthGrantKind::UserRefreshToken,
    );

    assert_eq!(failure.recovery_action, RecoveryAction::FixConfiguration);
    assert_eq!(failure.failure_code, "oauth_admin_policy_enforced");
    assert_eq!(
        failure.provider_error_subtype,
        Some("admin_policy_enforced")
    );
    assert_eq!(failure.retry_schedule, RetrySchedule::Configuration);
}

#[test]
fn oauth_access_denied_recovery_depends_on_grant_kind() {
    let user_failure = classify_oauth_token_error(
        reqwest::StatusCode::FORBIDDEN,
        br#"{"error":"access_denied"}"#,
        OAuthGrantKind::UserRefreshToken,
    );
    assert_eq!(user_failure.recovery_action, RecoveryAction::Reauthorize);
    assert_eq!(user_failure.failure_code, "oauth_access_denied");
    assert_eq!(user_failure.retry_schedule, RetrySchedule::Parked);

    let service_failure = classify_oauth_token_error(
        reqwest::StatusCode::FORBIDDEN,
        br#"{"error":"access_denied"}"#,
        OAuthGrantKind::NonInteractive,
    );
    assert_eq!(
        service_failure.recovery_action,
        RecoveryAction::FixConfiguration
    );
    assert_eq!(service_failure.failure_code, "oauth_access_denied");
    assert_eq!(service_failure.retry_schedule, RetrySchedule::Configuration);
}

#[test]
fn oauth_server_failure_remains_retryable() {
    let failure = classify_oauth_token_error(
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        br#"{"error":"invalid_grant"}"#,
        OAuthGrantKind::UserRefreshToken,
    );

    assert_eq!(failure.recovery_action, RecoveryAction::Retry);
    assert_eq!(failure.failure_code, "oauth_token_endpoint_retryable");
    assert_eq!(failure.retry_schedule, RetrySchedule::Short);
}

#[test]
fn unrecognized_oauth_error_requests_investigation_without_echoing_body() {
    let failure = classify_oauth_token_error(
        reqwest::StatusCode::BAD_REQUEST,
        br#"{"error":"vendor_secret_error","error_description":"do not expose me"}"#,
        OAuthGrantKind::UserRefreshToken,
    );

    assert_eq!(failure.recovery_action, RecoveryAction::Investigate);
    assert_eq!(failure.failure_code, "oauth_unrecognized_error");
    assert_eq!(failure.retry_schedule, RetrySchedule::Short);
    assert!(!failure.status.message().contains("vendor_secret_error"));
    assert!(!failure.status.message().contains("do not expose me"));
}

#[test]
fn html_and_malformed_oauth_errors_are_investigated_without_echoing_body() {
    for body in [b"<html>issuer failure</html>".as_slice(), b"{".as_slice()] {
        let failure = classify_oauth_token_error(
            reqwest::StatusCode::BAD_REQUEST,
            body,
            OAuthGrantKind::UserRefreshToken,
        );

        assert_eq!(failure.recovery_action, RecoveryAction::Investigate);
        assert_eq!(failure.failure_code, "oauth_unrecognized_error_response");
        assert!(!failure.status.message().contains("issuer failure"));
    }
}

#[tokio::test]
async fn oversized_oauth_error_body_is_bounded_and_investigated() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oversized"))
        .respond_with(ResponseTemplate::new(400).set_body_bytes(vec![
            b'x';
            MAX_OAUTH_ERROR_RESPONSE_BYTES
                + 512
        ]))
        .mount(&mock_server)
        .await;

    openshell_crypto::tls::ensure_default_provider();
    let response = reqwest::get(format!("{}/oversized", mock_server.uri()))
        .await
        .unwrap();
    let status = response.status();
    let body = read_bounded_oauth_error_body(response).await;
    assert_eq!(body.len(), MAX_OAUTH_ERROR_RESPONSE_BYTES);

    let failure = classify_oauth_token_error(status, &body, OAuthGrantKind::UserRefreshToken);
    assert_eq!(failure.recovery_action, RecoveryAction::Investigate);
    assert_eq!(failure.failure_code, "oauth_unrecognized_error_response");
}

#[tokio::test]
async fn request_token_sends_accept_json() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "minted-token",
            "expires_in": 3600
        })))
        .mount(&mock_server)
        .await;

    let minted = request_token(
        &format!("{}/token", mock_server.uri()),
        &[("grant_type".to_string(), "refresh_token".to_string())],
        60,
        OAuthGrantKind::UserRefreshToken,
    )
    .await
    .unwrap();
    assert_eq!(minted.outputs["access_token"], "minted-token");
}
