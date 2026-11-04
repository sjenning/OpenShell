// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn metrics_have_only_bounded_labels_and_never_error_bodies_or_identifiers() {
    let recorder = prometheus_builder().unwrap().build_recorder();
    let handle = recorder.handle();
    let _guard = metrics::set_default_local_recorder(&recorder);
    let result = observe(Operation::PutSecret, async {
        Err::<(), _>(Status::internal("private-upstream-body-token"))
    })
    .await;
    assert_eq!(result.unwrap_err().code(), Code::Internal);
    observe(Operation::GetGrant, async { Ok(()) })
        .await
        .unwrap();
    let denied = observe(Operation::ResolveSecrets, async {
        Err::<(), _>(Status::permission_denied("private-workspace-token"))
    })
    .await;
    assert!(denied.is_err());
    drop(Observation::new(Operation::EnsureFresh));
    scheduler_snapshot(&[0, 1, 0, 0, 2, 0, 3, 0, 0, 0], 123_000);
    let rendered = handle.render();
    assert!(rendered.contains("openshell_issuer_operation_failures_total"));
    assert!(rendered.contains("code=\"internal\""));
    assert!(rendered.contains("operation=\"put_secret\""));
    assert!(rendered.contains("outcome=\"cancelled\""));
    assert!(rendered.contains("openshell_issuer_operation_duration_seconds_bucket"));
    assert!(rendered.contains("openshell_issuer_access_denied_total"));
    assert!(rendered.contains("openshell_issuer_grants{phase=\"parked\"} 3"));
    assert!(!rendered.contains("private-"));
    for forbidden_label in [
        "workspace=",
        "provider=",
        "grant=",
        "reference=",
        "strategy=",
    ] {
        assert!(!rendered.contains(forbidden_label));
    }
}

#[test]
fn denial_audit_is_structured_and_only_contains_sanitized_classification() {
    let event = audit_event(Operation::ResolveSecrets, Code::PermissionDenied);
    let json = event.to_json_line().unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["class_uid"], 6003);
    assert_eq!(value["api"]["operation"], "resolve_secrets");
    assert!(json.contains("permission_denied"));
    assert!(json.contains("Issuer access denied"));
    assert!(!json.contains("openshell-supervisor"));
    assert!(!json.contains("fingerprint"));
}

#[test]
fn only_recognized_correlated_provider_subtypes_are_projectable() {
    assert_eq!(
        recognized_provider_error_subtype("oauth_invalid_grant", "invalid_rapt"),
        Some("invalid_rapt")
    );
    assert_eq!(
        recognized_provider_error_subtype("oauth_admin_policy_enforced", "admin_policy_enforced"),
        Some("admin_policy_enforced")
    );
    for (code, subtype) in [
        ("oauth_invalid_grant", "private-upstream-error"),
        ("oauth_invalid_grant", "admin_policy_enforced"),
        ("", "invalid_rapt"),
        ("remote_minter_retry", "invalid_rapt"),
    ] {
        assert_eq!(recognized_provider_error_subtype(code, subtype), None);
    }
    assert_eq!(safe_error_message(""), "");
    assert!(!safe_error_message("private-upstream-error").contains("private"));
}

#[tokio::test]
async fn maintained_exporter_serves_a_real_prometheus_scrape() {
    openshell_crypto::tls::ensure_default_provider();
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let (recorder, exporter) = prometheus_builder()
        .unwrap()
        .with_http_listener(address)
        .build()
        .unwrap();
    metrics::with_local_recorder(&recorder, || {
        counter!("openshell_issuer_operations_total", "operation" => "put_secret", "outcome" => "success").increment(1);
    });
    let task = tokio::spawn(exporter);
    let response = reqwest::get(format!("http://{address}/metrics"))
        .await
        .unwrap();
    assert!(response.status().is_success());
    let body = response.text().await.unwrap();
    assert!(body.contains("openshell_issuer_operations_total"));
    assert!(body.contains("operation=\"put_secret\""));
    task.abort();
}
