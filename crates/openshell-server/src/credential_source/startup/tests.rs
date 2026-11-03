// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{
    credential_source::{ProviderCredentialSource as _, tests::issuer::Issuer, wire},
    persistence::test_store,
};
use openshell_core::proto::ObjectMeta;
use std::{collections::HashMap, sync::atomic::Ordering};
fn config() -> RemoteConfig {
    toml::from_str(
        r#"
name="primary"
endpoint="https://issuer.example:8443"
server_ca_path="/trust/ca.pem"
client_cert_path="/identity/client.pem"
client_key_path="/identity/client.key"
"#,
    )
    .unwrap()
}
fn provider() -> Provider {
    Provider {
        metadata: Some(ObjectMeta {
            id: "provider".into(),
            name: "display".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        r#type: "custom".into(),
        ..Default::default()
    }
}
#[test]
fn remote_configuration_requires_explicit_trust_identity_and_bounded_intervals() {
    let valid = config();
    valid.validate().unwrap();
    assert_eq!(valid.startup_timeout_seconds, 30);
    assert_eq!(valid.cleanup_idle_seconds, 300);
    assert!(!format!("{valid:?}").contains("issuer.example"));
    for endpoint in [
        "http://localhost:1",
        "https://user:never-echo-this@issuer.example",
        "https://issuer.example/path",
        "https://issuer.example?secret=never-echo-this",
    ] {
        let mut invalid = valid.clone();
        invalid.endpoint = endpoint.into();
        let error = invalid.validate().unwrap_err();
        assert!(!error.to_string().contains("never-echo-this"));
    }
    for name in ["", "Primary", "with space", "path/name", &"a".repeat(129)] {
        let mut invalid = valid.clone();
        invalid.name = name.into();
        assert!(invalid.validate().is_err());
    }
    for name in ["primary", "issuer_1.local-prod", &"a".repeat(128)] {
        let mut config = valid.clone();
        config.name = name.into();
        config.validate().unwrap();
    }
    let mut invalid = valid.clone();
    invalid.client_key_path = None;
    assert!(invalid.validate().is_err());
    let mut invalid = valid.clone();
    invalid.server_ca_path = "relative.pem".into();
    assert!(invalid.validate().is_err());
    for seconds in [0, 301] {
        let mut invalid = valid.clone();
        invalid.startup_timeout_seconds = seconds;
        assert!(invalid.validate().is_err());
    }
    for seconds in [0, 59, 3601] {
        let mut invalid = valid.clone();
        invalid.cleanup_idle_seconds = seconds;
        assert!(invalid.validate().is_err());
    }
    let mut spiffe = valid;
    spiffe.client_cert_path = None;
    spiffe.client_key_path = None;
    spiffe.workload_api_endpoint = Some("unix:///run/spire/agent.sock".into());
    spiffe.spiffe_id = Some("spiffe://example.test/gateway/a".into());
    spiffe.validate().unwrap();
    spiffe.client_key_path = Some("/identity/key".into());
    assert!(spiffe.validate().is_err());
    spiffe.client_key_path = None;
    spiffe.workload_api_endpoint = Some("https://remote-agent".into());
    assert!(spiffe.validate().is_err());
}
#[test]
fn gateway_file_selection_is_strict_and_preflight_does_not_connect_or_read_identity_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("gateway.toml");
    let input = format!(
        "[openshell]\nversion=2\n[openshell.gateway.credential_issuer]\n{}",
        toml::to_string(&config()).unwrap()
    );
    std::fs::write(&path, &input).unwrap();
    let parsed = crate::config_file::load(&path).unwrap();
    assert!(parsed.openshell.gateway.credential_issuer.is_some());
    std::fs::write(&path, format!("{input}\nallow_insecure_transport=true\n")).unwrap();
    assert!(crate::config_file::load(&path).is_err());
    std::fs::write(
        &path,
        input.replace("https://issuer.example:8443", "http://issuer.example:8443"),
    )
    .unwrap();
    assert!(crate::config_file::load(&path).is_err());
    std::fs::write(
        &path,
        input.replace("name = \"primary\"", "name = \"Primary\""),
    )
    .unwrap();
    assert!(crate::config_file::load(&path).is_err());
}
#[tokio::test]
async fn remote_startup_registers_existing_bindings_without_values_or_provider_rewrites() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let owner = wire::SecretOwner {
        workspace: "default".into(),
        provider_id: "provider".into(),
        credential_key: "TOKEN".into(),
        provider: "display".into(),
    };
    let reserved = issuer
        .raw
        .reserve_secret(wire::ReserveSecretRequest {
            owner: Some(owner),
            idempotency_key: "reserved".into(),
        })
        .await
        .unwrap();
    let mut provider = provider();
    provider.credential_handles.insert(
        "TOKEN".into(),
        source.reference_handle(&reserved.reference, None).unwrap(),
    );
    store.put_message(&provider).await.unwrap();
    let before = store
        .get("provider", provider.object_id())
        .await
        .unwrap()
        .unwrap();
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    let selected = issuer.startup.connect(&store).await.unwrap();
    let versions = selected
        .reference_versions(&store, &provider)
        .await
        .unwrap();
    assert_eq!(versions["TOKEN"], 1);
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
    let after = store
        .get("provider", provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.payload, before.payload);
    assert_eq!(after.resource_version, before.resource_version);
    let mut wrong = issuer.startup.clone();
    wrong.name = "different".into();
    assert_eq!(
        wrong.connect(&store).await.unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
}
#[tokio::test]
async fn remote_startup_rejects_inline_credentials_and_embedded_grants_without_adoption() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let mut provider = provider();
    provider.credentials = HashMap::from([("TOKEN".into(), "never-transfer-on-startup".into())]);
    store.put_message(&provider).await.unwrap();
    let before = store
        .get("provider", provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        issuer.startup.connect(&store).await.unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        store
            .get("provider", provider.object_id())
            .await
            .unwrap()
            .unwrap()
            .payload,
        before.payload
    );
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
    let empty = test_store().await;
    empty
        .put(
            "provider_credential_refresh_state",
            "legacy",
            "legacy",
            "default",
            b"{}",
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        issuer.startup.connect(&empty).await.unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
}
#[tokio::test]
async fn startup_inventory_is_paged_and_rejects_late_legacy_rows() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    for index in 0..129 {
        let mut record = provider();
        record.metadata.as_mut().unwrap().id = format!("provider-{index:03}");
        record.metadata.as_mut().unwrap().name = format!("provider-{index:03}");
        store.put_message(&record).await.unwrap();
    }
    let mut legacy = provider();
    legacy.metadata.as_mut().unwrap().id = "zzz".into();
    legacy.metadata.as_mut().unwrap().name = "zzz".into();
    legacy
        .credentials
        .insert("TOKEN".into(), "must-not-adopt".into());
    store.put_message(&legacy).await.unwrap();
    assert_eq!(
        register_existing(&store, &source).await.unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn missing_trust_wrong_identity_and_tls_stalls_never_fall_back() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let mut missing = issuer.startup.clone();
    missing.server_ca_path = issuer
        .startup
        .server_ca_path
        .parent()
        .unwrap()
        .join("missing.pem");
    assert_eq!(
        missing.connect(&store).await.unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    let other = Issuer::start().await;
    let mut wrong = issuer.startup.clone();
    wrong.client_cert_path = other.startup.client_cert_path.clone();
    wrong.client_key_path = other.startup.client_key_path.clone();
    assert!(wrong.connect(&store).await.is_err());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut stalled = issuer.startup.clone();
    stalled.endpoint = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    stalled.startup_timeout_seconds = 1;
    let task = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    assert_eq!(
        stalled.connect(&store).await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
    task.abort();
}
