// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{
    credentials::InternalSecretOwner,
    persistence::{current_time_ms, test_store},
};
use openshell_core::{Config, proto::ObjectMeta};
use openshell_credential_issuer::remote_issuer::IssuerChange;
use std::time::Duration;
pub mod issuer;
mod long_keys;
fn provider() -> Provider {
    Provider {
        metadata: Some(ObjectMeta {
            id: "provider-id".into(),
            name: "provider".into(),
            workspace: "default".into(),
            resource_version: 7,
            ..Default::default()
        }),
        ..Default::default()
    }
}
fn put() -> wire::PutSecretRequest {
    wire::PutSecretRequest {
        owner: Some(owner(&provider(), "TOKEN").unwrap()),
        value: "remote-first".into(),
        idempotency_key: "initial".into(),
        ..Default::default()
    }
}
#[tokio::test]
async fn remote_refresh_epochs_are_source_and_grant_bound_without_resolving_values() {
    use std::sync::atomic::Ordering;
    let issuer = issuer::Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let other = RemoteProviderSource::new("other", issuer.watched.clone()).unwrap();
    let mut provider = provider();
    provider.credential_handles = HashMap::from([
        (
            "TOKEN".into(),
            source
                .reference_handle("first-reference", Some("first-grant"))
                .unwrap(),
        ),
        (
            "STATIC".into(),
            source.reference_handle("static-reference", None).unwrap(),
        ),
    ]);
    let first = source.refresh_authorization_epochs(&provider).unwrap();
    assert_eq!(first.len(), 1);
    assert!(first.contains_key("TOKEN"));
    provider.metadata.as_mut().unwrap().resource_version += 1;
    provider.credential_expiration_times.insert(
        "TOKEN".into(),
        openshell_core::time::timestamp_from_millis(1).unwrap(),
    );
    assert_eq!(
        source.refresh_authorization_epochs(&provider).unwrap(),
        first
    );
    assert!(other.refresh_authorization_epochs(&provider).is_err());
    provider.credential_handles.insert(
        "TOKEN".into(),
        source
            .reference_handle("second-reference", Some("second-grant"))
            .unwrap(),
    );
    assert_ne!(
        source.refresh_authorization_epochs(&provider).unwrap(),
        first
    );
    provider.credential_handles.insert(
        "STATIC".into(),
        other.reference_handle("static-reference", None).unwrap(),
    );
    assert!(source.refresh_authorization_epochs(&provider).is_err());
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn delivery_cache_cannot_satisfy_refresh_or_operator_export_reads() {
    use std::sync::atomic::Ordering;
    let issuer = issuer::Issuer::start().await;
    let stored = issuer.raw.put_secret(put()).await.unwrap();
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let mut provider = provider();
    provider.credential_handles.insert(
        "TOKEN".into(),
        source.reference_handle(&stored.reference, None).unwrap(),
    );
    source.register_provider(&provider).unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    let first = source
        .resolve_provider_handles(&provider, current_time_ms())
        .await
        .unwrap();
    assert_eq!(first.values["TOKEN"], "remote-first");
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 1);
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    for purpose in [
        CredentialReadPurpose::Refresh,
        CredentialReadPurpose::OperatorExport,
    ] {
        assert_eq!(
            source
                .resolve_provider_handles_for(&provider, current_time_ms(), purpose)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
    }
    assert_eq!(
        source
            .resolve_provider_handles(&provider, current_time_ms())
            .await
            .unwrap()
            .values["TOKEN"],
        "remote-first"
    );
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn remote_reader_projects_versions_without_rewriting_provider_or_touching_internal_storage() {
    let issuer = issuer::Issuer::start().await;
    let first = issuer.raw.put_secret(put()).await.unwrap();
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let mut provider = provider();
    provider.credential_handles.insert(
        "TOKEN".into(),
        source.reference_handle(&first.reference, None).unwrap(),
    );
    source.register_provider(&provider).unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    let store = test_store().await;
    let before = provider.clone();
    assert_eq!(
        source.reference_versions(&store, &provider).await.unwrap()["TOKEN"],
        1
    );
    let resolved = source
        .resolve_provider_handles(&provider, current_time_ms())
        .await
        .unwrap();
    assert_eq!(resolved.values["TOKEN"], "remote-first");
    assert!(!format!("{resolved:?}").contains("remote-first"));
    assert_eq!(resolved.versions["TOKEN"], 1);
    let local =
        CredentialRuntime::from_config(&Config::new(None).with_credential_drivers(["test-static"]))
            .unwrap();
    let internal = local.internal_secrets();
    let identity = InternalSecretOwner {
        kind: openshell_credential_issuer::SecretOwnerKind::Sandbox,
        name: "gateway-internal",
        workspace: "default",
        id: "internal-id",
    };
    let handles = internal
        .store(
            identity,
            "internal-object",
            &HashMap::from([("SSH_HOST_KEY".into(), "local-host-key".into())]),
        )
        .await
        .unwrap();
    assert_eq!(internal.stored_credential_count(), Some(1));
    assert_eq!(
        internal.resolve(identity, &handles).await.unwrap()["SSH_HOST_KEY"],
        "local-host-key"
    );
    let mut changes = issuer.watched.changes();
    issuer
        .raw
        .put_secret(wire::PutSecretRequest {
            reference: first.reference.clone(),
            value: "remote-second".into(),
            expected_version: Some(1),
            idempotency_key: "rotation".into(),
            ..put()
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let IssuerChange::Secret {
                reference, version, ..
            } = changes.recv().await.unwrap()
                && reference == first.reference
                && version == 2
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        source.reference_versions(&store, &provider).await.unwrap()["TOKEN"],
        2
    );
    assert_eq!(
        source
            .resolve_provider_handles(&provider, current_time_ms())
            .await
            .unwrap()
            .values["TOKEN"],
        "remote-second"
    );
    assert_eq!(provider, before);
    assert_eq!(internal.stored_credential_count(), Some(1));
    assert_eq!(
        internal.resolve(identity, &handles).await.unwrap()["SSH_HOST_KEY"],
        "local-host-key"
    );
    assert!(
        local
            .resolve_provider_handles(&provider, current_time_ms())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn remote_reader_rejects_wrong_sources_owners_inline_values_and_legacy_fallback() {
    let issuer = issuer::Issuer::start().await;
    let first = issuer.raw.put_secret(put()).await.unwrap();
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let other = RemoteProviderSource::new("different", issuer.watched.clone()).unwrap();
    let mut provider = provider();
    provider.credential_handles.insert(
        "TOKEN".into(),
        source.reference_handle(&first.reference, None).unwrap(),
    );
    source.register_provider(&provider).unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    assert!(other.register_provider(&provider).is_err());
    let mut forged = provider.clone();
    forged.metadata.as_mut().unwrap().id = "other-provider".into();
    assert!(source.register_provider(&forged).is_err());
    forged = provider.clone();
    forged.metadata.as_mut().unwrap().workspace = "other-workspace".into();
    assert!(source.register_provider(&forged).is_err());
    forged = provider.clone();
    forged.credentials.insert("TOKEN".into(), "inline".into());
    assert!(
        source
            .resolve_provider_handles(&forged, current_time_ms())
            .await
            .is_err()
    );
    forged = provider.clone();
    forged.credential_handles.get_mut("TOKEN").unwrap().driver = "test-static".into();
    assert!(source.register_provider(&forged).is_err());
    provider.metadata.as_mut().unwrap().name = "renamed-display".into();
    assert_eq!(
        source
            .resolve_provider_handles(&provider, current_time_ms())
            .await
            .unwrap()
            .values["TOKEN"],
        "remote-first"
    );
    provider.credential_expiration_times.insert(
        "TOKEN".into(),
        openshell_core::time::timestamp_from_millis(1).unwrap(),
    );
    let expired = source
        .resolve_provider_handles(&provider, current_time_ms())
        .await
        .unwrap();
    assert!(expired.values.is_empty());
    assert!(expired.expired_keys.contains("TOKEN"));
}
