// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    INTERMEDIATE_TOKEN_CACHE, IntermediateTokenCacheKeyInput, SubjectTokenLookup,
    get_provider_record, intermediate_token_cache_key, list_provider_records,
    load_provider_environment_records_with_source, lookup_subject_token,
    resolve_provider_environment_from_records_with_policy_bindings_and_credentials,
};
use crate::credentials::{CredentialRuntime, references};
use crate::persistence::{current_time_ms, test_store};
use openshell_core::proto::{ObjectMeta, Provider};
use openshell_core::{Config, ObjectId};
use std::collections::HashMap;
use std::sync::Arc;

mod expiration_authority;

fn provider() -> Provider {
    Provider {
        metadata: Some(ObjectMeta {
            id: "provider-id".to_string(),
            name: "provider".to_string(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[derive(Debug)]
struct Source(std::sync::atomic::AtomicU64);
#[async_trait::async_trait]
impl crate::credential_source::ProviderCredentialSource for Source {
    async fn project_expiration_metadata(
        &self,
        _store: &crate::persistence::Store,
        _provider: &mut Provider,
    ) -> Result<(), tonic::Status> {
        Ok(())
    }
    async fn reference_versions(
        &self,
        _store: &crate::persistence::Store,
        provider: &Provider,
    ) -> Result<HashMap<String, u64>, tonic::Status> {
        Ok(provider
            .credential_handles
            .keys()
            .map(|key| {
                (
                    key.clone(),
                    self.0.load(std::sync::atomic::Ordering::SeqCst),
                )
            })
            .collect())
    }
    async fn resolve_provider_handles_for(
        &self,
        provider: &Provider,
        _now: i64,
        _purpose: crate::credential_source::CredentialReadPurpose,
    ) -> Result<crate::credentials::ResolvedProviderCredentials, tonic::Status> {
        let version = self.0.load(std::sync::atomic::Ordering::SeqCst);
        Ok(crate::credentials::ResolvedProviderCredentials {
            values: provider
                .credential_handles
                .keys()
                .map(|key| (key.clone(), format!("source-{version}")))
                .collect(),
            versions: provider
                .credential_handles
                .keys()
                .map(|key| (key.clone(), version))
                .collect(),
            ..Default::default()
        })
    }
}
#[tokio::test]
async fn snapshot_reader_uses_one_source_for_capture_and_resolution_and_fences_changed_versions() {
    let store = test_store().await;
    let mut provider = provider();
    provider.r#type = "custom".into();
    provider.credential_handles.insert(
        "TOKEN".into(),
        openshell_core::proto::CredentialHandle {
            driver: "not-an-embedded-driver".into(),
            handle: "unreadable".into(),
            metadata: HashMap::new(),
        },
    );
    store.put_message(&provider).await.unwrap();
    let names = vec!["provider".into()];
    let source = Source(std::sync::atomic::AtomicU64::new(2));
    let records =
        load_provider_environment_records_with_source(&store, "default", &names, Some(&source))
            .await
            .unwrap();
    assert_eq!(records[0].credential_versions["TOKEN"], 2);
    let catalog = crate::provider_profile_sources::ProviderProfileSources::with_default_sources()
        .snapshot_catalog(&store, "default")
        .await
        .unwrap();
    let first = resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
        &catalog,
        &records,
        &HashMap::new(),
        &source,
        None,
    )
    .await
    .unwrap();
    assert_eq!(first.environment["TOKEN"], "source-2");
    source.0.store(3, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
            &catalog,
            &records,
            &HashMap::new(),
            &source,
            None
        )
        .await
        .unwrap_err()
        .code(),
        tonic::Code::Aborted
    );
    let current =
        load_provider_environment_records_with_source(&store, "default", &names, Some(&source))
            .await
            .unwrap();
    assert_eq!(current[0].resource_version, records[0].resource_version);
    assert_eq!(current[0].credential_versions["TOKEN"], 3);
}

#[test]
fn subject_cache_identity_includes_reference_version_even_with_unchanged_provider_revision() {
    let provider = provider();
    let key = |version| {
        intermediate_token_cache_key(IntermediateTokenCacheKeyInput {
            provider: &provider,
            dynamic_credential: "ACCESS_TOKEN",
            subject_credential: "SUBJECT_TOKEN",
            subject_credential_version: version,
            token_endpoint: "https://example.test/token",
            client_assertion_type: "jwt-bearer",
            subject_token_type: "access_token",
            audience: "service",
            requested_token_type: "access_token",
            supervisor_subject: "spiffe://example/supervisor",
            gateway_subject: "spiffe://example/gateway",
        })
    };
    assert_eq!(key(1), key(1));
    assert_ne!(key(1), key(2));
}

#[tokio::test]
async fn intermediate_cache_hit_never_resolves_subject_values_but_keeps_metadata_fences() {
    let runtime =
        CredentialRuntime::from_config(&Config::new(None).with_credential_drivers(["test-static"]))
            .unwrap();
    let mut provider = provider();
    let key = format!("cache-before-subject:{}", uuid::Uuid::new_v4());
    let handle = openshell_core::proto::CredentialHandle {
        driver: "unavailable-subject-backend".into(),
        handle: "opaque".into(),
        metadata: HashMap::new(),
    };
    provider
        .credential_handles
        .insert("SUBJECT_TOKEN".into(), handle.clone());
    let token = openshell_core::oauth::OAuthTokenResponse {
        access_token: "intermediate-token".into(),
        expires_in: 60,
        token_type: "Bearer".into(),
    };
    INTERMEDIATE_TOKEN_CACHE.set(key.clone(), &token, current_time_ms() + 60_000);
    let SubjectTokenLookup::Cached(cached) =
        lookup_subject_token(&runtime, &provider, "SUBJECT_TOKEN", &key)
            .await
            .unwrap()
    else {
        panic!("cache hit resolved a subject credential")
    };
    assert_eq!(cached.access_token, "intermediate-token");
    provider.credential_expiration_times.insert(
        "SUBJECT_TOKEN".into(),
        openshell_core::time::timestamp_from_millis(1).unwrap(),
    );
    assert!(
        lookup_subject_token(&runtime, &provider, "SUBJECT_TOKEN", &key)
            .await
            .is_err()
    );
    provider.credential_expiration_times.clear();
    provider.credential_handles.clear();
    assert!(
        lookup_subject_token(&runtime, &provider, "SUBJECT_TOKEN", &key)
            .await
            .is_err()
    );
    provider
        .credential_handles
        .insert("SUBJECT_TOKEN".into(), handle);
    INTERMEDIATE_TOKEN_CACHE.set(key.clone(), &token, 1);
    let error = lookup_subject_token(&runtime, &provider, "SUBJECT_TOKEN", &key)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn remote_subject_metadata_and_cache_hits_do_not_depend_on_available_value_storage() {
    use crate::credential_source::{ProviderCredentialSource as _, RemoteProviderSource};
    use openshell_core::proto::credentials::store::v1 as wire;
    use std::sync::atomic::Ordering;
    let issuer = crate::credential_source::tests::issuer::Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let store = test_store().await;
    let mut provider = provider();
    let owner = wire::SecretOwner {
        workspace: "default".into(),
        provider_id: provider.object_id().into(),
        credential_key: "SUBJECT_TOKEN".into(),
        provider: "display".into(),
    };
    let expiration = current_time_ms() + 60_000;
    let stored = issuer
        .raw
        .put_secret(wire::PutSecretRequest {
            owner: Some(owner.clone()),
            value: "stored-subject".into(),
            expiration_time: Some(openshell_core::time::timestamp_from_millis(expiration).unwrap()),
            idempotency_key: "subject".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    provider.credential_handles.insert(
        "SUBJECT_TOKEN".into(),
        source.reference_handle(&stored.reference, None).unwrap(),
    );
    source.register_provider(&provider).unwrap();
    issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    source
        .project_expiration_metadata(&store, &mut provider)
        .await
        .unwrap();
    assert_eq!(
        provider.credential_expiration_times["SUBJECT_TOKEN"],
        openshell_core::time::timestamp_from_millis(expiration).unwrap()
    );
    assert_eq!(
        source.reference_versions(&store, &provider).await.unwrap()["SUBJECT_TOKEN"],
        1
    );
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
    let key = format!("remote-subject:{}", uuid::Uuid::new_v4());
    let token = openshell_core::oauth::OAuthTokenResponse {
        access_token: "cached-intermediate".into(),
        expires_in: 60,
        token_type: "Bearer".into(),
    };
    INTERMEDIATE_TOKEN_CACHE.set(key.clone(), &token, expiration);
    let SubjectTokenLookup::Cached(cached) =
        lookup_subject_token(&source, &provider, "SUBJECT_TOKEN", &key)
            .await
            .unwrap()
    else {
        panic!("cache hit resolved issuer values")
    };
    assert_eq!(cached.access_token, "cached-intermediate");
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
    INTERMEDIATE_TOKEN_CACHE.set(key.clone(), &token, 1);
    assert_eq!(
        lookup_subject_token(&source, &provider, "SUBJECT_TOKEN", &key)
            .await
            .err()
            .unwrap()
            .code(),
        tonic::Code::Unavailable
    );
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 1);
    issuer
        .watched
        .put_secret(wire::PutSecretRequest {
            owner: Some(owner),
            reference: stored.reference,
            expected_version: Some(1),
            value: "nonexpiring-subject".into(),
            idempotency_key: "replace-subject".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    provider.credential_expiration_times.insert(
        "SUBJECT_TOKEN".into(),
        openshell_core::time::timestamp_from_millis(1).unwrap(),
    );
    source
        .project_expiration_metadata(&store, &mut provider)
        .await
        .unwrap();
    assert!(
        !provider
            .credential_expiration_times
            .contains_key("SUBJECT_TOKEN")
    );
    assert_eq!(
        source.reference_versions(&store, &provider).await.unwrap()["SUBJECT_TOKEN"],
        2
    );
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn public_get_and_list_use_selected_remote_expiration_without_value_reads_or_provider_writes()
{
    use super::super::{handle_get_provider, handle_list_providers};
    use super::{authed_request, test_server_state};
    use crate::credential_source::RemoteProviderSource;
    use openshell_core::proto::{
        GetProviderRequest, ListProvidersRequest, credentials::store::v1 as wire,
    };
    use std::sync::atomic::Ordering;
    let mut state = test_server_state().await;
    let issuer = crate::credential_source::tests::issuer::Issuer::start().await;
    let source = Arc::new(RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap());
    let mut provider = provider();
    let owner = wire::SecretOwner {
        workspace: "default".into(),
        provider_id: provider.object_id().into(),
        credential_key: "SUBJECT_TOKEN".into(),
        provider: "display".into(),
    };
    let stored = issuer
        .raw
        .put_secret(wire::PutSecretRequest {
            owner: Some(owner.clone()),
            value: "never-export-this-value".into(),
            idempotency_key: "public-metadata".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    provider.credential_handles.insert(
        "SUBJECT_TOKEN".into(),
        source.reference_handle(&stored.reference, None).unwrap(),
    );
    let legacy = openshell_core::time::timestamp_from_millis(1).unwrap();
    provider
        .credential_expiration_times
        .insert("SUBJECT_TOKEN".into(), legacy);
    source.register_provider(&provider).unwrap();
    issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    Arc::get_mut(&mut state).unwrap().provider_source = Some(source);
    state.store.put_message(&provider).await.unwrap();
    let before = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    let get = || {
        authed_request(GetProviderRequest {
            name: "provider".into(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        })
    };
    let initial = handle_get_provider(&state, get())
        .await
        .unwrap()
        .into_inner()
        .provider
        .unwrap();
    assert_eq!(initial.credential_expiration_times["SUBJECT_TOKEN"], legacy);
    let expiration = current_time_ms() + 60_000;
    let timestamp = openshell_core::time::timestamp_from_millis(expiration).unwrap();
    issuer
        .watched
        .put_secret(wire::PutSecretRequest {
            owner: Some(owner),
            reference: stored.reference,
            expected_version: Some(1),
            value: "still-never-export".into(),
            expiration_time: Some(timestamp),
            idempotency_key: "replace-public-metadata".into(),
        })
        .await
        .unwrap();
    issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    let get = handle_get_provider(&state, get())
        .await
        .unwrap()
        .into_inner()
        .provider
        .unwrap();
    let list = handle_list_providers(
        &state,
        authed_request(ListProvidersRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(list.providers.len(), 1);
    for provider in [&get, &list.providers[0]] {
        assert_eq!(
            provider.credential_expiration_times["SUBJECT_TOKEN"],
            timestamp
        );
        assert!(provider.credential_handles.is_empty());
        assert_eq!(provider.credentials["SUBJECT_TOKEN"], "REDACTED");
    }
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
    assert_eq!(
        state
            .store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap(),
        before
    );
}

#[tokio::test]
async fn get_and_list_project_current_reference_expiration_without_mutating_or_revealing_values() {
    let store = Arc::new(test_store().await);
    let runtime =
        CredentialRuntime::from_config_with_store(&Config::new(None), store.clone()).unwrap();
    let mut provider = provider();
    provider.credential_handles = runtime
        .store_provider_credentials(
            "provider",
            "default",
            "provider-id",
            &HashMap::from([("GITHUB_TOKEN".to_string(), "initial-secret".to_string())]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    let legacy_expiration = openshell_core::time::timestamp_from_millis(1).unwrap();
    provider
        .credential_expiration_times
        .insert("GITHUB_TOKEN".to_string(), legacy_expiration);
    store.put_message(&provider).await.unwrap();
    let before = store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        get_provider_record(&store, "default", "provider")
            .await
            .unwrap()
            .credential_expiration_times["GITHUB_TOKEN"],
        legacy_expiration
    );
    let current_expiration = current_time_ms() + 60_000;
    runtime
        .rotate_provider_reference(
            references::provider_scope(&provider, "GITHUB_TOKEN"),
            &provider.credential_handles["GITHUB_TOKEN"],
            1,
            "rotated-secret",
            Some(current_expiration),
        )
        .await
        .unwrap();
    let current_timestamp =
        openshell_core::time::timestamp_from_millis(current_expiration).unwrap();
    let get = get_provider_record(&store, "default", "provider")
        .await
        .unwrap();
    let list = list_provider_records(&store, "default", 10, 0)
        .await
        .unwrap();
    assert_eq!(
        get.credential_expiration_times["GITHUB_TOKEN"],
        current_timestamp
    );
    assert_eq!(
        list[0].credential_expiration_times["GITHUB_TOKEN"],
        current_timestamp
    );
    assert!(get.credential_handles.is_empty());
    assert_eq!(get.credentials["GITHUB_TOKEN"], "REDACTED");
    assert_eq!(
        store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap(),
        before
    );
    runtime
        .rotate_provider_reference(
            references::provider_scope(&provider, "GITHUB_TOKEN"),
            &provider.credential_handles["GITHUB_TOKEN"],
            2,
            "nonexpiring-secret",
            None,
        )
        .await
        .unwrap();
    assert!(
        !get_provider_record(&store, "default", "provider")
            .await
            .unwrap()
            .credential_expiration_times
            .contains_key("GITHUB_TOKEN")
    );
}
