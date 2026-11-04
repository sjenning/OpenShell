// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::grpc::{
    provider::{
        handle_configure_provider_refresh, handle_delete_provider_refresh, handle_update_provider,
        resolve_provider_environment_from_records_with_credentials,
        validate_provider_credential_key_available_for_attached_sandboxes_with_catalog,
        validate_provider_environment_keys_unique_with_catalog,
        validate_provider_update_against_attached_sandboxes_with_catalog,
    },
    test_support::{authed_request, test_server_state},
};
use openshell_core::proto::{
    ConfigureProviderRefreshRequest, DeleteProviderRefreshRequest,
    ProviderCredentialRefreshStrategy, Sandbox, SandboxSpec, UpdateProviderRequest,
};
use tonic::Code;

async fn stored(state: &crate::ServerState) -> Provider {
    let mut provider = provider();
    provider.r#type = "custom".into();
    provider.credential_handles = state
        .credentials
        .store_provider_credentials(
            "provider",
            "default",
            "provider-id",
            &HashMap::from([("TOKEN".into(), "first".into())]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    provider.credential_expiration_times.insert(
        "TOKEN".into(),
        openshell_core::time::timestamp_from_millis(1).unwrap(),
    );
    state.store.put_message(&provider).await.unwrap();
    state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap()
}

fn update(expiration: Option<i64>, clear: bool) -> UpdateProviderRequest {
    UpdateProviderRequest {
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        provider: Some(Provider {
            metadata: Some(ObjectMeta {
                name: "provider".into(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        credential_expiration_times: expiration
            .map(|expiration| {
                HashMap::from([(
                    "TOKEN".into(),
                    openshell_core::time::timestamp_from_millis(expiration).unwrap(),
                )])
            })
            .unwrap_or_default(),
        clear_credential_expiration_keys: if clear {
            vec!["TOKEN".into()]
        } else {
            Vec::new()
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn expiration_only_updates_cannot_silently_override_versioned_reference_authority() {
    let state = test_server_state().await;
    let provider = stored(&state).await;
    let expires = current_time_ms() + 60_000;
    state
        .credentials
        .rotate_provider_reference(
            references::provider_scope(&provider, "TOKEN"),
            &provider.credential_handles["TOKEN"],
            1,
            "rotated",
            Some(expires),
        )
        .await
        .unwrap();
    for request in [update(Some(1), false), update(None, true)] {
        let error = handle_update_provider(&state, authed_request(request))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("issuer-owned"));
        assert_eq!(
            state
                .store
                .get_message::<Provider>(provider.object_id())
                .await
                .unwrap()
                .unwrap(),
            provider
        );
    }
    // A caller echoing current metadata does not ask for an ineffective edit.
    handle_update_provider(&state, authed_request(update(Some(expires), false)))
        .await
        .unwrap();
    // Replacing a static value starts a new reference, so it may choose expiry.
    let mut replacement = update(Some(expires + 60_000), false);
    replacement
        .provider
        .as_mut()
        .unwrap()
        .credentials
        .insert("TOKEN".into(), "replacement".into());
    handle_update_provider(&state, authed_request(replacement))
        .await
        .unwrap();
    let replaced = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let resolved = state
        .credentials
        .resolve_provider_handles(&replaced, current_time_ms())
        .await
        .unwrap();
    assert_eq!(resolved.values["TOKEN"], "replacement");
    assert_eq!(resolved.expires_at_ms["TOKEN"], expires + 60_000);
}

#[tokio::test]
async fn version_one_expiration_updates_and_clears_still_control_delivery() {
    let state = test_server_state().await;
    let provider = stored(&state).await;
    let expires = current_time_ms() + 60_000;
    handle_update_provider(&state, authed_request(update(Some(expires), false)))
        .await
        .unwrap();
    let current = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let resolved = state
        .credentials
        .resolve_provider_handles(&current, current_time_ms())
        .await
        .unwrap();
    assert_eq!(resolved.expires_at_ms["TOKEN"], expires);
    handle_update_provider(&state, authed_request(update(None, true)))
        .await
        .unwrap();
    let current = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let resolved = state
        .credentials
        .resolve_provider_handles(&current, current_time_ms())
        .await
        .unwrap();
    assert_eq!(resolved.values["TOKEN"], "first");
    assert!(!resolved.expires_at_ms.contains_key("TOKEN"));
}

#[tokio::test]
async fn config_only_update_returns_projected_expiry_without_rewriting_stored_authority() {
    let state = test_server_state().await;
    let provider = stored(&state).await;
    let mut expires = Some(current_time_ms() + 60_000);
    for version in 1..=2 {
        state
            .credentials
            .rotate_provider_reference(
                references::provider_scope(&provider, "TOKEN"),
                &provider.credential_handles["TOKEN"],
                version,
                "rotated",
                expires,
            )
            .await
            .unwrap();
        let mut request = update(None, false);
        request
            .provider
            .as_mut()
            .unwrap()
            .config
            .insert("SETTING".into(), format!("value-{version}"));
        let response = handle_update_provider(&state, authed_request(request))
            .await
            .unwrap()
            .into_inner()
            .provider
            .unwrap();
        let current = state
            .store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.credential_handles, provider.credential_handles);
        assert_eq!(
            current.credential_expiration_times, provider.credential_expiration_times,
            "projection must not rewrite the stored legacy expiration"
        );
        assert_eq!(
            response.credential_expiration_times.get("TOKEN"),
            expires
                .map(|value| openshell_core::time::timestamp_from_millis(value).unwrap())
                .as_ref()
        );
        assert_eq!(response.config, current.config);
        assert_eq!(response.metadata, current.metadata);
        assert!(response.credential_handles.is_empty());
        assert_eq!(response.credentials["TOKEN"], "REDACTED");
        assert_eq!(
            response,
            get_provider_record(&state.store, "default", "provider")
                .await
                .unwrap()
        );
        expires = None;
    }
}

#[tokio::test]
async fn remote_config_only_update_projects_expiry_without_value_reads() {
    use crate::credential_source::RemoteProviderSource;
    use openshell_core::proto::{CreateProviderRequest, credentials::store::v1 as wire};
    use std::sync::atomic::Ordering;

    let mut state = test_server_state().await;
    let issuer = crate::credential_source::tests::issuer::Issuer::start().await;
    let source = Arc::new(RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap());
    Arc::get_mut(&mut state).unwrap().provider_source = Some(source.clone());
    crate::grpc::provider::handle_create_provider(
        &state,
        authed_request(CreateProviderRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            provider: Some(Provider {
                metadata: Some(ObjectMeta {
                    name: "provider".into(),
                    ..Default::default()
                }),
                r#type: "openai".into(),
                credentials: HashMap::from([("OPENAI_API_KEY".into(), "initial".into())]),
                ..Default::default()
            }),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let before = state
        .store
        .get_message_by_name::<Provider>("default", "provider")
        .await
        .unwrap()
        .unwrap();
    let binding: serde_json::Value =
        serde_json::from_str(&before.credential_handles["OPENAI_API_KEY"].handle).unwrap();
    let expires = current_time_ms() + 60_000;
    let timestamp = openshell_core::time::timestamp_from_millis(expires).unwrap();
    issuer
        .watched
        .put_secret(wire::PutSecretRequest {
            owner: Some(wire::SecretOwner {
                workspace: "default".into(),
                provider_id: before.object_id().into(),
                credential_key: "OPENAI_API_KEY".into(),
                provider: "provider".into(),
                ..Default::default()
            }),
            reference: binding["reference"].as_str().unwrap().into(),
            expected_version: Some(2),
            value: "rotated".into(),
            expiration_time: Some(timestamp),
            idempotency_key: "config-response-rotation".into(),
        })
        .await
        .unwrap();
    issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    let before_reads = issuer.resolves.load(Ordering::SeqCst);
    let mut request = update(None, false);
    request
        .provider
        .as_mut()
        .unwrap()
        .config
        .insert("SETTING".into(), "new-config".into());
    let response = handle_update_provider(&state, authed_request(request))
        .await
        .unwrap()
        .into_inner()
        .provider
        .unwrap();
    assert_eq!(
        response.credential_expiration_times["OPENAI_API_KEY"],
        timestamp
    );
    let current = state
        .store
        .get_message::<Provider>(before.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.credential_handles, before.credential_handles);
    assert_eq!(
        current.credential_expiration_times,
        before.credential_expiration_times
    );
    assert_eq!(response.config, current.config);
    assert_eq!(response.metadata, current.metadata);
    assert!(response.credential_handles.is_empty());
    assert_eq!(response.credentials["OPENAI_API_KEY"], "REDACTED");
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), before_reads);
}

fn configure(expiration: Option<i64>, secret: &str) -> ConfigureProviderRefreshRequest {
    ConfigureProviderRefreshRequest {
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        provider: "provider".into(),
        credential_key: "TOKEN".into(),
        strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
        material: HashMap::from([
            ("client_id".into(), "client".into()),
            ("client_secret".into(), secret.into()),
        ]),
        expiration_time: expiration
            .map(|value| openshell_core::time::timestamp_from_millis(value).unwrap()),
        ..Default::default()
    }
}

#[tokio::test]
async fn versioned_refresh_reconfiguration_checks_expiry_before_any_durable_effect() {
    let state = test_server_state().await;
    let provider = stored(&state).await;
    handle_configure_provider_refresh(&state, authed_request(configure(Some(1), "original")))
        .await
        .unwrap();
    let before_provider = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let expires = current_time_ms() + 60_000;
    state
        .credentials
        .rotate_provider_reference(
            references::provider_scope(&provider, "TOKEN"),
            &provider.credential_handles["TOKEN"],
            1,
            "rotated",
            Some(expires),
        )
        .await
        .unwrap();
    let before_grant = crate::provider_refresh::get_refresh_state(
        &state.store,
        "default",
        provider.object_id(),
        "TOKEN",
    )
    .await
    .unwrap()
    .unwrap();
    let before_count = state.credentials.stored_credential_count();
    for expiration in [1, 0, expires + 60_000] {
        let error = handle_configure_provider_refresh(
            &state,
            authed_request(configure(Some(expiration), "rejected")),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("issuer-owned"));
        assert_eq!(state.credentials.stored_credential_count(), before_count);
        assert_eq!(
            crate::provider_refresh::get_refresh_state(
                &state.store,
                "default",
                provider.object_id(),
                "TOKEN",
            )
            .await
            .unwrap()
            .unwrap(),
            before_grant,
            "rejected reconfiguration must preserve material handles and authorization epoch"
        );
        assert_eq!(
            state
                .store
                .get_message::<Provider>(provider.object_id())
                .await
                .unwrap()
                .unwrap(),
            before_provider
        );
    }
    for expiration in [None, Some(expires)] {
        let response = handle_configure_provider_refresh(
            &state,
            authed_request(configure(expiration, "accepted")),
        )
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
        assert_eq!(
            response.expiration_time,
            Some(openshell_core::time::timestamp_from_millis(expires).unwrap())
        );
        let grant = crate::provider_refresh::get_refresh_state(
            &state.store,
            "default",
            provider.object_id(),
            "TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(grant.expires_at_ms, expires);
        assert_ne!(grant.authorization_epoch, before_grant.authorization_epoch);
        assert_ne!(
            grant.secret_material_handles,
            before_grant.secret_material_handles
        );
        assert_eq!(
            state
                .store
                .get_message::<Provider>(provider.object_id())
                .await
                .unwrap()
                .unwrap(),
            before_provider,
            "versioned configure must not rewrite legacy provider expiration"
        );
    }
    let resolved = state
        .credentials
        .resolve_provider_handles(&before_provider, current_time_ms())
        .await
        .unwrap();
    assert_eq!(resolved.values["TOKEN"], "rotated");
    assert_eq!(resolved.expires_at_ms["TOKEN"], expires);

    // No expiration is also issuer-owned. A stale grant deadline must not be
    // resurrected when reconfiguration omits expiration.
    state
        .credentials
        .rotate_provider_reference(
            references::provider_scope(&provider, "TOKEN"),
            &provider.credential_handles["TOKEN"],
            2,
            "non-expiring",
            None,
        )
        .await
        .unwrap();
    let response =
        handle_configure_provider_refresh(&state, authed_request(configure(None, "non-expiring")))
            .await
            .unwrap()
            .into_inner()
            .status
            .unwrap();
    assert!(response.expiration_time.is_none());
    let grant = crate::provider_refresh::get_refresh_state(
        &state.store,
        "default",
        provider.object_id(),
        "TOKEN",
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!crate::provider_refresh::refresh_has_expiration(&grant));
}

#[tokio::test]
async fn replacing_expired_versioned_value_rejects_collision_and_preserves_published_handles() {
    let state = test_server_state().await;
    let mut provider = stored(&state).await;
    provider.credential_expiration_times.clear();
    state.store.put_message(&provider).await.unwrap();
    let provider = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    state
        .credentials
        .rotate_provider_reference(
            references::provider_scope(&provider, "TOKEN"),
            &provider.credential_handles["TOKEN"],
            1,
            "expired",
            Some(1),
        )
        .await
        .unwrap();
    let second = Provider {
        metadata: Some(ObjectMeta {
            id: "second-id".into(),
            name: "second".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        r#type: "custom".into(),
        credentials: HashMap::from([("TOKEN".into(), "other-live-value".into())]),
        ..Default::default()
    };
    state.store.put_message(&second).await.unwrap();
    state
        .store
        .put_message(&Sandbox {
            metadata: Some(ObjectMeta {
                id: "sandbox-id".into(),
                name: "sandbox".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            spec: Some(SandboxSpec {
                providers: vec!["provider".into(), "second".into()],
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    let before_count = state.credentials.stored_credential_count();
    let mut request = update(Some(current_time_ms() + 60_000), false);
    request
        .provider
        .as_mut()
        .unwrap()
        .credentials
        .insert("TOKEN".into(), "replacement-live-value".into());
    let error = handle_update_provider(&state, authed_request(request))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(error.message().contains("TOKEN"));
    assert_eq!(state.credentials.stored_credential_count(), before_count);
    assert_eq!(
        state
            .store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap(),
        provider
    );
    let mut retained = provider.clone();
    assert_eq!(
        references::capture_metadata(&state.store, &mut retained)
            .await
            .unwrap()["TOKEN"],
        2
    );
    assert_eq!(
        state
            .credentials
            .resolve_provider_handles(&provider, 0)
            .await
            .unwrap()
            .values["TOKEN"],
        "expired",
        "failed replacement must not retire or change the published reference"
    );
}

#[tokio::test]
async fn deleted_refresh_with_stale_provider_expiry_cannot_hide_a_live_key_collision() {
    let state = test_server_state().await;
    let provider = stored(&state).await;
    let expires = current_time_ms() + 60_000;
    state
        .credentials
        .rotate_provider_reference(
            references::provider_scope(&provider, "TOKEN"),
            &provider.credential_handles["TOKEN"],
            1,
            "live",
            Some(expires),
        )
        .await
        .unwrap();
    let grant = crate::provider_refresh::new_refresh_state(
        &provider,
        "default",
        "TOKEN",
        crate::provider_refresh::NewRefreshStateConfig {
            strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
            material: HashMap::new(),
            secret_material_keys: Vec::new(),
            expires_at_ms: expires,
            token_url: "https://issuer.example/token".into(),
            scopes: Vec::new(),
            refresh_before: None,
            max_lifetime: None,
            additional_output_keys: HashMap::new(),
        },
    )
    .unwrap();
    crate::provider_refresh::put_refresh_state(&state.store, &grant)
        .await
        .unwrap();
    handle_delete_provider_refresh(
        &state,
        authed_request(DeleteProviderRefreshRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            provider: "provider".into(),
            credential_key: "TOKEN".into(),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap();
    let names = vec!["provider".into()];
    let records = load_provider_environment_records_with_source(
        &state.store,
        "default",
        &names,
        Some(&state.credentials),
    )
    .await
    .unwrap();
    assert!(records[0].refresh_states.is_empty());
    assert_eq!(records[0].credential_versions["TOKEN"], 2);
    assert_eq!(
        records[0].provider.credential_expiration_times["TOKEN"],
        openshell_core::time::timestamp_from_millis(expires).unwrap()
    );
    assert_eq!(
        resolve_provider_environment_from_records_with_credentials(
            &catalog,
            &records,
            &state.credentials,
        )
        .await
        .unwrap()
        .environment["TOKEN"],
        "live"
    );

    let mut second = Provider {
        metadata: Some(ObjectMeta {
            id: "second-id".into(),
            name: "second".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        r#type: "custom".into(),
        ..Default::default()
    };
    state.store.put_message(&second).await.unwrap();
    state
        .store
        .put_message(&Sandbox {
            metadata: Some(ObjectMeta {
                id: "sandbox-id".into(),
                name: "sandbox".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            spec: Some(SandboxSpec {
                providers: vec!["provider".into(), "second".into()],
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    second.credentials.insert("TOKEN".into(), "conflict".into());
    let error = validate_provider_update_against_attached_sandboxes_with_catalog(
        &state.store,
        &catalog,
        "default",
        &second,
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(error.message().contains("TOKEN"));
    state.store.put_message(&second).await.unwrap();
    let names = vec!["provider".into(), "second".into()];
    assert!(
        validate_provider_environment_keys_unique_with_catalog(
            &state.store,
            &catalog,
            "default",
            &names,
        )
        .await
        .unwrap_err()
        .message()
        .contains("TOKEN")
    );
    let records = load_provider_environment_records_with_source(
        &state.store,
        "default",
        &names,
        Some(&state.credentials),
    )
    .await
    .unwrap();
    assert!(
        resolve_provider_environment_from_records_with_credentials(
            &catalog,
            &records,
            &state.credentials,
        )
        .await
        .unwrap_err()
        .message()
        .contains("TOKEN")
    );
    // An expired old reference must not suppress a prospective new refresh
    // output when configuring it would collide with the other provider.
    state
        .credentials
        .rotate_provider_reference(
            references::provider_scope(&provider, "TOKEN"),
            &provider.credential_handles["TOKEN"],
            2,
            "expired",
            Some(1),
        )
        .await
        .unwrap();
    assert!(
        validate_provider_credential_key_available_for_attached_sandboxes_with_catalog(
            &state.store,
            &catalog,
            "default",
            &provider,
            "TOKEN",
        )
        .await
        .unwrap_err()
        .message()
        .contains("TOKEN")
    );
}

#[derive(Debug)]
struct RacingMetadata(Source);
#[async_trait::async_trait]
impl crate::credential_source::ProviderCredentialSource for RacingMetadata {
    async fn project_expiration_metadata(
        &self,
        _: &crate::persistence::Store,
        _: &mut Provider,
    ) -> Result<(), tonic::Status> {
        self.0.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn reference_versions(
        &self,
        store: &crate::persistence::Store,
        provider: &Provider,
    ) -> Result<HashMap<String, u64>, tonic::Status> {
        crate::credential_source::ProviderCredentialSource::reference_versions(
            &self.0, store, provider,
        )
        .await
    }
    async fn resolve_provider_handles_for(
        &self,
        _: &Provider,
        _: i64,
        _: crate::credential_source::CredentialReadPurpose,
    ) -> Result<crate::credentials::ResolvedProviderCredentials, tonic::Status> {
        panic!("metadata capture must never resolve values")
    }
}

#[tokio::test]
async fn source_metadata_projection_cannot_race_its_captured_reference_versions() {
    let state = test_server_state().await;
    stored(&state).await;
    let source = RacingMetadata(Source(std::sync::atomic::AtomicU64::new(1)));
    let error = load_provider_environment_records_with_source(
        &state.store,
        "default",
        &["provider".into()],
        Some(&source),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), Code::Aborted);
}
