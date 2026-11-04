// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::credential_source::{
    ProviderCredentialSource as _, RemoteProviderSource, handoff::StaticHandoff,
    tests::issuer::Issuer,
};
use std::sync::{Arc, atomic::Ordering};
mod protections;
fn request_provider(value: &str, version: u64) -> Provider {
    Provider {
        metadata: Some(openshell_core::proto::ObjectMeta {
            name: "remote-provider".into(),
            resource_version: version,
            ..Default::default()
        }),
        r#type: "openai".into(),
        credentials: HashMap::from([("OPENAI_API_KEY".into(), value.into())]),
        ..Default::default()
    }
}
fn scope() -> openshell_core::proto::WorkspaceSelector {
    openshell_core::proto::workspace_selector("default")
}
#[tokio::test]
async fn selected_issuer_refresh_status_rpc_does_not_return_embedded_shadow_state() {
    let mut state = test_server_state().await;
    let issuer = Issuer::start().await;
    let source = Arc::new(RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap());
    Arc::get_mut(&mut state).unwrap().provider_source = Some(source);
    let provider = handle_create_provider(
        &state,
        authed_request(CreateProviderRequest {
            provider: Some(request_provider("sk-static", 0)),
            workspace_scope: Some(scope()),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .provider
    .unwrap();
    let shadow = crate::provider_refresh::new_refresh_state(
        &provider,
        "default",
        "OPENAI_API_KEY",
        crate::provider_refresh::NewRefreshStateConfig {
            strategy: ProviderCredentialRefreshStrategy::try_from(1).unwrap(),
            material: HashMap::new(),
            secret_material_keys: Vec::new(),
            expires_at_ms: 0,
            token_url: String::new(),
            scopes: Vec::new(),
            refresh_before: None,
            max_lifetime: None,
            additional_output_keys: HashMap::new(),
        },
    )
    .unwrap();
    crate::provider_refresh::create_refresh_state(&state.store, &shadow)
        .await
        .unwrap();
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    let reads = issuer.resolves.load(Ordering::SeqCst);
    let status = handle_get_provider_refresh_status(
        &state,
        authed_request(GetProviderRefreshStatusRequest {
            provider: "remote-provider".into(),
            credential_key: String::new(),
            workspace_scope: Some(scope()),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(status.credentials.is_empty());
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), reads);
}
#[tokio::test]
async fn selected_read_only_source_never_falls_back_to_embedded_mutations() {
    let mut state = test_server_state().await;
    let read_only = Arc::new(state.credentials.clone());
    Arc::get_mut(&mut state).unwrap().provider_source = Some(read_only);
    let error = handle_create_provider(
        &state,
        authed_request(CreateProviderRequest {
            provider: Some(request_provider("must-not-store", 0)),
            workspace_scope: Some(scope()),
            ..Default::default()
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(
        state
            .store
            .get_message_by_name::<Provider>("default", "remote-provider")
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
async fn selected_issuer_create_update_and_metadata_only_rpc_never_use_local_value_storage() {
    let mut state = test_server_state().await;
    let issuer = Issuer::start().await;
    let source = Arc::new(RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap());
    Arc::get_mut(&mut state).unwrap().provider_source = Some(source.clone());
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    let created = handle_create_provider(
        &state,
        authed_request(CreateProviderRequest {
            provider: Some(request_provider("sk-first", 0)),
            workspace_scope: Some(scope()),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .provider
    .unwrap();
    assert_eq!(created.metadata.as_ref().unwrap().resource_version, 1);
    let original = state
        .store
        .get_message::<Provider>(created.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(original.credentials.is_empty());
    assert_eq!(
        original.credential_handles["OPENAI_API_KEY"].driver,
        "credential-issuer"
    );
    assert_eq!(
        StaticHandoff::published_for_provider(&state.store, &source, &original)
            .await
            .unwrap()
            .len(),
        1
    );
    let updated = handle_update_provider(
        &state,
        authed_request(UpdateProviderRequest {
            provider: Some(request_provider("sk-replaced", 1)),
            workspace_scope: Some(scope()),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .provider
    .unwrap();
    assert_eq!(updated.metadata.as_ref().unwrap().resource_version, 2);
    let current = state
        .store
        .get_message::<Provider>(created.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(original.credential_handles, current.credential_handles);
    assert!(current.credentials.is_empty());
    let mut metadata = request_provider("unused", 2);
    metadata.credentials.clear();
    let updated = handle_update_provider(
        &state,
        authed_request(UpdateProviderRequest {
            provider: Some(metadata),
            workspace_scope: Some(scope()),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .provider
    .unwrap();
    assert_eq!(updated.metadata.as_ref().unwrap().resource_version, 3);
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
    let cleanup = StaticHandoff::recover_page(&state.store, &source, None, 128, i64::MIN)
        .await
        .unwrap();
    assert_eq!(cleanup.cleaned, 1);
    issuer.fail_resolves.store(false, Ordering::SeqCst);
    let current = state
        .store
        .get_message::<Provider>(created.object_id())
        .await
        .unwrap()
        .unwrap();
    source.register_provider(&current).unwrap();
    issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        source
            .resolve_provider_handles(&current, crate::persistence::current_time_ms())
            .await
            .unwrap()
            .values["OPENAI_API_KEY"],
        "sk-replaced"
    );
    handle_delete_provider(
        &state,
        authed_request(DeleteProviderRequest {
            name: "remote-provider".into(),
            workspace_scope: Some(scope()),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert!(
        state
            .store
            .get_message::<Provider>(created.object_id())
            .await
            .unwrap()
            .is_none()
    );
    let cleanup = StaticHandoff::recover_page(&state.store, &source, None, 128, i64::MIN)
        .await
        .unwrap();
    assert_eq!(cleanup.cleaned, 1);
}
#[tokio::test]
async fn selected_issuer_rejects_implicit_legacy_adoption_on_update() {
    let mut state = test_server_state().await;
    let issuer = Issuer::start().await;
    let source = Arc::new(RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap());
    Arc::get_mut(&mut state).unwrap().provider_source = Some(source);
    let mut existing = request_provider("legacy-inline", 0);
    existing.metadata.as_mut().unwrap().id = "legacy-id".into();
    existing.metadata.as_mut().unwrap().workspace = "default".into();
    state.store.put_message(&existing).await.unwrap();
    let error = handle_update_provider(
        &state,
        authed_request(UpdateProviderRequest {
            provider: Some(request_provider("sk-new", 1)),
            workspace_scope: Some(scope()),
            ..Default::default()
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    let unchanged = state
        .store
        .get_message::<Provider>("legacy-id")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.credentials["OPENAI_API_KEY"], "legacy-inline");
    assert_eq!(unchanged.metadata.as_ref().unwrap().resource_version, 1);
}
