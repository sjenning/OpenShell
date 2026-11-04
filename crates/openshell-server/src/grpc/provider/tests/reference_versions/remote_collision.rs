// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::credential_source::{
    ProviderCredentialSource as _, RemoteProviderSource, tests::issuer::Issuer,
};
use crate::grpc::{
    provider::*,
    test_support::{authed_request, test_server_state},
};
use openshell_core::proto::{
    Sandbox, SandboxSpec, UpdateProviderRequest, credentials::store::v1 as wire,
};
use std::{sync::atomic::Ordering, time::Duration};

async fn context() -> (
    Arc<ServerState>,
    Issuer,
    Arc<RemoteProviderSource>,
    Provider,
) {
    let mut state = test_server_state().await;
    let issuer = Issuer::start().await;
    let source = Arc::new(RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap());
    Arc::get_mut(&mut state).unwrap().provider_source = Some(source.clone());
    let mut provider = provider();
    provider.r#type = "custom".into();
    let value = issuer
        .watched
        .put_secret(wire::PutSecretRequest {
            owner: Some(wire::SecretOwner {
                workspace: "default".into(),
                provider_id: provider.object_id().into(),
                provider: "provider".into(),
                credential_key: "TOKEN".into(),
                ..Default::default()
            }),
            value: "published-token".into(),
            idempotency_key: "initial-collision-token".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    // A detached grant output has this same static handle shape and keeps its
    // issuer expiration, without copying expiration into the provider record.
    provider.credential_handles.insert(
        "TOKEN".into(),
        source.reference_handle(&value.reference, None).unwrap(),
    );
    state.store.put_message(&provider).await.unwrap();
    let second = Provider {
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
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    (state, issuer, source, provider)
}

async fn rotate(issuer: &Issuer, provider: &Provider, version: u64, expiration: Option<i64>) {
    let binding: serde_json::Value =
        serde_json::from_str(&provider.credential_handles["TOKEN"].handle).unwrap();
    issuer
        .watched
        .put_secret(wire::PutSecretRequest {
            owner: Some(wire::SecretOwner {
                workspace: "default".into(),
                provider_id: provider.object_id().into(),
                provider: "provider".into(),
                credential_key: "TOKEN".into(),
                ..Default::default()
            }),
            reference: binding["reference"].as_str().unwrap().into(),
            expected_version: Some(version),
            value: "rotated-token".into(),
            expiration_time: expiration
                .map(|value| openshell_core::time::timestamp_from_millis(value).unwrap()),
            idempotency_key: format!("collision-rotation-{version}"),
        })
        .await
        .unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
}

async fn populate_second(state: &Arc<ServerState>, issuer: &Issuer, _: &RemoteProviderSource) {
    // Use the public mutation so the binding also has durable retirement
    // ownership. A raw issuer value alone cannot authorize later replacement.
    handle_update_provider(
        state,
        authed_request(UpdateProviderRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            provider: Some(Provider {
                metadata: Some(ObjectMeta {
                    name: "second".into(),
                    ..Default::default()
                }),
                credentials: HashMap::from([("TOKEN".into(), "other-live-token".into())]),
                ..Default::default()
            }),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
}

#[tokio::test]
async fn remote_expiration_controls_attachment_and_update_collision_checks_without_value_reads() {
    let (state, issuer, source, provider) = context().await;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap();
    let mut candidate = state
        .store
        .get_message::<Provider>("second-id")
        .await
        .unwrap()
        .unwrap();
    candidate
        .credentials
        .insert("TOKEN".into(), "replacement".into());
    let names = vec!["provider".into(), "second".into()];
    assert!(
        validate_provider_update_against_attached_sandboxes_with_source(
            &state.store,
            &catalog,
            "default",
            &candidate,
            Some(source.as_ref())
        )
        .await
        .unwrap_err()
        .message()
        .contains("TOKEN")
    );
    rotate(&issuer, &provider, 1, Some(1)).await;
    populate_second(&state, &issuer, &source).await;
    let before_reads = issuer.resolves.load(Ordering::SeqCst);
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    validate_provider_update_against_attached_sandboxes_with_source(
        &state.store,
        &catalog,
        "default",
        &candidate,
        Some(source.as_ref()),
    )
    .await
    .unwrap();
    validate_provider_environment_keys_unique_with_source(
        &state.store,
        &catalog,
        "default",
        &names,
        Some(source.as_ref()),
    )
    .await
    .unwrap();
    let records = load_provider_environment_records_with_source(
        &state.store,
        "default",
        &names,
        Some(source.as_ref()),
    )
    .await
    .unwrap();
    assert_eq!(
        records[0].provider.credential_expiration_times["TOKEN"],
        openshell_core::time::timestamp_from_millis(1).unwrap()
    );
    assert!(
        source
            .resolve_provider_handles(&records[0].provider, current_time_ms())
            .await
            .unwrap()
            .expired_keys
            .contains("TOKEN")
    );
    assert_eq!(
        issuer.resolves.load(Ordering::SeqCst),
        before_reads,
        "collision checks and expired delivery must only inspect metadata"
    );
    assert!(
        state
            .store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap()
            .credential_expiration_times
            .is_empty()
    );
    // A later live version must reserve the key again, despite the unchanged
    // provider record and its still-absent legacy expiration.
    issuer.fail_resolves.store(false, Ordering::SeqCst);
    rotate(&issuer, &provider, 2, None).await;
    assert!(
        validate_provider_environment_keys_unique_with_source(
            &state.store,
            &catalog,
            "default",
            &names,
            Some(source.as_ref())
        )
        .await
        .unwrap_err()
        .message()
        .contains("TOKEN")
    );
}

#[tokio::test]
async fn remote_prospective_values_and_refresh_outputs_cannot_hide_behind_expired_references() {
    let (state, issuer, source, provider) = context().await;
    rotate(&issuer, &provider, 1, Some(1)).await;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap();
    populate_second(&state, &issuer, &source).await;
    let before = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let journals = state
        .store
        .list_by_type_after("credential_issuer_handoff_v1", None, 100)
        .await
        .unwrap();
    let error = handle_update_provider(
        &state,
        authed_request(UpdateProviderRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            provider: Some(Provider {
                metadata: Some(ObjectMeta {
                    name: "provider".into(),
                    ..Default::default()
                }),
                credentials: HashMap::from([("TOKEN".into(), "fresh-token".into())]),
                ..Default::default()
            }),
            ..Default::default()
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains("TOKEN"));
    assert_eq!(
        state
            .store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap(),
        before
    );
    assert_eq!(
        state
            .store
            .list_by_type_after("credential_issuer_handoff_v1", None, 100)
            .await
            .unwrap()
            .len(),
        journals.len(),
        "reject before staging a remote allocation"
    );
    assert!(
        validate_provider_credential_key_available_for_attached_sandboxes_with_source(
            &state.store,
            &catalog,
            "default",
            &provider,
            "TOKEN",
            Some(source.as_ref())
        )
        .await
        .unwrap_err()
        .message()
        .contains("TOKEN")
    );
    // Replacing the other provider succeeds even though staging its new value
    // invalidates watch metadata: validation must precede those remote effects.
    handle_update_provider(
        &state,
        authed_request(UpdateProviderRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            provider: Some(Provider {
                metadata: Some(ObjectMeta {
                    name: "second".into(),
                    ..Default::default()
                }),
                credentials: HashMap::from([("TOKEN".into(), "allowed-replacement".into())]),
                ..Default::default()
            }),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn configured_remote_refresh_epoch_reserves_expired_outputs_until_detach() {
    let (state, issuer, source, mut provider) = context().await;
    rotate(&issuer, &provider, 1, Some(1)).await;
    populate_second(&state, &issuer, &source).await;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap();
    let names = vec!["provider".into(), "second".into()];
    // The grant annotation is the fixed epoch established by handoff
    // publication. This metadata-only test changes that annotation to isolate
    // reservation semantics; no value or issuer reference identity changes.
    let binding: serde_json::Value =
        serde_json::from_str(&provider.credential_handles["TOKEN"].handle).unwrap();
    provider.credential_handles.insert(
        "TOKEN".into(),
        source
            .reference_handle(
                binding["reference"].as_str().unwrap(),
                Some("configured-grant"),
            )
            .unwrap(),
    );
    state.store.put_message(&provider).await.unwrap();
    let error = validate_provider_environment_keys_unique_with_source(
        &state.store,
        &catalog,
        "default",
        &names,
        Some(source.as_ref()),
    )
    .await
    .unwrap_err();
    assert!(error.message().contains("TOKEN"), "{error}");
    // Removing refresh ownership, as detach does, releases only the expired
    // reservation; a subsequent live reference version still collides.
    provider.credential_handles.insert(
        "TOKEN".into(),
        source
            .reference_handle(binding["reference"].as_str().unwrap(), None)
            .unwrap(),
    );
    state.store.put_message(&provider).await.unwrap();
    validate_provider_environment_keys_unique_with_source(
        &state.store,
        &catalog,
        "default",
        &names,
        Some(source.as_ref()),
    )
    .await
    .unwrap();
    rotate(&issuer, &provider, 2, None).await;
    assert!(
        validate_provider_environment_keys_unique_with_source(
            &state.store,
            &catalog,
            "default",
            &names,
            Some(source.as_ref())
        )
        .await
        .unwrap_err()
        .message()
        .contains("TOKEN")
    );
}
