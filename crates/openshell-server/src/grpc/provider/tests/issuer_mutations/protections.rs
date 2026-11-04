// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::credential_source::embedded::EmbeddedIssuer;
use openshell_core::proto::ObjectMeta;
use std::{collections::BTreeMap, time::Duration};

async fn embedded(state: &mut Arc<ServerState>) -> (EmbeddedIssuer, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let crypto = toml::Table::from_iter([(
        "key_encryption_key_path".into(),
        toml::Value::String(directory.path().join("issuer.key").display().to_string()),
    )]);
    let issuer = EmbeddedIssuer::new(
        "sqlite::memory:",
        &state.store,
        &state.credentials,
        &crypto,
        &BTreeMap::new(),
    )
    .await
    .unwrap();
    Arc::get_mut(state).unwrap().provider_source = Some(Arc::new(issuer.source.clone()));
    (issuer, directory)
}

async fn journals(state: &ServerState) -> Vec<(String, u64, Vec<u8>)> {
    state
        .store
        .list_by_type_after("credential_issuer_handoff_v1", None, 100)
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.id, row.resource_version, row.payload))
        .collect()
}

async fn exercise_refresh_update_protection(
    state: &Arc<ServerState>,
    source: &RemoteProviderSource,
) {
    for (name, provider_type, keys, strategy, material) in [
        (
            "single",
            "custom",
            vec!["TOKEN"],
            ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
            HashMap::from([
                ("client_id".into(), "client".into()),
                ("client_secret".into(), "secret".into()),
            ]),
        ),
        (
            "bundle",
            "aws",
            vec![
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
            ],
            ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
            HashMap::from([(
                "role_arn".into(),
                "arn:aws:iam::123456789012:role/Test".into(),
            )]),
        ),
    ] {
        state
            .store
            .put_message(&Provider {
                metadata: Some(ObjectMeta {
                    id: name.into(),
                    name: name.into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                r#type: provider_type.into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let configure = || ConfigureProviderRefreshRequest {
            workspace_scope: Some(scope()),
            provider: name.into(),
            credential_key: keys[0].into(),
            strategy: strategy.into(),
            material: material.clone(),
            ..Default::default()
        };
        handle_configure_provider_refresh(state, authed_request(configure()))
            .await
            .unwrap();
        source
            .issuer()
            .wait_synchronized(Duration::from_secs(5))
            .await
            .unwrap();
        let original = state
            .store
            .get_message::<Provider>(name)
            .await
            .unwrap()
            .unwrap();
        assert!(
            crate::provider_refresh::list_refresh_states_for_provider(&state.store, name)
                .await
                .unwrap()
                .is_empty(),
            "the production selected issuer has no legacy refresh rows"
        );
        let before = journals(state).await;
        let version = original.metadata.as_ref().unwrap().resource_version;
        let request = UpdateProviderRequest {
            workspace_scope: Some(scope()),
            provider: Some(Provider {
                metadata: Some(ObjectMeta {
                    name: name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            credential_expiration_times: HashMap::from([(
                keys[0].into(),
                openshell_core::time::timestamp_from_millis(1).unwrap(),
            )]),
            ..Default::default()
        };
        assert_eq!(
            handle_update_provider(state, authed_request(request))
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition,
            "pending version-one grant outputs do not regain provider expiry authority"
        );
        assert_eq!(journals(state).await, before);
        let mut selections = keys.iter().map(|key| vec![*key]).collect::<Vec<_>>();
        selections.push(keys.clone());
        for selected in selections {
            for value in ["replacement", ""] {
                let error = handle_update_provider(
                    state,
                    authed_request(UpdateProviderRequest {
                        workspace_scope: Some(scope()),
                        provider: Some(Provider {
                            metadata: Some(ObjectMeta {
                                name: name.into(),
                                resource_version: version,
                                ..Default::default()
                            }),
                            credentials: selected
                                .iter()
                                .map(|key| ((*key).into(), value.into()))
                                .collect(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                )
                .await
                .unwrap_err();
                assert_eq!(error.code(), Code::FailedPrecondition);
                for key in &selected {
                    assert!(error.message().contains(*key));
                }
                assert_eq!(
                    state
                        .store
                        .get_message::<Provider>(name)
                        .await
                        .unwrap()
                        .unwrap(),
                    original
                );
                assert_eq!(journals(state).await, before, "reject before staging");
            }
        }
        let metadata = || UpdateProviderRequest {
            workspace_scope: Some(scope()),
            provider: Some(Provider {
                metadata: Some(ObjectMeta {
                    name: name.into(),
                    resource_version: version,
                    ..Default::default()
                }),
                config: HashMap::from([("region".into(), "us-west-2".into())]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let updated = handle_update_provider(state, authed_request(metadata()))
            .await
            .unwrap()
            .into_inner()
            .provider
            .unwrap();
        assert_eq!(
            updated.metadata.as_ref().unwrap().resource_version,
            version + 1
        );
        assert_eq!(
            handle_update_provider(state, authed_request(metadata()))
                .await
                .unwrap_err()
                .code(),
            Code::Aborted,
            "metadata-only writes must retain provider CAS fencing"
        );
        // Only the explicit refresh path may replace an entire managed epoch.
        handle_configure_provider_refresh(state, authed_request(configure()))
            .await
            .unwrap();
        let replaced = state
            .store
            .get_message::<Provider>(name)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(original.credential_handles, replaced.credential_handles);
    }
}

#[tokio::test]
async fn selected_embedded_dispatcher_protects_single_and_complete_refresh_output_updates() {
    let mut state = test_server_state().await;
    let (issuer, _directory) = embedded(&mut state).await;
    exercise_refresh_update_protection(&state, &issuer.source).await;
    issuer.drain().await;
}

#[tokio::test]
async fn selected_remote_dispatcher_protects_refresh_outputs_without_value_reads() {
    let mut state = test_server_state().await;
    let issuer =
        Issuer::with_minters(Arc::new(openshell_credential_issuer::builtins::registry())).await;
    let source = Arc::new(RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap());
    Arc::get_mut(&mut state).unwrap().provider_source = Some(source.clone());
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    exercise_refresh_update_protection(&state, &source).await;
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn selected_remote_expiration_spec_noops_authenticate_fresh_metadata_before_staging() {
    use crate::persistence::AtomicWrite;
    use openshell_core::proto::credentials::store::v1 as wire;
    for expiration in [None, Some(1)] {
        for sibling in [false, true] {
            let mut state = test_server_state().await;
            let issuer = Issuer::start().await;
            let source =
                Arc::new(RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap());
            Arc::get_mut(&mut state).unwrap().provider_source = Some(source.clone());
            let mut provider = Provider {
                metadata: Some(ObjectMeta {
                    id: "legacy".into(),
                    name: "legacy".into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                r#type: "custom".into(),
                ..Default::default()
            };
            let owner = wire::SecretOwner {
                workspace: "default".into(),
                provider_id: "legacy".into(),
                provider: "legacy".into(),
                credential_key: "TOKEN".into(),
                ..Default::default()
            };
            let secret = issuer
                .raw
                .put_secret(wire::PutSecretRequest {
                    owner: Some(owner.clone()),
                    value: "version-one".into(),
                    idempotency_key: "noop-initial".into(),
                    ..Default::default()
                })
                .await
                .unwrap();
            provider.credential_handles.insert(
                "TOKEN".into(),
                source.reference_handle(&secret.reference, None).unwrap(),
            );
            provider.credential_expiration_times = expiration
                .map(|time| {
                    HashMap::from([(
                        "TOKEN".into(),
                        openshell_core::time::timestamp_from_millis(time).unwrap(),
                    )])
                })
                .unwrap_or_default();
            state
                .store
                .write_atomically(&[
                    AtomicWrite::Create {
                        object_type: "provider".into(),
                        id: "legacy".into(),
                        name: "legacy".into(),
                        workspace: "default".into(),
                        payload: provider.encode_to_vec(),
                    },
                    StaticHandoff::migration_write(&source, &provider, &["TOKEN".into()], None)
                        .unwrap(),
                ])
                .await
                .unwrap();
            source.register_provider(&provider).unwrap();
            issuer
                .watched
                .wait_synchronized(Duration::from_secs(5))
                .await
                .unwrap();
            issuer.hold_secret_watch.store(true, Ordering::SeqCst);
            issuer
                .raw
                .put_secret(wire::PutSecretRequest {
                    owner: Some(owner.clone()),
                    reference: secret.reference.clone(),
                    expected_version: Some(1),
                    value: "version-two".into(),
                    expiration_time: Some(
                        openshell_core::time::timestamp_from_millis(
                            crate::persistence::current_time_ms() + 60_000,
                        )
                        .unwrap(),
                    ),
                    idempotency_key: "noop-advance".into(),
                })
                .await
                .unwrap();
            assert_eq!(
                issuer
                    .watched
                    .known_secret(&owner, &secret.reference)
                    .unwrap()
                    .version,
                1,
                "the regression must keep the watch genuinely stale"
            );
            let before = state
                .store
                .get("provider", "legacy")
                .await
                .unwrap()
                .unwrap();
            let ownership = journals(&state).await;
            issuer.fail_resolves.store(true, Ordering::SeqCst);
            let error = handle_update_provider(
                &state,
                authed_request(UpdateProviderRequest {
                    workspace_scope: Some(scope()),
                    provider: Some(Provider {
                        metadata: Some(ObjectMeta {
                            name: "legacy".into(),
                            ..Default::default()
                        }),
                        credentials: if sibling {
                            HashMap::from([("SIBLING".into(), "must-not-stage".into())])
                        } else {
                            HashMap::new()
                        },
                        ..Default::default()
                    }),
                    credential_expiration_times: provider.credential_expiration_times.clone(),
                    clear_credential_expiration_keys: if expiration.is_none() {
                        vec!["TOKEN".into()]
                    } else {
                        Vec::new()
                    },
                    ..Default::default()
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), Code::FailedPrecondition);
            assert!(error.message().contains("issuer-owned"));
            let after = state
                .store
                .get("provider", "legacy")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(after.resource_version, before.resource_version);
            assert_eq!(after.payload, before.payload);
            assert_eq!(
                journals(&state).await,
                ownership,
                "spec-noop requests must reject before staging"
            );
            assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn selected_embedded_dispatcher_preserves_migrated_version_one_expiration_edits() {
    let mut state = test_server_state().await;
    let mut provider = Provider {
        metadata: Some(ObjectMeta {
            id: "legacy".into(),
            name: "legacy".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        r#type: "custom".into(),
        ..Default::default()
    };
    provider.credential_handles = state
        .credentials
        .store_provider_credentials(
            "legacy",
            "default",
            "legacy",
            &HashMap::from([("TOKEN".into(), "migrated-private".into())]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    provider.credential_expiration_times.insert(
        "TOKEN".into(),
        openshell_core::time::timestamp_from_millis(1).unwrap(),
    );
    state.store.put_message(&provider).await.unwrap();
    let (issuer, _directory) = embedded(&mut state).await;
    let migrated = state
        .store
        .get_message::<Provider>("legacy")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        issuer
            .source
            .reference_versions(&state.store, &migrated)
            .await
            .unwrap()["TOKEN"],
        1
    );
    for expiration in [Some(crate::persistence::current_time_ms() + 60_000), None] {
        let response = handle_update_provider(
            &state,
            authed_request(UpdateProviderRequest {
                workspace_scope: Some(scope()),
                provider: Some(Provider {
                    metadata: Some(ObjectMeta {
                        name: "legacy".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                credential_expiration_times: expiration
                    .map(|time| {
                        HashMap::from([(
                            "TOKEN".into(),
                            openshell_core::time::timestamp_from_millis(time).unwrap(),
                        )])
                    })
                    .unwrap_or_default(),
                clear_credential_expiration_keys: if expiration.is_none() {
                    vec!["TOKEN".into()]
                } else {
                    Vec::new()
                },
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .provider
        .unwrap();
        assert_eq!(
            response.credential_expiration_times.get("TOKEN").copied(),
            expiration.map(|time| openshell_core::time::timestamp_from_millis(time).unwrap())
        );
        let current = state
            .store
            .get_message::<Provider>("legacy")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.credential_handles, migrated.credential_handles);
        assert_eq!(
            current.credential_expiration_times,
            response.credential_expiration_times
        );
        let resolved = issuer
            .source
            .resolve_provider_handles(&current, crate::persistence::current_time_ms())
            .await
            .unwrap();
        assert_eq!(resolved.values["TOKEN"], "migrated-private");
        assert_eq!(resolved.expires_at_ms.get("TOKEN").copied(), expiration);
    }
    // Once the issuer advances, even an explicit clear absent from the stored
    // legacy spec must be rejected before staging an unrelated static value.
    let handle: serde_json::Value =
        serde_json::from_str(&migrated.credential_handles["TOKEN"].handle).unwrap();
    issuer
        .source
        .issuer()
        .put_secret(
            openshell_core::proto::credentials::store::v1::PutSecretRequest {
                owner: Some(openshell_core::proto::credentials::store::v1::SecretOwner {
                    workspace: "default".into(),
                    provider_id: "legacy".into(),
                    provider: "legacy".into(),
                    credential_key: "TOKEN".into(),
                    ..Default::default()
                }),
                reference: handle["reference"].as_str().unwrap().into(),
                expected_version: Some(1),
                value: "issuer-version-two".into(),
                expiration_time: Some(
                    openshell_core::time::timestamp_from_millis(
                        crate::persistence::current_time_ms() + 60_000,
                    )
                    .unwrap(),
                ),
                idempotency_key: "take-expiration-authority".into(),
            },
        )
        .await
        .unwrap();
    issuer
        .source
        .issuer()
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    let before = state
        .store
        .get("provider", "legacy")
        .await
        .unwrap()
        .unwrap();
    let ownership = journals(&state).await;
    let error = handle_update_provider(
        &state,
        authed_request(UpdateProviderRequest {
            workspace_scope: Some(scope()),
            provider: Some(Provider {
                metadata: Some(ObjectMeta {
                    name: "legacy".into(),
                    ..Default::default()
                }),
                credentials: HashMap::from([("SIBLING".into(), "must-not-stage".into())]),
                ..Default::default()
            }),
            clear_credential_expiration_keys: vec!["TOKEN".into()],
            ..Default::default()
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(error.message().contains("issuer-owned"));
    let after = state
        .store
        .get("provider", "legacy")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.resource_version, before.resource_version);
    assert_eq!(after.payload, before.payload);
    assert_eq!(journals(&state).await, ownership);
    issuer.drain().await;
}
