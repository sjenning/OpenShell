// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
mod catalog_cache;
mod deletion;
mod profile_repair;
mod profiles;
mod profiles_public;
use crate::credential_source::{
    ProviderCredentialSource as _, RemoteProviderSource, handoff::StaticHandoff,
    tests::issuer::Issuer,
};
use openshell_credential_issuer::minter::{
    MaterialDescriptor, MintFailure, MintRequest, MintResponse, StrategyDescriptor, TokenMinter,
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct Minter {
    calls: AtomicUsize,
    descriptor: StrategyDescriptor,
}
fn descriptor() -> StrategyDescriptor {
    StrategyDescriptor {
        name: "custom:company-sts".into(),
        config: vec![MaterialDescriptor {
            name: "audience".into(),
            required: true,
        }],
        secret_material: vec![MaterialDescriptor {
            name: "seed".into(),
            required: true,
        }],
        outputs: vec!["company_token".into()],
        rotated_secret_material: vec![],
    }
}
#[tonic::async_trait]
impl TokenMinter for Minter {
    fn describe(&self) -> StrategyDescriptor {
        self.descriptor.clone()
    }
    async fn mint(&self, request: MintRequest) -> Result<MintResponse, MintFailure> {
        assert_eq!(
            request.config,
            HashMap::from([("audience".into(), "private-audience".into())])
        );
        assert_eq!(
            request.secret_material,
            HashMap::from([("seed".into(), "private-seed".into())])
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(MintResponse {
            outputs: self
                .descriptor
                .outputs
                .iter()
                .map(|output| {
                    (
                        output.clone(),
                        if output == "company_token" {
                            "private-company-token".into()
                        } else {
                            format!("private-{output}")
                        },
                    )
                })
                .collect(),
            expiration_time_ms: crate::persistence::current_time_ms() + 60_000,
            rotated_secret_material: HashMap::new(),
        })
    }
}
async fn context(
    descriptor: StrategyDescriptor,
) -> (
    tempfile::TempDir,
    Arc<ServerState>,
    Issuer,
    Arc<Minter>,
    Provider,
) {
    let (directory, mut state) = protected_state().await;
    let minter = Arc::new(Minter {
        calls: AtomicUsize::new(0),
        descriptor,
    });
    let mut registry = openshell_credential_issuer::builtins::registry();
    registry.register_custom(minter.clone()).unwrap();
    let issuer = Issuer::with_minters(Arc::new(registry)).await;
    Arc::get_mut(&mut state).unwrap().provider_source = Some(Arc::new(
        RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap(),
    ));
    {
        let state = Arc::get_mut(&mut state).unwrap();
        state.provider_profile_sources = state
            .provider_profile_sources
            .clone()
            .with_strategy_source(state.provider_source.as_ref().unwrap().clone());
    }
    let imported = run(
        &state,
        authed_request(ImportProviderProfilesRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            profiles: vec![ProviderProfileImportItem {
                source: "company.yaml".into(),
                profile: Some(ProviderProfile {
                    id: "company-profile".into(),
                    display_name: "Company".into(),
                    category: ProviderProfileCategory::Other.into(),
                    endpoints: vec![NetworkEndpoint {
                        host: "api.company.example".into(),
                        port: 443,
                        allow_uninspected_credentials: true,
                        ..Default::default()
                    }],
                    credentials: vec![ProviderProfileCredential {
                        name: "company_token".into(),
                        env_vars: vec!["COMPANY_TOKEN".into()],
                        auth_style: "bearer".into(),
                        header_name: "Authorization".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            }],
            request_id: id(),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(imported.imported, "{:?}", imported.diagnostics);
    let provider = Provider {
        metadata: Some(meta("custom-provider")),
        r#type: "company-profile".into(),
        profile_workspace: "default".into(),
        ..Default::default()
    };
    state.store.put_message(&provider).await.unwrap();
    let provider = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    (directory, state, issuer, minter, provider)
}
fn configure() -> ConfigureProviderRefreshRequest {
    ConfigureProviderRefreshRequest {
        provider: "custom-provider".into(),
        credential_key: "COMPANY_TOKEN".into(),
        strategy_name: "custom:company-sts".into(),
        material: HashMap::from([
            ("audience".into(), "private-audience".into()),
            ("seed".into(), "private-seed".into()),
        ]),
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        request_id: id(),
        ..Default::default()
    }
}

#[tokio::test]
async fn custom_configuration_uses_descriptor_classification_and_replays_without_minting() {
    let (_directory, state, issuer, minter, provider) = context(descriptor()).await;
    let request = configure();
    let response = run(&state, authed_request(request.clone()))
        .await
        .unwrap()
        .into_inner();
    let status = response.status.as_ref().unwrap();
    assert_eq!(status.strategy, 0);
    assert_eq!(status.strategy_name, "custom:company-sts");
    assert_eq!(status.status, "configured");
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
    assert_eq!(replay(&state, request.clone()).await, response);
    let current = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let version = current.metadata.as_ref().unwrap().resource_version;
    let source = state.remote_provider_mutations().unwrap().unwrap();
    let owned = StaticHandoff::published_for_provider(&state.store, source, &current)
        .await
        .unwrap();
    assert_eq!(owned.len(), 1);
    assert_eq!(
        owned[0].published_grant(&current).unwrap().credential_keys,
        ["COMPANY_TOKEN"]
    );
    let rotation = RotateProviderCredentialRequest {
        provider: "custom-provider".into(),
        credential_key: "COMPANY_TOKEN".into(),
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        request_id: id(),
    };
    let rotated = run(&state, authed_request(rotation.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(rotated.status.as_ref().unwrap().status, "refreshed");
    assert_eq!(replay(&state, rotation).await, rotated);
    assert_eq!(replay(&state, request).await, response);
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
    issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    let values = source
        .resolve_provider_handles(&current, crate::persistence::current_time_ms())
        .await
        .unwrap();
    assert_eq!(values.values["COMPANY_TOKEN"], "private-company-token");
    let sandbox = Sandbox {
        metadata: Some(meta("consumer")),
        spec: Some(SandboxSpec {
            policy: Some(SandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            providers: vec!["custom-provider".into()],
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&sandbox).await.unwrap();
    let inputs = policy::load_sandbox_config_inputs(&state, sandbox.clone())
        .await
        .unwrap();
    let snapshot =
        policy::build_provider_environment_snapshot_from_inputs(&state, &inputs, true, true)
            .await
            .unwrap();
    assert_eq!(
        snapshot
            .values
            .iter()
            .find(|value| value.name == "COMPANY_TOKEN")
            .unwrap()
            .value,
        "private-company-token"
    );
    let binding = snapshot.values[0]
        .static_credential_binding
        .as_ref()
        .unwrap();
    assert!(!binding.workload_credential_handle.is_empty());
    let rotation = RotateProviderCredentialRequest {
        provider: "custom-provider".into(),
        credential_key: "COMPANY_TOKEN".into(),
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        request_id: id(),
    };
    run(&state, authed_request(rotation)).await.unwrap();
    issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    let next_inputs = policy::load_sandbox_config_inputs(&state, sandbox)
        .await
        .unwrap();
    let next =
        policy::build_provider_environment_snapshot_from_inputs(&state, &next_inputs, true, true)
            .await
            .unwrap();
    assert_ne!(snapshot.provider_env_revision, next.provider_env_revision);
    assert_eq!(
        snapshot.values[0].static_credential_binding,
        next.values[0].static_credential_binding
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        state
            .store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap()
            .metadata
            .unwrap()
            .resource_version,
        version
    );
    assert!(
        state
            .store
            .list_by_type_after("provider_credential_refresh_state", None, 100)
            .await
            .unwrap()
            .is_empty()
    );
    for kind in ["provider", "credential_issuer_handoff_v1", OBJECT_TYPE] {
        for row in state
            .store
            .list_by_type_after(kind, None, 100)
            .await
            .unwrap()
        {
            let bytes = String::from_utf8_lossy(&row.payload);
            for secret in ["private-audience", "private-seed", "private-company-token"] {
                assert!(!bytes.contains(secret), "{kind}");
            }
        }
    }
}

#[tokio::test]
async fn invalid_custom_inputs_never_allocate_a_handoff_or_change_the_provider() {
    let (_directory, state, issuer, minter, provider) = context(descriptor()).await;
    let before = state
        .store
        .get("provider", provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let mut cases = Vec::new();
    let mut request = configure();
    request.strategy = 3;
    cases.push(request);
    let mut request = configure();
    request.strategy = i32::MAX;
    cases.push(request);
    let mut request = configure();
    request.strategy_name = "custom:absent".into();
    cases.push(request);
    let mut request = configure();
    request.material.remove("seed");
    cases.push(request);
    let mut request = configure();
    request.material.insert("audience".into(), " ".into());
    cases.push(request);
    let mut request = configure();
    request
        .material
        .insert("unexpected".into(), "private-unknown".into());
    cases.push(request);
    let mut request = configure();
    request.secret_material_keys = vec!["audience".into()];
    cases.push(request);
    let mut request = configure();
    request.secret_material_keys = vec!["absent".into()];
    cases.push(request);
    for key in ["refresh_before_seconds", "max_lifetime_seconds"] {
        for value in ["-1", "43201", "private-noninteger"] {
            let mut request = configure();
            request.material.insert(key.into(), value.into());
            cases.push(request);
        }
    }
    let mut request = configure();
    request.expiration_time = Some(prost_types::Timestamp {
        seconds: 1,
        nanos: 0,
    });
    cases.push(request);
    for request in cases {
        let error = run(&state, authed_request(request)).await.unwrap_err();
        assert!(matches!(
            error.code(),
            Code::InvalidArgument | Code::FailedPrecondition
        ));
        assert!(!error.message().contains("private-"));
    }
    assert_eq!(
        state
            .store
            .get("provider", provider.object_id())
            .await
            .unwrap()
            .unwrap()
            .payload,
        before.payload
    );
    assert!(
        state
            .store
            .list_by_type_after("credential_issuer_handoff_v1", None, 100)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn custom_configuration_rejects_ambiguous_outputs_and_reserved_descriptor_fields() {
    let mut multi = descriptor();
    multi.outputs.push("another_output".into());
    let mut reserved = descriptor();
    reserved.config.push(MaterialDescriptor {
        name: "max_lifetime_seconds".into(),
        required: false,
    });
    for descriptor in [multi, reserved] {
        let (_directory, state, _issuer, minter, _provider) = context(descriptor).await;
        assert_eq!(
            run(&state, authed_request(configure()))
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        assert!(
            state
                .store
                .list_by_type_after("credential_issuer_handoff_v1", None, 100)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn custom_configuration_without_selected_issuer_does_not_enter_embedded_refresh() {
    let (_directory, state) = protected_state().await;
    let error = run(&state, authed_request(configure())).await.unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(
        state
            .store
            .list_by_type_after("provider_credential_refresh_state", None, 100)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn custom_configuration_retires_the_previous_epoch_and_fences_its_replay() {
    let (_directory, state, issuer, minter, provider) = context(descriptor()).await;
    let first = configure();
    run(&state, authed_request(first.clone())).await.unwrap();
    let old = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let source = state.remote_provider_mutations().unwrap().unwrap();
    let journals = StaticHandoff::published_for_provider(&state.store, source, &old)
        .await
        .unwrap();
    let binding = journals[0].published_grant(&old).unwrap();
    let sandbox = Sandbox {
        metadata: Some(meta("epoch-consumer")),
        spec: Some(SandboxSpec {
            policy: Some(SandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            providers: vec!["custom-provider".into()],
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&sandbox).await.unwrap();
    let rotate = || RotateProviderCredentialRequest {
        provider: "custom-provider".into(),
        credential_key: "COMPANY_TOKEN".into(),
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        request_id: id(),
    };
    let old_rotation = rotate();
    run(&state, authed_request(old_rotation.clone()))
        .await
        .unwrap();
    issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    let old_inputs = policy::load_sandbox_config_inputs(&state, sandbox.clone())
        .await
        .unwrap();
    let old_snapshot =
        policy::build_provider_environment_snapshot_from_inputs(&state, &old_inputs, true, true)
            .await
            .unwrap();
    let mut second = configure();
    second.secret_material_keys = vec!["seed".into()];
    second
        .material
        .insert("refresh_before_seconds".into(), "0".into());
    second
        .material
        .insert("max_lifetime_seconds".into(), "120".into());
    let response = run(&state, authed_request(second.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay(&state, second).await, response);
    assert!(binding.restore(&state.store).await.is_err());
    assert_eq!(
        reason(&run(&state, authed_request(first)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    let current = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(old.credential_handles, current.credential_handles);
    assert_ne!(
        source.refresh_authorization_epochs(&old).unwrap(),
        source.refresh_authorization_epochs(&current).unwrap()
    );
    assert_eq!(
        reason(&run(&state, authed_request(old_rotation)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    run(&state, authed_request(rotate())).await.unwrap();
    issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    let new_inputs = policy::load_sandbox_config_inputs(&state, sandbox)
        .await
        .unwrap();
    let new_snapshot =
        policy::build_provider_environment_snapshot_from_inputs(&state, &new_inputs, true, true)
            .await
            .unwrap();
    let old_handle = &old_snapshot.values[0]
        .static_credential_binding
        .as_ref()
        .unwrap()
        .workload_credential_handle;
    let new_handle = &new_snapshot.values[0]
        .static_credential_binding
        .as_ref()
        .unwrap()
        .workload_credential_handle;
    assert!(!old_handle.is_empty());
    assert_ne!(old_handle, new_handle);
    assert_eq!(minter.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn custom_configuration_checks_attached_sandbox_environment_collisions_before_allocation() {
    let (_directory, state, _issuer, minter, _provider) = context(descriptor()).await;
    state
        .store
        .put_message(&Provider {
            metadata: Some(meta("existing-provider")),
            r#type: "custom".into(),
            credentials: HashMap::from([("COMPANY_TOKEN".into(), "private-other-token".into())]),
            ..Default::default()
        })
        .await
        .unwrap();
    state
        .store
        .put_message(&Sandbox {
            metadata: Some(meta("collision")),
            spec: Some(SandboxSpec {
                providers: vec!["custom-provider".into(), "existing-provider".into()],
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    let error = run(&state, authed_request(configure())).await.unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(error.message().contains("conflict"));
    assert!(
        state
            .store
            .list_by_type_after("credential_issuer_handoff_v1", None, 100)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn custom_configuration_cannot_override_profile_refresh_defaults() {
    let (_directory, state, _issuer, _minter, mut provider) = context(descriptor()).await;
    let imported = run(
        &state,
        authed_request(ImportProviderProfilesRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            profiles: vec![ProviderProfileImportItem {
                source: "profile.yaml".into(),
                profile: Some(ProviderProfile {
                    id: "profile-refresh".into(),
                    display_name: "Profile refresh".into(),
                    category: ProviderProfileCategory::Other.into(),
                    credentials: vec![ProviderProfileCredential {
                        name: "company_token".into(),
                        env_vars: vec!["COMPANY_TOKEN".into()],
                        refresh: Some(ProviderCredentialRefresh {
                            strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials
                                .into(),
                            token_url: "https://token.example/token".into(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            }],
            request_id: id(),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(imported.imported, "{:?}", imported.diagnostics);
    provider.r#type = "profile-refresh".into();
    provider.profile_workspace = "default".into();
    state.store.put_message(&provider).await.unwrap();
    let error = run(&state, authed_request(configure())).await.unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(error.message().contains("profile refresh"));
    assert!(
        state
            .store
            .list_by_type_after("credential_issuer_handoff_v1", None, 100)
            .await
            .unwrap()
            .is_empty()
    );
}
