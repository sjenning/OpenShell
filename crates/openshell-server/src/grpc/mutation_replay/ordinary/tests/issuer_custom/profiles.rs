// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use openshell_core::proto::{
    LintProviderProfilesRequest, ProviderCredentialRefreshMaterial,
    ProviderCredentialRefreshOutput, UpdateProviderProfilesRequest,
};

pub(super) async fn declared_profile(state: &Arc<ServerState>) -> ProviderProfile {
    let mut profile = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap()
        .get_profile("company-profile")
        .unwrap();
    profile.credentials[0].required = true;
    profile.credentials[0].refresh = Some(ProviderCredentialRefresh {
        strategy_name: "custom:company-sts".into(),
        refresh_before: Some(prost_types::Duration {
            seconds: 12,
            nanos: 345_000_000,
        }),
        max_lifetime: Some(prost_types::Duration {
            seconds: 120,
            nanos: 1,
        }),
        material: vec![
            ProviderCredentialRefreshMaterial {
                name: "audience".into(),
                required: true,
                ..Default::default()
            },
            ProviderCredentialRefreshMaterial {
                name: "seed".into(),
                required: true,
                secret: true,
                ..Default::default()
            },
        ],
        additional_outputs: vec![ProviderCredentialRefreshOutput {
            output: "auxiliary".into(),
            credential: "auxiliary".into(),
        }],
        ..Default::default()
    });
    profile.credentials.push(ProviderProfileCredential {
        name: "auxiliary".into(),
        env_vars: vec!["COMPANY_AUXILIARY".into()],
        required: true,
        ..Default::default()
    });
    profile
}
pub(super) async fn update_profile(state: &Arc<ServerState>, profile: ProviderProfile) {
    let response = run(
        state,
        authed_request(UpdateProviderProfilesRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            id: profile.id.clone(),
            expected_resource_version: profile.resource_version,
            profile: Some(ProviderProfileImportItem {
                profile: Some(profile),
                source: "company.yaml".into(),
            }),
            request_id: id(),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(response.updated, "{:?}", response.diagnostics);
}
pub(super) fn multi_descriptor() -> StrategyDescriptor {
    let mut descriptor = descriptor();
    // Additional output comes first: primary is inferred by exclusion, not order.
    descriptor.outputs.insert(0, "auxiliary".into());
    descriptor
}

#[tokio::test]
async fn multi_output_profile_configuration_preserves_bundle_replay_and_reconfiguration_fences() {
    let (_directory, state, issuer, minter, provider) = context(multi_descriptor()).await;
    update_profile(&state, declared_profile(&state).await).await;
    let profile = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap()
        .get_type_profile("company-profile")
        .unwrap();
    assert!(profile.allows_empty_provider_credentials());
    assert!(profile.required_static_credentials().is_empty());
    // Both selectors can come from the profile for a custom strategy.
    let mut request = configure();
    request.strategy_name.clear();
    let response = run(&state, authed_request(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        response.status.as_ref().unwrap().strategy_name,
        "custom:company-sts"
    );
    assert_eq!(replay(&state, request.clone()).await, response);
    let current = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.credential_handles.len(), 2);
    let source = state.remote_provider_mutations().unwrap().unwrap();
    let handoffs = StaticHandoff::published_for_provider(&state.store, source, &current)
        .await
        .unwrap();
    let binding = handoffs[0].published_grant(&current).unwrap();
    assert_eq!(binding.credential_keys.len(), 2);
    let rotation = RotateProviderCredentialRequest {
        provider: "custom-provider".into(),
        credential_key: "COMPANY_TOKEN".into(),
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        request_id: id(),
    };
    run(&state, authed_request(rotation.clone())).await.unwrap();
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
    assert_eq!(values.values["COMPANY_AUXILIARY"], "private-auxiliary");
    let second = configure();
    run(&state, authed_request(second.clone())).await.unwrap();
    assert_eq!(
        reason(&run(&state, authed_request(request)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    assert_eq!(
        reason(&run(&state, authed_request(rotation)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    assert!(binding.restore(&state.store).await.is_err());
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
    assert!(issuer.resolves.load(Ordering::SeqCst) >= 2);
}

#[tokio::test]
async fn multi_output_configuration_checks_secondary_collisions_before_allocating_any_handoff() {
    let (_directory, state, _issuer, minter, _provider) = context(multi_descriptor()).await;
    update_profile(&state, declared_profile(&state).await).await;
    state
        .store
        .put_message(&Provider {
            metadata: Some(meta("other")),
            r#type: "custom".into(),
            credentials: HashMap::from([("COMPANY_AUXILIARY".into(), "private-conflict".into())]),
            ..Default::default()
        })
        .await
        .unwrap();
    state
        .store
        .put_message(&Sandbox {
            metadata: Some(meta("collision")),
            spec: Some(SandboxSpec {
                providers: vec!["custom-provider".into(), "other".into()],
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
async fn public_lint_and_import_reject_unregistered_names_and_false_secret_annotations() {
    let (_directory, state, _issuer, _minter, _provider) = context(multi_descriptor()).await;
    for false_secret in [false, true] {
        let mut profile = declared_profile(&state).await;
        profile.id = if false_secret {
            "false-secret"
        } else {
            "unregistered"
        }
        .into();
        let refresh = profile.credentials[0].refresh.as_mut().unwrap();
        if false_secret {
            refresh.material[1].secret = false;
        } else {
            refresh.strategy_name = "custom:missing".into();
        }
        let item = ProviderProfileImportItem {
            profile: Some(profile),
            source: "rejected.yaml".into(),
        };
        let response = provider::handle_lint_provider_profiles(
            &state,
            authed_request(LintProviderProfilesRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                profiles: vec![item.clone()],
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(!response.valid);
        let response = run(
            &state,
            authed_request(ImportProviderProfilesRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                profiles: vec![item],
                request_id: id(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(!response.imported);
    }
}

#[tokio::test]
async fn builtin_configuration_cannot_bypass_a_custom_profile_refresh_declaration() {
    let (_directory, state, _issuer, _minter, _provider) = context(multi_descriptor()).await;
    update_profile(&state, declared_profile(&state).await).await;
    let mut request = configure();
    request.strategy_name = "oauth2_client_credentials".into();
    assert_eq!(
        run(&state, authed_request(request))
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
}
