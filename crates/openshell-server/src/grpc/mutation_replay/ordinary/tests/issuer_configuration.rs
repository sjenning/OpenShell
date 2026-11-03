// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::credential_source::{
    ProviderCredentialSource as _, RemoteProviderSource, handoff::StaticHandoff,
    tests::issuer::Issuer,
};
use std::sync::atomic::Ordering;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
async fn context(endpoint: &str) -> (tempfile::TempDir, Arc<ServerState>, Issuer, Provider) {
    let (directory, mut state) = protected_state().await;
    let issuer =
        Issuer::with_minters(Arc::new(openshell_credential_issuer::builtins::registry())).await;
    Arc::get_mut(&mut state).unwrap().provider_source = Some(Arc::new(
        RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap(),
    ));
    let profile = ProviderProfile {
        id: "issuer-profile".into(),
        display_name: "Issuer".into(),
        category: ProviderProfileCategory::Other.into(),
        credentials: vec![ProviderProfileCredential {
            name: "access_token".into(),
            env_vars: vec!["ACCESS_TOKEN".into()],
            auth_style: "bearer".into(),
            header_name: "Authorization".into(),
            refresh: Some(ProviderCredentialRefresh {
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials.into(),
                token_url: endpoint.into(),
                material: vec![
                    ProviderCredentialRefreshMaterial {
                        name: "client_id".into(),
                        required: true,
                        ..Default::default()
                    },
                    ProviderCredentialRefreshMaterial {
                        name: "client_secret".into(),
                        secret: true,
                        required: true,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    let imported = run(
        &state,
        authed_request(ImportProviderProfilesRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            profiles: vec![ProviderProfileImportItem {
                profile: Some(profile),
                source: "issuer.yaml".into(),
            }],
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(imported.imported, "{:?}", imported.diagnostics);
    let provider = run(
        &state,
        authed_request(CreateProviderRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            provider: Some(Provider {
                metadata: Some(meta("issuer-provider")),
                r#type: "issuer-profile".into(),
                profile_workspace: "default".into(),
                credentials: HashMap::from([(
                    "ACCESS_TOKEN".into(),
                    "private-original-token".into(),
                )]),
                ..Default::default()
            }),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .provider
    .unwrap();
    (directory, state, issuer, provider)
}
fn configure(secret: &str) -> ConfigureProviderRefreshRequest {
    ConfigureProviderRefreshRequest {
        provider: "issuer-provider".into(),
        credential_key: "ACCESS_TOKEN".into(),
        strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials.into(),
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        request_id: id(),
        material: HashMap::from([
            ("client_id".into(), "private-client-id".into()),
            ("client_secret".into(), secret.into()),
        ]),
        ..Default::default()
    }
}
#[tokio::test]
async fn public_remote_configuration_is_value_free_replayable_and_mints_only_through_the_issuer() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"access_token":"private-minted-token","token_type":"Bearer","expires_in":3600}))).expect(1).mount(&server).await;
    let (_directory, state, issuer, provider) = context(&server.uri()).await;
    let req = configure("private-configured-secret");
    let response = run(&state, authed_request(req.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.status.as_ref().unwrap().status, "configured");
    assert!(response.status.as_ref().unwrap().expiration_time.is_none());
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
    assert!(server.received_requests().await.unwrap().is_empty());
    let current = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(current.credential_handles, provider.credential_handles);
    let version = current.metadata.as_ref().unwrap().resource_version;
    issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        state
            .remote_provider_mutations()
            .unwrap()
            .unwrap()
            .resolve_provider_handles(&current, crate::persistence::current_time_ms())
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(replay(&state, req.clone()).await, response);
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
    let rotated = run(
        &state,
        authed_request(RotateProviderCredentialRequest {
            provider: "issuer-provider".into(),
            credential_key: "ACCESS_TOKEN".into(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            request_id: id(),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(rotated.status.unwrap().status, "refreshed");
    assert_eq!(replay(&state, req).await, response);
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
            for secret in [
                "private-client-id",
                "private-configured-secret",
                "private-original-token",
                "private-minted-token",
            ] {
                assert!(!bytes.contains(secret), "{kind}");
            }
        }
    }
    server.verify().await;
}
#[tokio::test]
async fn remote_reconfiguration_replaces_the_entire_epoch_and_rejects_old_request_replay() {
    let (_directory, state, _issuer, provider) =
        context("https://issuer-upstream.example/token").await;
    let original = configure("first-private-secret");
    run(&state, authed_request(original.clone())).await.unwrap();
    let source = state.remote_provider_mutations().unwrap().unwrap();
    let first = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let owned = StaticHandoff::published_for_provider(&state.store, source, &first)
        .await
        .unwrap();
    let first_binding = owned
        .iter()
        .find(|handoff| handoff.grant_id().is_some())
        .unwrap()
        .published_grant(&first)
        .unwrap();
    let changed = configure("second-private-secret");
    let result = run(&state, authed_request(changed.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay(&state, changed).await, result);
    let next = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(next.credential_handles, first.credential_handles);
    assert!(first_binding.restore(&state.store).await.is_err());
    assert_eq!(
        reason(&run(&state, authed_request(original)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
}
#[tokio::test]
async fn invalid_remote_configuration_does_not_allocate_or_change_the_provider() {
    let (_directory, state, _issuer, provider) =
        context("https://issuer-upstream.example/token").await;
    let before = state
        .store
        .get("provider", provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let journals = state
        .store
        .list_by_type_after("credential_issuer_handoff_v1", None, 100)
        .await
        .unwrap()
        .len();
    let mut request = configure("private-secret");
    request.material.insert(
        "sts_endpoint_url".into(),
        "https://never-contact.example".into(),
    );
    assert!(run(&state, authed_request(request)).await.is_err());
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
    assert_eq!(
        state
            .store
            .list_by_type_after("credential_issuer_handoff_v1", None, 100)
            .await
            .unwrap()
            .len(),
        journals
    );
}
#[tokio::test]
async fn remote_aws_configuration_publishes_a_complete_pending_output_bundle() {
    let (_directory, state, issuer, _provider) =
        context("https://issuer-upstream.example/token").await;
    let provider = run(
        &state,
        authed_request(CreateProviderRequest {
            provider: Some(Provider {
                metadata: Some(meta("aws-issuer")),
                r#type: "aws".into(),
                ..Default::default()
            }),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .provider
    .unwrap();
    let request = ConfigureProviderRefreshRequest {
        provider: "aws-issuer".into(),
        credential_key: "AWS_ACCESS_KEY_ID".into(),
        strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole.into(),
        material: HashMap::from([(
            "role_arn".into(),
            "arn:aws:iam::123456789012:role/Test".into(),
        )]),
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        request_id: id(),
        ..Default::default()
    };
    let response = run(&state, authed_request(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.status.as_ref().unwrap().status, "configured");
    assert_eq!(replay(&state, request).await, response);
    let current = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.credential_handles.len(), 3);
    for key in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ] {
        assert!(current.credential_handles.contains_key(key));
    }
    let source = state.remote_provider_mutations().unwrap().unwrap();
    let journals = StaticHandoff::published_for_provider(&state.store, source, &current)
        .await
        .unwrap();
    assert_eq!(journals.len(), 1);
    let binding = journals[0].published_grant(&current).unwrap();
    assert_eq!(binding.credential_keys.len(), 3);
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn concurrent_remote_configuration_retries_publish_one_grant_epoch() {
    let (_directory, state, _issuer, provider) =
        context("https://issuer-upstream.example/token").await;
    let request = configure("private-concurrent-secret");
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let state = state.clone();
        let request = request.clone();
        tasks.spawn(async move { run(&state, authed_request(request)).await });
    }
    while let Some(result) = tasks.join_next().await {
        if let Err(status) = result.unwrap() {
            assert_eq!(reason(&status), "REQUEST_OUTCOME_UNCERTAIN");
        }
    }
    let result = replay(&state, request).await;
    assert_eq!(result.status.unwrap().status, "configured");
    let current = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        current.metadata.as_ref().unwrap().resource_version,
        provider.metadata.as_ref().unwrap().resource_version + 1
    );
    let source = state.remote_provider_mutations().unwrap().unwrap();
    let owned = StaticHandoff::published_for_provider(&state.store, source, &current)
        .await
        .unwrap();
    assert_eq!(owned.len(), 1);
    assert!(owned[0].grant_id().is_some());
    assert_eq!(
        state
            .store
            .list_by_type_after("credential_issuer_handoff_v1", None, 100)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn deleting_builtin_refresh_keeps_profile_credentials_exportable_without_another_mint() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"access_token":"private-final-token","token_type":"Bearer","expires_in":3600}))).expect(1).mount(&server).await;
    let (_directory, state, issuer, provider) = context(&server.uri()).await;
    run(&state, authed_request(configure("private-secret")))
        .await
        .unwrap();
    run(
        &state,
        authed_request(RotateProviderCredentialRequest {
            provider: "issuer-provider".into(),
            credential_key: "ACCESS_TOKEN".into(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            request_id: id(),
        }),
    )
    .await
    .unwrap();
    run(
        &state,
        authed_request(DeleteProviderRefreshRequest {
            provider: "issuer-provider".into(),
            credential_key: "ACCESS_TOKEN".into(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            request_id: id(),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    let current = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let source = state.remote_provider_mutations().unwrap().unwrap();
    assert!(
        source
            .refresh_statuses(&state.store, &current, "")
            .await
            .unwrap()
            .is_empty()
    );
    let mut request = Request::new(openshell_core::proto::GetProviderCredentialsRequest {
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        name: "issuer-provider".into(),
        credential_keys: vec!["ACCESS_TOKEN".into()],
        minimum_remaining_lifetime: None,
    });
    request.extensions_mut().insert(Principal::Operator(
        crate::auth::principal::OperatorPrincipal {
            identity: Identity {
                subject: "operator-test".into(),
                display_name: None,
                roles: vec!["operator".into()],
                scopes: vec![],
                provider: IdentityProvider::Mtls,
            },
            certificate_sha256: "verified-test-certificate".into(),
        },
    ));
    let exported = crate::grpc::provider_credentials::handle(&state, request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        exported.credentials["ACCESS_TOKEN"].value,
        "private-final-token"
    );
    assert!(
        exported.credentials["ACCESS_TOKEN"]
            .expiration_time
            .is_some()
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
