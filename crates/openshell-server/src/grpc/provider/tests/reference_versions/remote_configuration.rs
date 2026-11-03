// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    credential_source::{RemoteProviderSource, tests::issuer::Issuer},
    grpc::{
        provider::{handle_configure_provider_refresh, handle_import_provider_profiles},
        test_support::{authed_request, test_server_state},
    },
};
use openshell_core::proto::{
    ConfigureProviderRefreshRequest, ImportProviderProfilesRequest, ProviderCredentialRefresh,
    ProviderCredentialRefreshMaterial, ProviderCredentialRefreshStrategy, ProviderProfile,
    ProviderProfileCategory, ProviderProfileCredential, ProviderProfileImportItem,
};

#[tokio::test]
async fn remote_builtin_configuration_rejects_expiration_before_initial_or_replacement_effects() {
    let mut state = test_server_state().await;
    let issuer =
        Issuer::with_minters(Arc::new(openshell_credential_issuer::builtins::registry())).await;
    Arc::get_mut(&mut state).unwrap().provider_source = Some(Arc::new(
        RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap(),
    ));
    let profile = ProviderProfile {
        id: "issuer-expiration".into(),
        display_name: "Issuer expiration".into(),
        category: ProviderProfileCategory::Other.into(),
        credentials: vec![ProviderProfileCredential {
            name: "access_token".into(),
            env_vars: vec!["TOKEN".into()],
            auth_style: "bearer".into(),
            header_name: "Authorization".into(),
            refresh: Some(ProviderCredentialRefresh {
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials.into(),
                token_url: "https://issuer.example/token".into(),
                material: vec![
                    ProviderCredentialRefreshMaterial {
                        name: "client_id".into(),
                        required: true,
                        ..Default::default()
                    },
                    ProviderCredentialRefreshMaterial {
                        name: "client_secret".into(),
                        required: true,
                        secret: true,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    let imported = handle_import_provider_profiles(
        &state,
        authed_request(ImportProviderProfilesRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            profiles: vec![ProviderProfileImportItem {
                profile: Some(profile),
                source: "expiration.yaml".into(),
            }],
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(imported.imported, "{:?}", imported.diagnostics);
    let mut provider = provider();
    provider.r#type = "issuer-expiration".into();
    provider.profile_workspace = "default".into();
    state.store.put_message(&provider).await.unwrap();
    for configured in [false, true] {
        let before = state
            .store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap();
        let before_journals = state
            .store
            .list_by_type_after("credential_issuer_handoff_v1", None, 100)
            .await
            .unwrap()
            .len();
        for expiration in [0, 1, current_time_ms() + 60_000] {
            let error = handle_configure_provider_refresh(
                &state,
                authed_request(ConfigureProviderRefreshRequest {
                    workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                    provider: "provider".into(),
                    credential_key: "TOKEN".into(),
                    strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials.into(),
                    material: HashMap::from([
                        ("client_id".into(), "client".into()),
                        ("client_secret".into(), "rejected-secret".into()),
                    ]),
                    expiration_time: Some(
                        openshell_core::time::timestamp_from_millis(expiration).unwrap(),
                    ),
                    ..Default::default()
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
            assert!(error.message().contains("omit expiration_time"));
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
                before_journals
            );
        }
        if !configured {
            let response = handle_configure_provider_refresh(
                &state,
                authed_request(ConfigureProviderRefreshRequest {
                    workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                    provider: "provider".into(),
                    credential_key: "TOKEN".into(),
                    strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials.into(),
                    material: HashMap::from([
                        ("client_id".into(), "client".into()),
                        ("client_secret".into(), "accepted-secret".into()),
                    ]),
                    ..Default::default()
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(response.status.unwrap().status, "configured");
        }
    }
    assert_eq!(issuer.resolves.load(std::sync::atomic::Ordering::SeqCst), 0);
}
