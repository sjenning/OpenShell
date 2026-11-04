// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use openshell_core::proto::UpdateProviderProfilesRequest;

#[tokio::test]
async fn registered_custom_profile_import_and_failed_update_preserve_catalog_and_resource_version()
{
    let (_directory, state, _issuer, _minter, _provider) =
        context(profiles::multi_descriptor()).await;
    let mut profile = profiles::declared_profile(&state).await;
    profile.id = "imported-company".into();
    let response = run(
        &state,
        authed_request(ImportProviderProfilesRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            profiles: vec![ProviderProfileImportItem {
                profile: Some(profile),
                source: "company.yaml".into(),
            }],
            request_id: id(),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(response.imported, "{:?}", response.diagnostics);
    let mut imported = response.profiles[0].clone();
    let version = imported.resource_version;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap();
    assert!(
        catalog
            .get_type_profile("imported-company")
            .unwrap()
            .allows_runtime_provider_credentials()
    );
    imported.credentials[0]
        .refresh
        .as_mut()
        .unwrap()
        .strategy_name = "custom:unregistered".into();
    let response = run(
        &state,
        authed_request(UpdateProviderProfilesRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            id: imported.id.clone(),
            expected_resource_version: version,
            profile: Some(ProviderProfileImportItem {
                profile: Some(imported),
                source: "company.yaml".into(),
            }),
            request_id: id(),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(!response.updated);
    let current = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap()
        .get_profile("imported-company")
        .unwrap();
    assert_eq!(current.resource_version, version);
    assert_eq!(
        current.credentials[0]
            .refresh
            .as_ref()
            .unwrap()
            .strategy_name,
        "custom:company-sts"
    );
}

#[tokio::test]
async fn profile_lint_does_not_assume_builtin_strategies_exist_in_the_selected_issuer() {
    let (_directory, mut state, _issuer, _minter, _provider) = context(descriptor()).await;
    let empty = Issuer::start().await;
    let source: Arc<dyn crate::credential_source::ProviderCredentialSource> =
        Arc::new(RemoteProviderSource::new("primary", empty.watched.clone()).unwrap());
    let state_mut = Arc::get_mut(&mut state).unwrap();
    state_mut.provider_source = Some(source.clone());
    state_mut.provider_profile_sources = state_mut
        .provider_profile_sources
        .clone()
        .with_strategy_source(source);
    let profile = ProviderProfile {
        id: "missing-builtin".into(),
        display_name: "Missing builtin".into(),
        credentials: vec![ProviderProfileCredential {
            name: "token".into(),
            env_vars: vec!["TOKEN".into()],
            refresh: Some(ProviderCredentialRefresh {
                strategy_name: "oauth2_client_credentials".into(),
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    let response = provider::handle_lint_provider_profiles(
        &state,
        authed_request(openshell_core::proto::LintProviderProfilesRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            profiles: vec![ProviderProfileImportItem {
                profile: Some(profile),
                source: "builtin.yaml".into(),
            }],
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(!response.valid);
    assert!(
        response
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("selected issuer catalog"))
    );
}
