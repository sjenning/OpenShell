// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use openshell_core::proto::UpdateProviderProfilesRequest;

fn update(profile: ProviderProfile) -> UpdateProviderProfilesRequest {
    UpdateProviderProfilesRequest {
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        id: profile.id.clone(),
        expected_resource_version: profile.resource_version,
        profile: Some(ProviderProfileImportItem {
            profile: Some(profile),
            source: "repair.yaml".into(),
        }),
        request_id: id(),
    }
}

fn delete() -> DeleteProviderProfileRequest {
    DeleteProviderProfileRequest {
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        id: "company-profile".into(),
        request_id: id(),
        ..Default::default()
    }
}

async fn missing_minter_context() -> (tempfile::TempDir, Arc<ServerState>, Issuer, ProviderProfile)
{
    let (directory, mut state, _issuer, _minter, provider) =
        context(profiles::multi_descriptor()).await;
    profiles::update_profile(&state, profiles::declared_profile(&state).await).await;
    let profile = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap()
        .get_profile("company-profile")
        .unwrap();
    // It is unused, so both repair and deletion must remain possible after a
    // restart against a selected issuer that no longer has this custom minter.
    state
        .store
        .delete(Provider::object_type(), provider.object_id())
        .await
        .unwrap();
    let empty =
        Issuer::with_minters(Arc::new(openshell_credential_issuer::builtins::registry())).await;
    let source: Arc<dyn crate::credential_source::ProviderCredentialSource> =
        Arc::new(RemoteProviderSource::new("primary", empty.watched.clone()).unwrap());
    let state_mut = Arc::get_mut(&mut state).unwrap();
    state_mut.admin_role = "openshell-admin".into();
    state_mut.provider_source = Some(source.clone());
    state_mut.provider_profile_sources = state_mut
        .provider_profile_sources
        .clone()
        .with_strategy_source(source);
    (directory, state, empty, profile)
}

#[tokio::test]
async fn missing_minter_profile_can_be_repaired_but_new_content_must_validate_live() {
    let (_directory, state, _empty, mut profile) = missing_minter_context().await;
    let error = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(error.message().contains("selected issuer catalog"));
    let sandbox = Sandbox {
        metadata: Some(meta("invalid-profile-consumer")),
        spec: Some(SandboxSpec {
            policy: Some(SandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(
        policy::build_sandbox_config_snapshot(&state, &sandbox)
            .await
            .is_err(),
        "management topology must not authorize runtime use"
    );
    let before = state
        .store
        .get_message_by_name::<StoredProviderProfile>("default", &profile.id)
        .await
        .unwrap()
        .unwrap();
    for strategy in ["custom:company-sts", "custom:still-missing"] {
        profile.credentials[0]
            .refresh
            .as_mut()
            .unwrap()
            .strategy_name = strategy.into();
        let result = run(&state, authed_request(update(profile.clone())))
            .await
            .unwrap()
            .into_inner();
        assert!(!result.updated);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("selected issuer catalog"))
        );
        let stored = state
            .store
            .get_message_by_name::<StoredProviderProfile>("default", &profile.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored, before);
    }
    profile.credentials[0].refresh = None;
    let mut outdated = update(profile.clone());
    outdated.expected_resource_version += 1;
    assert_eq!(
        run(&state, authed_request(outdated))
            .await
            .unwrap_err()
            .code(),
        Code::Aborted,
        "repair must retain resource-version fencing"
    );
    let request = update(profile);
    let response = run(&state, authed_request(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(response.updated, "{:?}", response.diagnostics);
    assert_eq!(replay(&state, request).await, response);
    let repaired = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap()
        .get_type_profile("company-profile")
        .unwrap();
    assert!(!repaired.allows_runtime_provider_credentials());
}

#[tokio::test]
async fn missing_minter_unused_profile_can_be_deleted_and_replayed() {
    let (_directory, state, _empty, _profile) = missing_minter_context().await;
    let request = delete();
    let response = run(&state, authed_request(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.outcome, i32::from(DeletionOutcome::Completed));
    assert_eq!(replay(&state, request).await, response);
    assert!(
        state
            .store
            .get_message_by_name::<StoredProviderProfile>("default", "company-profile")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn missing_minter_profile_deletion_still_blocks_existing_provider_references() {
    let (_directory, state, _empty, _profile) = missing_minter_context().await;
    state
        .store
        .put_message(&Provider {
            metadata: Some(meta("still-using-profile")),
            r#type: "company-profile".into(),
            profile_workspace: "default".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let error = run(&state, authed_request(delete())).await.unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(
        error
            .message()
            .contains("in use by providers: still-using-profile")
    );
}

#[tokio::test]
async fn missing_minter_repair_and_delete_still_require_workspace_admin() {
    let (_directory, state, _empty, mut profile) = missing_minter_context().await;
    state
        .store
        .put_message(&WorkspaceMember {
            metadata: Some(meta("dev-user")),
            principal_subject: "dev-user".into(),
            role: WorkspaceRole::User.into(),
        })
        .await
        .unwrap();
    profile.credentials[0].refresh = None;
    let mut request = authed_request(update(profile));
    let Principal::User(user) = request.extensions_mut().get_mut::<Principal>().unwrap() else {
        panic!("expected user");
    };
    user.identity.roles.clear();
    assert_eq!(
        run(&state, request).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    let mut request = authed_request(delete());
    let Principal::User(user) = request.extensions_mut().get_mut::<Principal>().unwrap() else {
        panic!("expected user");
    };
    user.identity.roles.clear();
    assert_eq!(
        run(&state, request).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    assert!(
        state
            .store
            .get_message_by_name::<StoredProviderProfile>("default", "company-profile")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn repair_topology_preserves_source_managed_ownership_and_conflicts() {
    let (_directory, mut state, _empty, mut profile) = missing_minter_context().await;
    let stored = state
        .store
        .get_message_by_name::<StoredProviderProfile>("default", &profile.id)
        .await
        .unwrap()
        .unwrap();
    let selected = state.provider_source.as_ref().unwrap().clone();
    let repair_sources =
        crate::provider_profile_sources::ProviderProfileSources::from_test_profiles_with_user_source(
            vec![profile.clone()],
        )
        .with_strategy_source(selected);
    Arc::get_mut(&mut state).unwrap().provider_profile_sources = repair_sources;
    // The same ID across an interceptor and user source is a topology error,
    // even though neither path needs to validate the unavailable minter.
    profile.credentials[0].refresh = None;
    for error in [
        run(&state, authed_request(update(profile.clone())))
            .await
            .unwrap_err(),
        run(&state, authed_request(delete())).await.unwrap_err(),
    ] {
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("across configured sources"));
    }
    state
        .store
        .delete(StoredProviderProfile::object_type(), stored.object_id())
        .await
        .unwrap();
    let response = run(&state, authed_request(update(profile)))
        .await
        .unwrap()
        .into_inner();
    assert!(!response.updated);
    assert!(
        response
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("managed by source"))
    );
    let error = run(&state, authed_request(delete())).await.unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(error.message().contains("managed by source"));
}
