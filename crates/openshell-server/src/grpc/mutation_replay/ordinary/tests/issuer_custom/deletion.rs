// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use openshell_core::proto::{DeleteProviderRefreshRequest, GetProviderRefreshStatusRequest};

fn deletion() -> DeleteProviderRefreshRequest {
    DeleteProviderRefreshRequest {
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        provider: "custom-provider".into(),
        credential_key: "COMPANY_TOKEN".into(),
        request_id: id(),
        ..Default::default()
    }
}

#[tokio::test]
async fn public_refresh_deletion_preserves_static_delivery_expiry_and_replays_without_reminting() {
    let (_directory, state, issuer, minter, provider) = context(descriptor()).await;
    let configured = configure();
    run(&state, authed_request(configured.clone()))
        .await
        .unwrap();
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
    let source = state.remote_provider_mutations().unwrap().unwrap();
    let before = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let before_versions = source
        .reference_versions(&state.store, &before)
        .await
        .unwrap();
    let before_values = source
        .resolve_provider_handles(&before, crate::persistence::current_time_ms())
        .await
        .unwrap();
    let request = deletion();
    let reads = issuer.resolves.load(Ordering::SeqCst);
    let result = run(&state, authed_request(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(result.outcome, i32::from(DeletionOutcome::Completed));
    assert_eq!(replay(&state, request.clone()).await, result);
    assert_eq!(
        issuer.resolves.load(Ordering::SeqCst),
        reads,
        "deletion and replay must not resolve credential values"
    );
    issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    let after = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(after.credential_handles, before.credential_handles);
    assert_eq!(
        source
            .reference_versions(&state.store, &after)
            .await
            .unwrap(),
        before_versions
    );
    assert_eq!(
        source
            .resolve_provider_handles(&after, crate::persistence::current_time_ms())
            .await
            .unwrap()
            .values,
        before_values.values
    );
    let mut old_expiry = before.clone();
    let mut new_expiry = after.clone();
    source
        .project_expiration_metadata(&state.store, &mut old_expiry)
        .await
        .unwrap();
    source
        .project_expiration_metadata(&state.store, &mut new_expiry)
        .await
        .unwrap();
    assert_eq!(
        old_expiry.credential_expiration_times,
        new_expiry.credential_expiration_times
    );
    assert!(
        source
            .refresh_authorization_epochs(&after)
            .unwrap()
            .is_empty()
    );
    let status = provider::handle_get_provider_refresh_status(
        &state,
        authed_request(GetProviderRefreshStatusRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            provider: "custom-provider".into(),
            credential_key: String::new(),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(status.credentials.is_empty());
    let exported = source
        .resolve_provider_handles_for(
            &after,
            crate::persistence::current_time_ms(),
            crate::credential_source::CredentialReadPurpose::OperatorExport,
        )
        .await
        .unwrap();
    assert_eq!(exported.values, before_values.values);
    let sandbox = Sandbox {
        metadata: Some(meta("static-consumer")),
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
    let inputs = policy::load_sandbox_config_inputs(&state, sandbox)
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
    assert!(
        snapshot.values[0]
            .static_credential_binding
            .as_ref()
            .unwrap()
            .workload_credential_handle
            .is_empty(),
        "deleting refresh retires its workload identity even though the value is preserved"
    );
    assert_eq!(
        run(&state, authed_request(deletion()))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    let mut missing = deletion();
    missing.allow_missing = true;
    assert_eq!(
        run(&state, authed_request(missing))
            .await
            .unwrap()
            .into_inner()
            .outcome,
        i32::from(DeletionOutcome::AlreadyAbsent)
    );
    assert!(
        run(&state, authed_request(configured)).await.is_err(),
        "old configuration replay must not authorize detached refresh"
    );
    assert!(
        run(&state, authed_request(rotation)).await.is_err(),
        "old rotation replay must not authorize detached refresh"
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
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
async fn public_refresh_deletion_before_first_mint_fails_without_losing_configuration() {
    let (_directory, state, _issuer, minter, provider) = context(descriptor()).await;
    run(&state, authed_request(configure())).await.unwrap();
    let before = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        run(&state, authed_request(deletion()))
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    let after = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn refresh_deletion_with_missing_ownership_cannot_report_already_absent() {
    let (_directory, state, _issuer, _minter, provider) = context(descriptor()).await;
    run(&state, authed_request(configure())).await.unwrap();
    let before = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let source = state.remote_provider_mutations().unwrap().unwrap();
    let owned = StaticHandoff::published_for_provider(&state.store, source, &before)
        .await
        .unwrap();
    state
        .store
        .delete("credential_issuer_handoff_v1", owned[0].id())
        .await
        .unwrap();
    let mut request = deletion();
    request.allow_missing = true;
    assert_eq!(
        run(&state, authed_request(request))
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        state
            .store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap(),
        before
    );
}
