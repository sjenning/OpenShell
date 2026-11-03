// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::credential_source::ProviderCredentialSource as _;
#[tokio::test]
async fn selected_issuer_status_reads_metadata_only_and_groups_outputs_by_primary_key() {
    let store = test_store().await;
    let (issuer, source, minter) = issuer().await;
    let (_handoff, provider) = published(&store, &source).await;
    let row = store
        .get("provider", provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let reads = issuer.resolves.load(Ordering::SeqCst);
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    let statuses = source
        .refresh_statuses(&store, &provider, "")
        .await
        .unwrap();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].credential_key, "TOKEN");
    assert_eq!(statuses[0].strategy_name, "custom:journal");
    assert_eq!(statuses[0].status, "refreshed");
    assert!(statuses[0].expiration_time.is_some());
    assert_eq!(
        source
            .refresh_statuses(&store, &provider, "TOKEN")
            .await
            .unwrap(),
        statuses
    );
    assert!(
        source
            .refresh_statuses(&store, &provider, "OTHER_TOKEN")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        source
            .refresh_statuses(&store, &provider, "UNKNOWN")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), reads);
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
    let after = store
        .get("provider", provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.resource_version, row.resource_version);
    assert_eq!(after.payload, row.payload);
}
#[tokio::test]
async fn remote_status_never_reads_or_falls_back_to_embedded_grant_records() {
    use openshell_core::proto::ProviderCredentialRefreshStrategy;
    let store = test_store().await;
    let (_issuer, source, _minter) = issuer().await;
    let (_handoff, provider) = published(&store, &source).await;
    let mut shadow = crate::provider_refresh::new_refresh_state(
        &provider,
        "default",
        "SHADOW",
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
    shadow.status = "embedded-only".into();
    crate::provider_refresh::create_refresh_state(&store, &shadow)
        .await
        .unwrap();
    let statuses = source
        .refresh_statuses(&store, &provider, "")
        .await
        .unwrap();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].credential_key, "TOKEN");
    assert!(
        source
            .refresh_statuses(&store, &provider, "SHADOW")
            .await
            .unwrap()
            .is_empty()
    );
}
#[tokio::test]
async fn refresh_metadata_requires_current_complete_grant_ownership() {
    let store = test_store().await;
    let (_issuer, source, _minter) = issuer().await;
    let (handoff, mut provider) = published(&store, &source).await;
    let binding = source
        .decode(&provider.credential_handles["TOKEN"])
        .unwrap();
    provider.credential_handles.insert(
        "TOKEN".into(),
        source
            .reference_handle(&binding.reference, Some("different-grant"))
            .unwrap(),
    );
    assert_eq!(
        source
            .refresh_statuses(&store, &provider, "")
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let provider = store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    store
        .write_atomically(&[AtomicWrite::Delete {
            object_type: KIND.into(),
            id: handoff.id().into(),
            expected_version: handoff.revision,
        }])
        .await
        .unwrap();
    assert_eq!(
        source
            .refresh_statuses(&store, &provider, "")
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
}
#[tokio::test]
async fn status_projection_fences_a_stale_provider_identity_after_remote_reads() {
    let store = test_store().await;
    let (_issuer, source, minter) = issuer().await;
    let (_handoff, mut provider) = published(&store, &source).await;
    provider.metadata.as_mut().unwrap().name = "stale-name".into();
    let error = source
        .refresh_statuses(&store, &provider, "")
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Aborted);
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
}
