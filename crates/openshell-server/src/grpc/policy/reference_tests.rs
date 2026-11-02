// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::tests::{test_provider, test_sandbox};
use super::*;
use crate::grpc::test_support::test_server_state;

async fn versioned_provider(state: &ServerState) -> Provider {
    let mut provider = test_provider("versioned", "github");
    provider.credential_handles = state
        .credentials
        .store_provider_credentials_with_object_id(
            "versioned",
            "default",
            "provider-versioned",
            "initial-epoch",
            &provider.credentials,
            &HashMap::new(),
        )
        .await
        .unwrap();
    provider.credentials.clear();
    state.store.put_message(&provider).await.unwrap();
    provider
}

#[tokio::test]
async fn issuer_rotation_changes_both_snapshot_revisions_without_changing_provider() {
    let state = test_server_state().await;
    let provider = versioned_provider(&state).await;
    let record_before = state
        .store
        .get("provider", "provider-versioned")
        .await
        .unwrap()
        .unwrap();
    let sandbox = test_sandbox(
        "sb-versioned",
        "versioned",
        ProtoSandboxPolicy {
            version: 1,
            ..Default::default()
        },
        vec!["versioned".into()],
    );
    state.store.put_message(&sandbox).await.unwrap();
    let initial = load_sandbox_config_inputs(&state, sandbox.clone())
        .await
        .unwrap();
    let before = build_provider_environment_snapshot_from_inputs(&state, &initial, true, true)
        .await
        .unwrap();
    let old_binding = before
        .values
        .iter()
        .find(|value| value.name == "GITHUB_TOKEN")
        .unwrap()
        .static_credential_binding
        .clone();
    let reference = &provider.credential_handles["GITHUB_TOKEN"];
    state
        .credentials
        .rotate_provider_reference(
            crate::credentials::references::provider_scope(&provider, "GITHUB_TOKEN"),
            reference,
            1,
            "new-token",
            None,
        )
        .await
        .unwrap();
    // Captured configuration metadata cannot be paired with a newer secret.
    assert_eq!(
        build_provider_environment_snapshot_from_inputs(&state, &initial, true, true)
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    let current = load_sandbox_config_inputs(&state, sandbox).await.unwrap();
    let config = build_sandbox_config_snapshot_from_inputs(&state, &current)
        .await
        .unwrap();
    let after = build_provider_environment_snapshot_from_inputs(&state, &current, true, true)
        .await
        .unwrap();
    assert_ne!(before.provider_env_revision, after.provider_env_revision);
    assert_eq!(config.provider_env_revision, after.provider_env_revision);
    let value = after
        .values
        .iter()
        .find(|value| value.name == "GITHUB_TOKEN")
        .unwrap();
    assert_eq!(value.value, "new-token");
    assert_eq!(
        value.static_credential_binding, old_binding,
        "value versions must not change placeholders or their authorization epoch"
    );
    let record_after = state
        .store
        .get("provider", "provider-versioned")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record_before.payload, record_after.payload);
    assert_eq!(
        record_before.resource_version,
        record_after.resource_version
    );
}

#[tokio::test]
async fn revoked_reference_delivers_an_unresolved_bootstrap_instead_of_stale_values() {
    use crate::config_delivery::session::{BootstrapOutcome, build_session_bootstrap};
    let state = test_server_state().await;
    let provider = versioned_provider(&state).await;
    let sandbox = test_sandbox(
        "sb-revoked",
        "revoked",
        ProtoSandboxPolicy {
            version: 1,
            ..Default::default()
        },
        vec!["versioned".into()],
    );
    state.store.put_message(&sandbox).await.unwrap();
    let initial = build_session_bootstrap(&state, &sandbox).await.unwrap();
    assert_eq!(initial.outcome, BootstrapOutcome::Built);
    assert!(!initial.config.provider_environment.values.is_empty());
    state.credentials.fail_next_delete();
    assert_eq!(
        state
            .credentials
            .delete_provider_credential_handles(
                "versioned",
                "default",
                "provider-versioned",
                &provider.credential_handles
            )
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    let revoked = build_session_bootstrap(&state, &sandbox).await.unwrap();
    assert_eq!(revoked.outcome, BootstrapOutcome::ProviderEnvironmentFailed);
    assert!(revoked.config.provider_environment.values.is_empty());
    assert_ne!(
        initial.config.sandbox_config.provider_env_revision,
        revoked.config.sandbox_config.provider_env_revision
    );
}
