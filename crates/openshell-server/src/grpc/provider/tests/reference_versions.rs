// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    IntermediateTokenCacheKeyInput, get_provider_record, intermediate_token_cache_key,
    list_provider_records,
};
use crate::credentials::{CredentialRuntime, references};
use crate::persistence::{current_time_ms, test_store};
use openshell_core::proto::{ObjectMeta, Provider};
use openshell_core::{Config, ObjectId};
use std::collections::HashMap;
use std::sync::Arc;

fn provider() -> Provider {
    Provider {
        metadata: Some(ObjectMeta {
            id: "provider-id".to_string(),
            name: "provider".to_string(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn subject_cache_identity_includes_reference_version_even_with_unchanged_provider_revision() {
    let provider = provider();
    let key = |version| {
        intermediate_token_cache_key(IntermediateTokenCacheKeyInput {
            provider: &provider,
            dynamic_credential: "ACCESS_TOKEN",
            subject_credential: "SUBJECT_TOKEN",
            subject_credential_version: version,
            token_endpoint: "https://example.test/token",
            client_assertion_type: "jwt-bearer",
            subject_token_type: "access_token",
            audience: "service",
            requested_token_type: "access_token",
            supervisor_subject: "spiffe://example/supervisor",
            gateway_subject: "spiffe://example/gateway",
        })
    };
    assert_eq!(key(1), key(1));
    assert_ne!(key(1), key(2));
}

#[tokio::test]
async fn get_and_list_project_current_reference_expiration_without_mutating_or_revealing_values() {
    let store = Arc::new(test_store().await);
    let runtime =
        CredentialRuntime::from_config_with_store(&Config::new(None), store.clone()).unwrap();
    let mut provider = provider();
    provider.credential_handles = runtime
        .store_provider_credentials(
            "provider",
            "default",
            "provider-id",
            &HashMap::from([("GITHUB_TOKEN".to_string(), "initial-secret".to_string())]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    let legacy_expiration = openshell_core::time::timestamp_from_millis(1).unwrap();
    provider
        .credential_expiration_times
        .insert("GITHUB_TOKEN".to_string(), legacy_expiration);
    store.put_message(&provider).await.unwrap();
    let before = store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        get_provider_record(&store, "default", "provider")
            .await
            .unwrap()
            .credential_expiration_times["GITHUB_TOKEN"],
        legacy_expiration
    );
    let current_expiration = current_time_ms() + 60_000;
    runtime
        .rotate_provider_reference(
            references::provider_scope(&provider, "GITHUB_TOKEN"),
            &provider.credential_handles["GITHUB_TOKEN"],
            1,
            "rotated-secret",
            Some(current_expiration),
        )
        .await
        .unwrap();
    let current_timestamp =
        openshell_core::time::timestamp_from_millis(current_expiration).unwrap();
    let get = get_provider_record(&store, "default", "provider")
        .await
        .unwrap();
    let list = list_provider_records(&store, "default", 10, 0)
        .await
        .unwrap();
    assert_eq!(
        get.credential_expiration_times["GITHUB_TOKEN"],
        current_timestamp
    );
    assert_eq!(
        list[0].credential_expiration_times["GITHUB_TOKEN"],
        current_timestamp
    );
    assert!(get.credential_handles.is_empty());
    assert_eq!(get.credentials["GITHUB_TOKEN"], "REDACTED");
    assert_eq!(
        store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap(),
        before
    );
    runtime
        .rotate_provider_reference(
            references::provider_scope(&provider, "GITHUB_TOKEN"),
            &provider.credential_handles["GITHUB_TOKEN"],
            2,
            "nonexpiring-secret",
            None,
        )
        .await
        .unwrap();
    assert!(
        !get_provider_record(&store, "default", "provider")
            .await
            .unwrap()
            .credential_expiration_times
            .contains_key("GITHUB_TOKEN")
    );
}
