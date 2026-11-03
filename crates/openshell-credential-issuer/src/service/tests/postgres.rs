// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
#[ignore = "requires a disposable OPENSHELL_TEST_ISSUER_POSTGRES_URL"]
async fn postgres_store_replicas_share_idempotency_and_fence_updates_and_cleanup() {
    let url = std::env::var("OPENSHELL_TEST_ISSUER_POSTGRES_URL")
        .expect("set disposable issuer postgres URL");
    let actor = format!("spiffe://test.example/gateway/pg-{}", uuid::Uuid::new_v4());
    let scope = test_scope(&actor);
    let policy =
        GatewayPolicy::new(BTreeMap::from([(actor, vec!["default".to_string()])])).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut config = toml::Table::new();
    config.insert(
        "key_encryption_key_path".to_string(),
        toml::Value::String(dir.path().join("shared-key.bin").display().to_string()),
    );
    let repository_a = Repository::open(&url).await.unwrap();
    let repository_b = Repository::open(&url).await.unwrap();
    let build = |repository: &Arc<Repository>| {
        let driver: Arc<dyn CredentialDriver> = Arc::new(
            DbCredstoreCredentialDriver::from_config(repository.backend_objects(), &config)
                .unwrap(),
        );
        CredentialStorage::new(
            BTreeMap::from([("db".to_string(), driver)]),
            "db".to_string(),
        )
        .unwrap()
    };
    let a = CredentialStoreService::new(
        repository_a.clone(),
        build(&repository_a),
        policy.clone(),
        Duration::ZERO,
    )
    .unwrap()
    .runtime;
    let b = CredentialStoreService::new(
        repository_b.clone(),
        build(&repository_b),
        policy,
        Duration::ZERO,
    )
    .unwrap()
    .runtime;
    let (first, repeated) = tokio::join!(
        a.clone()
            .put(scope.clone(), put(), idempotency("put-one").unwrap()),
        b.clone()
            .put(scope.clone(), put(), idempotency("put-one").unwrap())
    );
    let first = first.unwrap();
    assert_eq!(first, repeated.unwrap());
    assert_eq!(
        repository_a
            .for_gateway(&scope)
            .events_after(0, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    let update = |key: &str, value: &str| wire::PutSecretRequest {
        reference: first.reference.clone(),
        expected_version: Some(1),
        value: value.to_string(),
        idempotency_key: key.to_string(),
        ..put()
    };
    let (left, right) = tokio::join!(
        a.clone().put(
            scope.clone(),
            update("left", "left-value"),
            idempotency("left").unwrap()
        ),
        b.clone().put(
            scope.clone(),
            update("right", "right-value"),
            idempotency("right").unwrap()
        )
    );
    assert_ne!(left.is_ok(), right.is_ok());
    let error = if let Err(error) = left {
        error
    } else {
        right.unwrap_err()
    };
    assert_eq!(error.code(), Code::Aborted);
    a.maintenance().await.unwrap();
    b.maintenance().await.unwrap();
    let store = repository_a.for_gateway(&scope);
    assert_eq!(store.current_sequence().await.unwrap(), 2);
    assert!(
        store
            .list(CANDIDATE_KIND, None, 128)
            .await
            .unwrap()
            .is_empty()
    );
    let state = repository_b
        .references(&scope)
        .load(&first.reference)
        .await
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(state.version, 2);
    assert!(state.pending_deletions.is_empty());
    let response = b
        .resolve(
            &scope,
            resolve(&first.reference, wire::ResolvePurpose::SandboxDelivery),
        )
        .await
        .unwrap();
    assert!(["left-value", "right-value"].contains(&response.secrets[0].value.as_str()));
    let repeated = a
        .clone()
        .put(scope, put(), idempotency("put-one").unwrap())
        .await
        .unwrap();
    assert_eq!(repeated, first);
}
