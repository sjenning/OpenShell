// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
#[tokio::test]
#[ignore = "requires OPENSHELL_TEST_ISSUER_POSTGRES_URL"]
async fn postgres_replicas_replay_reserved_bindings_and_initialize_only_once() {
    let url = std::env::var("OPENSHELL_TEST_ISSUER_POSTGRES_URL").unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = toml::Table::from_iter([(
        "key_encryption_key_path".into(),
        toml::Value::String(directory.path().join("key").to_str().unwrap().into()),
    )]);
    let identity = format!(
        "spiffe://test.example/gateway/reservation-{}",
        uuid::Uuid::new_v4()
    );
    let scope = test_scope(&identity);
    let policy = GatewayPolicy::new(BTreeMap::from([(identity, vec!["default".into()])])).unwrap();
    let minter = Arc::new(Minter::default());
    let (_, a) = services(
        Repository::open(&url).await.unwrap(),
        &config,
        policy.clone(),
        minter.clone(),
    );
    let (_, b) = services(
        Repository::open(&url).await.unwrap(),
        &config,
        policy,
        minter.clone(),
    );
    let request = super::super::reservations::reservation();
    minter.backend.store(true, Ordering::SeqCst);
    let (first, second) = tokio::join!(
        a.runtime
            .clone()
            .reserve(scope.clone(), request.clone(), "reserve".into()),
        b.runtime
            .clone()
            .reserve(scope.clone(), request.clone(), "reserve".into())
    );
    let reserved = first.unwrap();
    assert_eq!(second.unwrap(), reserved);
    a.runtime.tick().await.unwrap();
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
    minter.backend.store(false, Ordering::SeqCst);
    let initialize = super::super::reservations::initialization(&reserved.grant);
    let (first, second) = tokio::join!(
        a.runtime
            .clone()
            .initialize(scope.clone(), initialize.clone(), "initialize".into()),
        b.runtime
            .clone()
            .initialize(scope.clone(), initialize.clone(), "initialize".into())
    );
    let initialized = first.unwrap();
    assert_eq!(second.unwrap(), initialized);
    assert_eq!(initialized.status.unwrap().version, 2);
    assert_eq!(
        a.runtime
            .clone()
            .initialize(scope.clone(), initialize.clone(), "another-key".into())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    b.runtime
        .ensure(scope.clone(), reserved.grant.clone(), 0)
        .await
        .unwrap();
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
    b.runtime
        .clone()
        .delete(scope.clone(), reserved.grant.clone(), "delete".into())
        .await
        .unwrap();
    assert_eq!(
        a.runtime
            .clone()
            .initialize(scope.clone(), initialize, "initialize".into())
            .await
            .unwrap()
            .status
            .unwrap()
            .state,
        "pending"
    );
    minter.backend.store(true, Ordering::SeqCst);
    assert_eq!(
        a.runtime
            .clone()
            .reserve(scope, request, "reserve".into())
            .await
            .unwrap(),
        reserved
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
}
